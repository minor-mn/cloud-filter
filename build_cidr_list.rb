#!/usr/bin/env ruby
# frozen_string_literal: true

# ==============================================================================
# build_cidr_list.rb (Ruby 4.x)
# rezmoss/cloud-provider-ip-addresses から指定プロバイダーのCIDRを取得・統合し、
# ホワイトリスト減算および ipset restore 用スクリプトを生成する (外部gem依存ゼロ)
# ==============================================================================

require "fileutils"
require "ipaddr"
require "json"
require "net/http"
require "optparse"
require "socket"
require "uri"

module CloudFilter
  DEFAULT_PRIMARY_BASE_URL = "https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main"
  DEFAULT_FALLBACK_BASE_URL = "https://cdn.jsdelivr.net/gh/rezmoss/cloud-provider-ip-addresses@main"

  KNOWN_PROVIDERS = %w[
    akamai alibaba amazonbot apple_private_relay applebot atlassian aws azure
    backblaze baidu bingbot bunny cachefly circleci claudebot cloudflare
    commoncrawl contabo datadog digitalocean discord duckduckbot fastly gabia
    gcore github gocache googlebot googlecloud googleservices gptbot hetzner
    hostway huawei ibmcloud imperva internetarchive leaseweb linode meta
    microsoft365 mullvad nhncloud oracle ovhcloud perplexitybot pingdom play2go
    quiccloud rackspace salesforce scaleway statuscake stormwall sucuri teamcity
    telegram tencent tor upcloud uptimerobot vultr wasabi yandex zoho zoom zscaler
  ].freeze

  # Lightweight logger (Ruby 4.0 removed `logger` from default gems into bundled gems)
  class ConsoleLogger
    LEVELS = { debug: 0, info: 1, warn: 2, error: 3 }.freeze

    attr_accessor :level

    def initialize(io = $stdout, level: :info)
      @io = io
      @level = level
      @mutex = Mutex.new
    end

    def debug(msg) = log(:debug, msg)
    def info(msg)  = log(:info, msg)
    def warn(msg)  = log(:warn, msg)
    def error(msg) = log(:error, msg)

    private

    def log(severity, msg)
      return if LEVELS.fetch(severity) < LEVELS.fetch(@level)

      timestamp = Time.now.strftime("%Y-%m-%d %H:%M:%S")
      @mutex.synchronize do
        @io.puts("[#{timestamp}] #{severity.upcase}: #{msg}")
      end
    end
  end

  # Immutable CIDR value object using Ruby Data.define
  CidrNet = Data.define(:family, :max_bits, :net_int, :prefix, :last_int) do
    include Comparable

    def self.build(family, raw_net_int, prefix)
      max_bits = (family == Socket::AF_INET) ? 32 : 128
      shift = max_bits - prefix
      masked_net_int = (raw_net_int >> shift) << shift
      last_int = masked_net_int + (1 << shift) - 1
      new(family:, max_bits:, net_int: masked_net_int, prefix:, last_int:)
    end

    def self.parse(str)
      ip = IPAddr.new(str.strip)
      family = ip.ipv4? ? Socket::AF_INET : Socket::AF_INET6
      build(family, ip.to_i, ip.prefix)
    end

    def ipv4? = family == Socket::AF_INET
    def ipv6? = family == Socket::AF_INET6

    def overlaps?(other)
      family == other.family && net_int <= other.last_int && other.net_int <= last_int
    end

    def subnet_of?(other)
      family == other.family && other.net_int <= net_int && last_int <= other.last_int
    end

    # Subtract `excl` from `self`, returning an array of remaining CidrNet blocks
    def exclude(excl)
      return [self] unless overlaps?(excl)
      return [] if subnet_of?(excl)

      fragments = []
      cur = self
      while cur.prefix < excl.prefix
        next_prefix = cur.prefix + 1
        half_size = 1 << (max_bits - next_prefix)
        left = CidrNet.build(family, cur.net_int, next_prefix)
        right = CidrNet.build(family, cur.net_int + half_size, next_prefix)
        if excl.subnet_of?(left)
          fragments << right
          cur = left
        else
          fragments << left
          cur = right
        end
      end
      fragments
    end

    def <=>(other)
      return nil unless other.is_a?(CidrNet)

      [family, net_int, prefix] <=> [other.family, other.net_int, other.prefix]
    end

    def to_s = "#{IPAddr.new(net_int, family)}/#{prefix}"
  end

  class Builder
    attr_reader :logger

    def initialize(logger: ConsoleLogger.new)
      @logger = logger
    end

    # Collapse overlapping and adjacent CIDR blocks into minimal CIDR list
    def collapse_networks(nets)
      return [] if nets.empty?

      sorted = nets.sort
      deduped = []
      sorted.each do |net|
        next if !deduped.empty? && net.subnet_of?(deduped.last)

        deduped << net
      end

      merged = []
      deduped.each do |net|
        merged << net
        while merged.size >= 2
          right = merged[-1]
          left = merged[-2]
          break unless left.family == right.family && left.prefix == right.prefix && left.prefix > 0

          parent_prefix = left.prefix - 1
          parent_shift = left.max_bits - parent_prefix
          child_size = 1 << (left.max_bits - left.prefix)

          if ((left.net_int >> parent_shift) << parent_shift) == left.net_int &&
             (left.net_int + child_size) == right.net_int
            merged.pop
            merged[-1] = CidrNet.build(left.family, left.net_int, parent_prefix)
          else
            break
          end
        end
      end

      merged
    end

    # Subtract exclusions from targets and collapse the result
    def exclude_networks(targets, exclusions)
      collapsed_targets = collapse_networks(targets)
      collapsed_exclusions = collapse_networks(exclusions)
      return collapsed_targets if collapsed_targets.empty? || collapsed_exclusions.empty?

      result = []
      collapsed_targets.each do |target|
        fragments = [target]
        collapsed_exclusions.each do |excl|
          break if fragments.empty?
          next unless target.overlaps?(excl)

          fragments = fragments.flat_map do |frag|
            if !frag.overlaps?(excl)
              [frag]
            elsif frag.subnet_of?(excl)
              []
            else
              frag.exclude(excl)
            end
          end
        end
        result.concat(fragments)
      end

      collapse_networks(result)
    end

    # Parse CIDR lines into [v4_nets, v6_nets], ignoring comments and /0
    def parse_cidrs(lines, ip_version: nil)
      v4_nets = []
      v6_nets = []

      lines.each do |raw_line|
        line = raw_line.split("#", 2).first.to_s.strip
        next if line.empty?

        begin
          net = CidrNet.parse(line)
        rescue IPAddr::InvalidAddressError, IPAddr::AddressFamilyError, ArgumentError
          @logger.warn("Skipping invalid IP/CIDR entry: #{line.inspect}")
          next
        end

        if net.prefix == 0
          @logger.warn("Refusing to process /0 network: #{net}")
          next
        end

        if net.ipv4?
          v4_nets << net if ip_version.nil? || ip_version == 4
        elsif net.ipv6?
          v6_nets << net if ip_version.nil? || ip_version == 6
        end
      end

      [v4_nets, v6_nets]
    end

    def provider_candidate_paths(provider, ip_version)
      prov = provider.strip.downcase
      if prov == "all_providers"
        [
          "all_providers/all_providers_merged_v#{ip_version}.txt",
          "all_providers/all_providers_ips.txt"
        ]
      else
        [
          "#{prov}/#{prov}_ips_merged_v#{ip_version}.txt",
          "#{prov}/#{prov}_ips_v#{ip_version}.txt"
        ]
      end
    end

    def fetch_url(url_str, timeout: 30, redirect_limit: 5)
      raise ArgumentError, "Too many HTTP redirects" if redirect_limit <= 0

      uri = URI.parse(url_str)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = (uri.scheme == "https")
      http.open_timeout = timeout
      http.read_timeout = timeout

      req = Net::HTTP::Get.new(uri.request_uri)
      req["User-Agent"] = "cloud-filter-ipset-updater/1.0 (Ruby/#{RUBY_VERSION})"

      case resp = http.request(req)
      when Net::HTTPSuccess
        resp.body
      when Net::HTTPRedirection
        fetch_url(resp["location"], timeout:, redirect_limit: redirect_limit - 1)
      when Net::HTTPNotFound
        nil
      else
        raise "HTTP #{resp.code} #{resp.message} for #{url_str}"
      end
    end

    def fetch_with_fallback(rel_paths, base_urls, timeout: 30)
      last_err = nil
      rel_paths.each do |rel_path|
        base_urls.each do |base_url|
          url = "#{base_url.sub(%r{/\z}, '')}/#{rel_path.sub(%r{\A/}, '')}"
          begin
            body = fetch_url(url, timeout:)
            return body unless body.nil?
          rescue StandardError => e
            @logger.warn("Failed to fetch #{url}: #{e.message}")
            last_err = e
          end
        end
      end
      raise "All mirrors failed for #{rel_paths.inspect}: #{last_err.message}" if last_err

      nil
    end

    def fetch_providers_cidrs(providers, base_urls:, enable_v4: true, enable_v6: true, timeout: 30, max_threads: 8)
      v4_all = []
      v6_all = []
      tasks = []

      providers.each do |prov|
        p = prov.strip.downcase
        next if p.empty?

        tasks << [p, 4] if enable_v4
        tasks << [p, 6] if enable_v6
      end
      return [v4_all, v6_all] if tasks.empty?

      queue = Thread::Queue.new(tasks)
      mutex = Mutex.new
      errors = []

      workers = Array.new([max_threads, tasks.size].min) do
        Thread.new do
          while (task = queue.pop(true) rescue nil)
            prov, version = task
            begin
              paths = provider_candidate_paths(prov, version)
              content = fetch_with_fallback(paths, base_urls, timeout:)
              if content.nil?
                @logger.info("Provider '#{prov}' has no IPv#{version} list (404/empty), skipping.")
                next
              end
              v4_parsed, v6_parsed = parse_cidrs(content.lines, ip_version: version)
              mutex.synchronize do
                if version == 4
                  @logger.info("Fetched #{v4_parsed.size} IPv4 CIDRs for provider '#{prov}'")
                  v4_all.concat(v4_parsed)
                else
                  @logger.info("Fetched #{v6_parsed.size} IPv6 CIDRs for provider '#{prov}'")
                  v6_all.concat(v6_parsed)
                end
              end
            rescue StandardError => e
              mutex.synchronize { errors << e }
            end
          end
        end
      end
      workers.each(&:join)
      raise errors.first unless errors.empty?

      [v4_all, v6_all]
    end

    def next_power_of_two(n)
      val = 65_536
      val <<= 1 while val < n
      val
    end

    def generate_ipset_restore(
      set_name_v4:, cidrs_v4:,
      set_name_v6:, cidrs_v6:,
      allow_set_v4:, allow_cidrs_v4:,
      allow_set_v6:, allow_cidrs_v6:,
      enable_v4: true, enable_v6: true
    )
      lines = []
      append_block = lambda do |set_name, family, nets|
        tmp_name = "#{set_name}_tmp"
        maxelem = next_power_of_two(nets.size * 2)
        hashsize = (maxelem / 4).clamp(1024, 262_144)

        lines << "create #{set_name} hash:net family #{family} hashsize #{hashsize} maxelem #{maxelem} -exist"
        lines << "create #{tmp_name} hash:net family #{family} hashsize #{hashsize} maxelem #{maxelem} -exist"
        lines << "flush #{tmp_name}"
        nets.each { lines << "add #{tmp_name} #{it} -exist" }
        lines << "swap #{tmp_name} #{set_name}"
        lines << "destroy #{tmp_name}"
      end

      if enable_v4
        append_block.call(allow_set_v4, "inet", allow_cidrs_v4)
        append_block.call(set_name_v4, "inet", cidrs_v4)
      end

      if enable_v6
        append_block.call(allow_set_v6, "inet6", allow_cidrs_v6)
        append_block.call(set_name_v6, "inet6", cidrs_v6)
      end

      "#{lines.join("\n")}\n"
    end

    def parse_provider_arg(raw)
      raw.to_s.tr(",", " ").split.map { it.strip.downcase }.reject(&:empty?).uniq
    end

    def run_cli(argv)
      options = {
        list_providers: false,
        providers: ENV.fetch("PROVIDERS", "all_providers"),
        exclude_providers: ENV.fetch("EXCLUDE_PROVIDERS", ""),
        whitelist_files: [],
        whitelist_cidrs: [],
        output_dir: ENV.fetch("OUTPUT_DIR", "./output"),
        primary_base_url: ENV.fetch("PRIMARY_BASE_URL", DEFAULT_PRIMARY_BASE_URL),
        fallback_base_url: ENV.fetch("FALLBACK_BASE_URL", DEFAULT_FALLBACK_BASE_URL),
        ipset_drop_v4: ENV.fetch("IPSET_DROP_V4", "cloud_drop_v4"),
        ipset_drop_v6: ENV.fetch("IPSET_DROP_V6", "cloud_drop_v6"),
        ipset_allow_v4: ENV.fetch("IPSET_ALLOW_V4", "cloud_allow_v4"),
        ipset_allow_v6: ENV.fetch("IPSET_ALLOW_V6", "cloud_allow_v6"),
        enable_v4: true,
        enable_v6: true
      }

      parser = OptionParser.new do |opts|
        opts.banner = "Usage: build_cidr_list.rb [options]"
        opts.on("--list-providers", "List all supported provider names") { options[:list_providers] = true }
        opts.on("--providers LIST", "Space- or comma-separated target providers") { options[:providers] = it }
        opts.on("--exclude-providers LIST", "Providers to exclude from drop list") { options[:exclude_providers] = it }
        opts.on("--whitelist-file PATH", "Path to whitelist file") { options[:whitelist_files] << it }
        opts.on("--whitelist-cidr CIDR", "Additional IP/CIDR to whitelist") { options[:whitelist_cidrs] << it }
        opts.on("--output-dir DIR", "Output directory") { options[:output_dir] = it }
        opts.on("--primary-base-url URL", "Primary CDN base URL") { options[:primary_base_url] = it }
        opts.on("--fallback-base-url URL", "Fallback raw base URL") { options[:fallback_base_url] = it }
        opts.on("--ipset-drop-v4 NAME", "ipset name for IPv4 drop list") { options[:ipset_drop_v4] = it }
        opts.on("--ipset-drop-v6 NAME", "ipset name for IPv6 drop list") { options[:ipset_drop_v6] = it }
        opts.on("--ipset-allow-v4 NAME", "ipset name for IPv4 allow list") { options[:ipset_allow_v4] = it }
        opts.on("--ipset-allow-v6 NAME", "ipset name for IPv6 allow list") { options[:ipset_allow_v6] = it }
        opts.on("--no-ipv4", "Disable IPv4") { options[:enable_v4] = false }
        opts.on("--no-ipv6", "Disable IPv6") { options[:enable_v6] = false }
        opts.on("-v", "--verbose", "Enable debug logging") { @logger.level = :debug }
      end
      parser.parse!(argv.dup)

      if options[:list_providers]
        puts "Available providers (67 individual + 'all_providers'):"
        puts "  all_providers (unified merged list across all providers)"
        KNOWN_PROVIDERS.each { puts "  #{it}" }
        return 0
      end

      providers = parse_provider_arg(options[:providers])
      exclude_providers = parse_provider_arg(options[:exclude_providers])
      if providers.empty?
        @logger.error("No target providers specified. Set --providers or PROVIDERS.")
        return 1
      end

      base_urls = [options[:primary_base_url], options[:fallback_base_url]].reject { it.to_s.empty? }

      @logger.info("Fetching target providers: #{providers.join(', ')}")
      raw_drop_v4, raw_drop_v6 = fetch_providers_cidrs(
        providers,
        base_urls:,
        enable_v4: options[:enable_v4],
        enable_v6: options[:enable_v6]
      )

      excl_prov_v4 = []
      excl_prov_v6 = []
      unless exclude_providers.empty?
        @logger.info("Fetching excluded providers: #{exclude_providers.join(', ')}")
        excl_prov_v4, excl_prov_v6 = fetch_providers_cidrs(
          exclude_providers,
          base_urls:,
          enable_v4: options[:enable_v4],
          enable_v6: options[:enable_v6]
        )
      end

      wl_v4 = []
      wl_v6 = []
      options[:whitelist_files].each do |path|
        next unless File.file?(path)

        fv4, fv6 = parse_cidrs(File.readlines(path, chomp: true))
        wl_v4.concat(fv4)
        wl_v6.concat(fv6)
      end
      ev4, ev6 = parse_cidrs(options[:whitelist_cidrs])
      wl_v4.concat(ev4)
      wl_v6.concat(ev6)

      allow_v4 = collapse_networks(wl_v4 + excl_prov_v4)
      allow_v6 = collapse_networks(wl_v6 + excl_prov_v6)

      final_drop_v4 = options[:enable_v4] ? exclude_networks(raw_drop_v4, allow_v4) : []
      final_drop_v6 = options[:enable_v6] ? exclude_networks(raw_drop_v6, allow_v6) : []

      if final_drop_v4.empty? && final_drop_v6.empty?
        @logger.error("Fetched 0 CIDRs across all requested providers. Refusing to overwrite with empty list.")
        return 1
      end

      out_dir = options[:output_dir]
      FileUtils.mkdir_p(out_dir)

      write_lines = lambda do |filename, list|
        content = list.empty? ? "" : "#{list.map(&:to_s).join("\n")}\n"
        File.write(File.join(out_dir, filename), content)
      end

      write_lines.call("drop_v4.txt", final_drop_v4)
      write_lines.call("drop_v6.txt", final_drop_v6)
      write_lines.call("allow_v4.txt", allow_v4)
      write_lines.call("allow_v6.txt", allow_v6)

      ipset_content = generate_ipset_restore(
        set_name_v4: options[:ipset_drop_v4],
        cidrs_v4: final_drop_v4,
        set_name_v6: options[:ipset_drop_v6],
        cidrs_v6: final_drop_v6,
        allow_set_v4: options[:ipset_allow_v4],
        allow_cidrs_v4: allow_v4,
        allow_set_v6: options[:ipset_allow_v6],
        allow_cidrs_v6: allow_v6,
        enable_v4: options[:enable_v4],
        enable_v6: options[:enable_v6]
      )
      File.write(File.join(out_dir, "ipset_restore.txt"), ipset_content)

      summary = {
        ruby_version: RUBY_VERSION,
        providers:,
        exclude_providers:,
        drop_v4_cidrs: final_drop_v4.size,
        drop_v6_cidrs: final_drop_v6.size,
        allow_v4_cidrs: allow_v4.size,
        allow_v6_cidrs: allow_v6.size
      }
      File.write(File.join(out_dir, "summary.json"), "#{JSON.pretty_generate(summary)}\n")

      @logger.info(
        "Build complete -> IPv4 DROP: #{final_drop_v4.size} CIDRs (Allow: #{allow_v4.size}), " \
        "IPv6 DROP: #{final_drop_v6.size} CIDRs (Allow: #{allow_v6.size})"
      )
      0
    end
  end
end

if __FILE__ == $PROGRAM_NAME
  exit(CloudFilter::Builder.new.run_cli(ARGV))
end
