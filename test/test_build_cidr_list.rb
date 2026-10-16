#!/usr/bin/env ruby
# frozen_string_literal: true

require "minitest/autorun"
require "tmpdir"
require "stringio"
require_relative "../build_cidr_list"

class TestBuildCidrList < Minitest::Test
  def setup
    @log_io = StringIO.new
    @builder = CloudFilter::Builder.new(logger: CloudFilter::ConsoleLogger.new(@log_io))
  end

  def test_ruby_4_or_newer
    assert_operator(RUBY_VERSION.split(".").first.to_i, :>=, 4, "Expected Ruby 4.x, got #{RUBY_VERSION}")
  end

  def test_parse_cidrs_v4_and_v6_and_ignores_comments_and_zero_prefix
    lines = [
      "# header comment",
      "192.0.2.0/24 # inline comment",
      "192.0.2.128/25",
      "2001:db8::/32",
      "0.0.0.0/0",
      "::/0",
      "invalid_cidr",
      ""
    ]
    v4, v6 = @builder.parse_cidrs(lines)
    assert_equal(["192.0.2.0/24", "192.0.2.128/25"], v4.map(&:to_s))
    assert_equal(["2001:db8::/32"], v6.map(&:to_s))
  end

  def test_collapse_networks_merges_adjacent_and_overlapping
    nets = [
      CloudFilter::CidrNet.parse("10.0.0.0/25"),
      CloudFilter::CidrNet.parse("10.0.0.128/25"),
      CloudFilter::CidrNet.parse("10.0.1.0/24"),
      CloudFilter::CidrNet.parse("10.0.1.64/26") # redundant subnet
    ]
    collapsed = @builder.collapse_networks(nets)
    assert_equal(["10.0.0.0/23"], collapsed.map(&:to_s))
  end

  def test_exclude_networks_subtracts_subnet_and_collapses
    targets = [
      CloudFilter::CidrNet.parse("10.0.0.0/23"),
      CloudFilter::CidrNet.parse("10.0.1.0/24"),
      CloudFilter::CidrNet.parse("198.51.100.0/24")
    ]
    exclusions = [
      CloudFilter::CidrNet.parse("10.0.0.0/24"),     # half of 10.0.0.0/23
      CloudFilter::CidrNet.parse("198.51.100.0/23")  # superset of 198.51.100.0/24
    ]
    result = @builder.exclude_networks(targets, exclusions)
    assert_equal(["10.0.1.0/24"], result.map(&:to_s))
  end

  def test_generate_ipset_restore_uses_atomic_swap
    script = @builder.generate_ipset_restore(
      set_name_v4: "cloud_drop_v4",
      cidrs_v4: [CloudFilter::CidrNet.parse("203.0.113.0/24")],
      set_name_v6: "cloud_drop_v6",
      cidrs_v6: [CloudFilter::CidrNet.parse("2001:db8::/48")],
      allow_set_v4: "cloud_allow_v4",
      allow_cidrs_v4: [CloudFilter::CidrNet.parse("192.168.1.1/32")],
      allow_set_v6: "cloud_allow_v6",
      allow_cidrs_v6: [CloudFilter::CidrNet.parse("::1/128")]
    )
    assert_includes(script, "create cloud_drop_v4 hash:net family inet")
    assert_includes(script, "create cloud_drop_v4_tmp hash:net family inet")
    assert_includes(script, "add cloud_drop_v4_tmp 203.0.113.0/24 -exist")
    assert_includes(script, "swap cloud_drop_v4_tmp cloud_drop_v4")
    assert_includes(script, "destroy cloud_drop_v4_tmp")
    assert_includes(script, "add cloud_drop_v6_tmp 2001:db8::/48 -exist")
    assert_includes(script, "swap cloud_drop_v6_tmp cloud_drop_v6")
  end

  def test_run_cli_end_to_end_with_stubbed_fetch
    def @builder.fetch_with_fallback(rel_paths, _base_urls, timeout: 30)
      first = rel_paths.first
      if first.include?("gptbot") && first.include?("v4")
        "4.151.71.176/28\n203.0.113.0/24\n"
      elsif first.include?("gptbot") && first.include?("v6")
        nil
      elsif first.include?("cloudflare") && first.include?("v4")
        "203.0.113.128/25\n"
      elsif first.include?("cloudflare") && first.include?("v6")
        "2400:cb00::/32\n"
      end
    end

    Dir.mktmpdir do |tmpdir|
      rc = @builder.run_cli([
        "--providers", "gptbot",
        "--exclude-providers", "cloudflare",
        "--whitelist-cidr", "192.0.2.1/32",
        "--output-dir", tmpdir
      ])
      assert_equal(0, rc)
      drop_v4 = File.readlines(File.join(tmpdir, "drop_v4.txt"), chomp: true)
      assert_equal(["4.151.71.176/28", "203.0.113.0/25"], drop_v4)
    end
  end
end
