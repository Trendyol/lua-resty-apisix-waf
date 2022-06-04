#!/usr/bin/perl
use strict;
use warnings;
use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

my $pwd = cwd();

our $HttpConfig = qq{
	lua_package_path "$pwd/lib/?.lua;;";
	lua_package_cpath "$pwd/lib/?.lua;;";
};

repeat_each(3);
plan tests => repeat_each() * 4 * blocks();

no_shuffle();
run_tests();


__DATA__

=== TEST 1: Match Non-hexadecimal digits used
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
			local op = require "resty.waf.operators"
			local match, value = op.validate_urlencoding({_debug = true, _debug_log_level = ngx.INFO, transaction_id = '1'},"%0z")
			ngx.say(match)
		}
	}
--- request
GET /t
--- error_code: 200
--- response_body
true
--- error_log
Invalid URL Encoding: Non-hexadecimal digits used at
--- no_error_log
[error]

=== TEST 2: Match Not enough characters at the end of input
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
			local op = require "resty.waf.operators"
			local match, value = op.validate_urlencoding({_debug = true, _debug_log_level = ngx.INFO, transaction_id = '1'},"%0")
			ngx.say(match)
		}
	}
--- request
GET /t
--- error_code: 200
--- response_body
true
--- error_log
Invalid URL Encoding: Not enough characters at the end of input at
--- no_error_log
[error]

