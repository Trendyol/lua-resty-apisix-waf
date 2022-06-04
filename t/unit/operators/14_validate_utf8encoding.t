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
plan tests => repeat_each() * 3 * blocks() + repeat_each()*(blocks() -1);

no_shuffle();
run_tests();


__DATA__

=== TEST 1: Match valid utf8 string
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
			local op = require "resty.waf.operators"
			local match, value = op.validate_utf8encoding({}, string.char(228, 189, 160))
			ngx.say(match)
		}
	}
--- request
GET /t
--- error_code: 200
--- response_body
false
--- no_error_log
[error]

=== TEST 2: Match not enough bytes in character
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
			local op = require "resty.waf.operators"
			local match, value = op.validate_utf8encoding({_debug = true, _debug_log_level = ngx.INFO, transaction_id = '1'}, string.char(228, 189))
			ngx.say(match)
		}
	}
--- request
GET /t
--- error_code: 200
--- response_body
true
--- error_log
Invalid UTF-8 encoding: not enough bytes in character at
--- no_error_log
[error]

=== TEST 3: Match invalid byte value in character
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
			local op = require "resty.waf.operators"
			local match, value = op.validate_utf8encoding({_debug = true, _debug_log_level = ngx.INFO, transaction_id = '1'}, string.char(228, 0, 160))
			ngx.say(match)
		}
	}
--- request
GET /t
--- error_code: 200
--- response_body
true
--- error_log
Invalid UTF-8 encoding: invalid byte value in character at
--- no_error_log
[error]
