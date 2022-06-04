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
plan tests => repeat_each() * 3 * blocks();

no_shuffle();
run_tests();


__DATA__

=== TEST 1: reload ac_lookup
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
			local op = require "resty.waf.operators"
			local match, value = op.ac_lookup("foo", { "foo", "bar", "baz", "qux" }, { id = 1 })
			ngx.say(match)
			ngx.say(op.reload_cache(1))
		}
	}
--- request
GET /t
--- error_code: 200
--- response_body
true
true
--- no_error_log
[error]


=== TEST 2: reload byterange
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
			local op   = require "resty.waf.operators"
            local pattens =  {"10"}
			local match, value = op.validate_byterange(string.char(10), pattens, { id = 1 })
			ngx.say(match)
			ngx.say(op.reload_cache(1))
		}
	}
--- request
GET /t
--- error_code: 200
--- response_body
false
true
--- no_error_log
[error]
