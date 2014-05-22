# vim:set ft= ts=4 sw=4 et:

use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(3);

plan tests => repeat_each(1) * blocks();

my $pwd = cwd();

our $HttpConfig = qq{
    lua_package_path "$pwd/lib/resty/?.lua;;";
    lua_package_cpath "/usr/local/openresty-debug/lualib/?.so;/usr/local/openresty/lualib/?.so;;";
    init_by_lua "waf = require 'waf'";
    access_by_lua "waf.run()";
};

no_long_string();
#no_diff();

run_tests();

__DATA__

=== TEST 1: basic get
--- http_config eval: $::HttpConfig
--- config
--- request
GET /?t=<script>
--- error_code: 412

=== TEST 2: basic post
--- http_config eval: $::HttpConfig
--- config
--- request
POST /
t=<script>&foo=1&bar=2
--- error_code: 412

=== TEST 1: basic get
--- http_config eval: $::HttpConfig
--- config
--- request
GET /
--- error_code: 200
