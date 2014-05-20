local rule = require "rule"
local count = table.getn(rule)
local _M = {}

local DENY = 0
local ALLOW = 1
local PASS = 2

local match = ngx.re.match

function waf_eq(v1, v2)
	if v1 == v2 then
		return true
	end

	return false
end

function waf_regex(v1, regex)
	local m, err = match(v1, regex)
	if m then
		return true
	elseif err then
		ngx.log(ngx.ERR, "error:", err)
		return false
	end

	return false
end

function waf_log(str)
	ngx.log(ngx.ERR, str)
end

function waf_deny()
	ngx.exit(412)
end

local function waf_collect_data()
	_M.method = ngx.req.get_method()
	_M.args_get = ngx.var.args
	if (_M.method == "POST") then
		_M.args_post = ngx.req.get_post_args()
		ngx.req.read_body()
		_M.body_data = ngx.req.get_body_data()
	end
end

function _M.run()
	waf_collect_data()
	for i=1, count do
		rule[i](_M)
	end
end

return _M