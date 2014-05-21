local _M = {
	rules = require "rule",
	method = {},
	args_get = {},
	args_post = {},
	body_data = {} 
}

function waf_eq(v1, v2)
	if v1 == v2 then
		return true
	end

	return false
end

function waf_regex(v1, regex)
	local m, err = ngx.re.match(v1, regex)
	print (regex)
	if m then
		return true
	elseif err then
		ngx.log(ngx.ERR, "error:", err)
		return false
	end
	return false
end

function waf_deny()
	ngx.exit(412)
end

local function waf_collect_data()
	_M.method = ngx.req.get_method()
	_M.args_get = ngx.unescape_uri(ngx.var.args)
	if (_M.method == "POST") then
		_M.args_post = ngx.unescape_uri(ngx.req.get_post_args())
		ngx.req.read_body()
		_M.body_data = ngx.unescape_uri(ngx.req.get_body_data())
	end
end

function _M.run()
	waf_collect_data()
	local count = table.getn(_M.rules)

	for i=1, count do
		_M.rules[i]()
	end
end

return _M