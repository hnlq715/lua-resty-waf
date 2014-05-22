local rules = require "rule"

local _M = {
	method = "",
	args_get = "",
	args_post = ""
}

local match = ngx.re.match
local get_headers = ngx.req.get_headers

function waf_eq(v1, v2)
	if v1 == "" or v2 == "" then
		return false
	end

	if v1 == v2 then
		return true
	end

	return false
end

function waf_regex(v1, regex)
	if v1 == "" or regex == "" then
		return false
	end

	print (v1, "====", regex)
	local m, err = match(v1, regex, "isjo")
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

local function waf_get_boundary()
    local header = get_headers()["content-type"]
    if not header then
        return nil
    end

    if type(header) == "table" then
    	print (header)
        header = header[1]
    end

    local m = string.match(header, ';%s*boundary=\"([^\"]+)\"')
    if m then
        return m
    end

	return string.match(header, ";%s*boundary=([^\",;]+)")
end

local function waf_get_args_post()
	ngx.req.read_body()
	local args = ngx.req.get_post_args()
	if not args then
		return ""
	end

	local post_args, data = ""
	for key, val in pairs(args) do
		if type(val) == "table" then
			data=table.concat(val, ", ")
		else
			data=val
		end
		print (data)
		if data and type(data) ~= "boolean" then
			post_args = post_args..data
		end
	end

	return post_args
end

local function waf_get_args_get()
	local args = ngx.req.get_uri_args()
	if not args then
		return ""
	end

	local args_get, data = ""
	for key, val in pairs(args) do
		if type(val) == "table" then
			data=table.concat(val, ", ")
		else
			data=val
		end
	end

	if data and type(data) ~= "boolean" then
		args_get = args_get..data
	end

	return args_get
end

local function waf_get_body_data()
	local sock, err = ngx.req.socket()
	if not sock then
		return
	end

	ngx.req.init_body(128 * 1024)
	sock:settimeout(0)
	local content_length = nil
		content_length=tonumber(get_headers()['content-length'])
	local chunk_size = 4096
	if content_length < chunk_size then
		chunk_size = content_length
	end

	local size = 0
	while size < content_length do
		local data, err, partial = sock:receive(chunk_size)
		data = data or partial
		if not data then
			return
		end
		ngx.req.append_body(data)

		size = size + string.len(data)
		local less = content_length - size
		if less < chunk_size then
			chunk_size = less
		end
	end
	_M.body = data
	ngx.req.finish_body()
end

local function waf_collect_data()
	_M.method = ngx.req.get_method()
	_M.args_get = ngx.unescape_uri(waf_get_args_get())

	if (_M.method == "POST") then
		local boundary = waf_get_boundary()
		if boundary then
			waf_get_body_data()
		else
			_M.args_post = ngx.unescape_uri(waf_get_args_post())
		end
	end
end

function _M.run()
	waf_collect_data()
	local count = table.getn(rules)
	for i=1, count do
		rules[i]()
	end
end

return _M