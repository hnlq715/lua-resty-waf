local _M = {}

local function register_rule(fn)
	table.insert(_M, fn)
end

local function rule_test(waf)
	if waf_eq(waf.method, "GET") then
		waf_log("This is rule test")
		waf_deny()
	end
end
register_rule(rule_test)

return _M