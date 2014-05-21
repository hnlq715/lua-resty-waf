local _M = {}

local xss_rule = {
"<(?:s(?:cript|tyle)|i(?:frame|n(?:put|s))|f(?:rame(?:set)?|orm)|a(?:pplet|ddress|rea)|b(?:ase|gsound|ody)|l(?:ayer|ink)|meta|object|textareai|embed)[^>]*>"
}

local xss_rule_num = table.getn(xss_rule)

local xss_rule_processor = function()
	for i=1, xss_rule_num do
		if waf_regex(waf.args_get, xss_rule[i]) then
			waf_deny()
		end
		if waf.method == "POST" then
			if waf_regex(waf.args_post, xss_rule[i]) then
				waf_deny()
			end
		end
	end
end

table.insert(_M, xss_rule_processor)

return _M