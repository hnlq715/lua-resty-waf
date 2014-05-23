lua-resty-waf
=============

This is a simple Web Application Firewall based on OpenResty.


Synopsis
=============
```
http{

  lua_package_path '/path/to/waf/?.lua;;';

  init_by_lua '
    waf = require "waf"
  ';

  access_by_lua "waf:run()";

}
```
