local p=io.popen("whoami")
local x=p:read("*a")
p:close()
