require("zip")

function init (args)
    local needs = {}
    needs["http.response_body"] = tostring(true)
    return needs
end


-- return match via table
function match(args)

    rtn = 0

    t = tostring(args["http.response_body"])
    tmpname = os.tmpname()
    tmp = io.open(tmpname,'w')
    tmp:write(t)
    tmp:close()

    z = zip.open(tmpname)

    if z then 
        for w in z:files() do
            f = z:open(w.filename);
            t = f:read("*all")
            f:close()
--- Blackhole URL obfuscation string
            fnd = string.find(t,"EpgKF3twh",1,true) 
            if fnd then
               rtn = 1
               break
            end
--- Zelix obfuscator version string as used in Blackhole
            fnd = string.find(t,"ZKM5.4.3",1,true) 
            if fnd then
               rtn = 1
               break
            end
--- g01pack URL obfuscation string
            fnd = string.find(t,"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/.:_-?&=%#;",1,true)
            if fnd then
               rtn = 1
               break
            end
--- Nuclear URL obfuscation string
            fnd = string.find(t,"DEvuYp",1,true)
            if fnd then
               rtn = 1
               break
            end
--- Base64-encoded class file
            fnd = string.find(t,"yv66v",1,true)
            if fnd then
               rtn = 1
               break
            end
        end
        z:close()
    end
    os.remove(tmpname)
    return rtn
end
