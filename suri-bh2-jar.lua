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
-- Look for URL obfuscation string
            fnd = string.find(t,"EpgKF3twh",1,true) 
            if fnd then
                rtn = 1
            end
-- Look for Zelix obfuscator version string
            fnd = string.find(t,"ZKM5.4.3",1,true) 
            if fnd then
                rtn = 1
            end
        end
        z:close()
    end
    os.remove(tmpname)
    return rtn
end
