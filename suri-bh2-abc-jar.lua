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

    numfiles = 0
    stub = {}

    z = zip.open(tmpname)

    if z then 
        for w in z:files() do
            numfiles = numfiles + 1
            fstub = string.find(w.filename,"[a-c].class",1,false)
            if fstub then
                stub[w.filename:sub(fstub,fstub)] = w.filename:sub(1,fstub-1)
            end
        end
        z:close()
    end
    if stub["a"] and stub["b"] and stub["c"] and (numfiles < 10) then
        if (stub["a"] == stub["b"]) and (stub["b"] == stub["c"]) and (string.len(stub["a"]) > 3) then
            rtn = 1
        end
    end
    os.remove(tmpname)
    return rtn
end
