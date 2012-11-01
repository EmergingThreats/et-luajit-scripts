--[[
#*************************************************************
#  Copyright (c) 2003-2012, Emerging Threats
#  All rights reserved.
#  
#  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the 
#  following conditions are met:
#  
#  * Redistributions of source code must retain the above copyright notice, this list of conditions and the following 
#    disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the 
#    following disclaimer in the documentation and/or other materials provided with the distribution.
#  * Neither the name of the nor the names of its contributors may be used to endorse or promote products derived 
#    from this software without specific prior written permission.
#  
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS AS IS AND ANY EXPRESS OR IMPLIED WARRANTIES, 
#  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
#  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE 
#  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
#
#*************************************************************
--]]

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
