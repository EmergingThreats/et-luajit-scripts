--[[
#*************************************************************
#  Copyright (c) 2003-2013, Emerging Threats
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

Detection for suspicious pack200/gzip Java files
Requires the lua zlib module https://github.com/brimworks/lua-zlib

This lua script can be run standalone and verbosely on a pack200/gzip file with
echo "run()" | lua -i <script name> <pack200/gzip file>

Chris Wakelin
Will Metcalf
--]]

local lz = require("zlib")

-- {strings to match, number of matching strings needed, simple strings, description}
susp_class = {
              {"yv66v",1,true,"Base-64-encoded class file",0},
              {"CAFEBABE",1,true,"Hex-encoded class file",0},
              {"[Cc].?.?.?[Aa].?.?.?[Ff].?.?.?[Ee].?.?.?[Bb].?.?.?[Aa].?.?.?[Bb].?.?.?[Ee]",1,false,"Hex-encoded class file (possibly obfuscated)",0},
              {"etSecurityManager",1,true,"[gs]etSecurityManager www.fireeye.com/blog/technical/2013/06/get-set-null-java-security.html",0},
              {"reganaMytiruceS",1,true,"SecurityManger reversed PrivatePack June 27 2013",0},
              {"isableSecurity",1,true,"Generic [Dd]isableSecurity (Observed in Styx)",0},
              {"image","Raster","SampleModel",3,true,"Classes used in awt exploits",0},
              {"image","SinglePixelPacked",2,true,"CVE-2013-2471",0},
              {"image","MultiPixelPacked",2,true,"CVE-2013-2465/2463",0},
              {"javafx","application","Preloader","Stage","Application",5,true,"Java7u21 Click2play Bypass http://seclists.org/bugtraq/2013/Jul/41 ???",0} 
             }

function init (args)
    local needs = {}
    needs["http.response_body"] = tostring(true)
    return needs
end

function match_strings(a,match_set,verbose)
    local rtn = 0
    local n,m
    local num_strings = #match_set - 4 
    
    local match_num = match_set[num_strings+1]
    local plain = match_set[num_strings+2]
    local desc = match_set[num_strings+3]
    local fnd
    
    for n = 1, num_strings, 1 do
        m = match_set[n]
        if m ~= 0 then
            fnd = string.find(a,m,1,plain)
            if fnd then
                match_set[num_strings+4] = match_set[num_strings+4] + 1
                if verbose == 1 then print("Found String " .. m .. " " .. match_set[num_strings+4] .. " of " .. match_num) end
                --match_set[num_strings+4] is our counter
                if match_set[num_strings+4] == match_num then
                    if verbose == 1 then print("Found " .. desc) end
                    match_set[n] = 0
                    rtn = 1
                    break
                else
                    --Found lets zero it out so we don't check again
                    match_set[n] = 0
                end
           end
        end
    end
    return rtn
end

function common(t,verbose)

    rtn = 0

    stream = lz.inflate()
    u, eof, bytes_in, uncompressed_len = stream(t)

    if string.sub(u,1,4) == "\202\254\208\013"  then -- CAFED00D in decimal
        if (verbose==1) then print("Found pack200-ed file") end
        for l,s in pairs(susp_class) do
            if (verbose==1) then print("Looking for " .. s[#s-1] .. " in uncompressed stream") end
            if match_strings(u,s,verbose) == 1 then
                rtn = 1
                if (verbose == 0) then
                   break
                end
            end
        end
    end
    return rtn
end

-- return match via table
function match(args)
    local t = tostring(args["http.response_body"])
    return common(t,0)
end

function run()
  local f = io.open(arg[1])
  local t = f:read("*all")
  f:close()
  if common(t,1) == 1 then print("Found Suspicious String in " .. arg[1]) end
end

