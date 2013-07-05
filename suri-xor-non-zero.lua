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

This lua script can be run standalone and verbosely on a binary file with
echo "run()" | lua -i <script name> <binary file>

Chris Wakelin
--]]

function init (args)
    local needs = {}
    needs["http.response_body"] = tostring(true)
    return needs
end

function xor0(byte, key)
   local bit = require("bit")
   if byte == key or byte == 0 then
       return byte
   end
   return bit.bxor(byte,key)
end

-- return match via table
function common(a,verbose)
    local result = {}
    local bit = require("bit")

    if #a < 1024 then 
        return 0
    end

-- Check for 1 or 2-byte XOR with 0 and XOR-key bytes left alone
-- Should also match other key lengths that divide 0x3c and the PE offset (e.g. 4)
    k1 = xor0(a:byte(1), string.byte('M'))
    k2 = xor0(a:byte(2), string.byte('Z'))

    pe = xor0(a:byte(0x3c+1),k1) + (256*xor0(a:byte(0x3c+2),k2))
    if verbose==1 then print("Trying PE header at " .. pe) end

    if (pe < 2048) then
        if xor0(a:byte(pe+1),k1) == string.byte('P') and
           xor0(a:byte(pe+2),k2) == string.byte('E') and
           a:byte(pe+3) == 0 and
           a:byte(pe+4) == 0 then
            if verbose==1 then print("Found XOR-but-not-zero key " .. k1 .. "," .. k2 .. " - PE block at " .. pe) end
            return 1
        end
    end

    return 0
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
  common(t,1)
end
