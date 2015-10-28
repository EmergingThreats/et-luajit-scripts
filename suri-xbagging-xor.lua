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

Detect modified XOR-ed payloads downloaded by "Xbagging" malicious MS Office macros

This lua script can be run standalone and verbosely on a binary file with
echo "run()" | lua -i <script name> <binary file>

Chris Wakelin
--]]

function init (args)
    local needs = {}
    needs["http.response_body"] = tostring(true)
    return needs
end

-- return match via table
function common(a,verbose)
    local bit = require("bit")

    key = {}

    if #a < 1024 then 
        return 0
    end

-- Usually bytes 0x30 to 0x3b are 0-padding,
-- so may actually contain the Key; decode PE offset at 0x3c and check
-- it points to bytes that then decode to PE|00 00|
-- 7,8,9,10,11,12 also cover their divisors 1 - 6, but include 4 four safety

    key_lengths = {4,5,6,7,8,9,10,11,12}

    for n, l in pairs(key_lengths) do

        koffset = ((l-(0x30 % l)) % l)

        for i = 0, l-1, 1 do
           key[i+1] = bit.bxor(a:byte(0x30+1+((i+koffset) % l)),(0x30+((i+koffset) % l)))
        end
        

        pe = bit.bxor(bit.bxor(a:byte(0x3c+1), key[1+(0x3c % l)]), 0x3c)
        if verbose==1 then print("Trying " .. l .. "-byte XOR key; PE block at " .. pe) end
        if ((pe < 256) and (pe < #a-4)) then
            offset = pe % l
            if (bit.bxor(bit.bxor(a:byte(pe+1), key[offset+1]), pe) == string.byte('P')) and 
               (bit.bxor(bit.bxor(a:byte(pe+2), key[((1+offset)%l)+1]), pe+1) == string.byte('E')) then
                if verbose==1 then print("Found " .. l .. "-byte XOR key; PE block at " .. pe) end
                return 1
            end
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
