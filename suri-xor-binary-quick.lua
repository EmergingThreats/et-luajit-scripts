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

    key = {}

    if #a < 1024 then 
        return 0
    end

-- Usually bytes 0x30 to 0x3b are 0-padding,
-- so may actually contain the Key; decode PE offset at 0x3c and check
-- it points to bytes that then decode to PE|00 00|
-- 7,8,9,10,11,12 also cover their divisors 1 - 6, but include 4 four safety

    key_lengths = {4,7,8,9,10,11,12}

    for n, l in pairs(key_lengths) do

        koffset = ((l-(0x30 % l)) % l)

        for i = 0, l-1, 1 do
           key[i+1] = a:byte(0x30+1+((i+koffset) % l))
        end
        

        pe = bit.bxor(a:byte(0x3c+1), key[1+(0x3c % l)]) + (256*bit.bxor(a:byte(0x3c+2), key[1+((0x3c+1) % l)]))
        if verbose==1 then print("Trying " .. l .. "-byte XOR key; PE block at " .. pe) end
        if (pe < 1024) then
            offset = pe % l
            if (bit.bxor(a:byte(pe+1), key[offset+1]) == string.byte('P')) and 
               (bit.bxor(a:byte(pe+2), key[((1+offset)%l)+1]) == string.byte('E')) and
               (bit.bxor(a:byte(pe+3), key[((2+offset)%l)+1]) == 0) and
               (bit.bxor(a:byte(pe+4), key[((3+offset)%l)+1]) == 0) then
                if verbose==1 then print("Found " .. l .. "-byte XOR key; PE block at " .. pe) end
                return 1
            end
        end
    end

-- Check for g01pack/Blackhole 1-byte XOR key
    k = a:byte(1);
    pe = bit.bxor(a:byte(0x3c+2), k) + (256*bit.bxor(a:byte(0x3c+3),k))
    if (pe < 1024) then
        if (bit.bxor(a:byte(pe+2), k) == string.byte('P')) and 
           (bit.bxor(a:byte(pe+3), k) == string.byte('E')) and
           (bit.bxor(a:byte(pe+4), k) == 0) and
           (bit.bxor(a:byte(pe+5), k) == 0) then
            if verbose==1 then print("Found g01pack 1-byte XOR key " .. k .. " - PE block at " .. pe) end
            return 1
        end
    end

-- Check for SofosFO-obfuscated binary

    b = ""
    -- Quick check that 2nd byte -> 'Z'
    k1 = bit.bxor(a:byte(1), string.byte('M'))
    k2 = bit.bxor((k1 + 170) % 256, 0x48)

    if bit.bxor(a:byte(2),k2) == string.byte('Z') then 
    -- now check for a PE header
        k = (bit.bxor(a:byte(1), string.byte('M'), 0x48) - 170) % 256
        k1 = k
          for i = 1, 1024, 1 do
          k = bit.bxor((k + 170) % 256, 0x48)
          b = b .. string.char(bit.bxor(a:byte(i), k))
        end

        pe = b:byte(0x3c+1) + (256*b:byte(0x3c+2))

        if (pe < 1024) then
            if b:byte(pe+1) == string.byte('P') and
               b:byte(pe+2) == string.byte('E') and
               b:byte(pe+3) == 0 and
               b:byte(pe+4) == 0 then
                if verbose==1 then print("Found SofosFO XOR seed " .. k1 .. " - PE block at " .. pe) end
                return 1
            end
        end
    end

-- Check for 1-byte XOR with 0 and XOR-key bytes left alone
    k1 = xor0(a:byte(1), string.byte('M'))
    if xor0(a:byte(2),k1) == string.byte('Z') then
        pe = xor0(a:byte(0x3c+1),k1) + (256*xor0(a:byte(0x3c+2),k1))
        if (pe < 1024) then
            if xor0(a:byte(pe+1),k1) == string.byte('P') and
               xor0(a:byte(pe+2),k1) == string.byte('E') and
               a:byte(pe+3) == 0 and
               a:byte(pe+4) == 0 then
                if verbose==1 then print("Found XOR-but-not-zero key " .. k1 .. " - PE block at " .. pe) end
                return 1
            end
        end
    end

-- Check for NicePack reversed/4-byte XORed binary
    for i = 0, 4, 1 do
      key[i+1] = a:byte(#a-0x30-i)
    end

    pe = bit.bxor(a:byte(#a-0x3c), key[1]) + (256*bit.bxor(a:byte(#a-0x3c-1), key[2]))
    if (pe < 1024) then
        offset = pe % 4
        if (bit.bxor(a:byte(#a-pe), key[offset+1]) == string.byte('P')) and 
           (bit.bxor(a:byte(#a-1-pe), key[((1+offset)%4)+1]) == string.byte('E')) and
           (bit.bxor(a:byte(#a-2-pe), key[((2+offset)%4)+1]) == 0) and
           (bit.bxor(a:byte(#a-3-pe), key[((3+offset)%4)+1]) == 0) then
            if verbose==1 then print("Found 4-byte XOR key for reversed binary; PE block at " .. pe) end
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
