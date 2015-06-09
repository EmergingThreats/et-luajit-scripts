--[[
#*************************************************************
#  Copyright (c) 2003-2015, Emerging Threats
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

This lua script can be run standalone and verbosely on a vbe file with
echo "run()" | lua -i <script name> <vbe file>

VBE decoding based on tool written in Pascal in http://seclists.org/fulldisclosure/2003/Sep/734 :-
  program vbs_dec;  { Decrypts encrypted VBScript and JScript programs }
  { Copyright (c) 09/2003 Andreas Marx / http://www.av-test.org }

Chris Wakelin
Will Metcalf
--]]

--local lz = require("zlib")
local bit = require("bit")

-- {strings to match, number of matching strings needed, simple strings, description}
susp_class = {
              {"http://",1,true,"Embedded URL",0},
              {"[Rr][Ee][Aa][Dd][Mm][Ee][Mm][Oo]]",1,false,"Readmemory function",0},
              {"powershell",1,true,"Powershell call",0},
              {"[Ss][Hh][Ee][Ll][Ll][Ee][Xx][Ee][Cc]",1,false,"ShellExecute call",0},
              {"[Ww][Ss][Cc][Rr][Ii][Pp][Tt]%.[Ss][Hh][Ee][Ll][Ll]",1,false,"WScript.Shell call",0},
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
 
    u = deobfuscate(decode_vbe(t),verbose)

    if #u > 0 then
        if (verbose==1) then print("Found encoded VBE section(s)") end
        for l,s in pairs(susp_class) do
            if (verbose==1) then print("Looking for " .. s[#s-1] .. " in decoded sections") end
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

function base64_d(a,force_ascii)
-- requires a to be a valid base64 string -
-- only valid chars, multiple of 4 in length - else it will crash!
-- converted from Blackhole JS version :-)
    keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    b = ""
    for i = 1, #a, 4 do
        enc1 = keyStr:find(a:sub(i,i),1,true)-1
        enc2 = keyStr:find(a:sub(i+1,i+1),1,true)-1
        enc3 = keyStr:find(a:sub(i+2,i+2),1,true)-1
        enc4 = keyStr:find(a:sub(i+3,i+3),1,true)-1
        chr1 = bit.bor(bit.lshift(enc1,2),bit.rshift(enc2,4))
        chr2 = bit.bor(bit.lshift(bit.band(enc2,15),4),bit.rshift(enc3,2))
        chr3 = bit.bor(bit.lshift(bit.band(enc3,3),6),enc4)
        b = b .. string.char(chr1)
        if enc3 ~= 64 then b = b .. string.char(chr2) end
        if enc4 ~= 64 then b = b .. string.char(chr3) end
    end
    if force_ascii == true and b:gsub("[%w%p%s]","") ~= "" then
        return a,0
    else
        return b,1
    end
end

D_tabs = {
     {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x57,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
      0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
      0x2E,0x47,0x7A,0x56,0x42,0x6A,0x2F,0x26,0x49,0x41,0x34,0x32,0x5B,0x76,0x72,0x43,
      0x38,0x39,0x70,0x45,0x68,0x71,0x4F,0x09,0x62,0x44,0x23,0x75,0x3C,0x7E,0x3E,0x5E,
      0xFF,0x77,0x4A,0x61,0x5D,0x22,0x4B,0x6F,0x4E,0x3B,0x4C,0x50,0x67,0x2A,0x7D,0x74,
      0x54,0x2B,0x2D,0x2C,0x30,0x6E,0x6B,0x66,0x35,0x25,0x21,0x64,0x4D,0x52,0x63,0x3F,
      0x7B,0x78,0x29,0x28,0x73,0x59,0x33,0x7F,0x6D,0x55,0x53,0x7C,0x3A,0x5F,0x65,0x46,
      0x58,0x31,0x69,0x6C,0x5A,0x48,0x27,0x5C,0x3D,0x24,0x79,0x37,0x60,0x51,0x20,0x36}
     ,
     {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x7B,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
      0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
      0x32,0x30,0x21,0x29,0x5B,0x38,0x33,0x3D,0x58,0x3A,0x35,0x65,0x39,0x5C,0x56,0x73,
      0x66,0x4E,0x45,0x6B,0x62,0x59,0x78,0x5E,0x7D,0x4A,0x6D,0x71,0x3C,0x60,0x3E,0x53,
      0xFF,0x42,0x27,0x48,0x72,0x75,0x31,0x37,0x4D,0x52,0x22,0x54,0x6A,0x47,0x64,0x2D,
      0x20,0x7F,0x2E,0x4C,0x5D,0x7E,0x6C,0x6F,0x79,0x74,0x43,0x26,0x76,0x25,0x24,0x2B,
      0x28,0x23,0x41,0x34,0x09,0x2A,0x44,0x3F,0x77,0x3B,0x55,0x69,0x61,0x63,0x50,0x67,
      0x51,0x49,0x4F,0x46,0x68,0x7C,0x36,0x70,0x6E,0x7A,0x2F,0x5F,0x4B,0x5A,0x2C,0x57}
     ,
     {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x6E,0x0A,0x0B,0x0C,0x06,0x0E,0x0F,
      0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
      0x2D,0x75,0x52,0x60,0x71,0x5E,0x49,0x5C,0x62,0x7D,0x29,0x36,0x20,0x7C,0x7A,0x7F,
      0x6B,0x63,0x33,0x2B,0x68,0x51,0x66,0x76,0x31,0x64,0x54,0x43,0x3C,0x3A,0x3E,0x7E,
      0xFF,0x45,0x2C,0x2A,0x74,0x27,0x37,0x44,0x79,0x59,0x2F,0x6F,0x26,0x72,0x6A,0x39,
      0x7B,0x3F,0x38,0x77,0x67,0x53,0x47,0x34,0x78,0x5D,0x30,0x23,0x5A,0x5B,0x6C,0x48,
      0x55,0x70,0x69,0x2E,0x4C,0x21,0x24,0x4E,0x50,0x09,0x56,0x73,0x35,0x61,0x4B,0x58,
      0x3B,0x57,0x22,0x6D,0x4D,0x25,0x28,0x46,0x4A,0x32,0x41,0x3D,0x5F,0x4F,0x42,0x65}
} -- cipher tables

I_tab = {
      0x00,0x02,0x01,0x00,0x02,0x01,0x02,0x01,0x01,0x02,0x01,0x02,0x00,0x01,0x02,0x01,
      0x00,0x01,0x02,0x01,0x00,0x00,0x02,0x01,0x01,0x02,0x00,0x01,0x02,0x01,0x01,0x02,
      0x00,0x00,0x01,0x02,0x01,0x02,0x01,0x00,0x01,0x00,0x00,0x02,0x01,0x00,0x01,0x02,
      0x00,0x01,0x02,0x01,0x00,0x00,0x02,0x01,0x01,0x00,0x00,0x02,0x01,0x00,0x01,0x02
} -- cipher table selector

esc_tab = {[0x26] = 0x0a; [0x23] = 0x0d; [0x2a] = 0x3e; [0x21] = 0x3c; [0x24] = 0x40} -- escaped chars

function decode_vbe(s)
  t = ""
  for r in string.gmatch(s,"#@~%^[%w%+/=][%w%+/=][%w%+/=][%w%+/=][%w%+/=][%w%+/=][%w%+/=][%w%+/=].-%^#~@") do
    x = base64_d(r:sub(5,12))
    size = x:byte(1)+(256*x:byte(2))+(256*256*x:byte(3))+(256*256*256*x:byte(4))
    p = 0;
    skip = 0;
    for i = 1+12, math.min(size+12,#r), 1 do
      if (skip == 0) then
        c = r:byte(i)
        if (c < 128) then
          d = D_tabs[I_tab[(p % 64)+1]+1][c+1]
          if ((d == 255) and (i < #r)) then
            if (esc_tab[r:byte(i+1)] ~= nil) then
              t = t .. string.char(esc_tab[r:byte(i+1)])
            end
            skip = 1
          else
            t = t .. string.char(d)
          end
        else
          t = t .. string.char(c)
        end
        p = p + 1
      else
        skip = 0
      end
    end
  end   
  return t
end

function deobfuscate(a, verbose)
    if verbose==1 then print("Deobfuscating : " .. a) end 
    recursion_count = 0
    num_matches = 1
    while (recursion_count < 10) and (num_matches > 0) do
        num_matches = 0
        recursion_count = recursion_count + 1
        a,n = a:gsub('\\u00(%x%x)',function(i) return string.format("%c", "0x" .. i) end) num_matches = num_matches + n
        a,n = a:gsub('\\x(%x%x)',function(i) return string.format("%c", "0x" .. i) end) num_matches = num_matches + n
        a,n = a:gsub('\\([0-7][0-7][0-7])',function(i) return string.format("%c", i:sub(3,3)+(8*i:sub(2,2))+(8*8*i:sub(1,1))) end) num_matches = num_matches + n
        a,n = a:gsub('[Cc][Hh][Rr][Ww]?%((%d+)%)',function(i) return string.format("\39%c\39", i % 256) end) num_matches = num_matches + n
        a,n = a:gsub('(["\39]) *[%&%+] *%1','') num_matches = num_matches + n
        if verbose==1 and num_matches > 0 then print("Got some matches - repeating ...") end
        end
    if verbose==1 then print("Deobfuscating after " .. recursion_count .. " loops got : " .. a) end 
    return a
end
