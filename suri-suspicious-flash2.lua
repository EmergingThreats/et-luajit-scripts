--[[
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

Detection for CVE-2012-1535 and suspicious strings in general
Stronger checks for some strings that may yield false positives

    ###Parsing bit is Based on swf.py from Jsunpack which is GPLv2 so we use that as well
    https://code.google.com/p/jsunpack-n/source/browse/trunk/swf.py

    ###Requirements
    
    #struct module
    sudo luarocks install struct

    #lua-zlib
    https://github.com/brimworks/lua-zlib
   
    ###Technical Description of the CVE-2012-1535 Vuln
    http://www.exploit-db.com/wp-content/themes/exploit/docs/21928.pdf

    ###Source of some suspicious strings
    http://www.symantec.com/connect/blogs/elderwood-project-behind-latest-internet-explorer-zero-day-vulnerability

This lua script can be run standalone and verbosely on a Flash file with
echo "run()" | lua -i <script name> <Flash file>

Will Metcalf
Chris Wakelin
--]]


-- {strings to match, number of matching strings needed, simple match, DoABC tag needed, description}
susp_class = {
              {"shellcode",1,true,"shellcode mentioned"},
              {"HeapSpary",1,true,"Elderwood name HeapSpary"},
              {"Flahs_Version",1,true,"Elderwood name Flahs_version"},
              {"base64","Q1dT",2,true,"Base64 encoded Flash file"},
              {"LadyBoyle_",1,true,"Flash 0day LadyBoyle string"},
              {"function(p,a,c,k,e,d)",1,true,"Edwards packer"},
             }

--[[
susp_class_doabc = {
                    {"Spray",1,true,"Spray in actionscript"},
                    {"vuln",1,true,"vuln in actionscript"}
                   }
--]]

local lz = require 'zlib'
local struct = require 'struct'
local bit = require("bit")


function init (args)
    local needs = {}
    needs["http.response_body"] = tostring(true)
    return needs
end

function match_strings(a,match_set,verbose)
    local rtn = 0
    local n,m
    local num_strings = #match_set - 3
    
    local match_num = match_set[num_strings+1]
    local plain = match_set[num_strings+2]
    local desc = match_set[num_strings+3]
    local cnt=0
    local fnd
    
--    if verbose == 1 then print("Looking for " .. match_num .. " out of " .. num_strings .. " strings : " .. desc) end
    for n = 1, num_strings, 1 do
        m = match_set[n]
--        if verbose == 1 then print("Looking for string " .. cnt .. " of " .. match_num .. " : " .. m) end
        fnd = string.find(a,m,1,plain)
        if fnd then
            cnt = cnt + 1
--            if verbose == 1 then print("Found string " .. cnt .. " of " .. match_num .. " : " .. m) end
            if cnt == match_num then
                if verbose == 1 then print("Found " .. desc) end
                rtn = 1
                break
            end
        end
    end
    return rtn
end

function common(t,o,verbose)
    -- CWS and FWS are both 3 bytes long
    -- Method should work for Flash inside of OLE etc.
--    local o = args["offset"]
    rtn = 0

    t = string.sub(t,o - 3) 
    local tlen = string.len(t)

    --Parse the SWF Header
    local sig = string.sub(t,1, 3)
    local ver = string.byte(t,4)
    local len = struct.unpack("<I4",string.sub(t,5,8))

    --subtract sig,ver,len
    local parsed_len = (len - 8)

    -- store uncompressed length
    local uncompressed_len = 0

    if verbose==1 then print("Sig = " .. sig) end
    if sig  == "CWS" then 
        stream = lz.inflate()
        t, eof, bytes_in, uncompressed_len = stream(string.sub(t,9))
    elseif sig ~= "FWS" then
        if verbose==1 then print("Not a SWF file bailing" .. sig) end
        return 0
    end

    for l,s in pairs(susp_class) do
        if (verbose==1) then print("Looking for " .. s[#s]) end
        if match_strings(t,s,verbose) == 1 then
            rtn = 1
            if (verbose == 0) then
                break
            end
        end
    end
    if rtn == 1 then return 1 end

    local offset = 9 
    --get number of bits in the rect
    local rectbits = bit.rshift(string.byte(t,9),3)

    if ((rectbits * 4) % 8) == 0 then
        more = rectbits * 4 / 8
    else
        more = math.floor(rectbits * 4 / 8) + 1
    end

    offset = offset + more + 1
    offset = offset + 4 

    --iterate over the tags---
    while offset + 1 < len do
        b = string.byte(t,offset)
        a = string.byte(t,offset + 1)

        -- Out of bytes
        if a == nil or b == nil then 
           if verbose==1 then print("out of bytes") end
           return 0
        end

        -- get tag bits --
        offset = offset + 2
        tagtype = bit.band(((bit.lshift(a,2)) + (bit.rshift(b,6))),0x03ff)
        shortlen = bit.band(b,0x3f)

        -- is this a long tag format?
        if shortlen == 0x3f then
            shortlen = struct.unpack("<I4",string.sub(t,offset,offset+4))
            offset = offset + 4
        end

        if tagtype == 91 then
            ttfoffset = offset + 3
            -- Find the end of the font name
            ttfoffset = string.find(t,'\x00',ttfoffset,true) + 1
            if verbose==1 then print("ttoffset = " .. ttfoffset) end
            ttf = string.sub(t,ttfoffset, ttfoffset + shortlen)
            ktag = string.find(ttf,'kern',12,true)
            if ktag ~= nil then
                -- Inside TTF we are big endian
                ktoffset = struct.unpack(">I4",string.sub(ttf,ktag + 8, ktag + 11))
                if verbose==1 then print("ktoffset, shortlen = " .. ktoffset .. "," .. shortlen) end
                --make sure this is the type we are looking for
                if string.sub(ttf,ktoffset + 1, ktoffset + 4) == "\x00\x01\x00\x00" then
                    --print("made it this far")
                    ntables = struct.unpack(">I4",(string.sub(ttf,ktoffset + 5, ktoffset + 8)))
                    ntables_bad = struct.unpack(">I4","\x10\x00\x00\x00") 
                    if ntables >= ntables_bad then
                        if verbose==1 then print("we have a match " .. ntables) end
                        return 1
                    end 
                end
            end
        end
        --DoABC tag
        if tagtype == 82 then
            DoABC = string.sub(t,offset, offset + shortlen)
            s,e = string.find(DoABC,"RegExp",0,true)
            if s ~= nil then
                if string.find(DoABC,"%#[\x20-\x7f]*%(%?[sxXmUJ]*i[sxXmUJ]*%-?[sxXmUJ]*%)[\x20-\x7f]*%(%?[sxXmUJ]*%-[sxXmUJ]*i[sxXmUJ]*%)[\x20-\x7f]*%|%|",s) ~= nil then
                    if verbose==1 then print("Found CVE-2013-0634") end
                    return 1
                end
            end
        end
        offset = offset + shortlen  
    end
    return 0
end

function match(args)
    local t = tostring(args["http.response_body"])
    local o = args["offset"]
    return common(t,o,0)
end

function run()
  local f = io.open(arg[1])
  local t = f:read("*all")
  f:close()
  common(t,4,1)
end

