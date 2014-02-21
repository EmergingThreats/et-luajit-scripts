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

    #ltn12ce to build on Ubuntu-12.04 I had to "cmake .. -DBUILD_ZLIB=Off"
    https://github.com/mkottman/ltn12ce
       
    ###Technical Description of the CVE-2012-1535 Vuln
    http://www.exploit-db.com/wp-content/themes/exploit/docs/21928.pdf

    ###Source of some suspicious strings
    http://www.symantec.com/connect/blogs/elderwood-project-behind-latest-internet-explorer-zero-day-vulnerability

This lua script can be run standalone and verbosely on a Flash file with
echo "run()" | luajit -i <script name> <Flash file>

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
              {"DirtyData","OYaDood",2,true,"Malvertisng Redirect"},
              {"getVersion(\x22Java\x22)",1,true,"Malvertising PluginDetect Get Java Version"},
              {"getVersion(\x22AdobeReader\x22)",1,true,"Malvertising PluginDetect Get Adobe Reader Version"},
              {"C\x3a\x5cUsers\x5cVlaDis\x5cDocuments\x5cFlashDevelop\x5ccareer\x5csrc",1,true,"Malvertising EK Redirect"},
              {"9b909c8a929a918bd19c8d9a9e8b9aba939a929a918bd7d896998d9e929ad8d6c4",1,true,"Malvertising xor'd iframe http://malware.dontneedcoffee.com/2013/08/cbeplayp-history-increased-activity.html"},
              {"978b8b8fc5d0d0",1,true,"Malvertising xor'd http:// http://malware.dontneedcoffee.com/2013/08/cbeplayp-history-increased-activity.html"},
              {"King Lich V",1, true,"CK EK http://www.kahusecurity.com/2013/deobfuscating-the-ck-exploit-kit"},
              {"ExploitSwf",1, true,"Angler EK"},
              {"\x01\x00\x00\x00\x00\x00\xfe\x1f\xca",1,true,"Malvertising XORed Flash file #1"},
              {"\x01\x00\x00\x00\x00\x00\xce\x5f\xc5",1,true,"Malvertising XORed Flash file #2"},
              {"\x01\x00\x00\x00\x00\x00\xce\xa2\x6f",1,true,"Malvertising XORed Flash file #3"},
              {"SharePoint.OpenDocuments.4","SharePoint.OpenDocuments.3","ms-help\x3a\x2f\x2f","location.href",4,true,"ms-help as location href likely spray attempt"},
              {"JavaWebStart.isInstalled.1.6.0.0","JavaWebStart.isInstalled.1.7.0.0",1,true,"Possible ASLR Bypass JavaWebStart"},
              {"BITCH_SEARCH_RADIUS_DWORDS",1,true,"e-how/livestrong malicious SWF file"},
              {"createIframe(","getCookie(","createCookie(","navigator.userAgent.toString",4,true,"SWF CookieBomb"},
              {"Protected by secureSWF<br/>Demo version.",1,true,"secureSWF Demo Version Used in ehow/livestrong attacks"},
              {"cookie_al_new","externalXML","navigator.userAgent.toString","externalXML",4,true,"SWF CookieBomb 2"},
              {"rop_gadget","DoExploit","attacker_class_bin",1,true,"SWT/GrandSoft Exploit"},
              {"[hH][eE][aA][pP][sS][Pp][Rr][Aa][Yy]",1,false,"Unknown heapspray string found"},
              {"makePayloadWin",1,true,"Possible 2014-0497 https://www.securelist.com/en/blog/8177/CVE_2014_0497_a_0_day_vulnerability"},
              {"counterswfcookie","{addDiv('<iframe src=","{return document.cookie;}","window.navigator.userAgent",4,true,"Fiesta Redirect"},
              {"Vector","\x1d\x01\x01\x05OZZDLG[DCM[GE[@AZ\x16\x14\x19\x16DDD[\x10\x0d\x10uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu0000000000000000000000\x01\x02",2,true,"VFW ASLR Bypass"},
              {"C:\x5cUsers\x5c007\x5cDesktop\x5cFlashExp(ie)\x5csrc",1,true,"Flash 0-day Feb 19 2014 007 Debug String"},
              --{"_doswf_package",1, true,"DoSWF encoded Flash File http://www.kahusecurity.com/2013/deobfuscating-the-ck-exploit-kit"},
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
local max_nesting_cnt = 0
local max_nesting_limit = 1

local core = require "ltn12ce.core"

io.stdout:setvbuf'no'
assert(core.lzma, 'no lzma ltn12ce.core')
assert(not pcall(core.lzma), 'expecting error')

function init (args)
    local needs = {}
    needs["http.response_body"] = tostring(true)
    return needs
end

function lzma_d(cdata)
    local append = table.insert
    local d = assert(core.lzma('decompress'), 'failed to start decompression')

    local decompressed = {}
    string.gsub(cdata,"(.)",
    function (c)
        local ret,p = pcall(function()return d:update(c)end)
        if ret then
            append(decompressed, p)
        end
    end)
    local ret,f = pcall(function()d:finish()end)
    if ret then
        append(decompressed, f)
    end

    decompressed = table.concat(decompressed)
    return decompressed
end

--http://snippets.luacode.org/?p=snippets/String_to_Hex_String_68
function HexDumpString(str,spacer)
    return (
    string.gsub(str,"(.)",
    function (c)
        return string.format("%02X%s",string.byte(c), spacer or "\\")
    end)
    )
end

function xor_bin_check (a,verbose)
    if #a < 1024 then
       return 0
    end

    local bit = require("bit")

    local pe = a:byte(0x3c+1) + (256*a:byte(0x3c+2))
    local key = {}
    local i, l, n, key_lengths, offset, koffset, zeroes

    if (pe < 4096) then
        if a:byte(pe+1) == string.byte('P') and
           a:byte(pe+2) == string.byte('E') and
           a:byte(pe+3) == 0 and
           a:byte(pe+4) == 0 then
            if (verbose==1) then print('Found PE32 executable') end
            return 0
        end
    end

    key_lengths = {4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24}

    for n, l in pairs(key_lengths) do
        zeroes = 0x30;
        if (l > 12) then zeroes = 0x28; end
        if (l > 20) then zeroes = 0x20; end

        koffset = ((l-(zeroes % l)) % l)

        for i = 0, l-1, 1 do
           key[i+1] = a:byte(zeroes+1+((i+koffset) % l))
        end


        pe = bit.bxor(a:byte(0x3c+1), key[1+(0x3c % l)]) + (256*bit.bxor(a:byte(0x3c+2), key[1+((0x3c+1) % l)]))
        if verbose==1 then print("Trying " .. l .. "-byte XOR key; PE block at " .. pe) end
        if (pe < 4096) then
            offset = pe % l
            if a:byte(pe+4) ~= nil and key[((3+offset)%l)+1] ~= nil then
                if (bit.bxor(a:byte(pe+1), key[offset+1]) == string.byte('P')) and
                   (bit.bxor(a:byte(pe+2), key[((1+offset)%l)+1]) == string.byte('E')) and
                   (bit.bxor(a:byte(pe+3), key[((2+offset)%l)+1]) == 0) and
                   (bit.bxor(a:byte(pe+4), key[((3+offset)%l)+1]) == 0) then
                   if verbose==1 then print("Found " .. l .. "-byte XOR key; PE block at " .. pe) end
                     return 1
                end
            end
        end
    end

    return 0
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
    -- Method should work for Flash inside of OLE etc.
--    local o = args["offset"]
    rtn = 0
    local t = string.sub(t,o - 3) 
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
    elseif sig == "ZWS" then
        lzma = t:sub(13,17)
        lzma = lzma .. struct.pack("<I8",parsed_len)
        c_data = t:sub(18)
        lzma = lzma .. c_data
        t=lzma_d(lzma)
    elseif sig == "FWS" then
        t=string.sub(t,9)
    else
        if verbose==1 then print("Not a SWF file bailing" .. sig) end
        return 0
    end
    --print(t)
    for l,s in pairs(susp_class) do
        if (verbose==1) then print("Looking for " .. s[#s]) end
        if match_strings(t,s,verbose) == 1 then
            rtn = 1
            if (verbose == 0) then
                break
            end
        end
    end
    if (verbose == 0) then
        if rtn == 1 then return 1 end
    end
    --get number of bits in the rect
    local rectbits = bit.rshift(bit.band(string.byte(t,1),0xff),3)
    offset = math.floor((7 + (rectbits*4) - 3) / 8) + 5 + 1

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
                _,_,capture =string.find(DoABC,"(%#[\x20-\x7f]*%(%?[sxXmUJ]*i[sxXmUJ]*%-?[sxXmUJ]*%)[\x20-\x7f]*%(%?[sxXmUJ]*%-[sxXmUJ]*i[sxXmUJ]*%)[\x20-\x7f]*%|%|)",s)
                if capture ~= nil then
                    if verbose==1 then print("Found CVE-2013-0634 " .. capture) end
                    return 1
                end
            end
        end
        if tagtype == 87 then
            binoffset = offset + 6
            if verbose==1 then print("DefineBinary tag id " .. ((256*t:byte(offset+1)) + t:byte(offset)) .. " at " .. offset) end
            if string.sub(t,binoffset,binoffset+2) ~= "CWS" and bit.bxor(t:byte(binoffset),t:byte(binoffset+1)) == 20 and bit.bxor(t:byte(binoffset),t:byte(binoffset+2)) == 16 then
                if verbose==1 then print("Found XORed Flash header 'CWS' in binary file") end
                return 1
            end
            -- Look for Embedded XOR bins
            if xor_bin_check(string.sub(t,offset + 6,offset + shortlen),verbose) == 1 then
                return 1
            end
            -- Inspect Embeded Flash to a certian point. If nesting is to deep fire an event
            if string.sub(t,binoffset,binoffset+2) == "CWS" or string.sub(t,binoffset,binoffset+2) == "FWS" then
                if max_nesting_cnt < max_nesting_limit then
                    if common(string.sub(t,offset + 6,offset + shortlen),4,verbose) == 1 then
                        if verbose==1 then print("Found Evil in Embedded Flash File") end
                        return 1
                    else
                        max_nesting_cnt = max_nesting_cnt + 1
                    end
                --[[else
                    if verbose==1 then print("We passed a Maximum Flash Nesting Count Limit of " .. max_nesting_limit) end
                    return 1]]--
                end
            end 
        end
        --[[if verbose == 1 then
            print("++++++++++++++++++++++++++++++++++++++++++++")
            print("tagtype:"..tagtype)
            print(string.sub(t,offset, offset + shortlen))
        end--]]
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

