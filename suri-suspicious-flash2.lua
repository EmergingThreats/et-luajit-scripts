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
              {"FindRopGadgets",1,true,"FindRopGadgets Function Observed in FlashPack"},
              {"0x9Rl5W59Rl5W59Rl5W59Rl5W5",1,true,"SWT/RIG 2014-0569 NOP with subs"},
              {"E:\092CrackAndHack",1,true,"RIG FlashFile"}, 
              {"HeapSpary",1,true,"Elderwood name HeapSpary"},
              {"Flahs_Version",1,true,"Elderwood name Flahs_version"},
              {"payloadRc4Key","import exploit","exploitUrl",1,true,"Job314 EK"},
              {"exploit","crypt","landing",3,true,"Job314 EKv2"},
              {"#default#VML","dashstyle.array.length",2,"true","Probable CVE-2013-2551 Exploit"},
              --{"<applet",1,"true","Applet Tag Inside of Flash"},
              {"base64","Q1dT",2,true,"Base64 encoded Flash file"},
              {"LadyBoyle_",1,true,"Flash 0day LadyBoyle string"},
              {"function(p,a,c,k,e,d)",1,true,"Edwards packer"},
              {"DirtyData","OYaDood",2,true,"Malvertisng Redirect"},
              {"getVersion(\034Java\034)",1,true,"Malvertising PluginDetect Get Java Version"},
              {"getVersion(\034AdobeReader\034)",1,true,"Malvertising PluginDetect Get Adobe Reader Version"},
              {"C\058\092Users\092VlaDis\092Documents\092FlashDevelop\092career\092src",1,true,"Malvertising EK Redirect"},
              {"9b909c8a929a918bd19c8d9a9e8b9aba939a929a918bd7d896998d9e929ad8d6c4",1,true,"Malvertising xor'd iframe http://malware.dontneedcoffee.com/2013/08/cbeplayp-history-increased-activity.html"},
              {"978b8b8fc5d0d0",1,true,"Malvertising xor'd http:// http://malware.dontneedcoffee.com/2013/08/cbeplayp-history-increased-activity.html"},
              {"King Lich V",1, true,"CK EK http://www.kahusecurity.com/2013/deobfuscating-the-ck-exploit-kit"},
              {"ExploitSwf",1, true,"Angler EK"},
              {"\001\000\000\000\000\000\254\031\202",1,true,"Malvertising XORed Flash file #1"},
              {"\001\000\000\000\000\000\206\095\197",1,true,"Malvertising XORed Flash file #2"},
              {"\001\000\000\000\000\000\206\162\111",1,true,"Malvertising XORed Flash file #3"},
              {"SharePoint.OpenDocuments.4","SharePoint.OpenDocuments.3","ms-help\058\047\047","location.href",4,true,"ms-help as location href likely spray attempt"},
              {"JavaWebStart.isInstalled.1.6.0.0","JavaWebStart.isInstalled.1.7.0.0",1,true,"Possible ASLR Bypass JavaWebStart"},
              {"BITCH_SEARCH_RADIUS_DWORDS",1,true,"e-how/livestrong malicious SWF file"},
              {"createIframe(","getCookie(","createCookie(","navigator.userAgent.toString",4,true,"SWF CookieBomb"},
              {"Protected by secureSWF<br/>Demo version.",1,true,"secureSWF Demo Version Used in ehow/livestrong attacks"},
              {"cookie_al_new","externalXML","navigator.userAgent.toString","externalXML",4,true,"SWF CookieBomb 2"},
              {"rop_gadget","DoExploit","attacker_class_bin",1,true,"SWT/GrandSoft Exploit"},
              {"[hH][eE][aA][pP][sS][Pp][Rr][Aa][Yy]",1,false,"Unknown heapspray string found"},
              {"[Rr][Oo][Pp][_]-[Gg][Aa][Dd][Gg][Ee][Tt]",1,false,"RopGadget string found"},
              {"makePayloadWin",1,true,"Possible 2014-0497 https://www.securelist.com/en/blog/8177/CVE_2014_0497_a_0_day_vulnerability"},
              {"counterswfcookie","{addDiv('<iframe src=","{return document.cookie;}","window.navigator.userAgent",4,true,"Fiesta Redirect"},
              {"Vector","\029\001\001\005OZZDLG[DCM[GE[@AZ\022\020\025\022DDD[\016\013\016uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu0000000000000000000000\001\002",2,true,"VFW ASLR Bypass"},
              {"C:\092Users\092007\092Desktop\092FlashExp(ie)\092src",1,true,"Flash 0-day Feb 19 2014 007 Debug String"},
              {"createRandomPassword","allowLoadBytesCodeExecution","%]%.replace%(%/.-%/g,[^%)]-%)%.replace%(%/.-%/g,[^%)]-%)%}eval%(",3,false,"Malvertising With Plugin-Detect"},
              {"RegExp","||||||||||||||||||||","(?i)()()(?-i)",3,true,"NuclearEK"},
              {"RegExp","\040\063\045\074\041\040\063\045\105\041","||||||||||||||||||||","\041\040\063\045\105\041",3,true,"Flash Exploit"},
              {"RegExp","\040\063\061\040\063\061\040\063\061\040\063\061\040\063\061\040\063\061\040\063\061\040\063\061\040\063\061\040\063\061\040\063\061",2,true,"Flash Exploit"},
              {"DoExploit","scan_for_rop_gadgets","make_vtable_rop_and_shellcode",1,true,"NuclearEK"},
              {"func_decodestr","func_strtobytearr","loadBytes","%W0x%W",4,false,"NuclearEK"},
              {"y5ncGlra25lcw","vial",2,true,"Goon/Fiesta"},
              {"bb4v45nywriteUns","soonug","ibvctm3tloadB","g4f53addEven",1,true,"FiestaEK"},
              {"Tope","Pidj7gbU",2,true,"DeputyDog"},
              {"naidnEelttil","reverse",2,true,"CottonCastle"},
              {"avm2.intrinsics.memory","domainMemory","Capabilities","11,0,1,152","ByteArray","littleEndian",6,true,"Possible CVE-2014-0497"},
              {"boobe","90909090909090909090909090909090","atomicCompareAndSwapLength","RegExp",4,true,"Possible SweetOrange"},
              {"F:\092EXP\092CVE-2014-0569","ropgadget","buildx32rop","buildx64rop",1,"true","Possible Nuclear 2014-0569"},
              {"C:\092project1\092src;;aeryk.as",1,true,"Archie"},
              {"101d1952....4a4a",1,false,"NullHole XOR 74 ZWS File"},
              {"086c15c68e55a86ce8695e74431e",1,true,"Unknown EK Flash Exploit Key"},
              {"liveTimeLock","applyXor","paint.net",3,true,"Unknown EK Flash Exploit"},
              {"l%d+o%d+a%d+d%d+B%d+y%d+t%d+e%d+s",1,false,"Angler EK"},
              {"%22%20%66%72%61%6D%65%62%6F%72%64%65%72%3D%22%30%22%20%68%65%69%67%68%74%3D%22%30%22%20%77%69%64%74%68%3D%22%30%22%20%3E%3C%2F%69%66%72%61%6D%65%3E%27%3B","I:\092__WRK\092BANNER_V3\092src;;Main.as",1,true,"SoakSoak"},
              {"rF4gR7geU7d6t5LJfr8sb","write_Byte",2,true,"AnglerEK"},
              {"\007\000\000\000\000\000\055\098\128\147\215\021\006\000\000\000\000\000","\003\000\000\000\000\000\CWS",2,true,"2015-0311 Exploit"},
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

function job314_check(a,verbose)
    local rtn = 0
    s,e,m,c1,c2,c3,c4 = string.find(a,"(_a[-_]+%W-%W_a[-_]+%W-_a[-_]+%W+([a-z]+)\036([a-f0-9]+)\045-%d+%W+([a-z]+)\036([a-f0-9]+)\045-%d+%W-[a-z]+%W)")
    if s ~= nil then
         if string.len(c1) > 6 and string.len(c1) < 20 and string.len(c2) > 31 and string.len(c2) < 43 and string.len(c3) > 6 and string.len(c3) < 20 and string.len(c4) > 31 and string.len(c4) < 43 then
            if verbose == 1 then print("Found Job314") end
            rtn = 1
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
    if job314_check(t,verbose) == 1 then
        if (verbose == 0) then
            return 1
        else
            rtn = 1
        end 
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
            ttfoffset = string.find(t,'\000',ttfoffset,true) + 1
            if verbose==1 then print("ttoffset = " .. ttfoffset) end
            ttf = string.sub(t,ttfoffset, ttfoffset + shortlen)
            ktag = string.find(ttf,'kern',12,true)
            if ktag ~= nil then
                -- Inside TTF we are big endian
                ktoffset = struct.unpack(">I4",string.sub(ttf,ktag + 8, ktag + 11))
                if verbose==1 then print("ktoffset, shortlen = " .. ktoffset .. "," .. shortlen) end
                --make sure this is the type we are looking for
                if string.sub(ttf,ktoffset + 1, ktoffset + 4) == "\000\001\000\000" then
                    --print("made it this far")
                    ntables = struct.unpack(">I4",(string.sub(ttf,ktoffset + 5, ktoffset + 8)))
                    ntables_bad = struct.unpack(">I4","\016\000\000\000") 
                    if ntables >= ntables_bad then
                        if verbose==1 then print("we have a match " .. ntables) end
                        return 1
                    end 
                end
            end
        end
        --[[
        if tagtype == 20 or tagtype == 36 then
            local imgid = struct.unpack("<I2",string.sub(t,offset, offset + 1))
            local format = struct.unpack("<I1",string.sub(t,offset + 2,offset + 2))
            local width = struct.unpack("<I2",string.sub(t,offset + 3, offset + 4))
            local height = struct.unpack("<I2",string.sub(t,offset + 5, offset + 6))
            local color_table_cnt = struct.unpack("<I1",string.sub(t,offset + 7,offset + 7)) + 1

            if format == 0 or format == 1 or format == 2 then
                if verbose==1 then print("Found DefineLossless with Unsupported imgformat" .. format) end
                    return 1
            end
        end
        ]]--
        --DoABC tag
        if tagtype == 82 then
            DoABC = string.sub(t,offset, offset + shortlen)
            s,e = string.find(DoABC,"RegExp",0,true)
            if s ~= nil then
                _,_,capture =string.find(DoABC,"(%#[\032-\127]*%(%?[sxXmUJ]*i[sxXmUJ]*%-?[sxXmUJ]*%)[\032-\127]*%(%?[sxXmUJ]*%-[sxXmUJ]*i[sxXmUJ]*%)[\032-\127]*%|%|)",s)
                if capture ~= nil then
                    if verbose==1 then print("Found CVE-2013-0634 " .. capture) end
                    return 1
                end
                s,e,c1,c2=string.find(DoABC,"(0x9([A-Za-z0-8][A-Za-z0-8]+)9)")
                if c1 ~= nil then
                    local swt_split = c1 .. c2 .. "9" .. c2
                    if string.sub(DoABC,s,s + string.len(swt_split)-1) == swt_split  and string.find(DoABC,"%W0x%W") ~= nil then
                        if verbose==1 then print("Found SweetOrange Split " .. swt_split) end
                        return 1
                    end
                end            
            end
            s,e = string.find(DoABC,"[TtcCpP]ropChain")
            if s == nil then
                s,e = string.find(DoABC,"[Rr][Oo][Pp][Cc][Hh][Aa][Ii][Nn]")
                if s ~= nil then
                    if verbose==1 then print("Found RopChain") end
                    return 1                        
                end
            end
        end
        if tagtype == 87 then
            binoffset = offset + 6
            local bindata = string.sub(t,offset + 6,offset + shortlen)
            local tagid = ((256*t:byte(offset+1)) + t:byte(offset))
            if verbose==1 then print("DefineBinary tag id " .. tagid .. " at " .. offset) end
            if string.find(bindata,"defaultValue",0,true) ~= nil and string.find(bindata,"maxValue",0,true) ~= nil and string.find(bindata,"minValue",0,true) ~= nil then
                local cs,ce =string.find(bindata,"\162\007\100\101\102\097\117\108\116\086\097\108\117\101\000")
                if ce ~= nil then
                    local m2 = string.sub(bindata,ce+5,ce+8)
                    sfloat = struct.unpack("<I4",m2)
                    if sfloat > 2000000000 then
                        if verbose==1 then print("Found CVE-2014-0515 Exploit") end
                        return 1
                    end
                end
            end
            if string.sub(t,binoffset,binoffset+2) ~= "CWS" and bit.bxor(t:byte(binoffset),t:byte(binoffset+1)) == 20 and bit.bxor(t:byte(binoffset),t:byte(binoffset+2)) == 16 then
                if verbose==1 then print("Found XORed Flash header 'CWS' in binary file") end
                return 1
            end
            -- Look for Embedded XOR bins
            if xor_bin_check(string.sub(t,offset + 6,offset + shortlen),verbose) == 1 then
                return 1
            end
            if string.find(bindata,"doswf",0,true) ~= nil then
                block_size = string.sub(bindata,1,1)
	        key = string.sub(bindata,2,2)
	        offset = struct.unpack("<I4",string.sub(bindata,3,6))
	        length = struct.unpack("<I4",string.sub(bindata,6,9))
                print(HexDumpString(block_size))
                print(HexDumpString(key))
                print(offset)
                print(length)

                --print(HexDumpString(bindata))
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

