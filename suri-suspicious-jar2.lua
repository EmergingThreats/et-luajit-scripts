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

Detection for suspicious Jar files requires lua zip module.
sudo apt-get install liblua5.1-zip-dev 

This lua script can be run standalone and verbosely on a Jar file with
echo "run()" | lua -i <script name> <jar file>

Chris Wakelin
Will Metcalf
--]]

require("zip")
-- {strings to match, number of matching strings needed, simple strings, description}
susp_class = {
              {"EpgKF3twh",1,true,"Blackhole URL obfuscation string",0},
              {"ZKM5.4.3",1,true,"Blackhole Zelix obfuscator string",0},
              {"/.:_-?&=%#;",1,true,"g01pack obfuscation string",0},
              {"zoOloloshit","MyPa@yload@.cla@@ss","getololoByName",1,true,"Metasploit based EK",0},
              {"%zI.........................................................................\1%zI.........................................................................\12",1,false,"possible g01pack obfuscation strings",0},
              {"DEvuYp",1,true,"Nuclear obfuscation string",0},
              {"9.-=_/:?&",1,true,"RedKit/Sakura obfuscation string",0},
              {"yv66v",1,true,"Base-64-encoded class file",0},
              {"/upload/install_flash_player.",1,true,"Unknown EK Payload Download",0},
              {"glassfish/gmbal",1,true,"glassfish/gmbal CVE-2012-5076 exploit class file",0},
              {"jmx/mbeanserver",1,true,"jmx/mbeanserver Java 7u9 exploit class file",0},
              {"mbeanserver/Introspector",1,true,"mbeanserver/Introspector Java 7u11 exploit class file",0},
              {'glassfish/external/statistics/impl',1,true,"CVE-2012-5076 2 exploit class file",0},
              {"management/MBeanServer",1,true,"management/MBeanServer Java 7 exploit class file",0},
              {'sun.org.mozilla.javascript.internal.Context','sun.org.mozilla.javascript.internal.GeneratedClassLoader',2,true,"Mozilla JS Class Creation Used in Various Exploits",0},
              {"SunToolkit", "getField","forName","setSecurityManager","execute",5,true,"CVE-2012-4681 Metasploit and others",0},
              {"AtomicReferenceArray","ProtectionDomain","AllPermission","defineClass","newInstance",5,true,"BH CVE-2012-0507 Metasploit and Others",0},
              {'java/awt/color/ColorSpace','BufferedImage','StackTrace',3,true,"CVE-2013-1493 exploit",0},
              {"f428e4e8",1,true,"Blackhole obfuscated class file",0},
              {"CAFEBABE",1,true,"Hex-encoded class file",0},
              {"[Cc].?.?.?[Aa].?.?.?[Ff].?.?.?[Ee].?.?.?[Bb].?.?.?[Aa].?.?.?[Bb].?.?.?[Ee]",1,false,"Hex-encoded class file (possibly obfuscated)",0},
              {"F-Abr-rb",1,true,"Cool EK/SofosFO encoded class file",0},
              {'fuck','Payload','java.security.AllPermission','AtomicReferenceArray',4,true,"Blackhole Atomic Reference Array exploit",0},
              {'invokeWithArguments','invoke/MethodHandle','invoke/MethodType','forName',4,true,"CVE-2012-5088 exploit class file",0},
              {'wnin.frphevgl',1,true,"rot13-encoded class name",0},
              {"reflect/Field","invoke/MethodHandle","invokeExact","findStaticSetter",3,true,"CVE-2013-2423",0},
              {"etSecurityManager",1,true,"[gs]etSecurityManager www.fireeye.com/blog/technical/2013/06/get-set-null-java-security.html",0},
              {"jdbc:msf:sql://",1,true,"CVE-2013-1488 Metasploit",0},
              {"reganaMytiruceS",1,true,"SecurityManger reversed PrivatePack June 27 2013",0},
              {"tracing/ProviderFactory",1,true,"CVE-2013-2460",0},
              {"java/security/ProtectionDomain",1,true,"Generic java/security/ProtectionDomain (Observed in Styx)",0},
              {"isableSecurity",1,true,"Generic [Dd]isableSecurity (Observed in Styx)",0},
              {"java/awt/image/","Raster","SampleModel",3,true,"CVE-2013-2465/2471",0}
             }

obfus_strings = {
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

function xor_bin_check (a,verbose)
    if #a < 1024 then
       return 0
    end

    local bit = require("bit")

    local pe = a:byte(0x3c+1) + (256*a:byte(0x3c+2))
    local key = {}
    local i, l, n, key_lengths, offset, koffset, zeroes

    if (pe < 2048) then
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
        if (pe < 2048) then
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

    return 0
end

function xor_class_check (a,verbose)
    if #a < 1024 then
       return 0
    end
    local bit = require("bit")
    local k = bit.bxor(a:byte(1), 0xca) 
    if k ~= 0 then
        if (bit.bxor(a:byte(2), k) == 0xfe) and
           (bit.bxor(a:byte(3), k) == 0xba) and
           (bit.bxor(a:byte(4), k) == 0xbe) then
            if (verbose==1) then print('Found class file XORed with ' .. k) end
            return 1
        end
    end
    return 0
end

function common(t,verbose)

    rtn = 0

    -- tmpfs setup should be faster
    -- mkdir -p /home/suricata/scratch  && sudo mount -t tmpfs -o size=1G,mode=0700 tmpfs /home/suricata/scratch && sudo chown suricata:suricata /home/suricata/scratch/
    -- tmpname = "/home/suricata/scratch/eviljars." .. tostring(os.time()) .. "." .. tostring(math.random(2000000,9000000))
    tmpname = os.tmpname()

    tmp = io.open(tmpname,'w')
    tmp:write(t)
    tmp:close()

    z = zip.open(tmpname)

    if z then 
        for w in z:files() do
            f = z:open(w.filename);
            u = f:read("*all")
            f:close()
            if (verbose==1) then print("Checking " .. w.filename) end
            if (string.sub(u,1,4) == "\202\254\186\190" or string.sub(u,1,2) == "\172\237") then -- CAFEBABE or ACED in decimal
                for l,s in pairs(susp_class) do
                    if (verbose==1) then print("Looking for " .. s[#s-1] .. " in ".. w.filename) end
                    if match_strings(u,s,verbose) == 1 then
                        rtn = 1
                        if (verbose == 0) then
                           break
                        end
                    end
                end
                
            else 

--- Not a class file - see if it is some form of EXE

--- SPL obfuscated EXE - XOR key
                fnd = string.find(u,"\201\203\195\162\145",1,true)
                if fnd then
                    rtn = 1
                    if (verbose==1) then
                        print('Found SPL 5-byte XOR key in ' .. w.filename)
                    else
                        break
                    end
                end
-- CAFEBABE XORed with single byte as found in Styx; can't be XORed with 0 or we wouldn't be here
                if xor_class_check(u,verbose) == 1 then
                    rtn = 1
                    if (verbose==1) then
                        print('Found XORed class file in ' .. w.filename)
                    else
                        break
                    end
                end
-- CAFEBABE XORed with 0x0a in class file used in Styx
                if string.sub(u,1,4) == "\192\244\176\180" then
                    rtn = 1
                    if (verbose==1) then
                        print('Found Styx XORed class file in ' .. w.filename)
                    else
                        break
                    end
                end
-- Stolen GoDaddy certificate Serial number 2b:73:43:2a:a8:4f:44
                fnd = string.find(u,"\43\115\67\42\168\79\68",1,true) 
                if fnd then
                    rtn = 1
                    if (verbose==1) then
                        print('Found Stolen GoDaddy CLEARESULT certificate in ' .. w.filename)
                    else
                        break
                    end
                end
-- Registry File
                if (string.sub(u,1,8) == "REGEDIT4" or string.sub(u,1,8) == "REGEDIT5" or string.sub(u,1,23) == "Windows Registry Editor") then
                    rtn = 1
                    if (verbose==1) then
                        print('Registry File Found in ' .. w.filename)
                    else
                        break
                    end
                end
-- XORed PE32 Executable
                if xor_bin_check(u,verbose) == 1 then
                    rtn = 1
                    if (verbose==1) then
                        print('Found possibly XORed PE32 executable in ' .. w.filename) 
                    else
                        break
                    end
                end
            end
            if (rtn == 1) and (verbose == 0) then
                break
            end
        end
        z:close()
    end
    os.remove(tmpname)
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

