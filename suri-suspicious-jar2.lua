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
              {"EpgKF3twh",1,true,"Blackhole URL obfuscation string"},
              {"ZKM5.4.3",1,true,"Blackhole Zelix obfuscator string"},
              {"/.:_-?&=%#;",1,true,"g01pack obfuscation string"},
              {"DEvuYp",1,true,"Nuclear obfuscation string"},
              {"yv66v",1,true,"Base-64-encoded class file"},
              {"glassfish/gmbal",1,true,"glassfish/gmbal CVE-2012-5076 exploit class file"},
              {"jmx/mbeanserver",1,true,"jmx/mbeanserver Java 0-day exploit class file"},
              {"SunToolkit", "getField","forName","setSecurityManager","execute",5,true,"CVE-2012-4681 Metasploit and others"},
              {"AtomicReferenceArray","ProtectionDomain","AllPermission","defineClass","newInstance",5,true,"BH CVE-2012-0507 Metasploit and Others"},
              {"f428e4e8",1,true,"Blackhole obfuscated class file"},
              {"CAFEBABE",1,true,"Hex-encoded class file"},
              {"hqicJqJc",1,true,"SofosFO encoded class file"},
              {'fuck','Payload','java.security.AllPermission','AtomicReferenceArray',4,true,"Blackhole Atomic Reference Array exploit"}
             }

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
    
    for n = 1, num_strings, 1 do
        m = match_set[n]
        fnd = string.find(a,m,1,plain)
        if fnd then
            cnt = cnt + 1
            if cnt == match_num then
                if verbose == 1 then print("Found " .. desc) end
                rtn = 1
                break
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
    local i, l, n, key_lengths

    if (pe < 1024) then
        if a:byte(pe+1) == string.byte('P') and
           a:byte(pe+2) == string.byte('E') and
           a:byte(pe+3) == 0 and
           a:byte(pe+4) == 0 then
            if (verbose==1) then print('Found PE32 executable') end
            return 0
        end
    end

    for i = 0, 11, 1 do
      key[i+1] = a:byte(0x30+i+1)
    end

    key_lengths = {4,5,6,12}
    for n, l in pairs(key_lengths) do
        koffset = ((l-(0x30 % l)) % l)
        pe = bit.bxor(a:byte(0x3c+1), key[1+koffset]) + (256*bit.bxor(a:byte(0x3c+2), key[2+koffset]))
        if (pe < 1024) then
            offset = pe % l
            if (bit.bxor(a:byte(pe+1), key[offset+koffset+1]) == string.byte('P')) and
               (bit.bxor(a:byte(pe+2), key[((1+offset+koffset)%l)+1]) == string.byte('E')) and
               (bit.bxor(a:byte(pe+3), key[((2+offset+koffset)%l)+1]) == 0) and
               (bit.bxor(a:byte(pe+4), key[((3+offset+koffset)%l)+1]) == 0) then
                if (verbose==1) then print('Found ' .. l .. '-byte XORed binary') end
                return 1
            end
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
            if string.sub(u,1,4) == "\202\254\186\190" then -- CAFEBABE in decimal

                for l,s in pairs(susp_class) do
                    if (verbose==1) then print("Looking for " .. s[#s] .. " in ".. w.filename) end
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
-- CAFEBABE XORed with 0x0a in decimal class file used in Styx
                if string.sub(u,1,4) == "\192\244\176\180" then
                    rtn = 1
                    if (verbose==1) then
                        print('Found Styx XORed class file in ' .. w.filename)
                    else
                        break
                    end
                end
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

