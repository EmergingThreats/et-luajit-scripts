--[[
#*************************************************************
#  Copyright (c) 2003-2012, Emerging Threats
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

Chris Wakelin
Will Metcalf
--]]

require("zip")

function init (args)
    local needs = {}
    needs["http.response_body"] = tostring(true)
    return needs
end

function find_set_match_multi_file(input_s,g_match_set,g_match_cnt,return_on_single)
    local rtn = 0
    for n,m in pairs(g_match_set) do
        --for i,v in ipairs(g_match_set) do print(i,v) end
        -- Do a non-regex match "plain" match for our strings
        if m ~= 0 then
            local fnd = string.find(input_s,m,1,true)
            if fnd then
                if return_on_single then
                    rtn = 1
                    --print("This is my BOOM stick " .. m)
                    break
                else
                    --print("found " .. m .. n)
                    g_match_cnt[1] = g_match_cnt[1] + 1
                    g_match_set[n]=0
                    --print(g_match_cnt[1])
                    --If we have match_cnt == number of input strings everything matched
                    if g_match_cnt[1] == #g_match_set then
                        --print("Then it came after me, it got into my hand and it went bad, so I lopped it off at the wrist.")
                        rtn = 1
                        break
                    end
                end
            end
        end
    end
    return rtn
end

function match(args)
    local t = tostring(args["http.response_body"])
    local rtn = 0

    --Need tables for the match_cnt as well so they are passed as reference. Ya these can probably all live a a strings table but I'm still a lua newb. 
    -- CVE-2012-4681 Metasploit and others
    s2f1 = {'SunToolkit', 'getField','forName','setSecurityManager','execute'}
    s2f1_mcnt = {0}

    -- BH CVE-2012-0507 Metasploit and Others
     s2f2 = {'AtomicReferenceArray','ProtectionDomain','AllPermission','defineClass','newInstance'}
     s2f2_mcnt = {0}

    -- Metasploit and Others CVE-2012-5076
    s2f3 = {'glassfish/gmbal','GenericConstructor','ManagedObjectManagerFactory','/reflect'}
    s2f3_mcnt = {0}

    -- If any of these match assume it's evil and return
    -- Blackhole URL obfuscation string EpgKF3twh
    -- Zelix obfuscator version string as used in Blackhole ZKM5.4.3
    -- g01pack URL obfuscation string "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/.:_-?&=%#;"
    -- Nuclear URL obfuscation string "DEvuYp"
    -- Base64-encoded class file "yv66v"
    -- GlassFish classes used in CVE-2012-5076 exploit "glassfish/gmbal"
    s_one_and_done={'EpgKF3twh','ZKM5.4.3','f428e4e8','0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/.:_-?&=%#;','DEvuYp','yv66v'} 
    s_one_and_done_cnt = {0}

    -- Store our jar to the fs should probably use tmpfs or something
    --Should work for all systems
    local tmpname = os.tmpname()

    -- tmpfs setup should be faster
    -- mkdir -p /home/suricata/scratch  && sudo mount -t tmpfs -o size=1G,mode=0700 tmpfs /home/suricata/scratch && sudo chown suricata:suricata /home/suricata/scratch/
    --local tmpname = "/home/suricata/scratch/eviljars." .. tostring(os.time()) .. "." .. tostring(math.random(2000000,9000000))
    local tmp = io.open(tmpname,'w')
    tmp:write(t)
    tmp:close()
    
    --Open our jar file
    local z = zip.open(tmpname)

    --Open each file in the zip and inspect it 
    if z then 
        for w in z:files() do
            local f = z:open(w.filename);
            local t = f:read("*all")
            f:close()
            --print("working with " .. w.filename)            
            -- Is this a class file? If not we don't want to inspect more
            if string.sub(t,1,4) == "\202\254\186\190" then
                -- Find our Evil strings
                if find_set_match_multi_file(t,s_one_and_done,s_one_and_done_cnt,true) == 1 then
                    rtn = 1
                    break
                elseif find_set_match_multi_file(t,s2f2,s2f2_mcnt) == 1 then
                    --print("CVE-2012-0507")
                    rtn = 1
                    break
                elseif find_set_match_multi_file(t,s2f1,s2f1_mcnt) == 1 then
                    --print("CVE-2012-4681")
                    rtn = 1
                    break
                elseif find_set_match_multi_file(t,s2f3,s2f3_mcnt) == 1 then
                    --print("CVE-2012-5076")
                    rtn = 1
                    break
                end
            end
        end
    -- Close out our zip
    z:close()
    end
    -- Remove the tmpfile
    os.remove(tmpname)
    return rtn
end
