--[[
#*************************************************************
#  Copyright (c) 2014, Victor Julien <victor@inliniac.net> 
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

Victor Julien
--]]

function init (args)
    local needs = {}
    needs["payload"] = tostring(true)
    return needs
end

function match(args)
    local p = args['payload']
    if p == nil then
        --print ("no payload")
        return 0
    end
 
    if #p < 8 then
        --print ("payload too small")
    end
    if (p:byte(1) ~= 24) then
        --print ("not a heartbeat")
        return 0
    end
 
    -- message length
    len = 256 * p:byte(4) + p:byte(5)
    --print (len)
 
    -- heartbeat length
    hb_len = 256 * p:byte(7) + p:byte(8)

    -- 1+2+16
    if (1+2+16) >= len  then
        ---print ("invalid length heartbeat")
        return 1
    end

    -- 1 + 2 + payload + 16
    if (1 + 2 + hb_len + 16) > len then
        --print ("heartbleed attack detected: " .. (1 + 2 + hb_len + 16) .. " > " .. len)
        return 1
    end
    --print ("no problems")
    return 0
end
return 0
