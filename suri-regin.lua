--[[
#*************************************************************
# Copyright (c) 2003-2013, Emerging Threats
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
# following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this list of conditions and the following
# disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
# following disclaimer in the documentation and/or other materials provided with the distribution.
# * Neither the name of the nor the names of its contributors may be used to endorse or promote products derived
# from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS AS IS AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#*************************************************************
Detection for Regin malware
http://symantec.com/content/en/us/enterprise/media/security_response/whitepapers/regin-analysis.pdf
http://securelist.com/files/2014/11/Kaspersky_Lab_whitepaper_Regin_platform_eng.pdf
Darien Huss
Will Metcalf
--]]

local apr = require 'apr.core'

function init (args)
	local needs = {}
	needs["payload"] = tostring(true)
	return needs
end

function match(args)
	local p = tostring(args["payload"])
	if p == nil then
		return 0
		--print ("no payload")
	end
	return common(p,0)
end

function common(p,verbose)

	--need to correct base64 string with appended equal signs if needed
	base64_append = #p % 4

	if base64_append == 1 then
		--print("Invalid base64 encoded length")
		return 0
	elseif base64_append == 2 then
		p = p .. "=="
	elseif base64_append == 3 then
		p = p .. "="
	end
	p = string.gsub(p, "%.", "+")
	p = string.gsub(p, "_", "/")

	decodedata = tostring(apr.base64_decode(p))

	if ((decodedata:byte(1) == 1 and #decodedata == decodedata:byte(2)) or 
		(decodedata:byte(1) ~= 1 and #decodedata == decodedata:byte(5))) and
		decodedata:byte(9) == string.byte('s') and
		decodedata:byte(18) == string.byte('h') and
		decodedata:byte(27) == string.byte('i') and
		decodedata:byte(36) == string.byte('t') then
			if verbose == 1 then print("Data matches Regin init struct") end
			return 1
	end
	if verbose == 1 then print("Data does not match Regin init struct") end
	return 0
end

function run()
	local t = arg[1]
	common(t,1)
end
