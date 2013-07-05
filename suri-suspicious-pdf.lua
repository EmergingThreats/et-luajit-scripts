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
Detection for suspicious PDF files. Currently only supports /FlateDecode requires luazlib  module.

#lua-zlib
https://github.com/brimworks/lua-zlib
#lua-apr
sudo apt-get install lua-apr lua-apr-dev

This lua script can be run standalone and verbosely on a PDF file with
echo "run()" | lua -i <script name> <pdf file>

Chris Wakelin
Will Metcalf
--]]
local lz = require 'zlib'
require 'struct'
local apr = require 'apr.core'

function init (args)
    local needs = {}
    needs["http.response_body"] = tostring(true)
    return needs
end

function cve_2013_2729(xfa,verbose)
    if string.find(xfa,"<image[^>]*>[%n%s\r]-Qk[A-Za-z0-9%+%/%n%s\r]-AAL/AAAC/wAAAv8AAAL/AAAC/wAAAv8AAAL/AAAC/wAAAv8AAAL/AAAC") ~= nil then
        if verbose == 1 then print("Evil CVE-2013-2729") end
        return 1
    end
    return 0
end

function suspicious_string_search(js,verbose)
    local ret = 0
    local fnd = nil

    _,_,fnd  = string.find(js,">(SUkqADggAA[^<]-)<")    
    if fnd ~= nil then
        local tiffdata = apr.base64_decode(fnd)
        if struct.unpack("<I4",string.sub(tiffdata,5,8)) == 0x2038 then
            if verbose == 1 then
                print ("likely CVE-2010-0188 PDF")
                ret = 1
            else
                return 1
            end
        end
    end
    _,_,fnd  = string.find(js,">(TU0AKgAA[^<]-)<")
    if fnd ~= nil then
        local tiffdata = apr.base64_decode(fnd)
        if struct.unpack(">I4",string.sub(tiffdata,5,8)) == 0x2038 then
            if verbose == 1 then
                print ("likely CVE-2010-0188 PDF")
                ret = 1
            else
                return 1
            end
        end
    end

    --Evertyhing below this line has quotes and + removed
    js = string.gsub(js,"[\x22\x27%+]","")
    fnd = string.find(js,"=%[XA%(%(%d%),0-[A-F0-9]-%),XA%(%(%d%),0-[A-F0-9]-%),XA%(%(%d%),0-[A-F0-9]-%)")
    if fnd ~= nil then
        if verbose == 1 then
            print("Suspicous: Found Sytx/Cool PDF")
            ret = 1
        else
            return 1
        end
    end
    
    fnd = string.find(js,"ImageField1.ZZA(321,513613",0,true)
    if fnd ~= nil then
        if verbose == 1 then
            print("Suspicous: Found BHEK PDF")
            ret = 1
        else
            return 1
        end
    end
    fnd = string.find(js,"charCodeAt",0,true)
    if fnd ~= nil then
        if verbose == 1 then
            print("Suspicous: Found charCodeAt in JS")
            ret = 1
        else
            return 1
        end
    end
    fnd = string.find(js,".replace",0,true)
    if fnd ~= nil then
        if verbose == 1 then
            print("Suspicous: Found .replace in JS")
            ret = 1
        else
            return 1
        end
    end
    fnd = string.find(js,"eval%(",0,true)
    if fnd ~= nil then
        if verbose == 1 then
            print("Suspicous: Found eval in JS")
            ret = 1
        else
            return 1
        end
    end
    fnd = string.find(js,"unescape",0,true)
    if fnd ~= nil then
        if verbose == 1 then
            print("Suspicous: Found unescape in JS")
            ret = 1
        else
            return 1
        end
    end
    fnd = string.find(js,"This Program Cannot Be Run in DOS Mode",0,true)
    if fnd ~= nil then
        if verbose == 1 then
            print("Suspicous: Found This Program Cannot Be Run in DOS")
            ret = 1
        else
            return 1
        end
    end
    fnd = string.find(js,"app.setTimeOut",0,true)
    if fnd ~= nil then
        if verbose == 1 then
            print("Suspicous: Found app.setTimeOut in JS")
            ret = 1
        else
            return 1
        end
    end
    fnd = string.find(js,"\x5cu4f4f\x5cu4f4f",0,true)
    if fnd ~= nil then
        if verbose == 1 then
            print("Suspicous: Found \x5cu4f4f\x5cu4f4f Spray String in JS")
            ret = 1
        else
            return 1
        end
    end
    fnd = string.find(js,"u9090",0,true)
    if fnd ~= nil then
        if verbose == 1 then
            print("Suspicous: Found u9090 Spray String in JS")
            ret = 1
        else
            return 1
        end
    end
    fnd = string.find(js,".fromCharCode",0,true)
    if fnd ~= nil then
        if verbose == 1 then
            print("Suspicous: Found .fromCharCode")
            ret = 1
        else
            return 1
        end
    end
    fnd = string.find(js,".substr%(",0,true)
    if fnd ~= nil then
        if verbose == 1 then
            print("Suspicous: Found .substr%(")
            ret = 1
        else
            return 1
        end
    end
--[[    _,_,fnd = string.find(js,"return%([%n\r%s]-[\x22\x27]([a-zA-Z0-9%+]-)[\x22\x27]")
    if fnd ~= nil and string.len(fnd) > 512 then
        if verbose == 1 then
            print("Suspicous: Found return of static hex string longer than 512 chars")
            ret = 1
        else
            return 1
        end
    end
]]--
    return ret
end
-- Replace this. It is actually a really dumb way to deal with >> in stream data 
function parse_object(obj_data,verbose)
    local stream_data,sstart,send = nil
    local stream_data_final = nil
    local dict_start,dict_end,tag_data = string.find(obj_data,"<<(.*)>>")
    if tag_data ~= nil then
        if string.find(tag_data,">>[\r%n%s%%]*stream[%s\r%n]*") ~= nil then
            _,_,tag_data = string.find(obj_data,"^(.*)>>[\r%n%s%%]*stream[%s\r%n]*",dict_start+2)
            dict_end = dict_start + string.len(tag_data) + 3 
        end
        _,stream_start = string.find(obj_data,"^[\r%n%s%%]*stream[%s\r%n]*",dict_end+1)
        if stream_start ~= nil then
            if string.find(tag_data,'FlateDecode') ~= nil and string.find(tag_data,'ObjStm') ~= nil then
                    _,_,offset = string.find(tag_data,'First%s*(%d+)')
                    if offset ~= nil then
                        --print(offset)
                        stream_start = stream_start + offset
                    end
            end 
            local sstart,send,stream_data = string.find(obj_data,"^(.-)%n?endstream",stream_start+1)
            if string.find(string.gsub(tag_data, "#(%x%x)", function(h) return string.char(tonumber(h,16)) end),'FlateDecode') ~= nil then
                stream = lz.inflate()
                stream_data_final, eof, bytes_in, uncompressed_len = stream(stream_data)
            else
                stream_data_final = stream_data
            end
        end
    end
--[[
    if verbose == 1 then
           if tag_data ~= nil then
               print("--obj data--\n" .. tag_data .. "\n--obj data--")
           end
           if stream_data_final ~= nil then
               print("--stream data--\n" .. stream_data_final .. "\n--stream data--")
           end
    end
]]--
    return {tag_data,stream_data_final}
end

function populate_objects_table(pdf,pdf_objects_tbl,verbose)
    for obj_num,obj_data in string.gfind(pdf,"%n?(%d+%s+%d+)%s+obj%s*(.-)%s*%n?endobj") do
         pdf_objects_tbl[obj_num]=parse_object(obj_data,verbose)
    end          
end

function common(t,verbose)
   local ret = 0
   local tret = 0
   pdf_objects_tbl={}
   populate_objects_table(t,pdf_objects_tbl,verbose)
   for k,v in pairs(pdf_objects_tbl) do
       if pdf_objects_tbl[k][1] ~= nil then
           if pdf_objects_tbl[k][2] then 
               tret = cve_2013_2729(tostring(pdf_objects_tbl[k][2]),verbose)
               if tret == 1 then
                   if verbose == 1 then
                       ret = 1
                   else
                       return 1
                   end
               end
               tret = suspicious_string_search(tostring(pdf_objects_tbl[k][2]),verbose)
               if tret == 1 then
                   if verbose == 1 then
                       ret = 1
                   else
                       return 1
                   end
               end
           end
       end
   end
   return ret
end

function match(args)
    local t = tostring(args["http.response_body"])
    local o = args["offset"]
    ret=common(t,0)
    return ret 
end

function run()
  local f = io.open(arg[1])
  local t = f:read("*all")
  f:close()
  common(t,1)
end
