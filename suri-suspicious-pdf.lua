local lz = require 'zlib'
require 'struct'
function init (args)
    local needs = {}
    needs["http.response_body"] = tostring(true)
    return needs
end

function cve_2013_2729(xfa,verbose)
    if verbose == 1 then print("looking for cve_2013_2729") end
    if string.find(xfa,"<image[^>]*>[%n%s\r]-Qk[A-Za-z0-9%+%/%n%s\r]-AAL/AAAC/wAAAv8AAAL/AAAC/wAAAv8AAAL/AAAC/wAAAv8AAAL/AAAC") ~= nil then
        if verbose == 1 then print("Evil CVE-2013-2729") end
        return 1
    end
    return 0
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
            if string.find(tag_data,'FlateDecode') ~= nil then
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
           end
       end
   end
   return ret
end

function match(args)
    local t = tostring(args["http.response_body"])
    local o = args["offset"]
    return common(t,0)
end

function run()
  local f = io.open(arg[1])
  local t = f:read("*all")
  f:close()
  common(t,1)
end
