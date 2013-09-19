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

Requirements:

    #lua-zlib
    https://github.com/brimworks/lua-zlib
   
This lua script can be run standalone and verbosely on a suspicious file with
echo "run()" | luajit -i <script name> <file>

Will Metcalf
Chris Wakelin
--]]

local lz = require 'zlib'
function init (args)
    local needs = {}
    needs["http.response_body"] = tostring(true)
    return needs
end

function common(t,verbose)
    rtn = 0
--- Look for zlib magic
    if string.sub(t,-1) == "\x78" then
        stream = lz.inflate()
        ustream, eof, bytes_in, uncompressed_len = stream(string.reverse(t))
        if string.sub(ustream,1,2) == "MZ" then
            rtn = 1
            if (verbose==1) then
                print('Found Reversed Compressed MZ')
            end
        end
    end
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
  if common(t,1) == 1 then print("Found Suspicious file in " .. arg[1]) end
end
