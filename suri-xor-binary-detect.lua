function init (args)
    local needs = {}
    needs["http.response_body"] = tostring(true)
    return needs
end


-- return match via table
function match(args)
    local result = {}
    local bit = require("bit")

    -- "This program cannot be run in DOS mode."
    --  could match (4 byte key) "K'$#x=,=x.?<q3*q35km(4?$$q"

    -- "This program must be run in Win32"
    --  could match (4 byte key) "K'$#x=,=x +!kr()km(4?8$5z8q"

    -- "This program " (match strings for 4 byte and 6 byte keys)
    local tp4_string,tp6_string = "K'$#x=,=x","Ihan.r="

    local p = "This p"

    local search_start,search_stop = 70,100
    -- Probably 79,104 for string "This program ... DOS mode."
    -- Probably 81,107 for string "This program ... win32"
    -- Only looking for "This program "

    a = tostring(args["http.response_body"])
    b4,b6 = "",""
    key = {}

    if #a < 1024 then 
        return 0
    end

    for i = search_start,search_stop,1 do
        b4 = b4 .. string.char(bit.bxor(a:byte(i),a:byte(i+4),0x3f))
        b6 = b6 .. string.char(bit.bxor(a:byte(i),a:byte(i+6),0x6f))
    end

    -- Look for matched XORed string, 4-byte key first
    -- If found, see if we started "MZ" at byte 1
    -- If MZ not found, identify PE header offset and look for PE|00|
    -- also check the same for extra byte 0 (g01pack)
    -- If not found, repeat for 6-byte key (except g01pack which is 1-byte key anyway)
    
    f = string.find(b4,tp4_string,1,true)
    if f ~= nil then
        do 
            offset = (search_start + f - 2) % 4
            for i = offset, offset + 3, 1 do
                key[(i%4)+1] = bit.bxor(a:byte(search_start+f-1+(i%4)),p:byte((i%4)+1))
            end

            if (bit.bxor(a:byte(1),key[offset+1]) == string.byte('M')) and 
               (bit.bxor(a:byte(2),key[((offset+1)%4)+1]) == string.byte('Z')) then 
                return 1
            end

            if (bit.bxor(a:byte(2),key[((offset+1)%4)+1]) == string.byte('M')) and 
               (bit.bxor(a:byte(3),key[((offset+2)%4)+1]) == string.byte('Z')) then 
                return 1
            end

            pe = bit.bxor(a:byte(0x3c+1), key[((0x3c+offset)%4)+1])+(256*bit.bxor(a:byte(0x3c+2), key[((0x3c+offset+1)%4)+1]))
            if (pe < 1024) then
                do
                    if (bit.bxor(a:byte(pe+1), key[((pe+offset)%4)+1]) == string.byte('P')) and
                       (bit.bxor(a:byte(pe+2), key[((pe+offset+1)%4)+1]) == string.byte('E')) and
                       (bit.bxor(a:byte(pe+3), key[((pe+offset+2)%4)+1]) == 0) and
                       (bit.bxor(a:byte(pe+4), key[((pe+offset+3)%4)+1]) == 0) then
                        return 1
                    end
                end
            end

            pe = bit.bxor(a:byte(0x3c+2), key[((0x3c+offset+1)%4)+1])+(256*bit.bxor(a:byte(0x3c+3), key[((0x3c+offset+2)%4)+1]))
            if (pe < 1024) then
                do
                    if (bit.bxor(a:byte(pe+2), key[((pe+offset+1)%4)+1]) == string.byte('P')) and
                       (bit.bxor(a:byte(pe+3), key[((pe+offset+2)%4)+1]) == string.byte('E')) and
                       (bit.bxor(a:byte(pe+4), key[((pe+offset+3)%4)+1]) == 0) and
                       (bit.bxor(a:byte(pe+5), key[((pe+offset+4)%4)+1]) == 0) then
                        return 1
                    end
                end
            end

        end
    end

    f = string.find(b6,tp6_string,1,true)
    if f ~= nil then
        do
            offset = (search_start + f - 2) % 6
            for i = offset, offset + 5, 1 do
                key[(i%6)+1] = bit.bxor(a:byte(search_start+f-1+(i%6)),p:byte((i%6)+1))
            end

            if (bit.bxor(a:byte(1),key[offset+1]) == string.byte('M')) and 
               (bit.bxor(a:byte(2),key[((offset+1)%6)+1]) == string.byte('Z')) then 
                return 1
            end

            pe = bit.bxor(a:byte(0x3c+1), key[((0x3c+offset)%6)+1])+(256*bit.bxor(a:byte(0x3c+2), key[((0x3c+offset+1)%6)+1]))
            if (pe < 1024) then
                do
                    if (bit.bxor(a:byte(pe+1), key[((pe+offset)%6)+1]) == string.byte('P')) and
                       (bit.bxor(a:byte(pe+2), key[((pe+offset+1)%6)+1]) == string.byte('E')) and
                       (bit.bxor(a:byte(pe+3), key[((pe+offset+2)%6)+1]) == 0) and
                       (bit.bxor(a:byte(pe+4), key[((pe+offset+3)%6)+1]) == 0) then
                        return 1
                    end
                end
            end

        end
    end 

-- Long shot; usually bytes 0x30 to 0x3b are 0-padding,
-- so may actually contain the Key; decode PE offset and check
-- it points to bytes that then decode to PE|00 00|

    for i = 0, 5, 1 do
      key[i+1] = a:byte(0x30+i+1)
    end
    pe = bit.bxor(a:byte(0x3c+1), key[1]) + (256*bit.bxor(a:byte(0x3c+2), key[2]))
    if (pe < 1024) then
        do
            offset = pe % 4
            if (bit.bxor(a:byte(pe+1), key[offset+1]) == string.byte('P')) and 
               (bit.bxor(a:byte(pe+2), key[((1+offset)%4)+1]) == string.byte('E')) and
               (bit.bxor(a:byte(pe+3), key[((2+offset)%4)+1]) == 0) and
               (bit.bxor(a:byte(pe+4), key[((3+offset)%4)+1]) == 0) then
                return 1
            end
            offset = pe % 6
            if (bit.bxor(a:byte(pe+1), key[offset+1]) == string.byte('P')) and 
               (bit.bxor(a:byte(pe+2), key[((1+offset)%6)+1]) == string.byte('E')) and
               (bit.bxor(a:byte(pe+3), key[((2+offset)%6)+1]) == 0) and
               (bit.bxor(a:byte(pe+4), key[((3+offset)%6)+1]) == 0) then
                return 1
            end
        end
    end

    return 0
end

return 0
