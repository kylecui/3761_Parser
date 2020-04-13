-- a parser for wireshark to decode 376.1 protocol
-- by kylecui
-- on Jun 27, 2019
require "bit32"

do
    -- declare the protocol
    local dl_proto = Proto("3761", "Dianli 376.1 protocol")

    -- declare fields in protocol
    local f_spec_identifier = ProtoField.uint8("3761.Spec.identifier", "Spec_Identifier", 
        base.HEX,
        {[0] = "Disabled", [1] = "130-2005", [2] = "376.1", [3] = "Reserved"})
    local f_data_length = ProtoField.uint8("3761.UserData.length", "Length", base.DEC)
    local f_crc = ProtoField.uint8("3761.CRC", "CRC", base.HEX)
    --local f_payload = ProtoField.string("3761.UserData.Payload", "Payload", base.ASCII)
    local f_payload = ProtoField.new("Payload", "3761.UserData.Payload", ftypes.BYTES)

    local f_control_dir = ProtoField.uint8("3761.Control.Direction", "Direction", base.DEC, 
        {[0] = "Downstream", [1] = "Upstream"})
    
    local f_control_prm = ProtoField.uint8("3761.Control.PRM", "PRM", base.DEC, 
        {[0]= "Responder", [1] = "Initiator"})

    local f_control_fcb_acd = ProtoField.string("3761.Control.fcb_acd", "FCB/ACD", base.ASCII)
    local f_control_fcv = ProtoField.string("3761.Control.fcv", "FCV", base.ASCII)
    local f_control_functions = ProtoField.string("3761.Control.Codes", "Codes", base.ASCII)


    local data_dis = Dissector.get("data")

    dl_proto.fields = {f_spec_identifier,
        f_data_length,
        f_crc,
        f_payload,
        f_control_dir,
        f_control_prm,
        f_control_fcb_acd,
        f_control_fcv,
        f_control_functions
        } 

    -- Create a function for dissect the packet
    local function dl_3761_dissector(buffer, pinfo, tree)
        pinfo.cols.protocol = "3761"
        --local v_identifier = buffer(0,1)
        local buf_len = buffer:len()

        -- sample 
        -- 68 32 00 32 00 68 7B 01 58 11 28 02 0C 60 02 01 01 10 8F 16
        -- 68 == start
        -- 32 00 / 32 00, length and spec identifier, twice. 
        -- 68 == data starts
        -- 7B::10 data payload
        -- 8F == CRC
        -- 16 == End byte

        -- read spec and length bytes 
        local v_length_low = buffer(1,1)
        local v_length_high = buffer(2,1)
        --string.reverse(buffer(1,2))
        local v_length_confirm_low = buffer(3,1)
        local v_length_confirm_high = buffer(4,1)
        --string.reverse(buffer (3,2))

        if ((buffer(0,1):uint()~=104) 
            or (buffer(5,1):uint()~=104) 
            or (buffer(buf_len-1,1):uint()~=22)) then
            -- this is not our protocol
            return false
        end

        if ((v_length_low ~= v_length_confirm_low) or 
            (v_length_high ~= v_length_confirm_high)) then
            -- this is a wrong packet, ignore it temporarily
            return false
        end
        
        -- parse the length and spec
        local v_spec_identifier = bit32.band(v_length_low:uint(),3) --3 = 0b11
        local v_length_real = bit32.rshift(v_length_low:uint(),2) + v_length_high:uint() * 256 --move right 2 bits
        
        -- parse the payload
        local v_payload = buffer(6,buf_len-2-6)

        -- first byte in payload, 控制域. 
        --[[  
            masks:
            128 = 10000000 == DIRection 0:下行， 1:上行
            64  = 01000000 == PRM 启动标志位 0:从动， 1:主动
            32  = 00100000 == FCB/ACD 下行为帧计数位FCB，上行为要求访问位ACD
            16  = 00010000 == FCV/reserved 下行为帧计数有效位FCV，上行为保留字
            15  = 00001111 == function codes 
        ]]

        local v_control = buffer(6,1):uint()
        local v_flow_direction = bit32.rshift(bit32.band(v_control, 128),7)
        local v_prm = bit32.rshift(bit32.band(v_control, 64),6)
        local v_fcb_acd_tmp = bit32.rshift(bit32.band(v_control, 32),5)
        local v_fcv_tmp = bit32.rshift(bit32.band(v_control, 16),4)
        local v_control_function_tmp = bit32.band(v_control, 15)
        local v_fcb_acd = ""
        local v_fcv = ""
        local v_control_function = "Frame type: %s, function: %s. (%d)"
        if (v_flow_direction==0) then 
            -- 0 is true. downstream
            v_fcb_acd =  string.format("FCB = %d (%s)", v_fcb_acd_tmp, ((v_fcv_tmp==1) and {"valid"} or {"invalid"})[1])
            v_fcv = string.format("FCV = %d", v_fcv_tmp)
        else
            -- upstream
            v_fcb_acd =  string.format("ACD = %d", v_fcb_acd_tmp)
            v_fcv = string.format("Reserved (%d)", v_fcv_tmp)
        end
        
        if (v_prm == 1) then 
            -- 1, 4, 9, 10 ,11 are used.
            if (v_control_function_tmp == 1) then 
                v_control_function = string.format(v_control_function, "Send/Ack", "RESET", v_control_function_tmp)
            elseif (v_control_function_tmp == 4) then
                v_control_function = string.format(v_control_function, "Send/No Response", "User Data", v_control_function_tmp) 
            elseif (v_control_function_tmp == 9) then 
                v_control_function = string.format(v_control_function, "Request/Response", "Link Test", v_control_function_tmp)
            elseif (v_control_function_tmp == 10) then 
                v_control_function = string.format(v_control_function, "Request/Response", "Request Class 1 Data", v_control_function_tmp)
            elseif (v_control_function_tmp == 11) then 
                v_control_function = string.format(v_control_function, "Request/Response", "Request Class 2 Data", v_control_function_tmp)
            else
                v_control_function = string.format("Reserved (%d)", v_control_function_tmp)
            end
        else
            -- 0, 8, 9, 11 are used. 
            if (v_control_function_tmp == 0) then 
                v_control_function = string.format(v_control_function, "Ack", "Acknowledged", v_control_function_tmp)
            elseif (v_control_function_tmp == 8) then 
                v_control_function = string.format(v_control_function, "Response", "User Data", v_control_function_tmp)
            elseif (v_control_function_tmp == 9) then  
                v_control_function = string.format(v_control_function, "Response", "Denied: No data for request", v_control_function_tmp)
            elseif (v_control_function_tmp == 11) then 
                v_control_function = string.format(v_control_function, "Response", "Link Status", v_control_function_tmp)
            else
                v_control_function = string.format("Reserved (%d)", v_control_function_tmp)
            end
        end

        -- the CRC byte
        local v_crc = buffer(buf_len-2,1)

        
        -- show tree view in wireshark. 
        local subtree = tree:add(dl_proto, buffer(), "376.1 Protocol Data")
        subtree:add(f_spec_identifier, v_spec_identifier)
        subtree:add(f_data_length, v_length_real)
        local payload_tree = subtree:add(f_payload, v_payload)
        payload_tree:add(f_control_dir, v_flow_direction)
        payload_tree:add(f_control_prm, v_prm)
        payload_tree:add(f_control_fcb_acd, v_fcb_acd)
        payload_tree:add(f_control_fcv, v_fcv)
        payload_tree:add(f_control_functions, v_control_function)
        subtree:add(f_crc, v_crc)

        return true
    end
    
    function dl_proto.dissector(buffer, pinfo, tree)
        if dl_3761_dissector(buffer, pinfo, tree) then
            -- valid 3761 diagram
        else
            -- call default 
            data_dis:call(buffer, pinfo, tree)
        end
    end


    -- load the tcp.port table
    tcp_table = DissectorTable.get("tcp.port")
    -- register the protocol to handle tcp port 10000
    tcp_table:add(10000, dl_proto)

end
