-- a parser for wireshark to decode 376.1 protocol
-- by kylecui
-- on Jun 27, 2019
bit32=require "bit32"

do
    -- declare the protocol
    local dl_proto = Proto("3761", "my protocol")

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

    local f_administration_division_code = ProtoField.string('3761.Address.administration_division_code','administration_division_code',base.ASCII)
    local f_terminal_address=ProtoField.uint8('3761.Address.terminal_address','terminal_address',base.DEC)
    local f_server_address=ProtoField.string('3761.Address.server_address','server_address',base.ASCII)

    local f_application_afn=ProtoField.string('3761.Application.afn','AFN',base.ASCII)
    local f_seq_tpv=ProtoField.uint8('3761.seq.tpv','TpV',base.DEC)    
    local f_seq_fir=ProtoField.uint8('3761.seq.fir','FIR',base.DEC)    
    local f_seq_fin=ProtoField.uint8('3761.seq.fin','FIN',base.DEC)    
    local f_seq_con=ProtoField.uint8('3761.seq.con','CON',base.DEC)    
    local f_seq_pseq_rseq=ProtoField.uint8('3761.seq.pseq_rseq','PSEQ/RSEQ',base.DEC)
    local f_pn=ProtoField.int16('3761.pn','PN',base.DEC)
    local f_fn=ProtoField.int16('3761.fn','FN',base.DEC)
        --
    local f_application_da=ProtoField.uint8('3761.Application.da','DA',base.DEC)
    local f_application_dt=ProtoField.uint8('3761.Application.dt','DT',base.DEC)
    local f_application_aux=ProtoField.uint8('3761.Application.aux','AUX',base.DEC)

    local data_dis = Dissector.get("data")
    
    dl_proto.fields = {f_spec_identifier,
        f_data_length,
        f_crc,
        f_payload,
        f_control_dir,
        f_control_prm,
        f_control_fcb_acd,
        f_control_fcv,
        f_control_functions,
        f_administration_division_code,
        f_terminal_address,
        f_server_address,
        f_application_afn,
        f_seq_tpv,
        f_seq_fir,
        f_seq_fin,
        f_seq_con,
        f_seq_pseq_rseq,
        f_pn,
        f_fn
    } 
    
    -- Create a function for dissect the packet
    local function dl_3761_dissector(buffer, pinfo, tree)
        pinfo.cols.protocol = "376.1"
        --local v_identifier = buffer(0,1)
        local buf_len = buffer:len()
        local subtree = tree:add(dl_proto, buffer(), "376.1 Protocol Data")
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


        local v_administration_division_code=buffer(8,1)..buffer(7,1)
        local v_terminal_address=buffer(9,2)
        local v_server_address=buffer(11,1):uint()
        --local subtree = tree:add(dl_proto, buffer(), "376.1 Protocol Data")


        s={[0]='ack/noack',[1]='reset',[2]='linkTestApi',[3]='RelayStationCommand',
        [4]='settingParameters',[5]='controlCommands',[6]='identityAuthenticationAndKeyAgreement',[7]='spare',
        [8]='terminalReporting',[9]='requestTerminalConfiguration',[10]='queryParameter',[11]='taskDataQuery',[12]='realTimeData',[13]='historicalData',
        [14]='eventData',[15]='fileTransfer',[16]='dataForwarding'}
        local v_application_afn_tmp=buffer(12,1):uint()
        --local v_application_afn=buffer(12,1):uint()
        v_application_afn=string.format('%d,type:%s',v_application_afn_tmp,s[v_application_afn_tmp])

        --对位值
        local v_pn_low=buffer(14,1):uint()
        local v_pn_high=buffer(15,1):uint()
        local v_pn=''
        if(v_pn_low==0 and v_pn_high==0) then
            v_pn=0
            --表示终端信息点
        end
        if(v_pn_low==1 and v_pn_high==1) then 
            v_pn=1
            --表示全体信息点
        end
        if(v_pn_high>0) then
            v_pn=(buffer(15,1):uint()-1)*8+math.sqrt(buffer(14,1):uint())--记录pn
            --表示全体
        end
        local v_fn=(buffer(17,1):uint())*8+math.sqrt(buffer(16,1):uint()) --记录fn

        if (v_application_afn_tmp==0) then
            if(v_fn==1 and v_pn==0) then
                --f1:全部确认 无数据体
            end
            if(v_fn==2 and v_pn==0) then
                --f2:全部否认 无数据体
            end
            if(v_fn==3 and v_pn==0) then
                --f3:按数据单元标识确认和否认
            end
            if(v_fn==4 and v_pn==0) then
                --f4:硬件安全认证错误应答
            end
            if(v_fn>=5) then
                --f5-248:备用
            end
        end
        if (v_application_afn_tmp==1) then
        --[[68 8A 00 8A 00 68 41 03 44 07 00 02 01 F1 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 C1 37 58 10 17 00 FC 16]]
            if(v_fn==1 and v_pn==0) then
                --f1:硬件初始化
            end
            if(v_fn==2 and v_pn==0) then
                --f2:数据区初始化
            end
            if(v_fn==3 and v_pn==0) then
                --f3:参数及全体数据区初始化（即恢复至出厂配置）
            end
            if(v_fn==4 and v_pn==0) then
                --f4:参数（除与系统主站通信有关的）及全体数据区初始化
            end
            if(v_fn>=5) then
                 --f5-248:备用
            end
            --复位命令的上行报文为确认/否认报文 同上
            local f_PW=ProtoField.string('3761.PW','PW',base.ASCII)
            local f_TP=ProtoField.string('3761.TP','TP',base.ASCII)
            local v_PW=buffer(18,16)  --消息认证码 afn=1时 必须定义的
            local v_TP=buffer(34,6) --时间标签TP 6字节
        end

        if (v_application_afn_tmp==2) then
            if(v_fn==1 and v_pn==0) then
                --f1:登录
            end
            if(v_fn==2 and v_pn==0) then
                --f2:退出登录
            end
            if(v_fn==3 and v_pn==0) then
                --f3:心跳
            end
            if(v_fn>=4) then
                --f4-248:备用
            end
            --链路接口检测命令下行报文为确认/否认报文中的F3按数据单元标识确认和否认
        end

        if (v_application_afn_tmp==3) then

              --[[f1:中继站工作状态控制,f2:中继站工作状态查询,f3:中继站工作状态切换记录查询,
                --f4:中继站运行状况统计数据查询,f5-248:备用--]]

            --upstream
            if(v_flow_direction==1) then
                if(v_fn==1) then
                    local v_data_unit=buffer(18,1):uint() 
                end
                if(v_fn==2) then
                     --无数据单元
                end
                if(v_fn==3) then
                    local time1=buffer(18,5) --最近十次切换时间：分时日月年
                    local status1=buffer(23,1) --最近十次切换前中继站工作状态
                    local status2=buffer(24,1) --最近十次切换后中继站工作状态
                    local time2=buffer(25,5) --最近一次切换时间：分时日月年
                    local status3=buffer(30,1) --最近一次切换前中继站工作状态
                    local status4=buffer(31,1) --最近一次切换后中继站工作状态
                end
                if(v_fn==4) then
                    local number1=buffer(18,2) --切换累计次数
                    local time1=buffer(20,2) --A机值班累计时间
                    local time2=buffer(22,2) --A机正常运行累计时间
                    local time3=buffer(24,2) --B机值班累计时间
                    local time4=buffer(26,2) --B机正常运行累计时间
                end
            end

            --downstream
            if(v_flow_direction==0) then
                if(v_fn==1) then
                    local v_data_unit=buffer(18,1):uint()
                end

                if(v_fn==2) then
                    --无数据单元
                end

                if(v_fn==3) then
                    --无数据单元
                end

                if(v_fn==4) then
                    --无数据单元
                end
                
                --if(v_fn==)
            end
        end


        if (v_application_afn_tmp==4) then
            --downstream
            local v_configureNumber=buffer(18,2):le_unit() --本次电能表/交流采样装置配置数量n
            local v_device_sn=buffer(20,2):le_unit() --电能表/交流采样装置序号
            local v_test_point_num=buffer(22,2):le_unit() --所属测量点号
            local v_comm=buffer(24,1):unit() --[[通信速率及通信端口号，对应二进制值为0b00000001
            ──D7～D5编码表示电能表、交流采样装置与终端的通信波特率， 1～7依次表示600、1200、2400、
            4800、7200、9600、19 200；
            0表示无需设置或使用默认的──D4～D0编码表示电能表、
            交流采样装置与终端连接所对应的终端通信端口号，数值范围1～31，其他值无效。实际对应端口为1，                   即为交采口
            --]]
            local v_comm_bot_speed=bit32.band(bit32.rshift(v_comm,5),7)
            local v_comm_port=bit32.band(v_comm,31)
            local v_comm_protocol=buffer(25,1):uint() --[[通信协议类型：数值范围0～255，其中0：表示终端无
            需对本序号的电能表/交流采样装置进行抄表；1表示DL/T 645—1997；2表示交流采样装置通信协议；
            30表示DL/T 645—2007；31表示“串行接口连接窄带低压载波通信模块”接口协议；其他为备用。]]
            local v_comm_address=buffer(26,6) --通信地址
            local v_comm_passwd=buffer(32,6) --通信密码
            local v_comm_energy_bills=buffer(38,1)--电能费率个数，D5～D0编码表示通信接入的测量点的电能费率个数，数值范围1～48。本次设置的费率数为4费率
            local v_comm_energy=buffer(39,1)--[[有功电能示值整数位及小数位个数，对应值为0b00001001
            ──D7～D4编码表示备用。
            ──D3～D2编码表示通信接入的电能表的有功电能示值的整数位个数，
            数值范围0～3依次表示4～7位整数。对应为红色为0b10—6位整数
            ──D1～D0编码表示通信接入的电能表的有功电能示值的小数位个数，
            数值范围0～3依次表示1～4位小数。对应为绿色为0b01—2位小数]]
            local v_comm_intger=bit32.rshift(bit32.band(v_comm_energy,12),2) --整数
            local v_comm_float=bit32.band(v_comm_energy,3) --小数
            local v_collector=buffer(40,6) --所属采集器通信地址
            local v_user_class=buffer(46,1) --用户大类号及用户小类号
            local v_PW=buffer(74,16) --消息认证码字段PW，协议格式中AFN=0x04有硬性规定必须使用消息认证码字段
            local v_TP=buffer(90,6) --时间标签Tp

        end
        if (v_application_afn_tmp==5) then
            --downstream
            local v_time_settings=buffer(18,6) --对应的要设置的时间
            local v_PW=buffer(24,16) --消息认证码字段PW
            local v_time_table=buffer(40,6) --时间标签
            --上行报文为确认/否认报文
        end

        if (v_application_afn_tmp==6) then --身份认证及密钥协商（AFN=06H）
            --[[F1:身份认证请求,F2:身份认证响应,F3:取随机数,f4:取随机数响应]]
            if(v_fn==1) then
                local data1=buffer(18,16) --认证请求信息
            end

            if(v_fn==2) then
                local data2=buffer(18,16) --认证响应信息
            end

            if(v_fn==3) then
                local data3=buffer(18,16) --随机数信息
            end

            if(v_fn==4) then
                local data4=buffer(18,16) --随机数响应信息
            end

        end

        if (v_application_afn_tmp== 7) then
        end

        if (v_application_afn_tmp== 8) then --请求被级联终端主动上报（AFN=08H）
            --downstream
            if(v_flow_direction==0) then
                --字段length未知
            end
            
            --upstream
            if(v_flow_direction==1) then
                -- 无
            end
        end

        if (v_application_afn_tmp== 9) then --请求终端配置及信息
            --upstream
            if(v_flow_direction==1) then
                
                if(v_fn==1) then
                    local number1=buffer(18,4) --厂商代号
                    local number2=buffer(22,8) --设备编号
                    local number3=buffer(30,4) --终端软件版本号
                    local number4=buffer(34,3) --终端软件发布日期：日月年
                    local number5=buffer(37,11) --终端配置容量信息码
                    local number6=buffer(48,4) --终端通信协议.版本号
                    local number7=buffer(52,4) --终端硬件版本号
                    local number8=buffer(56,3) --终端硬件发布日期：日月年
                end

                if(v_fn==2) then
                    local number1=buffer(18,1) --脉冲量输入路数
                    local number2=buffer(19,1) --开关量输入路数
                    local number3=buffer(20,1) --直流模拟量输入路数
                    local number4=buffer(21,1) --开关量输出路数
                    local number5=buffer(22,2) --支持的抄电能表/交流采样装置最多个数
                    local number6=buffer(24,2) --支持的终端上行通信最大接收缓存区字节数
                    local number7=buffer(26,2) --支持的终端上行通信最大发送缓存区字节数
                    local number8=buffer(28,1) --终端MAC地址1段
                    local number9=buffer(29,1) --终端MAC地址2段
                    local number9=buffer(30,1) --终端MAC地址3段
                    local number9=buffer(31,1) --终端MAC地址4段
                    local number9=buffer(32,1) --终端MAC地址5段
                    local number9=buffer(33,1) --终端MAC地址6段
                    local number10=buffer(34,1) --通信端口数量n
                    local number11=buffer(35,2) --第1个通信端口的端口号及信息字
                    local number12=buffer(37,4) --第1个通信端口支持的最高波特率（bps）
                    local number13=buffer(41,2) --第1个通信端口支持的设备个数
                    local number14=buffer(43,2) --第1个通信端口支持的最大接收缓存区字节数
                    local number15=buffer(45,2) --第1个通信端口支持的最大发送缓存区字节数
                    local number16=buffer(47,2) --第n个通信端口的端口号及信息字
                    local number17=buffer(49,4) --第n个通信端口支持的最高波特率（bps）
                    local number18=buffer(53,2) --第n个通信端口支持的设备个数
                    local number19=buffer(55,2) --第n个通信端口支持的最大接收缓存区字节数
                    local number20=buffer(57,2) --第n个通信端口支持的最大发送缓存区字节数
                end

                if(v_fn==3) then
                    local number1=buffer(18,2) --支持的测量点最多点数
                    local number2=buffer(20,1) --支持的总加组最多组数
                    local number3=buffer(21,1) --支持的任务最多个数
                    local number4=buffer(22,1) --支持的有功总电能量差动组最多组数
                    local number5=buffer(23,1) --支持的最大费率数
                    local number6=buffer(24,1) --支持的测量点数据最大冻结密度
                    local number7=buffer(25,1) --支持的总加组有功功率数据最大冻结密度
                    local number8=buffer(26,1) --支持的总加组无功功率数据最大冻结密度
                    local number9=buffer(27,1) --支持的总加组有功电能量数据最大冻结密度
                    local number10=buffer(28,1) --支持的总加组无功电能量数据最大冻结密度
                    local number11=buffer(29,1) --支持的日数据最多存放天数
                    local number12=buffer(30,1) --支持的月数据最多存放月数
                    local number13=buffer(31,1) --支持的时段功控定值方案最多个数
                    local number14=buffer(32,1) --支持的谐波检测最高谐波次数
                    local number15=buffer(33,1) --支持的无功补偿电容器组最多组数
                    local number16=buffer(34,1) --支持的台区集中抄表重点户最多户数
                    local number17=buffer(35,2) --支持的用户大类号标志
                    local number18=buffer(37,1) --支持0号用户大类下的用户小类号个数
                    local number19=buffer(38,1) --支持1号用户大类下的用户小类号个数
                    local number20=buffer(39,1) --支持15号用户大类下的用户小类号个数
                end

                if(v_fn==4 or v_fn==5) then
                    local number1=buffer(18,1) --支持的信息类组数n
                    local number2=buffer(19,1) --支持的第1组信息类组所对应的信息类元标志位
                    local number3=buffer(20,1) --支持的第n组信息类组所对应的信息类元标志位
                end

                if(v_fn==6) then
                    local number1=buffer(18,2) --支持的用户大类号标志（flag）
                    local number2=buffer(20,1) --支持的信息类组数n
                    local number3=buffer(21,1) --支持的第1组信息类组所对应的信息类元标志位
                    local number4=buffer(22,1) --no desp
                    local number4=buffer(23,1) --支持的第n组信息类组所对应的信息类元标志位
                    local number5=buffer(24,1) --no desp
                    local number5=buffer(25,1) --支持的信息类组数n
                    local number6=buffer(26,1) --支持的第1组信息类组所对应的信息类元标志位
                    local number7=buffer(27,1) --no desp
                    local number8=buffer(28,1) --支持的第n组信息类组所对应的信息类元标志位
                end
            end
        end


        if (v_application_afn_tmp== 10) then --查询参数（AFN=0AH）
            --downstream
            if(v_flow_direction==0) then

                if(v_fn==10) then
                    local number1=buffer(18,2) --本次查询数量n
                    local number2=buffer(20,2) --本次查询的第1个对象序号
                    local number3=buffer(22,2) --本次查询的第n个对象序号
                end

                if(v_fn==11 or v_fn==13 or v_fn==14 or v_fn==15 or v_fn==33 or v_fn==34) then --终端脉冲配置参数
                    local number1=buffer(18,1) --本次查询数量n
                    local number2=buffer(19,1) --本次查询的第1个对象序号
                    local number3=buffer(20,1) --本次查询的第n个对象序号
                end

                if(v_fn==38 or v_fn==39) then
                    local number1=buffer(18,1) --本次查询的用户大类号
                    local number2=buffer(19,1) --本次查询数量n
                    local number3=buffer(20,1) --本次查询的第1个用户小类号
                    local number4=buffer(21,1) --本次查询的第n个用户小类号
                end
            end

            if(v_flow_direction==1) then --请求任务数据
                --同afn==4 下行
            end
        end

        if (v_application_afn_tmp== 11) then
            --downstream
            if(v_flow_direction==0 or v_flow_direction==1) then --上行报文根据请求的定时上报任务的数据类别，分别用请求1类数据和请求2类数据的上行报文进行应答。

                if(v_fn==1) then
                    --无数据
                end

                if(v_fn==2) then --请求定时上报1类数据任务
                    local time1=buffer(18,5) --请求的任务中的数据的起始时间ts：分时日月年
                end

            end
        end

        if (v_application_afn_tmp== 12) then --请求1类数据
            --downstream
            if(v_flow_direction==0) then

            end
        end

        if (v_application_afn_tmp== 13) then

        end

        if (v_application_afn_tmp== 14) then --请求3类数据
            --downstream
            if(v_flow_direction==0) then
                
                if(v_fn==1) then --请求重要事件
                    local pointer1=buffer(18,1) --请求事件记录起始指针Pm
                end

                if(v_fn==2)  then --请求一般事件
                    local pointer2=buffer(18,1) --请求事件记录结束指针Pn
                end
            end
            
            --upstream
            if(v_flow_direction==1) then
                if(v_fn==1 or v_fn==2) then
                    local t1=buffer(18,1) --当前重要事件计数器EC1
                    local t2=buffer(19,1) --当前重要事件计数器EC2
                    local t3=buffer(20,1) --本帧报文传送的事件记录起始指针Pm
                    local t4=buffer(21,1) --本帧报文传送的事件记录结束指针Pn
                    local t5=buffer(22,1) --事件代码ERC
                    if((t5)==1) then
                        local t6=buffer(23,1) --长度Le
                        local t7=buffer(24,5) --初始化/版本变更时间：分时日月年
                        local t8=buffer(29,1) --事件标志
                        local t9=buffer(30,4) --变更前软件版本号
                        local t10=buffer(34,4) --变更后软件版本号

                    elseif((t5)==2) then
                        local t6=buffer(23,1) --长度Le
                        local t7=buffer(24,5) --发生时间（分时日月年）
                        local t8=buffer(29,1) --事件标志

                    elseif((t5)==3) then
                        local t6=buffer(23,1) --长度Le
                        local t7=buffer(24,5) --参数更新时间：分时日月年
                        local t8=buffer(29,1) --启动站地址
                        local t9=buffer(30,4) --变更参数数据单元标识1

                    elseif((t5)==4) then
                        local t6=buffer(23,1) --长度Le
                        local t7=buffer(24,5) --变位时间：分时日月年
                        local t8=buffer(29,1) --状态变位
                        local t9=buffer(30,1) --变位后状态

                    elseif((t5==5)) then
                        local t6=buffer(23,1) --长度Le
                        local t7=buffer(24,5) --跳闸时间：分时日月年
                        local t8=buffer(29,1) --跳闸轮次
                        local t9=buffer(30,2) --跳闸时功率（总加功率）
                        local t10=buffer(32,2) --跳闸后2分钟的功率（总加功率）

                    else

                    end
                end  
            end     
        end

        if (v_application_afn_tmp== 15) then
        end
        if (v_application_afn_tmp== 16) then
        end


        
        
        local v_application_seq=buffer(13,1):uint()
        local v_seq_tpv=''
        local v_seq_fir=''
        local v_seq_fin=''
        local v_seq_con=''
        local v_seq_pseq_rseq=''
        v_seq_tpv=bit32.rshift(v_application_seq,7)
        v_seq_fir=bit32.band(bit32.rshift(v_application_seq,6),1)
        v_seq_fin=bit32.band(bit32.rshift(v_application_seq,5),1)
        v_seq_con=bit32.band(bit32.rshift(v_application_seq,4),1)
        v_seq_pseq_rseq=bit32.band(v_application_seq,15)

        -- the CRC byte
        local v_crc = buffer(buf_len-2,1)
        
        -- show tree view in wireshark. 
        
        subtree:add(f_spec_identifier, v_spec_identifier)
        subtree:add(f_data_length, v_length_real)
        local payload_tree = subtree:add(f_payload, v_payload)
        payload_tree:add(f_control_dir, v_flow_direction)
        payload_tree:add(f_control_prm, v_prm)
        payload_tree:add(f_control_fcb_acd, v_fcb_acd)
        payload_tree:add(f_control_fcv, v_fcv)
        payload_tree:add(f_control_functions, v_control_function)
        payload_tree:add(f_administration_division_code,v_administration_division_code)
        payload_tree:add(f_terminal_address,v_terminal_address)
        payload_tree:add(f_server_address,v_server_address)
        payload_tree:add(f_application_afn,v_application_afn)
        payload_tree:add(f_seq_tpv,v_seq_tpv)
        payload_tree:add(f_seq_fir,v_seq_fir)
        payload_tree:add(f_seq_fin,v_seq_fin)
        payload_tree:add(f_seq_con,v_seq_con)
        payload_tree:add(f_seq_pseq_rseq,v_seq_pseq_rseq)
        payload_tree:add(f_pn,v_pn)
        payload_tree:add(f_fn,v_fn)
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
