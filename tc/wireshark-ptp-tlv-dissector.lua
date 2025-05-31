-- Copy this file to ~/.local/lib/wireshark/plugins/ 
--
-- Define the Lua dissector
local ptp_tlv_dissector = Proto("CustomPTPTLV", "PTP INT")

-- Define the fields for the custom TLV
local f_type      =  ProtoField.uint16("customtlv.type", "TLV Type", base.HEX)
local f_length    =  ProtoField.uint16("customtlv.length", "TLV Length", base.DEC)
local f_switch_id =  ProtoField.uint16("customtlv.value", "Switch ID", base.DEC)
local f_ingress_ts = ProtoField.uint64("customtlv.value", "Ingress Timestamp", base.DEC)
local f_egress_ts  = ProtoField.uint64("customtlv.value", "Egress  Timestamp", base.DEC)
-- declare 64bit but we will extract only 48bit latter
local f_correct_ns = ProtoField.uint64("customtlv.value", "Correction Ns", base.DEC)

-- Add the fields to the protocol
ptp_tlv_dissector.fields = { f_type, f_length, f_switch_id, f_ingress_ts, f_egress_ts, f_correct_ns }


local original_ptp_dissector

-- declare some fields to be read
local f_ptp_msg_type   = Field.new("ptp.v2.messagetype")
local f_ptp_msg_length = Field.new("ptp.v2.messagelength")

local PTP_PKT_SIZE_WITHOUT_TLV =
{
  [0x08] = 44,
  [0x09] = 54,
}

-- Dissector function
function ptp_tlv_dissector.dissector(buffer, pinfo, tree)
    -- Ensure there's enough data for a TLV (4 bytes for type and length)
    if buffer:len() < 4 then return end

    -- run the original dissector
    original_ptp_dissector:call(buffer,pinfo,tree)

    -- get PTP info
    local ptp_type = f_ptp_msg_type().value
    local ptp_len  = f_ptp_msg_length().value

    -- size of PTP packet without TLV extensions
    local std_ptp_pkt_size = PTP_PKT_SIZE_WITHOUT_TLV[ ptp_type ]

    print("ptp_type:", ptp_type, std_ptp_pkt_size)
    
    if not std_ptp_pkt_size then -- we are not interested in other packets
        print("no interested")
        return
    end

    if ptp_len <= std_ptp_pkt_size then
        print("no space")
        return -- no space for TLV extenssion
    end
    
    local tlv_start_offset = std_ptp_pkt_size
    -- iterate over the TLV extensions
    while tlv_start_offset < buffer:len() do 

        -- Parse the TLV fields
        local tlv_type = buffer(tlv_start_offset, 2):uint()
        local tlv_length = buffer(tlv_start_offset + 2, 2):uint()

         -- our customized TLV
        if tlv_type == 0x0010 then

           -- Add a subtree for the TLV
           local subtree = tree:add(ptp_tlv_dissector, buffer( tlv_start_offset ), "Custom PTP TLV")

           ----- Parse the TLV Type (2 bytes)
           --local tlv_type = buffer(tlv_start_offset, 2):uint()
           subtree:add(f_type,   buffer(tlv_start_offset + 0, 2))
           subtree:add(f_length, buffer(tlv_start_offset + 2, 2))
           subtree:add(f_switch_id, buffer(tlv_start_offset + 4, 2))
           subtree:add(f_ingress_ts, buffer(tlv_start_offset + 6, 8))
           subtree:add(f_egress_ts, buffer(tlv_start_offset + 14, 8))

          --local correction_ns = buffer(tlv_start_offset + 22, 6):uint64() -- Read 6 bytes as a 64-bit value
          -- Mask the upper 16 bits since we only need 48 bits
          --correction_ns = correction_ns % (2 ^ 48) -- Ensure only 48 bits are used

          --subtree:add(f_correct_ns, correction_ns)
          subtree:add(f_correct_ns, buffer(tlv_start_offset + 22, 6))
          
        end
        -- jump to the next TLV 
        tlv_start_offset = tlv_start_offset + tlv_length + 4

   end
end

-- Register the dissector with the PTP protocol
-- Assuming PTP is on Ethernet type 0x88F7
local eth_type = DissectorTable.get("ethertype")
original_ptp_dissector = eth_type:get_dissector(0x88f7)
eth_type:add(0x88f7, ptp_tlv_dissector)

-- attach to UDP
-- Get the UDP port dissector table
local udp_port_table = DissectorTable.get("udp.port")

-- Save original dissector (optional, for fallback)
original_ptp_udp_dissector = udp_port_table:get_dissector(319)

-- Register your custom dissector
udp_port_table:add(319, ptp_tlv_dissector)
udp_port_table:add(320, ptp_tlv_dissector)
