from scapy.packet import Packet
from scapy.fields import *

from util.string_to_ascii import string_to_ascii


class ACKPacket(Packet):
    name = "ACKPacket"
    fields_desc = [
        XByteField("Public_Flags", 0x08),
        StrFixedLenField("CID", string_to_ascii(""), 8),
        # StrFixedLenField("Version", "Q043", 4),
        StrFixedLenField("Packet_Number", "0", 1),

        # Message authentication hash
        StrFixedLenField("Message_Authentication_Hash", string_to_ascii(""), 12),
        XByteField("Frame_Type", 0x40),
        XByteField("Largest_Acked", 2),
        LEShortField("Largest_Acked_Delta_Time", 45362),
        XByteField("First_Ack_Block_Length", 2),
        ByteField("Num_Timestamp", 0),
    ]
