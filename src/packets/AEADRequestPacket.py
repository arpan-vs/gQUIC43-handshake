from scapy.fields import *
from scapy.packet import Packet

from util.string_to_ascii import string_to_ascii


class AEADRequestPacket(Packet):
    """
    Class that holds the raw data for the AEAD Packets
    But without the div nonce, used for sending the requests.
    """
    name = "AEAD Packet"

    fields_desc = [
        XByteField("Public_Flags", 0x08),
        StrFixedLenField("CID", string_to_ascii(""), 8),
        StrFixedLenField("Packet_Number", 1, 1), # LEShortField
    ]
