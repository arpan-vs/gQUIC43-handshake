from scapy.fields import *
from scapy.packet import Packet

from util.string_to_ascii import string_to_ascii


class AEADRequestPacketLongNumber(Packet):
    """
    Class that holds the raw data for the AEAD Packets
    But without the div nonce, used for sending the requests.
    """
    name = "AEAD Packet"

    fields_desc = [
        XByteField("Public_Flags", 0x18),
        StrFixedLenField("CID", string_to_ascii(""), 8),
        StrFixedLenField("Packet_Number", 1, 2), # LEShortField
        # XStrFixedLenField("Payload", string_to_ascii(""), 23),
    ]
