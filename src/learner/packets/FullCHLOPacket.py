from scapy.fields import *
from scapy.packet import Packet

from util.SessionInstance import SessionInstance
from util.string_to_ascii import string_to_ascii


class FullCHLOPacket(Packet):
    """
    Full client hello packet
    Taken from Wireshark Capture example-local-clemente-aesgcm
    """
    name = "FullCHLO"

    fields_desc = [
        XByteField("Public_Flags", 0x08),
        StrFixedLenField("CID", string_to_ascii(""), 8),
        StrFixedLenField("Packet_Number", 1, 1), # LEShortField

        # Message Authentication Hash, 12 bytes
        StrFixedLenField("Message_Authentication_Hash", string_to_ascii("5f67187558566e93f02ce5d0"), 12),

        
        XByteField("Frame_Type", 0xa4),  # Stream
        ByteField("Stream_ID", 1),
        LEShortField("Offset", 0x0004),  # there in the source
        LEShortField("Data_Length", 0x0004), #LEIntField
        StrFixedLenField("Tag1", "CHLO", 4),
        LEShortField("Tag_Number", 23),
        ShortField("Padding", 0),

        # List of tags

        StrFixedLenField("PAD", "PAD", 3),
        ByteField("Xtra_1", 0),
        LEIntField("tag_offset_end_1", 539),
        
        StrFixedLenField("SNI", "SNI", 3), #9
        ByteField("Xtra_2", 0),
        LEIntField("tag_offset_end_2", 548),
        
        StrFixedLenField("STK", "STK", 3), # 60
        ByteField("Xtra_3", 0),
        LEIntField("tag_offset_end_3", 608), #

        StrFixedLenField("SNO", "SNO", 3), # 56
        ByteField("Xtra_4", 0),
        LEIntField("tag_offset_end_4", 664),

        StrFixedLenField("VER", "VER", 3), # 4
        ByteField("Xtra_5", 0),
        LEIntField("tag_offset_end_5", 668),

        StrFixedLenField("CCS", "CCS", 3), # 16
        ByteField("Xtra_6", 0),
        LEIntField("tag_offset_end_6", 684),

        StrFixedLenField("NONC", "NONC", 4), # 32
        LEIntField("tag_offset_end_7", 716),

        StrFixedLenField("AEAD", "AEAD", 4), #4
        LEIntField("tag_offset_end_8", 720),
        
        StrFixedLenField("UAID", "UAID", 4), #12
        LEIntField("tag_offset_end_9", 732),

        StrFixedLenField("SCID", "SCID", 4), # 16
        LEIntField("tag_offset_end_10", 748),
        
        StrFixedLenField("TCID", "TCID", 4), #4
        LEIntField("tag_offset_end_11", 752),

        StrFixedLenField("PDMD", "PDMD", 4),
        LEIntField("tag_offset_end_12", 756),

        StrFixedLenField("SMHL", "SMHL", 4),  # 4
        LEIntField("tag_offset_end_13", 760),
        
        StrFixedLenField("ICSL", "ICSL", 4), # 4
        LEIntField("tag_offset_end_14", 764),

        StrFixedLenField("PUBS", "PUBS", 4), # 32
        LEIntField("tag_offset_end_15", 796),

        StrFixedLenField("MIDS", "MIDS", 4), # 4
        LEIntField("tag_offset_end_16", 800),

        StrFixedLenField("SCLS", "SCLS", 4),  # 4
        LEIntField("tag_offset_end_17", 804), 

        StrFixedLenField("KEXS", "KEXS", 4),  # 4
        LEIntField("tag_offset_end_18", 808),

        StrFixedLenField("XLCT", "XLCT", 4), # 16
        LEIntField("tag_offset_end_19", 816),

        StrFixedLenField("CSCT", "CSCT", 4), # 0
        LEIntField("tag_offset_end_20", 816),

        StrFixedLenField("CCRT", "CCRT", 4), # 8
        LEIntField("tag_offset_end_21", 824),

        StrFixedLenField("CFCW", "CFCW", 4), # 4
        LEIntField("tag_offset_end_22", 828),

        StrFixedLenField("SFCW", "SFCW", 4), # 4
        LEIntField("tag_offset_end_23", 832),


        StrFixedLenField("Padding_value", string_to_ascii("2d"*539), 539),

        StrFixedLenField("Server_Name_Indication", "localhost", 9),

        StrFixedLenField("STK_Value", string_to_ascii("f7214fe6649467547b2c4e006d97c716097d05ac737b34f426404fd965e2290677fecb437701364808ec4af796bacea645afd897525ef16f"), 60),
        
        StrFixedLenField("SNO_Value", string_to_ascii("e4d458e2594b930f6d4f77711215adf9ebe99096c479dbf765f41d28646c4b87a0ec735e63cc4f19b9207d369e36968b2b2071ed"), 56),
        
        LEIntField("Version_Value", 0x33343051),
        
        StrFixedLenField("CCS_Value", string_to_ascii("01e8816092921ae87eed8086a2158291"), 16),
        
        StrFixedLenField("NONC_Value", string_to_ascii("5ac349e90091b5556f1a3c52eb57f92c12640e876e26ab2601c02b2a32f54830"), 32),
        
        StrFixedLenField("AEAD_Value", "AESG", 4),
        
        StrFixedLenField("UAID_Value", "lsquic/4.0.1", 12),
        
        StrFixedLenField("SCID_Value", string_to_ascii("01e8816092921ae87eed8086a2158291"), 16),

        LEIntField("TCID_Value", 0x00000000),

        StrFixedLenField("PDMD_Value", "X509", 4),

        LEIntField("SMHL_Value", 0x00000001),

        LEIntField("ICSL_Value", 30),

        StrFixedLenField("PUBS_Value", string_to_ascii("1403c2f3138a820f8114f282c4837d585bd00782f4ec0e5f1d39c06c49cc8043"), 32),

        LEIntField("MIDS_Value", 0x00000064),

        LEIntField("SCLS_Value", 1),

        StrFixedLenField("KEXS_Value", "C255", 4),

        StrFixedLenField("XLCT_Value", string_to_ascii("3e9f2d138eb2b48b"), 8),

        StrFixedLenField("CCRT_Value", string_to_ascii("3e9f2d138eb2b48b"), 8),
        
        LEIntField("CFCW_Value", 0x00f00000),

        LEIntField("SFCW_Value", 0x00600000),

        # Additional frame: PADDING (0x00)
        StrFixedLenField("Padding_Value", string_to_ascii("00"*318), 318),
        
        #XByteField("Padding832", 0x00), 
        
    ]