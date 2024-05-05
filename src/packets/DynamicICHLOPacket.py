import random
import secrets
import struct
from util.PacketNumberInstance import PacketNumberInstance
from crypto.fnv128a import FNV128A

from util.SessionInstance import SessionInstance
from util.string_to_ascii import string_to_ascii

class DynamicICHLOPacket:



    __header = b""
    __body = b""
    __body_size = 1344
    __offset = 0

    def __init__(self):
        self.__tags = [
{
    'name': b'PAD',
    'value': '2d'*(800 - len(SessionInstance.get_instance().destination_ip))
},
{
    'name': b'SNI',
    'value': SessionInstance.get_instance().destination_ip.encode("utf-8").hex()
},
{
    'name': b'STK',
    'value': ""
},
{
    'name': b'SNO',
    'value': ""
},
{
    'name': b'VER',
    'value': (b'Q043').hex()
},
{
    'name': b'CCS',
    'value': '01e8816092921ae87eed8086a2158291'
},
{
    'name': b'AEAD',
    'value': (b'AESG').hex()  # AESGCM12
},
{
    'name': b'UAID',
    'value': (b'lsquic/4.0.1').hex()  # AESGCM12
},
{
    'name': b'TCID',
    'value': "00"*4
},
{
    'name': b'PDMD',
    'value': (b'X509').hex()
},
{
    'name': b'SMHL',
    'value': '01000000'
},
{
    'name': b'ICSL',
    'value': '1e000000'
},
{
    'name': b'MIDS',
    'value': '64000000'
},
{
    'name': b'SCLS',
    'value': '01000000'
},
{
    'name': b'KEXS',
    'value': (b'C255').hex()  # C25519
},
{
    'name': b'CSCT',
    'value': ''  # C25519
},
{
    'name': b'CFCW',
    'value': '0000f000'
},
{
    'name': b'SFCW',
    'value': '00006000'
}
]

    def __write_to_header(self, data):
        self.__header += bytes.fromhex(data)
        # print(self.__header)

    def __write_to_body(self, data):
        self.__body += bytes.fromhex(data)

    def build_header(self):
        self.__write_to_header("09")
        self.__write_to_header(SessionInstance.get_instance().connection_id)
        self.__write_to_header(b"Q043".hex())
        self.__write_to_header(PacketNumberInstance.get_instance().get_next_packet_number().to_bytes(1, byteorder='big').hex())

        return self.__header.hex()

    def build_body(self):
        len_of_tags = len(self.__tags).to_bytes(2, byteorder="little").hex()

        self.__write_to_body("a0")  # Crypto
        self.__write_to_body("01")
        self.__write_to_body("0400")
        self.__write_to_body((b"CHLO").hex())    # Fixed CHLO  tag
        self.__write_to_body(len_of_tags)
        self.__write_to_body("0000")

        for index, tag in enumerate(self.__tags):
            tag_as_hex = tag['name'].hex().ljust(8, '0')
            # print(tag_as_hex)
            length_as_hex = (self.__offset + int(len(tag['value'])/int(2))).to_bytes(4, byteorder="little").hex()
            # print(length_as_hex)
            self.__offset += int(len(tag['value'])/2)

            # self.__body += bytes.fromhex(tag_as_hex)
            self.__write_to_body(tag_as_hex)
            self.__write_to_body(length_as_hex)

        for tag in self.__tags:
            self.__write_to_body(tag['value'])
            # print(tag['value'])
        self.__write_to_body("00"*316)
        return self.__body.hex()
    
    def fuzz_random_tag(self):
        print("InvalidICHLO")
        index = random.randrange(len(self.__tags))
        print(self.__tags[index])
        if random.randint(0,1):
            print("Tag Removed")
            self.__tags.remove(self.__tags[index])
            print()
        else:
            print("Tag Modified")
            self.__tags[index].update({'value': secrets.token_hex(len(self.__tags[index]['value'])//2)})
            print(self.__tags[index])
            print()

    def build_packet(self, InvalidPacket = False, Fuzz = False):
        if Fuzz and InvalidPacket:
            self.fuzz_random_tag()

        header = self.build_header()
        body = self.build_body()

        associated_data = [header[i:i + 2] for i in range(0, len(header), 2)]
        body_mah = [body[i:i + 2] for i in range(0, len(body), 2)]

        if InvalidPacket == False or Fuzz:
            message_authentication_hash = FNV128A().generate_hash(associated_data, body_mah)
        else:
            message_authentication_hash = "00"*12

        return string_to_ascii(header + message_authentication_hash + body)
    
    def CHLO_value(self):
        return self.__body[4 : 4 + 1024].hex()
