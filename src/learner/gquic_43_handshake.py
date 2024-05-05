import secrets
import time, os
import random
import re

from Crypto.Cipher import AES

import socket

from hpack import Encoder, HeaderTuple

from packets.ACKNotificationPacket import AckNotificationPacket
from packets.ACKPacket import ACKPacket
from packets.AEADRequestPacket import AEADRequestPacket
from packets.AEADRequestPacketlongPacketNumber import AEADRequestPacketLongNumber
from packets.DynamicFullCHLOPacket import DynamicFullCHLOPacket
from packets.DynamicICHLOPacket import DynamicICHLOPacket
from packets.DynamicZeroRTTPacket import DynamicZeroRTTPacket
from util.PacketNumberInstance import PacketNumberInstance
from crypto.dhke import dhke
from crypto.fnv128a import FNV128A
from events.Events import *
from util.SessionInstance import SessionInstance
from util.cert_decompress import cert_decomp
from util.packet_to_hex import extract_from_packet, extract_from_packet_as_bytestring
from util.string_to_ascii import string_to_ascii
import time
import logging
import os


# header lenght: 22 bytes
DPORT=4433



class Scapy:

    TIMEOUT = 0.3263230323791504 * 10
    server_adress_token = b''
    server_nonce = b''
    server_connection_id = b''
    Largest_Acked = 0


    def __init__(self, dns, Fuzz = False) -> None:
        
        self.logger = logging.getLogger(__name__)
        self._fuzz = Fuzz
        SessionInstance.get_instance().destination_ip = dns
        SessionInstance.get_instance().shlo_received = False
        conn_id = random.getrandbits(64)
        SessionInstance.get_instance().connection_id_as_number = conn_id
        SessionInstance.get_instance().connection_id = str(format(conn_id, 'x').zfill(16))
        self.UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.UDPClientSocket.connect((SessionInstance.get_instance().destination_ip, DPORT))
        self.UDPClientSocket.settimeout(.25)

        dhke.set_up_my_keys()

    def reset(self, reset_run=True):
        if reset_run:
            self.run = ""
            SessionInstance.get_instance().shlo_received = False
            SessionInstance.get_instance().scfg = ""
            SessionInstance.get_instance().zero_rtt = False
            self.logger.info("Changing CID from {}".format(SessionInstance.get_instance().connection_id))
            conn_id = random.getrandbits(64)
            SessionInstance.get_instance().connection_id_as_number = conn_id
            SessionInstance.get_instance().connection_id = str(format(conn_id, 'x').zfill(16))  # Pad to 16 chars
            PacketNumberInstance.get_instance().reset()
            self.logger.info("To {}".format(SessionInstance.get_instance().connection_id))
            self.Largest_Acked = 0

            dhke.set_up_my_keys()

    def send_chlo(self, InvalidPacket = False):
        self.reset()

        chlo = DynamicICHLOPacket()

        data = chlo.build_packet(InvalidPacket, self._fuzz)

        SessionInstance.get_instance().chlo = chlo.CHLO_value()

        self.UDPClientSocket.send(data)

        try:
            ans = self.UDPClientSocket.recv(2000)
            self.UDPClientSocket.recv(2000)
            self.Largest_Acked += 2


            packet = ans
            pattern = b"REJ"
            result = re.search(pattern, packet)
            if result:
                STK = re.search(b"STK\x00",packet).span()
                SNO = re.search(b"SNO\x00",packet).span()
                SCFG = re.search(b"SCFG",packet).span()
                SCID = re.search(b"SCID", packet).span()
                PUBS = re.search(b"PUBS", packet).span()
                EXPY = re.search(b"EXPY", packet).span()
                CRT = re.search(b"CRT\xff",packet).span()
                value_start = CRT[1] + 4
                scfg_value_start = EXPY[1] + 4
                stk_start, stk_end = 0, int(packet[STK[1]: STK[1] + 4][::-1].hex(),16)
                sno_start, sno_end = stk_end, int(packet[SNO[1]: SNO[1] + 4][::-1].hex(),16)
                scfg_start, scfg_end = int(packet[SCFG[0] - 4: SCFG[0]][::-1].hex(),16), int(packet[SCFG[1]: SCFG[1] + 4][::-1].hex(),16)
                scid_start, scid_end = int(packet[SCID[0] - 4: SCID[0]][::-1].hex(),16), int(packet[SCID[1]: SCID[1] + 4][::-1].hex(),16)
                pubs_start, pubs_end = int(packet[PUBS[0] - 4: PUBS[0]][::-1].hex(),16), int(packet[PUBS[1]: PUBS[1] + 4][::-1].hex(),16)
                crt_start, crt_end = int(packet[CRT[0] - 4: CRT[0]][::-1].hex(),16), int(packet[CRT[1]: CRT[1] + 4][::-1].hex(),16)

                self.server_adress_token = packet[value_start + stk_start : value_start + stk_end]
                self.server_nonce = packet[value_start + sno_start : value_start + sno_end]
                self.server_connection_id = packet[scfg_value_start + scid_start : scfg_value_start + scid_end]
                PUBS_value = packet[scfg_value_start + pubs_start : scfg_value_start + pubs_end]
                CERT_chain = packet[value_start + crt_start : value_start + crt_end]

                SessionInstance.get_instance().server_nonce_initial = self.server_nonce.hex()
                SessionInstance.get_instance().scfg = packet[value_start + scfg_start : value_start + scfg_end].hex()
                SessionInstance.get_instance().server_config_id = self.server_connection_id.hex()
                SessionInstance.get_instance().source_address_token = self.server_adress_token.hex()
                SessionInstance.get_instance().peer_public_value_initial = bytes.fromhex(PUBS_value[3:].hex())
                
                SessionInstance.get_instance().cert_chain = bytes.fromhex(CERT_chain[6:].hex())

                cert_decomp.cert_Decompress()
                self.send_first_ack()
                return b"REJ"
            else:
                return b"ERROR"
        except:
            return b"EXP"

    def send_first_ack(self):
        chlo = ACKPacket()

        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        chlo.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))
        chlo.setfieldval("Packet_Number", packet_number.to_bytes(1, byteorder='big'))

        chlo.setfieldval('Largest_Acked', int(str(self.Largest_Acked), 16))
        chlo.setfieldval('First_Ack_Block_Length', int(str(self.Largest_Acked), 16))

        associated_data = extract_from_packet(chlo, end=10)
        body = extract_from_packet(chlo, start=22)

        message_authentication_hash = FNV128A().generate_hash(associated_data, body)
        chlo.setfieldval('Message_Authentication_Hash', string_to_ascii(message_authentication_hash))

        data = bytes.fromhex(extract_from_packet_as_bytestring(chlo))
        self.UDPClientSocket.send(data)
        ans = self.UDPClientSocket.recv(2000)
        self.Largest_Acked +=1 
        
    def send_ack_for_encrypted_message(self):
        ack = AckNotificationPacket()

        ack.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))

        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        ack.setfieldval("Packet_Number", packet_number.to_bytes(1, byteorder='big'))

        ack_body = "40"
        ack_body += str(self.Largest_Acked).zfill(2)
        ack_body += "0062"
        ack_body += str(self.Largest_Acked).zfill(2)
        ack_body += "00"
        
        keys = SessionInstance.get_instance().final_keys

        try:
            addData = bytes.fromhex(extract_from_packet_as_bytestring(ack, end=10))
            nonce = SessionInstance.get_instance().final_keys['iv1'] + packet_number.to_bytes(8, byteorder='little')
            encoder = AES.new(SessionInstance.get_instance().final_keys['key1'], AES.MODE_GCM, nonce, mac_len=12)
            encoder = encoder.update(addData)
            ciphertext = encoder.encrypt_and_digest(bytes.fromhex(ack_body))
        except:
            return b"ERROR"

        data = bytes.fromhex(extract_from_packet_as_bytestring(ack))
        self.UDPClientSocket.send(data+ciphertext[0]+ciphertext[1])
        try:
            for _ in range(2):
                x = self.UDPClientSocket.recv(2000)
                self.Largest_Acked +=1
        except:
            pass

    def send_full_chlo(self, EmptyCertHash = False, RemoveCertHash = False, RemoveSNO = False, InvalidPacket = False):

        epochtime = int(time.time()).to_bytes(4, byteorder="little").hex()
        sORBIT = '0'*16
        randomString = bytes.hex(os.urandom(20))

        NONC = epochtime + sORBIT + randomString
        SessionInstance.get_instance().client_nonce = NONC

        fullchlo = DynamicFullCHLOPacket()

        if RemoveSNO:
            fullchlo.set_removed_SNO()
        if RemoveCertHash:
            fullchlo.set_removedCERT_Hash()
        if EmptyCertHash:
            fullchlo.set_emptyCERT_Hash()

        data = fullchlo.build_packet(InvalidPacket, self._fuzz)

        SessionInstance.get_instance().chlo = fullchlo.CHLO_value()

        self.UDPClientSocket.send(data)
        try:
            ans = self.UDPClientSocket.recv(2000)
            self.UDPClientSocket.recv(2000)
            self.Largest_Acked +=2

            packet = ans
            pattern = b"REJ"
            result = re.search(pattern, packet)
            if result:
                STK = re.search(b"STK\x00",packet).span()
                SNO = re.search(b"SNO\x00",packet).span()
                SCFG = re.search(b"SCFG",packet).span()
                SCID = re.search(b"SCID", packet).span()
                PUBS = re.search(b"PUBS", packet).span()
                EXPY = re.search(b"EXPY", packet).span()
                CRT = re.search(b"CRT\xff",packet).span()

                value_start = CRT[1] + 4
                scfg_value_start = EXPY[1] + 4
                stk_start, stk_end = 0, int(packet[STK[1]: STK[1] + 4][::-1].hex(),16)
                sno_start, sno_end = stk_end, int(packet[SNO[1]: SNO[1] + 4][::-1].hex(),16)
                scfg_start, scfg_end = int(packet[SCFG[0] - 4: SCFG[0]][::-1].hex(),16), int(packet[SCFG[1]: SCFG[1] + 4][::-1].hex(),16)
                scid_start, scid_end = int(packet[SCID[0] - 4: SCID[0]][::-1].hex(),16), int(packet[SCID[1]: SCID[1] + 4][::-1].hex(),16)
                pubs_start, pubs_end = int(packet[PUBS[0] - 4: PUBS[0]][::-1].hex(),16), int(packet[PUBS[1]: PUBS[1] + 4][::-1].hex(),16)
                crt_start, crt_end = int(packet[CRT[0] - 4: CRT[0]][::-1].hex(),16), int(packet[CRT[1]: CRT[1] + 4][::-1].hex(),16)
                
                self.server_adress_token = packet[value_start + stk_start : value_start + stk_end]
                self.server_nonce = packet[value_start + sno_start : value_start + sno_end]
                self.server_connection_id = packet[scfg_value_start + scid_start : scfg_value_start + scid_end]
                PUBS_value = packet[scfg_value_start + pubs_start : scfg_value_start + pubs_end]
                CERT_chain = packet[value_start + crt_start : value_start + crt_end]

                SessionInstance.get_instance().server_nonce_initial = self.server_nonce.hex()
                SessionInstance.get_instance().scfg = packet[value_start + scfg_start : value_start + scfg_end].hex()
                SessionInstance.get_instance().server_config_id = self.server_connection_id.hex()
                SessionInstance.get_instance().source_address_token = self.server_adress_token.hex()
                SessionInstance.get_instance().peer_public_value_initial = bytes.fromhex(PUBS_value[3:].hex())

                try:
                    SessionInstance.get_instance().cert_chain = bytes.fromhex(CERT_chain[6:].hex())
                    cert_decomp.cert_Decompress()
                except:
                    pass


                self.send_first_ack()
                return b"REJ"
            else:
                div_nonce = packet[9:9+32]
                packet_number = packet[41]
                addData = packet[:42]
                ciphertext = packet[42:]
                dhke.generate_keys(SessionInstance.get_instance().peer_public_value_initial, False, False, "localhost")
                diversed_key = dhke.diversify(SessionInstance.get_instance().initial_keys['key2'], SessionInstance.get_instance().initial_keys['iv2'], div_nonce)
                try:
                    aesg_nonce = diversed_key['diversified_iv'] + packet_number.to_bytes(8, byteorder='little')
                    decoder = AES.new(diversed_key['diversified_key'], AES.MODE_GCM, aesg_nonce, mac_len=12)
                    decoder = decoder.update(addData)
                    plain_text = decoder.decrypt_and_verify(ciphertext[:-12],ciphertext[-12:])
                except:
                    return b"ERROR"
                
                if plain_text[6:10] == b"SHLO":
                    SessionInstance.get_instance().shlo_received = True
                
                SNO = re.search(b"SNO\x00",plain_text).span()
                PUBS = re.search(b"PUBS", plain_text).span()
                SFCW = re.search(b"SFCW", plain_text).span()

                sno_start, sno_end = int(plain_text[SNO[0] - 4: SNO[0]][::-1].hex(),16), int(plain_text[SNO[1]: SNO[1] + 4][::-1].hex(),16)
                pubs_start, pubs_end = int(plain_text[PUBS[0] - 4: PUBS[0]][::-1].hex(),16), int(plain_text[PUBS[1]: PUBS[1] + 4][::-1].hex(),16)
                value_start = SFCW[1] + 4
                SessionInstance.get_instance().peer_public_value_final = plain_text[value_start + pubs_start:value_start + pubs_end]
                SessionInstance.get_instance().server_nonce_final = plain_text[value_start + sno_start : value_start + sno_end].hex()

                dhke.generate_keys(SessionInstance.get_instance().peer_public_value_final, True, False, "localhost")

                pattern = b"SHLO"
                result = re.search(pattern,plain_text)
                if result:
                    self.send_ack_for_encrypted_message()
                    return b"SHLO"
                else:
                    return b"ERROR"
        except:
            return b"EXP"
  
    def send_zerortt(self, EmptyCertHash = False, RemoveCertHash = False, RemoveSNO = False, InvalidPacket = False):

        PacketNumberInstance.get_instance().reset()
        SessionInstance.get_instance().connection_id = str(format(random.getrandbits(64), 'x').zfill(16))
        self.Largest_Acked = 0
        
        epochtime = int(time.time()).to_bytes(4, byteorder="little").hex()
        sORBIT = '0'*16
        randomString = bytes.hex(os.urandom(20))

        NONC = epochtime + sORBIT + randomString
        SessionInstance.get_instance().client_nonce = NONC

        zerortt = DynamicZeroRTTPacket()

        if RemoveSNO:
            zerortt.set_removed_SNO()

        if RemoveCertHash:
            zerortt.set_removedCERT_Hash()
        if EmptyCertHash:
            zerortt.set_emptyCERT_Hash()

        data = zerortt.build_packet(InvalidPacket, self._fuzz)

        SessionInstance.get_instance().chlo = zerortt.CHLO_value()

        self.UDPClientSocket.send(data)
        try:
            ans = self.UDPClientSocket.recv(2000)
            self.UDPClientSocket.recv(2000)
            self.Largest_Acked += 2

            packet = ans
            pattern = b"REJ"
            result = re.search(pattern, packet)
            if result:
                STK = re.search(b"STK\x00",packet).span()
                SNO = re.search(b"SNO\x00",packet).span()
                SCFG = re.search(b"SCFG",packet).span()
                SCID = re.search(b"SCID", packet).span()
                PUBS = re.search(b"PUBS", packet).span()
                EXPY = re.search(b"EXPY", packet).span()
                CRT = re.search(b"CRT\xff",packet).span()

                value_start = CRT[1] + 4
                scfg_value_start = EXPY[1] + 4
                stk_start, stk_end = 0, int(packet[STK[1]: STK[1] + 4][::-1].hex(),16)
                sno_start, sno_end = stk_end, int(packet[SNO[1]: SNO[1] + 4][::-1].hex(),16)
                scfg_start, scfg_end = int(packet[SCFG[0] - 4: SCFG[0]][::-1].hex(),16), int(packet[SCFG[1]: SCFG[1] + 4][::-1].hex(),16)
                scid_start, scid_end = int(packet[SCID[0] - 4: SCID[0]][::-1].hex(),16), int(packet[SCID[1]: SCID[1] + 4][::-1].hex(),16)
                pubs_start, pubs_end = int(packet[PUBS[0] - 4: PUBS[0]][::-1].hex(),16), int(packet[PUBS[1]: PUBS[1] + 4][::-1].hex(),16)
                crt_start, crt_end = int(packet[CRT[0] - 4: CRT[0]][::-1].hex(),16), int(packet[CRT[1]: CRT[1] + 4][::-1].hex(),16)
                
                self.server_adress_token = packet[value_start + stk_start : value_start + stk_end]
                self.server_nonce = packet[value_start + sno_start : value_start + sno_end]
                self.server_connection_id = packet[scfg_value_start + scid_start : scfg_value_start + scid_end]
                PUBS_value = packet[scfg_value_start + pubs_start : scfg_value_start + pubs_end]
                CERT_chain = packet[value_start + crt_start : value_start + crt_end]

                SessionInstance.get_instance().server_nonce_initial = self.server_nonce.hex()
                SessionInstance.get_instance().scfg = packet[value_start + scfg_start : value_start + scfg_end].hex()
                SessionInstance.get_instance().server_config_id = self.server_connection_id.hex()
                SessionInstance.get_instance().source_address_token = self.server_adress_token.hex()
                SessionInstance.get_instance().peer_public_value_initial = bytes.fromhex(PUBS_value[3:].hex())

                try:
                    SessionInstance.get_instance().cert_chain = bytes.fromhex(CERT_chain[6:].hex())
                    cert_decomp.cert_Decompress()
                except:
                    pass


                self.send_first_ack()
                return b"REJ"
            else:
                div_nonce = packet[9:9+32]
                packet_number = packet[41]
                addData = packet[:42]
                ciphertext = packet[42:]
                dhke.generate_keys(SessionInstance.get_instance().peer_public_value_initial, False, True, "localhost")
                diversed_key = dhke.diversify(SessionInstance.get_instance().initial_keys['key2'], SessionInstance.get_instance().initial_keys['iv2'], div_nonce)
                try:
                    aesg_nonce = diversed_key['diversified_iv'] + packet_number.to_bytes(8, byteorder='little')
                    decoder = AES.new(diversed_key['diversified_key'], AES.MODE_GCM, aesg_nonce, mac_len=12)
                    decoder = decoder.update(addData)
                    plain_text = decoder.decrypt_and_verify(ciphertext[:-12],ciphertext[-12:])
                except:
                    return b"ERROR"
                
                if plain_text[6:10] == b"SHLO":
                    SessionInstance.get_instance().shlo_received = True
                
                SNO = re.search(b"SNO\x00",plain_text).span()
                PUBS = re.search(b"PUBS", plain_text).span()
                SFCW = re.search(b"SFCW", plain_text).span()

                sno_start, sno_end = int(plain_text[SNO[0] - 4: SNO[0]][::-1].hex(),16), int(plain_text[SNO[1]: SNO[1] + 4][::-1].hex(),16)
                pubs_start, pubs_end = int(plain_text[PUBS[0] - 4: PUBS[0]][::-1].hex(),16), int(plain_text[PUBS[1]: PUBS[1] + 4][::-1].hex(),16)
                value_start = SFCW[1] + 4
                SessionInstance.get_instance().peer_public_value_final = plain_text[value_start + pubs_start:value_start + pubs_end]
                SessionInstance.get_instance().server_nonce_final = plain_text[value_start + sno_start : value_start + sno_end].hex()

                dhke.generate_keys(SessionInstance.get_instance().peer_public_value_final, True, False, "localhost")

                pattern = b"SHLO"
                result = re.search(pattern,plain_text)
                if result:
                    self.send_ack_for_encrypted_message()
                    return b"SHLO"
                else:
                    return b"ERROR"
        except:
            return b"EXP"

    def get(self, InvalidPacket = False):
        
        frame_data = "a003002400001b012500000005000000000f"

        if self._fuzz and InvalidPacket:
            frame_data = secrets.token_hex(len(frame_data)//2)

        e = Encoder()
        header = [HeaderTuple(":method","GET"),
                  HeaderTuple(":scheme","https"),
                  HeaderTuple(":path","/"),
                  HeaderTuple(":authority",SessionInstance.get_instance().destination_ip),
                  HeaderTuple("user-agent","lsquic/4.0.1")]
        encoded_data = e.encode(header)

        frame_data += encoded_data.hex()
        get = AEADRequestPacketLongNumber()
        get.setfieldval("Public_Flags", 0x18)
        get.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        get.setfieldval('Packet_Number', packet_number.to_bytes(2, byteorder='big'))
        error = False
        try:
            nonce = SessionInstance.get_instance().final_keys['iv1'] + packet_number.to_bytes(8, byteorder='little')
            encoder = AES.new(SessionInstance.get_instance().final_keys['key1'], AES.MODE_GCM, nonce, mac_len=12)
            addData = bytes.fromhex(extract_from_packet_as_bytestring(get))
            encoder = encoder.update(addData)
            ciphertext = encoder.encrypt_and_digest(bytes.fromhex(frame_data))
        except:
            error = True
            
        data = extract_from_packet_as_bytestring(get)

        if error or (InvalidPacket and not self._fuzz):
            associated_data = [data[i:i + 2] for i in range(0, len(data), 2)]
            body_mah = [frame_data[i:i + 2] for i in range(0, len(frame_data), 2)]
            if InvalidPacket:
                message_authentication_hash = "00"*12
            else:
                message_authentication_hash = FNV128A().generate_hash(associated_data, body_mah)
            self.UDPClientSocket.send(string_to_ascii(data + message_authentication_hash + frame_data))
        else:
            self.UDPClientSocket.send(bytes.fromhex(data) + ciphertext[0] + ciphertext[1])

        try:
            ans = self.UDPClientSocket.recv(2000)
            self.Largest_Acked += 1
            packet = ans

            if packet[0] == 16:
                packet_number = packet[2]
                ciphertext = packet[3:]
                addData = packet[:3]
            else:
                packet_number = packet[1]
                ciphertext = packet[2:]
                addData = packet[:2]

            try:
                aesg_nonce = SessionInstance.get_instance().final_keys['iv2'] + packet_number.to_bytes(8, byteorder='little')
                decoder = AES.new(SessionInstance.get_instance().final_keys['key2'], AES.MODE_GCM, aesg_nonce, mac_len=12)
                decoder = decoder.update(addData)
                plain_text = decoder.decrypt_and_verify(ciphertext[:-12],ciphertext[-12:])
            except:
                return b"ERROR"

            pattern = b"html"
            result = re.search(pattern, plain_text)
            if result:
                self.send_ack_for_encrypted_message()
                return b"html"
            else:
                return b"ERROR"
        except:
            return b"EXP"

    def close_connection(self, InvalidPacket = False):
        
        frame_data = "02000000100000"

        if self._fuzz and InvalidPacket:
            frame_data = secrets.token_hex(len(frame_data)//2)


        close = AEADRequestPacket()
        close.setfieldval("Public_Flags", 0x08)
        close.setfieldval('CID', string_to_ascii(SessionInstance.get_instance().connection_id))
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        close.setfieldval('Packet_Number', packet_number.to_bytes(1, byteorder='big'))
        error = False
        try:
            aesg_nonce = SessionInstance.get_instance().final_keys['iv1'] + packet_number.to_bytes(8, byteorder='little')
            encoder = AES.new(SessionInstance.get_instance().final_keys['key1'], AES.MODE_GCM, aesg_nonce, mac_len=12)
            addData = bytes.fromhex(extract_from_packet_as_bytestring(close))
            encoder = encoder.update(addData)
            ciphertext = encoder.encrypt_and_digest(bytes.fromhex(frame_data))
        except:
            error = True
            
        data = extract_from_packet_as_bytestring(close)

        if error or (InvalidPacket and not self._fuzz):
            associated_data = [data[i:i + 2] for i in range(0, len(data), 2)]
            body_mah = [frame_data[i:i + 2] for i in range(0, len(frame_data), 2)]
            if InvalidPacket:
                message_authentication_hash = "00"*12
            else:
                message_authentication_hash = FNV128A().generate_hash(associated_data, body_mah)

            self.UDPClientSocket.send(string_to_ascii(data + message_authentication_hash + frame_data))
        else:
            self.UDPClientSocket.send(bytes.fromhex(data) + ciphertext[0] + ciphertext[1])

        try:
            for i in range(2):
                ans = self.UDPClientSocket.recv(2000)
                packet = ans
                if packet[0] == 16:
                    packet_number = packet[2]
                    ciphertext = packet[3:]
                    addData = packet[:3]
                else:
                    packet_number = packet[1]
                    ciphertext = packet[2:]
                    addData = packet[:2]
                    
                try:
                    aesg_nonce = SessionInstance.get_instance().final_keys['iv2'] + packet_number.to_bytes(8, byteorder='little')
                    decoder = AES.new(SessionInstance.get_instance().final_keys['key2'], AES.MODE_GCM, aesg_nonce, mac_len=12)
                    decoder = decoder.update(addData)
                    plain_text = decoder.decrypt_and_verify(ciphertext[:-12],ciphertext[-12:])
                except:
                    return b"ERROR"
                
                if plain_text[0] == 2:
                    return b"closed"
                else:
                    continue
            return b"EXP"
        except:
            return b"EXP"

    def send(self, command):
        try:
            if isinstance(command, SendInitialCHLOEvent):
                return self.send_chlo()
            elif isinstance(command, SendFullCHLOEvent):
                return self.send_full_chlo()
            elif isinstance(command, SendZeroRTTCHLOEvent):
                return self.send_zerortt()
            elif isinstance(command, SendGETRequestEvent):
                return self.get()
            elif isinstance(command, CloseConnectionEvent):
                return self.close_connection()
            elif isinstance(command, SendInvalidInitialCHLOEvent):
                return self.send_chlo(InvalidPacket = True)
            elif isinstance(command, SendInvalidFullCHLOEvent):
                return self.send_full_chlo(InvalidPacket = True)
            elif isinstance(command, SendInvalidZeroRTTCHLOEvent):
                return self.send_zerortt(InvalidPacket = True)
            elif isinstance(command, SendEmptyCERTHashFullCHLOEvent):
                return self.send_full_chlo(EmptyCertHash = True)
            elif isinstance(command, SendEmptyCERTHashZeroRTTCHLOEvent):
                return self.send_zerortt(EmptyCertHash = True)
            elif isinstance(command, SendRemovedCERTHashFullCHLOEvent):
                return self.send_full_chlo(RemoveCertHash= True)
            elif isinstance(command, SendRemovedCERTHashZeroRTTCHLOEvent):
                return self.send_zerortt(RemoveCertHash = True)
            elif isinstance(command, SendInvalidGETRequestEvent):
                return self.get(InvalidPacket = True)
            elif isinstance(command, InvalidCloseConnectionEvent):
                return self.close_connection(InvalidPacket = True)
            else:
                pass
        except Exception as err:
            self.logger.exception(err)

