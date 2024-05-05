
import sys
sys.path.append("../../../src")
from gquic_43_handshake import Scapy
from events.Events import *


s = Scapy("localhost")
print(s.send_chlo())
print(s.send_full_chlo(RemoveSNO=True))
print(s.send_zerortt(RemoveSNO=True))
# print(s.send(SendZeroRTTCHLOEvent()))
# print(s.send(SendFullCHLOEvent()))
# print(s.send(SendGETRequestEvent()))
# print(s.send(SendGETRequestEvent()))
# print(s.send(CloseConnectionEvent()))