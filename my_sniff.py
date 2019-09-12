from scapy.all import *
from binascii import hexlify
import datetime

ComLogFile = open("ComLogFile.txt", "a+")


def AnalyzePacket(packet):
    AnalyzePacket.Counter = AnalyzePacket.Counter + 1
    print ("new packet number %s at %s \n"% (AnalyzePacket.Counter, datetime.datetime.now()))
  
#    print (packet)
#    packet.show()

    ComLogFile.write("new packet number %s at %s \n"% (AnalyzePacket.Counter, datetime.datetime.now()))
    try:
      ComLogFile.write(packet[IP].dst+'\n')
    except:
      ComLogFile.write("\n ***** NON IP ****** \n")
    ComLogFile.write(str(packet))
    ComLogFile.write("\n")
    ComLogFile.write(str((bytes(packet)).hex()))
    ComLogFile.write("\n")
#    hexdump(packet)
#    ls(packet)
#    packet.show()
#    ComLogFile.write(packet.show(dump = True))
    ComLogFile.flush()
    
AnalyzePacket.Counter = 0
    

sniff(filter = "tcp", prn = AnalyzePacket, count = 15)
ComLogFile.close()

