# #################################################################################################################### #
# Imports                                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select


# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __icmpTarget = ""               # Remote Host
        __destinationIpAddress = ""     # Remote Host IP Address
        __header = b''                  # Header after byte packing
        __data = b''                    # Data after encoding
        __dataRaw = ""                  # Raw string data before encoding
        __icmpType = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0            # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0          # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0      # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 30
        __ttl = 255                     # Time to live

        __replyRtt = 0                  # 220714 added
        __replyDropped = False          # 220715 added / False default

        __DEBUG_IcmpPacket = False      # Allows for debug output
     
        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #

        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        # 220714 added 
        def getReplyRtt(self):
            return self.__replyRtt

        # 220715 added
        def getReplyDropped(self):
            return self.__replyDropped

        def getDestinationIpAddress(self):
            return self.__destinationIpAddress

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        # 220714 added 
        def setReplyRtt(self, rtt):
            self.__replyRtt = rtt

        # 220715 added
        def setReplyDropped(self):
            self.__replyDropped = True 

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                   self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                   self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                   self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                   self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                   self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                   )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())               # Used to track overall round trip time
                                                                    # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()                 # packHeader() and encodeData() transfer data to their respective bit
                                                # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Hint: Work through comparing each value and identify if this is a valid response.
            # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm

            # 220710 added within these lines
            # TODO other values???

            # Check sequence number 
            if self.getPacketSequenceNumber() == icmpReplyPacket.getIcmpSequenceNumber():
                icmpReplyPacket.setIcmpSequenceNumber_isValid()

            # Check packet identifier 
            if self.getPacketIdentifier() == icmpReplyPacket.getIcmpIdentifier(): 
                icmpReplyPacket.setIcmpIdentifier_isValid()

            # Check raw data 
            if self.getDataRaw() == icmpReplyPacket.getIcmpData():
                icmpReplyPacket.setIcmpData_isValid()

            # Check checksum
            # Accounting for difference in IcmpType (8 for Icmp Packet / 0 for Echo Reply)...
            # ...difference in the checksum will be 8 * 256 = 2048. Add this to validate checksum. 
            # https://edstem.org/us/courses/23561/discussion/1611910
            typeDifference =  (self.getIcmpType() - icmpReplyPacket.getIcmpType()) * 256 
            if typeDifference + self.getPacketChecksum() == icmpReplyPacket.getIcmpHeaderChecksum():
                icmpReplyPacket.setIcmpChecksum_isValid()

            # Set the valid data variable in the IcmpPacketgit_EchoReply class based on the
            # outcome of the data comparison 
            if icmpReplyPacket.getIcmpIdentifier_isValid() and \
                icmpReplyPacket.getIcmpSequenceNumber_isValid() and \
                icmpReplyPacket.getIcmpData_isValid() and \
                icmpReplyPacket.getIcmpChecksum_isValid():
                icmpReplyPacket.setIsValidResponse(True) # All true is valid response 
            # One or more comparisons fail, set False
            else:
                icmpReplyPacket.setIsValidResponse(False)
                self.setReplyDropped() # "Mangled" packet per: https://edstem.org/us/courses/23561/discussion/1620536 / ULA discussion


        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def icmpResponseCode(self, icmpType, icmpCode):
            """
            Parse the ICMP response error codes and display the 
            corresponding error results to the user. 
            """
            icmpCodeDict = {
                0:{
                    0: "Echo / No code"
                },
                3:{
                    0: "Net Unreachable [RFC792]",
                    1: "Host Unreachable [RFC792]",
                    2: "Protocol Unreachable [RFC792]",
                    3: "Port Unreachable [RFC792]",
                    4: "Fragmentation Needed and Don't Fragment was Set [RFC792]",
                    5: "Source Route Failed [RFC792]",
                    6: "Destination Network Unknown [RFC1122]",
                    7: "Destination Host Unknown [RFC1122]",
                    8: "Source Host Isolated [RFC1122]",
                    9: "Communication with Destination Network is Administratively Prohibited [RFC1122]",
                    10: "Communication with Destination Host is Administratively Prohibited [RFC1122]",
                    11: "Destination Network Unreachable for Type of Service [RFC1122]",
                    12: "Destination Host Unreachable for Type of Service [RFC1122]",
                    13: "Communication Administratively Prohibited [RFC1812]",
                    14: "Host Precedence Violation [RFC1812]",
                    15: "Precedence cutoff in effect [RFC1812]"
                },
                11:{
                    0: "Time to Live exceeded in Transit",
                    1:  "Fragment Reassembly Time Exceeded "	
                }
            }
            try:
                code = icmpCodeDict[icmpType][icmpCode]
            except:
                code = "Unknown ICMP type/code"
            return code

        def sendEchoRequest(self):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress)

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print("\t*\t*\t*\t*\t*Request timed out.")
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print("\t*\t*\t*\t*\t*Request timed out (By no remaining time left).")

                else:
                    # Fetch the ICMP type and code from the received packet
                    # icmpType, icmpCode = recvPacket[20:22]
                    icmpType, icmpCode = 3, 3
                    
                    # "Modify the Pinger program to parse the ICMP response error codes and 
                    # ...display the corresponding error results to the user." 
                    # See: icmpResponseCode() above

                    if icmpType == 11:                          # Time Exceeded
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                (
                                    self.getTtl(),
                                    (timeReceived - pingStartTime) * 1000,
                                    icmpType,
                                    icmpCode,
                                    addr[0]
                                )
                              )
                        # Print type and code message
                        print(f"ICMP Type: {icmpType}-Time Exceeded\nICMP Code: {self.icmpResponseCode(icmpType,icmpCode)}")


                    elif icmpType == 3:                         # Destination Unreachable
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                  (
                                      self.getTtl(),
                                      (timeReceived - pingStartTime) * 1000,
                                      icmpType,
                                      icmpCode,
                                      addr[0]
                                  )
                              )
                        # Print type and code message
                        print(f"ICMP Type: {icmpType}-Destination unreachable\nICMP Code: {self.icmpResponseCode(icmpType,icmpCode)}")

                    elif icmpType == 0:                         # Echo Reply

                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        icmpPacketSequenceNumber = self.getPacketSequenceNumber() # 220713 added
                        icmpPacketIdentifer = self.getPacketIdentifier() # 220713 added
                        icmpPacketData = self.getDataRaw() # 220713 added
                        icmpPacketChecksum = self.getPacketChecksum()
                        icmpValidationData = [icmpPacketSequenceNumber,icmpPacketIdentifer,icmpPacketData,icmpPacketChecksum] # 220713 added
                        icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr, icmpValidationData) #220713 added icmpValidationData
                        self.setReplyRtt(icmpReplyPacket.getReplyRtt())#220714 added
                        return      # Echo reply is the end and therefore should return

                    else:
                        print("error") 
                        # "Lost" packet per: https://edstem.org/us/courses/23561/discussion/1620536 / ULA discussion
                        self.setReplyDropped() # 220715 JFB
            except timeout:
                print("\t*\t*\t*\t*\t*Request timed out (By Exception).")
            finally:
                mySocket.close()

        ###################
        # 220718 added
        def sendTraceroute(self, maxHops=30):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            print("Traceroute to (" + self.__icmpTarget + ") " + self.__destinationIpAddress)
            print("Hop\tTime\tIP\t\tHost")
            print("-"*64)

            ttl = 1
            hopCount = 1
            atDestination = False
            while hopCount <= maxHops and atDestination is False:
                mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
                mySocket.settimeout(self.__ipTimeout)
                mySocket.bind(("", 0))
                mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))  # Unsigned int - 4 bytes

                try:
                    mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                    timeLeft = 2
                    pingStartTime = time.time()
                    startedSelect = time.time()
                    whatReady = select.select([mySocket], [], [], timeLeft)
                    endSelect = time.time()
                    howLongInSelect = (endSelect - startedSelect)

                    if whatReady[0] == []: # timeout
                        print(f"{hopCount}\t*\t*\t*\tRequest timed out.") 
                        hopCount += 1

                    else:
                        recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                        timeReceived = time.time()
                        self.setReplyRtt((timeReceived - pingStartTime) * 1000)
                        timeLeft = timeLeft - howLongInSelect

                        if timeLeft <= 0: # timeout
                            print(f"{hopCount}\t*\t*\t*\tRequest timed out.")    

                        else: # found intermediary host
                            print(f"{hopCount}\t{int(round(self.getReplyRtt(), 0))}ms\t{addr[0]}\t{getfqdn(addr[0])}")
                            if str(addr[0]) == self.getDestinationIpAddress():
                                atDestination = True
                            ttl += 1
                            hopCount += 1
                except:
                    break
                finally:
                    mySocket.close()


        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False
        # Create variables within the IcmpPacket_EchoReply class that identify whether 
        # each value that can be obtained from the class is valid. 
        __icmpIdentifier_isValid = False # 220712 Added 
        __icmpSequenceNumber_isValid = False # 220712 Added 
        __icmpData_isValid = False # 220712 Added 
        __icmpChecksum_isValid = False 
        __replyRtt = 0  # 220714 Added 

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)   # Used to track overall round trip time
                                                               # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        #  220712 getter functions for each validation variable 
        def getIcmpSequenceNumber_isValid(self):
            return self.__icmpSequenceNumber_isValid

        def getIcmpIdentifier_isValid(self):
            return self.__icmpIdentifier_isValid
            
        def getIcmpData_isValid(self):
            return self.__icmpData_isValid 

        def getIcmpChecksum_isValid(self):      # 220719 added
            return self.__icmpChecksum_isValid

        def isValidResponse(self):
            return self.__isValidResponse

        def getReplyRtt(self):         # 220714 added
            return self.__replyRtt


        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        def setIcmpSequenceNumber_isValid(self):         # 220712 added 
            self.__icmpSequenceNumber_isValid = True

        def setIcmpIdentifier_isValid(self):         # 220712 added 
            self.__icmpIdentifier_isValid = True
            
        def setIcmpData_isValid(self):         # 220712 added 
            self.__icmpData_isValid = True 

        def setIcmpChecksum_isValid(self):      # 220719 added
            self.__icmpChecksum_isValid = True
           
        def setReplyRtt(self, rtt):         # 220712 added 
            self.__replyRtt = rtt


        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def printResultToConsole(self, ttl, timeReceived, addr, icmpValidationData):
            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
            # 220718 JFB add 
            print(f"ICMP Type: 0-Echo Reply\nICMP Code: [no code]") #TODO is this necessary?

            # 220714 JFB add 
            rtt = (timeReceived - timeSent) * 1000
            self.setReplyRtt(rtt)
            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d        Identifier=%d    Sequence Number=%d    %s" %
                  (
                      ttl,
                      rtt, #(timeReceived - timeSent) * 1000,
                      self.getIcmpType(),
                      self.getIcmpCode(),
                      self.getIcmpIdentifier(),
                      self.getIcmpSequenceNumber(),
                      addr[0]
                  )
                 )

            #220713 Added 
            print("\nVALIDATION RESULTS")
            for i in (  [self.__icmpSequenceNumber_isValid, "ICMP sequence number",icmpValidationData[0], self.getIcmpSequenceNumber()],
                        [self.__icmpIdentifier_isValid, "ICMP identifier", icmpValidationData[1], self.getIcmpIdentifier()],
                        [self.__icmpData_isValid, "ICMP data", icmpValidationData[2], self.getIcmpData()],
                        [self.__icmpChecksum_isValid, "ICMP checksum", icmpValidationData[3], self.getIcmpHeaderChecksum()]
                    ):
                    if i[0] is True:
                        print(f"{i[1]} is valid.")
                    else:
                        print(f"\033[91m{i[1]} is NOT valid.\n\t* Actual reply: \t{i[3]}\n\t* Expected reply: \t{i[2]}\033[00m ")
            print("-"*66)


    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False                  # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __sendIcmpEchoRequest(self, host):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        rttTimes = [] #220714 JFB add track cumulative RTT
        droppedReplies = 0
        echoRequests = 4

        for i in range(echoRequests):
            # Build packet
        
            icmpPacket = IcmpHelperLibrary.IcmpPacket()
            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                           # Some PIDs are larger than 16 bit
            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            icmpPacket.sendEchoRequest()                                                # Build IP

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            # we should be confirming values are correct, such as identifier and sequence number and data

            # 220714 added to get cumulative RTT
            replyRtt = icmpPacket.getReplyRtt()
            if icmpPacket.getReplyDropped():
                droppedReplies += 1
            rttTimes.append(replyRtt) # add to times list

        # 220714 added final stats
        rttMin = round(min(rttTimes))
        rttMax = round(max(rttTimes))
        rttAvg = round((sum(rttTimes)/echoRequests))
        print("="*64)
        print(f"RESULTS\nRTT min:{rttMin}ms\tRTT max: {rttMax}ms\tRTT avg: {rttAvg}ms")
        print(f"Packets transmitted: {echoRequests}, Packets received: {echoRequests-droppedReplies}")
        print(f"Packet loss: { ((echoRequests-(echoRequests-droppedReplies)) / echoRequests)*100}%")
        print("="*64)

    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        # Build code for trace route here

        # Set maximum number of hops
        maxHops = 30

        icmpPacket = IcmpHelperLibrary.IcmpPacket()
        randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                        # Some PIDs are larger than 16 bit
        packetIdentifier = randomIdentifier
        packetSequenceNumber = 1

        icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
        icmpPacket.setIcmpTarget(host)
        icmpPacket.sendTraceroute(maxHops)                                               # Build IP

    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)


# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()

    # Choose one of the following by uncommenting out the line
    # icmpHelperPing.sendPing("209.233.126.254")
    # icmpHelperPing.sendPing("www.google.com")
    # icmpHelperPing.sendPing("oregonstate.edu")
    icmpHelperPing.sendPing("gaia.cs.umass.edu")
    # icmpHelperPing.sendPing("9.9.9.9") # Switzerland 
    # icmpHelperPing.sendPing("128.65.210.8") #Germany

    # icmpHelperPing.traceRoute("oregonstate.edu")
    # icmpHelperPing.traceRoute("gaia.cs.umass.edu")
    # icmpHelperPing.traceRoute("9.9.9.9") # Switzerland 
    # icmpHelperPing.traceRoute("128.65.210.8") #Germany

if __name__ == "__main__":
    main()
