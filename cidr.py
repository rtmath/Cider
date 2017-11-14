import sys
import math
import argparse

# ----- NOMENCLATURE -----
# binStr -> This refers to a Binary String for an IP Address or Subnet Mask,
#     such as (in the case of Subnet Mask 255.255.255.0) '11111111111111111111111100000000'
# address -> This refers to a string representing group of 4 octets/bytes seperated by periods, such as '192.168.0.0'

# ----- DEBUG MODE // SUPPRESS TRACEBACKS -----
debug = False # Toggle True to enable Tracebacks

def exception_handler(exception_type, exception, traceback, debug_hook=sys.excepthook):
    if debug:
        debug_hook(exception_type, exception, traceback)
    else:
        print("%s: %s" % (exception_type.__name__, exception))

sys.excepthook = exception_handler
# ---------------------------------------------

class ipAddress:
    def __init__(self, ipString):
        bytes = list(map(int, ipString.split(".")))
        self._octets = bytes
        self._binaryRepresentation = getBinRepresentation(ipString)
        self._address = ipString

        assert len(self._octets) == 4, "\n    Invalid Ip Length for Ip Address %s" % self._address
        for byte in self._octets:
            assert isInRange(byte), "\n    Invalid octet range '%s'\n    in Ip Address %s" % (byte, self._address)

    def getOctet(self, n):
        return self._octets[n]

class subnetMask(ipAddress):
    def __init__(self, bitmaskString):
        bytes = list(map(int, bitmaskString.split(".")))
        self._octets = bytes
        self._binaryRepresentation = getBinRepresentation(bitmaskString)
        self._address = bitmaskString

        for i in range(1, len(self._octets)):
            assert self._octets[i - 1] >= self._octets[i], "Invalid subnet mask: %s" % self._address
        assert isValidSubnetMask(self._binaryRepresentation), "\n    Invalid subnet mask (%s) \n    Bits are not contiguous: %s" % (self._address, self._binaryRepresentation)

class wildcardMask(ipAddress):
    def __init__(self, wcMaskString):
        bytes = list(map(int, wcMaskString.split(".")))
        self._octets = bytes
        self._binaryRepresentation = invertBinary(getBinRepresentation(wcMaskString))
        self._address = reconstructAddressFromBin(self._binaryRepresentation)

class cidr(ipAddress):
    def __init__(self, cidr):
        self._cidr = cidr
        self._binaryRepresentation = cidrToBin(self._cidr)
        self._address = reconstructAddressFromBin(self._binaryRepresentation)
        self._octets = list(map(int, self._address.split(".")))

def isInRange(byte):
    return byte in range(0, 256)

def getBinRepresentation(address):
    bytes = list(map(int, address.split(".")))
    stringRep = ""
    for byte in bytes:
        stringRep += format(byte, '08b')
    return stringRep

def invertBinary(binStr):
    stringRep = ""
    for bit in (binStr):
        stringRep += '0' if (bit == '1') else '1'
    return stringRep

def prettyPrintBinary(binStr):
    octet = 8
    newString = [binStr[i:i+octet] for i in range(0, len(binStr), octet)]
    print(" ".join(str(octet) for octet in newString))

def prettyPrint(ipObject, objectName):
    print("{:>20}".format(objectName + ": ") + "{:<18}".format(ipObject._address))

def prettyPrintNetmask(netmaskObject, headerString):
        print(headerString)
        print("CIDR: /%s"  % netmaskObject._cidr)
        print(" -- OR -- ")
        print("Subnet Mask: %s" % netmaskObject._address)

def getIntFromBin(baseTwoBinary):
    return int(baseTwoBinary, 2)

def reconstructAddressFromBin(binaryStr):
    octet = 8
    address = [binaryStr[i:i+octet] for i in range(0, len(binaryStr), octet)]
    reconAddress = []
    for byte in address:
        reconAddress.append(getIntFromBin(byte))
    return ".".join(str(octet) for octet in reconAddress)

def validUserInputs(ipAddress, subnetMask):
    return isInRange(ipAddress) and isInRange(subnetMask)

def countContiguousBits(binStr):
    count = 0
    for bit in binStr:
        if (bit == '1'):
            count += 1
        else:
            break
    return count

def isValidSubnetMask(binStr):
    contiguous = True
    for bit in binStr:
        if (bit == '1' and not contiguous):
            return False
        elif (bit == '0'):
            contiguous = False
    return True

def availNumOfAddresses(subBinStr):
    numHostBits = (32 - countContiguousBits(subBinStr))
    return 2 ** numHostBits

def printPossibleAddresses(ip, subBinStr):
    numPossibilities = availNumOfAddresses(subBinStr)
    firstThreeOctets = ".".join(list(ip.split("."))[:-1])
    for fourthOctet in range(0, numPossibilities):
        print(firstThreeOctets + "." + str(fourthOctet))

def cidrToBin(n):
    binary = ""
    n = int(n)
    for i in range(1, n + 1):
        binary += '1'
    for i in range(0, 32 - n):
        binary += '0'
    return binary

def bitAnd(ipBinStr, subnetBinStr):
    result = ""
    for ipBit, subnetBit in zip(ipBinStr, subnetBinStr):
        andResult = int(ipBit) & int(subnetBit)
        result += str(andResult)
    return result

def extractIp(ipCidrCombo):
    ip = None
    if "\\" in ipCidrCombo:
        ip = ipCidrCombo.split("\\")[0]
    elif "/" in ipCidrCombo:
        ip = ipCidrCombo.split("/")[0]
    if (ip is None):
        raise ValueError("Invalid IP provided")
    else:
        return ip

def extractCidr(ipCidrCombo):
    cidr = None
    if "\\" in ipCidrCombo:
        cidr = ipCidrCombo.split("\\")[1]
    elif "/" in ipCidrCombo:
        cidr = ipCidrCombo.split("/")[1]
    if (cidr is None):
        raise ValueError("Invalid CIDR provided")
    else:
        return cidr

def identifyClass(ipObject):
    firstOctet = ipObject.getOctet(0)
    if (firstOctet in range(1, 127)):
        return "Class A"
    elif (firstOctet in range(128, 192)):
        return "Class B"
    elif (firstOctet in range(192, 224)):
        return "Class C"
    elif (firstOctet in range(224, 240)):
        return "Class D"
    elif (firstOctet in range(240, 255)):
        return "Class E"
    else:
        return "Invalid Class/Octet Value"

def getNetworkAddress(ipObject, subnetObject):
    return reconstructAddressFromBin(bitAnd(ipObject._binaryRepresentation, subnetObject._binaryRepresentation))

def getBroadcastAddress(ipObject, subnetObject):
    ipBin = ipObject._binaryRepresentation
    subBin = subnetObject._binaryRepresentation
    broadcastBin = ""
    for ipBit, subBit in zip(ipBin, subBin):
        if subBit == '1':
            broadcastBin += ipBit
        elif subBit == '0':
            broadcastBin += '1'
    return reconstructAddressFromBin(broadcastBin)

def findRequiredMaskLength(numberOfHosts):
    hostBits = math.log(numberOfHosts, 2)
    return 32 - math.ceil(hostBits)

def findMinimumNetMask(ipObject1, ipObject2):
    bin1 = ipObject1._binaryRepresentation
    bin2 = ipObject2._binaryRepresentation
    count = 0
    for bit1, bit2 in zip(bin1, bin2):
        if (bit1 != bit2):
            return count
        count += 1
    return 0

def printCidrs():
    for i in reversed(range(0, 33)):
        print(("{:<10}".format("CIDR /%s" % i) + " | " + "{:<16}".format(cidr(i)._address)))

def printIpCidrCombo(args):
    userIp = ipAddress(extractIp(args.ipCidrCombo[0]))
    userCidr = cidr(extractCidr(args.ipCidrCombo[0]))
    wildcard = wildcardMask(userCidr._address)
    prettyPrint(userIp, "Ip Address")
    prettyPrint(userCidr, "Subnet Mask")
    prettyPrint(wildcard, "Wildcard Mask")
    prettyPrint(ipAddress(getNetworkAddress(userIp, userCidr)), "Network Address")
    prettyPrint(ipAddress(getBroadcastAddress(userIp, userCidr)), "Broadcast Address")
    print("{:>20}".format("Class: ") + "{:<18}".format(identifyClass(userIp)))

def printNetmask(args):
    userIp1 = ipAddress(args.netmask[0])
    userIp2 = ipAddress(args.netmask[1])
    cidrFromMin = cidr(findMinimumNetMask(userIp1, userIp2))
    prettyPrintNetmask(cidrFromMin, "IPs %s and %s are contained within: " % (userIp1._address, userIp2._address))

def printHost(args):
    newCidrNum = findRequiredMaskLength(args.hosts[0])
    newCidr = cidr(newCidrNum)
    prettyPrintNetmask(newCidr, "To contain %s hosts, you would need: " % str(args.hosts[0]))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', dest='listCidrs', action='store_true', default=False, help='List all CIDR/Subnet Mask combinations')
    parser.add_argument('--ic', dest='ipCidrCombo', action='store', help='Get info on a valid IP/CIDR combination', nargs=1, metavar=('0.0.0.0/0'))
    parser.add_argument('--nm', dest='netmask', action="store", help="Find minimum net mask which contains two IPs", nargs=2, metavar=('0.0.0.0', '0.0.0.0'))
    parser.add_argument('--hosts', dest='hosts', action="store", type=int, help="Calculate CIDR to contain n hosts", nargs=1, metavar=('n'))

    args = parser.parse_args()
    if (args.listidrs):
        printCidrs()
    elif (args.ipCidrCombo is not None):
        printIpCidrCombo(args)
    elif (args.netmask is not None):
        printNetmask(args)
    elif (args.hosts is not None):
        printHost(args)

if __name__ == "__main__":
    main()
