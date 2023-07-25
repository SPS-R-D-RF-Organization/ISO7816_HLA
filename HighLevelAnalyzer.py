# High Level Analyzer For more information and documentation, please go to
# https://support.saleae.com/extensions/high-level-analyzer-extensions
import math

import saleae
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
import Constants
from Constants import Title, InitBinary, Bits, EDC_Type
from APDU_Frame import APDU_Frame


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    edc_type = ChoicesSetting([EDC_Type.NA, EDC_Type.LRC, EDC_Type.CRC])

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in
    # Logic 2.
    result_types = {
        'ATR': {
            'format': 'Type : {{data.category}} | Data : {{data.transmitted_data}} | Hex : {{data.hex}}'
        },
        'Undefined': {
            'format': 'Type : {{data.category}} | Data : {{data.transmitted_data}} | Hex : {{data.hex}}'
        },
        'PPS': {
            'format': 'Type : {{data.category}} | Data : {{data.transmitted_data}} | Hex : {{data.hex}}'
        },
        'APDU': {
            'format': 'Type : {{data.category}} | Data : {{data.transmitted_data}} | Hex : {{data.hex}}'
        },
        'APDU Ans': {
            'format': 'Type : {{data.category}} | Data : {{data.transmitted_data}} | Hex : {{data.hex}}'
        },
        'Exchange using T=1': {
            'format': 'Type : {{data.category}} | Data : {{data.transmitted_data}} | Hex : {{data.hex}}'
        }

    }

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''

        # Initializing algorithme variables

        self.cameOnce = False
        self.instructionType = None
        self.f = Constants.DEFAULT_f
        self.errorInPPS_ANSWER = False
        self.PPSMessage = []
        self.readData = None
        self.type = None
        self.title = None
        self.DIpps = None
        self.FIpps = None
        self.communicationContext = Title.ATR
        self.subContext = None
        self.isTypeDefined = False  # For this variable, type means direct or inverted
        self.isFormatDefined = False
        self.charCount = 0
        self.nbFormatCount = 1
        self.interfaceOctets = []
        self.histoOctets = []
        self.totalBinaryString = []
        self.totalByteStrings = []
        self.totalHexStrings = []
        self.neededIndent = 0
        self.holdNeeded = False
        self.isEndOfHold = False
        self.bigBeginning = None
        self.firstHexString = None
        self.PPSi = {}
        self.Ti = {}
        self.ppsiOctets = []
        self.bits = {}
        self.mightTriggerPPS = False
        self.lastEndTime = None
        self.frame = None
        self.Le = ''
        self.binaryLe = ''
        self.messageFrames = []
        self.outputFrames = None
        self.len = None

        # Initializing iso7816 variables

        self.isDirect = None
        self.K = 0
        self.T = []
        self.FI = None
        self.DI = None
        self.II = None
        self.PI1 = None
        self.N = None
        self.canChangeMode = None
        self.tEnSpec = None
        self.WI = 10
        self.isParamParInterface = None
        self.n = None
        self.sspT = None

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''

        self.frame = frame

        binaryString = bytesToBinary(self.frame.data['data'])
        # Storing current binary string for later checking
        self.totalByteStrings.append(self.frame.data['data'])

        # Convert binary to hex :
        hexString = binaryToHex(binaryString)

        self.totalHexStrings.append('0x' + hexString)

        if self.isTypeDefined:
            # Reformat bits if needed
            if self.isDirect:
                pass
            else:
                # Invert and reverse the binary string to match the reversed encoding
                binaryString = reverseBits(invertBits(binaryString))

        self.saveBits(binaryString)
        self.totalBinaryString.append(binaryString)

        if self.communicationContext is Title.ATR:
            self.handleATR(binaryString)

        # Not used anymore
        # elif self.communicationContext is Title.HEADER:
        #    self.handleHEADER(binaryString, hexString)
        #
        # elif self.communicationContext is Title.DATA:
        #    self.handleDATA(binaryString)

        elif self.communicationContext is Title.PPS:
            self.handlePPS(binaryString)

        elif self.communicationContext is Title.PPS_ANSWER:
            self.handlePPS_ANSWER(binaryString)

        elif self.communicationContext is Title.LOOKING_FOR_KNOWN_INIT:
            self.handleSearchingInit(binaryString)

        elif self.communicationContext is Title.STORING_FRAMES:
            self.holdNeeded = True
            self.handleStoringFrames()

        elif self.communicationContext is Title.T1EXCHANGE:
            self.handleT1(binaryString)

        else:
            self.title = Title.UNDEFINED
            self.type = Title.UNDEFINED
            self.readData = Title.UNDEFINED
            # TODO: Handle context searching

        self.charCount += 1
        self.lastEndTime = frame.end_time
        # Return the data frame itself
        if not self.holdNeeded:
            if self.outputFrames is not None:
                out = self.outputFrames.copy()
                self.outputFrames.clear()
                return out
            if self.isEndOfHold:
                self.isEndOfHold = False
                return AnalyzerFrame(self.title, self.bigBeginning, frame.end_time, {
                    'category': self.type,
                    'transmitted_data': self.readData,
                    'hex': hexString
                })
            else:
                return AnalyzerFrame(self.title, frame.start_time, frame.end_time, {
                    'category': self.type,
                    'transmitted_data': self.readData,
                    'hex': hexString
                })

    # This function takes the binary string of the current octet (T0 or TD(i)), analyze what octets will come next
    # and store these information.
    def storeUpcomingOctets(self, binaryString):
        names = ['D', 'C', 'B', 'A']
        for i in range(4):
            # Build the names to handle several letters and indexes.
            name = 'T' + names[i] + '(' + str(self.nbFormatCount) + ')'
            if binaryString[i] == '1':
                self.Ti[name] = True
            else:
                self.Ti[name] = False
            print("Name : ", name, 'State : ', self.Ti[name])

        # If this is the first time we come here, it means the current character is a format one. The end of the
        # binary string defines then the number of history octets.
        # If not, this part of the octet defines a new available protocol.
        if self.charCount == 1:
            self.K = binaryToDecimal(binaryString[4:8])
        else:
            newProtocol = binaryToDecimal(binaryString[4:8])
            if newProtocol not in self.T:
                self.T.append(binaryToDecimal(binaryString[4:8]))

        # Update list of upcoming octets
        self.setOctetsList()

        if self.nbFormatCount == 1:
            # Handle missing values
            self.setDefaultData()

        out = self.printFormat()

        self.nbFormatCount += 1

        return out

    # This function creates a string with every information contained in a T0 or TD(i).
    def printFormat(self):
        strg = ''
        if self.Ti['TA({})'.format(self.nbFormatCount)] is True:
            strg += 'TA({}) '.format(self.nbFormatCount)
        if self.Ti['TB({})'.format(self.nbFormatCount)] is True:
            strg += 'TB({}) '.format(self.nbFormatCount)
        if self.Ti['TC({})'.format(self.nbFormatCount)] is True:
            strg += 'TC({}) '.format(self.nbFormatCount)
        if self.Ti['TD({})'.format(self.nbFormatCount)] is True:
            strg += 'TD({}) '.format(self.nbFormatCount)
        if self.nbFormatCount == 1:
            strg += '; K=' + str(self.K)
            if self.Ti['TD(1)'] is False:
                strg += "; T=" + str(self.T)

        return strg

    def getMessageLength(self):
        length = 0
        for key in self.Ti:
            if self.Ti[key] is True:
                length += 1
        length += self.K
        return length

    # Update the list of upcoming octets
    def setOctetsList(self):
        if self.Ti['TA({})'.format(self.nbFormatCount)] is True:
            self.interfaceOctets.append('TA({})'.format(self.nbFormatCount))
        if self.Ti['TB({})'.format(self.nbFormatCount)] is True:
            self.interfaceOctets.append('TB({})'.format(self.nbFormatCount))
        if self.Ti['TC({})'.format(self.nbFormatCount)] is True:
            self.interfaceOctets.append('TC({})'.format(self.nbFormatCount))
        if self.Ti['TD({})'.format(self.nbFormatCount)] is True:
            self.interfaceOctets.append('TD({})'.format(self.nbFormatCount))

        if self.nbFormatCount == 1:
            for i in range(self.K):
                self.histoOctets.append('T{}'.format(str(i + 1)))

    def setPPSiOctetsList(self):
        if self.PPSi['PPS1'] is True:
            self.ppsiOctets.append('PPS1')
        if self.PPSi['PPS2'] is True:
            self.ppsiOctets.append('PPS2')
        if self.PPSi['PPS3'] is True:
            self.ppsiOctets.append('PPS3')

    # Handle the data storage for every Tx(i) case.
    def computeData(self, binaryString, octetType):
        self.readData = ''
        if octetType == 'TA(1)':
            fiBits = binaryString[0:4]
            diBits = binaryString[4:8]
            self.FI = Constants.CONV_FI[fiBits]
            self.DI = Constants.CONV_DI[diBits]

            # Check if interface can trigger PPS
            if self.FI is not Constants.DEFAULT_Fi or self.DI is not Constants.DEFAULT_Di:
                self.mightTriggerPPS = True
                print("Interface might trigger PPS")
            else:
                print("Interface cannot trigger PPS.")

            print("FI :", self.FI, ', DI :', self.DI)
            self.readData += "FI : " + str(self.FI) + ' , DI : ' + str(self.DI)
        elif octetType == 'TB(1)':
            iiBits = binaryString[1:3]
            pi1Bits = binaryString[3:8]
            self.II = Constants.CONV_II[iiBits]
            self.PI1 = binaryToDecimal(pi1Bits)
            print("II :", self.II, ', PI1 :', self.PI1)
            self.readData += "II : " + str(self.II) + ' , PI1 : ' + str(self.PI1)
        elif octetType == 'TC(1)':
            self.N = binaryToDecimal(binaryString)
            print("N :", self.N)
            self.readData += 'N : ' + str(self.N)
            # TODO: Handle computing
        elif octetType == 'TC(2)':
            self.WI = binaryToDecimal(binaryString)
            self.readData += "WI = " + str(self.WI)
        elif octetType == 'TD({})'.format(self.nbFormatCount - 1):
            self.T.append(binaryToDecimal(binaryString[3:8]))
            if len(self.T) > 1:
                print("Available protocols T =", self.T)
            else:
                print("Available protocols T =", self.T)
            self.readData = 'T +:{}'.format(self.T[-1])
            self.readData += ', ' + self.storeUpcomingOctets(binaryString)

        # If it's not the first octet
        elif self.nbFormatCount > 1:
            if octetType == 'TA(2)':  # Octet du mode spécifique
                if binaryString[0] == '0':
                    self.canChangeMode = True
                else:
                    self.canChangeMode = False

                if binaryString[3] == '0':
                    self.isParamParInterface = True
                else:
                    self.isParamParInterface = False
                self.tEnSpec = binaryToDecimal(binaryString[4:8])
            # TODO: Name of Histo octetType changed. It's 'T + {index of current histo}'.
            elif octetType == "Histo":
                pass
            # TODO: Handle other cases
        return self.readData

    def checkNeedCntrlChar(self):
        for protocol in self.T:
            if int(protocol) is not 0:
                return True
        return False

    def setDefaultData(self):
        if self.Ti['TA(1)'] is False:
            self.FI = Constants.DEFAULT_Fi
            self.DI = Constants.DEFAULT_Di
            print("Default FI :", self.FI, ', Default DI :', self.DI)
        if self.Ti['TB(1)'] is False:
            pass
        if self.Ti['TC(1)'] is False:
            self.N = Constants.DEFAULT_N
            print("Default N :", self.N)
            # TODO: Handle computing
        if self.Ti['TD(1)'] is False:
            self.T.append(0)
            print("Default protocol : T =", self.T[0])

    def setPPSDefaultData(self):
        if self.PPSi['PPS1'] is True:
            self.FIpps = Constants.DEFAULT_Fi
            self.DIpps = Constants.DEFAULT_Di
            print("Default FI :", self.FIpps, ', Default DI :', self.DIpps)
        if self.PPSi['PPS2'] is True:
            pass  # RFU
        if self.PPSi['PPS3'] is True:
            pass  # RFU

    def clearingProcess(self, newTitle):
        print("End of {}. Clearing binary string.".format(self.communicationContext))
        self.totalBinaryString.clear()
        self.totalHexStrings.clear()
        self.totalByteStrings.clear()
        self.neededIndent = 0

        if newTitle is not Title.PPS_ANSWER:
            self.PPSMessage.clear()

        self.charCount = 0
        self.communicationContext = newTitle

        self.messageFrames = []

    def clearingProcessForAPDU(self):
        tempBinaryString = self.totalBinaryString[-1]
        tempHexStr = self.totalHexStrings[-1]
        tempByteStr = self.totalByteStrings[-1]

        self.clearingProcess(Title.STORING_FRAMES)

        # Store the current frame
        self.messageFrames.append(self.frame)
        self.totalBinaryString.append(tempBinaryString)
        self.totalHexStrings.append(tempHexStr)
        self.totalByteStrings.append(tempByteStr)

        self.holdNeeded = False
        self.isEndOfHold = True

    def checkCntrlChar(self):
        if self.communicationContext == Title.ATR:
            self.totalBinaryString = self.totalBinaryString[1:]
        calculatedTCK = calculate_TCK(self.totalBinaryString)
        if calculatedTCK == self.totalBinaryString[-1]:
            ans = True
        else:
            ans = False
        print('Checksum :', ans)
        return ans

    def handleATR(self, binaryString):
        commEnded = False
        self.title = Title.ATR
        # Check if it's the first time we decode an octet to know if it's an initial octet
        if not self.isTypeDefined:
            self.type = 'TS'
            if binaryString[2:5] == "111":
                self.isDirect = True
                self.isTypeDefined = True
                self.readData = 'direct'
            elif binaryString[2:5] == "000":
                self.isDirect = False
                self.isTypeDefined = True
                self.readData = 'inverted'
            print("Encoding mode :", self.readData + ".")
        # For every other times
        else:

            # Check if the formatting have been defined : check if we can decode the octets
            if self.isTypeDefined:
                # Check if the format character have been defined
                if not self.isFormatDefined:
                    self.type = 'T0'

                    self.readData = self.storeUpcomingOctets(binaryString)

                    self.isFormatDefined = True

                elif self.charCount - 2 < len(self.interfaceOctets):
                    self.type = self.interfaceOctets[self.charCount - 2]
                    self.readData = self.computeData(binaryString, self.type)

                elif self.charCount - len(self.interfaceOctets) - 2 < len(self.histoOctets):
                    self.type = self.histoOctets[self.charCount - len(self.interfaceOctets) - 2]
                    self.readData = self.computeData(binaryString, self.type)

                    if not self.checkNeedCntrlChar() and self.charCount - len(self.interfaceOctets) - 2 == len(
                            self.histoOctets) - 1:
                        commEnded = True

                elif self.checkNeedCntrlChar() and self.charCount - 2 == len(self.interfaceOctets) + len(
                        self.histoOctets):
                    self.type = "TCK"

                    transferOk = self.checkCntrlChar()
                    if transferOk:
                        self.readData = 'Transfer OK'
                    else:
                        self.readData = 'Error in transfer'
                    self.neededIndent = 1

                    commEnded = True

                else:
                    self.type = Title.UNDEFINED
                    self.readData = Title.UNDEFINED

                if commEnded:
                    if not self.mightTriggerPPS:
                        if self.T[0] == 0:
                            nextTitle = Title.STORING_FRAMES
                        elif self.T[0] == 1:
                            nextTitle = Title.T1EXCHANGE
                        else:
                            nextTitle = Title.UNDEFINED
                    else:
                        nextTitle = Title.LOOKING_FOR_KNOWN_INIT

                    print("Next : ", nextTitle)
                    self.clearingProcess(nextTitle)

    def handleDATA(self, binaryString):
        self.title = Title.DATA
        self.type = 'T{}'.format(str(self.charCount))

        if (
                self.frame.start_time - self.lastEndTime).__float__() <= 2 * self.getMinGuardTime() and self.n <= self.charCount < self.n + 3:
            # Le octet are present
            self.type = 'Le'
            self.binaryLe += binaryString
            self.readData = binaryString

            print((self.frame.start_time - self.lastEndTime).__float__(), self.getMinGuardTime())
            print(self.binaryLe)
            print(self.charCount, self.n)

        elif self.charCount == self.n + 3:
            self.Le = binaryToDecimal(self.binaryLe)
            self.readData = 'Max answer length = ' + str(self.Le)
            self.binaryLe = ''
            self.handleDataAnswer(binaryString)
        elif self.charCount > self.n:
            if self.binaryLe != '':
                self.Le = binaryToDecimal(self.binaryLe)
                self.readData = 'Max answer length = ' + str(self.Le)
                self.binaryLe = ''
                self.handleDataAnswer(binaryString)
            else:
                self.clearingProcess(Title.LOOKING_FOR_KNOWN_INIT)
                self.handleSearchingInit(binaryString)

    def handleDataAnswer(self, binaryString):
        self.type = Title.DATA_ANSWER
        self.title = Title.DATA_ANSWER

    def handlePPS(self, binaryString):
        self.title = Title.PPS

        print("PPS. Binary :", binaryString)
        if self.charCount == 1:
            self.type = 'PPSS'
            self.readData = "Init octet"
        elif self.charCount == 2:
            self.readData = ''
            self.type = 'PPS0'

            if binaryString[1] == '1':
                self.PPSi['PPS3'] = True
                self.readData += ' PPS3 '
            else:
                self.PPSi['PPS3'] = False
            if binaryString[2] == '1':
                self.PPSi['PPS2'] = True
                self.readData += ' PPS2 '
            else:
                self.PPSi['PPS2'] = False
            if binaryString[3] == '1':
                self.PPSi['PPS1'] = True
                self.readData += ' PPS1 '
            else:
                self.PPSi['PPS1'] = False
            self.sspT = binaryToDecimal(binaryString[4:8])
            self.setPPSiOctetsList()

        elif self.charCount - 3 < len(self.ppsiOctets):
            self.type = self.ppsiOctets[self.charCount - 3]
            print('Type :', self.type)

            if self.type == 'PPS1':
                fiBits = binaryString[0:4]
                diBits = binaryString[4:8]
                self.FIpps = Constants.CONV_FI[fiBits]
                self.DIpps = Constants.CONV_DI[diBits]
                print("PPS : FI :", self.FIpps, ', DI :', self.DIpps)
                self.readData = "FI : " + str(self.FIpps) + ' , DI : ' + str(self.DIpps)
                self.setPPSDefaultData()
            if self.type == 'PPS2':
                self.readData = 'RFU'
                pass  # RFU
            if self.type == 'PPS3':
                self.readData = 'RFU'
                pass  # RFU

        elif self.charCount - len(self.ppsiOctets) - 1 == 2:
            self.type = 'PCK'
            transferOk = self.checkCntrlChar()
            if transferOk:
                self.readData = 'Transfer OK'
            else:
                self.readData = 'Error in transfer'

            self.PPSMessage = self.totalBinaryString.copy()

            self.mightTriggerPPS = False
            self.clearingProcess(Title.PPS_ANSWER)

    def handlePPS_ANSWER(self, binaryString):
        self.title = self.communicationContext
        if self.errorInPPS_ANSWER is False:
            if self.charCount == 2 and binaryString[4:8] == self.PPSMessage[self.charCount - 1][4:8]:
                print("PPS answer; rare pattern.")
                if self.bits[Bits.b5] == 1:
                    print("rPPS1 = dPPS1 : saving FIpps and DIpps.")
                    self.FI = self.FIpps
                    self.DI = self.DIpps
                else:
                    print("No PPS1 : using default FI and DI")
                    self.FI = Constants.DEFAULT_Fi
                    self.DI = Constants.DEFAULT_Di

                # RFU
                if self.bits[Bits.b6] == 1:
                    print("rPPS2 = dPPS2. RFU.")
                else:
                    print("No PPS2. RFU")

                # RFU
                if self.bits[Bits.b7] == 1:
                    print("rPPS3 = dPPS3. RFU.")
                else:
                    print("No PPS3. RFU")

            elif binaryString != self.PPSMessage[self.charCount - 1]:
                self.errorInPPS_ANSWER = True

        self.type = self.communicationContext
        self.readData = 'Answer ok = ' + str(not self.errorInPPS_ANSWER)
        print("PPS answer; classic pattern.")

        if self.charCount == len(self.PPSMessage):
            if self.errorInPPS_ANSWER:
                print('End of PPS Answer. Something went wrong !')
            else:
                print('End of PPS Answer. Everything is okay.')
            self.clearingProcess(Title.STORING_FRAMES)

    def handleSearchingInit(self, binaryString):
        if binaryString == InitBinary.PPS_INIT and self.mightTriggerPPS:
            print('PPS detected !')
            self.communicationContext = Title.PPS
            self.handlePPS(binaryString)

        else:
            self.title = Title.UNDEFINED
            self.type = Title.UNDEFINED
            self.readData = Title.UNDEFINED
            self.charCount = 0

    def saveBits(self, binaryString):
        self.bits[Bits.b1] = binaryString[7]
        self.bits[Bits.b2] = binaryString[6]
        self.bits[Bits.b3] = binaryString[5]
        self.bits[Bits.b4] = binaryString[4]
        self.bits[Bits.b5] = binaryString[3]
        self.bits[Bits.b6] = binaryString[2]
        self.bits[Bits.b7] = binaryString[1]
        self.bits[Bits.b8] = binaryString[0]

    # Return the minimum guard time between two characters in ms.
    def getMinGuardTime(self):
        if 15 in self.T:
            q = Constants.DEFAULT_Fi / Constants.DEFAULT_Di
        else:
            q = self.FI / self.DI

        return 12 * self.getETU() + (q * self.N / self.f)

    # Return the Character Waiting Time
    def getCWT(self):

        cwt = self.getETU()

        if 1 in self.T:
            cwt *= 11 + math.pow(2, self.WI)
        else:
            cwt *= 11

        return cwt

    def getETU(self):
        return self.FI / (self.DI * self.f)

    # BUG: Since we process an APDU message in the first frame after it finished,
    #  whe never process the last message
    def handleStoringFrames(self):
        # The current character is part of the message
        if (
                self.frame.start_time - self.lastEndTime).__float__() < self.getCWT() * 1.3 or self.charCount == 1:
            self.messageFrames.append(self.frame)
        else:
            print("End of current message.")
            if self.subContext is None:
                self.subContext = Title.APDU

            if self.subContext is Title.APDU and len(self.messageFrames) >= 4:
                self.handleAPDU()
            elif self.subContext is Title.APDU_ANSWER:
                self.handleAPDUAnswer(self.messageFrames, self.totalBinaryString[:-1])
            else:
                print("Error in decoding last message ! Ignoring this part.")
                self.clearingProcessForAPDU()

            print('End of handling.\n\n')

    # Deprecated : There is now a new way of handling APDU's
    def handleHEADER(self, binaryString, hexString):
        self.title = Title.HEADER

        # Case T=0
        if self.T[0] == 0:
            if self.charCount == 1:
                self.type = 'CLA'
                self.readData = decodeCLA(hexString, binaryString)
            elif self.charCount == 2:
                self.type = 'INS'
                self.readData = decodeINS(hexString, binaryString)
            elif self.charCount == 3:
                self.type = 'P1'
                self.holdNeeded = True
                self.bigBeginning = self.frame.start_time
                self.firstHexString = hexString
            elif self.charCount == 4:
                self.type = 'P1 + P2'
                self.holdNeeded = False
                self.isEndOfHold = True
                hexString = self.firstHexString + hexString
                self.readData = "Ref : " + hexString
            elif self.charCount == 5:
                self.type = 'P3 (Le)'
                self.n = binaryToDecimal(binaryString)
                self.readData = 'n = ' + str(self.n)
                # TODO: Handle 'n=0' Case.
                self.totalBinaryString.clear()
                self.communicationContext = Title.DATA
                self.charCount = 0
            else:
                self.title = Title.UNDEFINED
                self.totalBinaryString.clear()
                self.communicationContext = Title.LOOKING_FOR_KNOWN_INIT
                self.charCount = 0
        else:
            self.title = Title.HEADER
            self.readData = 'T=1. Unsupported.'
            self.type = Title.UNDEFINED
            self.communicationContext = Title.LOOKING_FOR_KNOWN_INIT
            self.charCount = 0

    def handleAPDU(self):
        print("Handling APDU")
        self.outputFrames = []

        dataLen = len(self.messageFrames) - 4

        # SEE: iso7816_4 part 5.3.2 (conditions on L)
        sb1 = ''
        sb2 = ''
        sb3 = ''
        b1 = 0
        b2 = 0
        b3 = 0

        if dataLen + 4 > 4:
            b1 = binaryToDecimal(self.totalBinaryString[4])
            sb1 = self.totalBinaryString[4]
            if dataLen + 4 > 5:
                b2 = binaryToDecimal(self.totalBinaryString[5])
                sb2 = self.totalBinaryString[5]
                if dataLen + 4 > 6:
                    b3 = binaryToDecimal(self.totalBinaryString[6])
                    sb3 = self.totalBinaryString[6]

        sbL = self.totalBinaryString[-1]
        bL = binaryToDecimal(sbL)

        case = getAPDUCase(self.messageFrames, self.totalBinaryString)

        framesFromAPDU = self.messageFrames
        apduBinaryStrings = self.totalBinaryString

        cuttingPoints = self.findCuttingPoints(dataLen)
        print('C Pts :', cuttingPoints)

        if case == 'INV':
            # Maybe we also have the answer.

            print("INV Type. Trying with shrinking 1.")
            case = getAPDUCase(self.messageFrames[0: -2], self.totalBinaryString[0: -2])

            if case == 'INV':

                print("Still INV Type. Trying with shrinking 2.")

                if len(cuttingPoints) > 0:
                    cuttingIndex = cuttingPoints[0]
                    shrinkOut = self.shrinkMessage(cuttingIndex)

                    framesFromAPDU = shrinkOut['apduFrames']
                    apduBinaryStrings = shrinkOut['apduBStr']
                    framesFromAnswer = shrinkOut['ansFrames']
                    apduAnsBinaryStrings = shrinkOut['ansBin']

                    case = getAPDUCase(framesFromAPDU, apduBinaryStrings)

            else:
                framesFromAPDU = self.messageFrames[0: -2]
                apduBinaryStrings = self.totalBinaryString[0: -2]

                framesFromAnswer = self.messageFrames[-2:]
                apduAnsBinaryStrings = self.totalBinaryString[-3:-1]
        elif len(cuttingPoints) > 0:
            if cuttingPoints[0] == 5:
                shrinkOut = self.shrinkMessage(cuttingPoints[0])
                framesFromAPDU = shrinkOut['apduFrames']
                apduBinaryStrings = shrinkOut['apduBStr']
                framesFromAnswer = shrinkOut['ansFrames']
                apduAnsBinaryStrings = shrinkOut['ansBin']

                case = getAPDUCase(framesFromAPDU, apduBinaryStrings)

        print("Case :", case)

        i = 0
        hexCLA = self.totalHexStrings[i]
        cla = decodeCLA(self.totalHexStrings[i], apduBinaryStrings[i])
        frame = APDU_Frame('APDU', 'CLA', cla, self.totalHexStrings[i], framesFromAPDU[i])
        self.outputFrames.append(frame.getOutputFrame())
        i += 1
        ins = decodeINS(self.totalHexStrings[i][2:4], apduBinaryStrings[i], hexCLA)
        frame = APDU_Frame('APDU', 'INS', ins,
                           self.totalHexStrings[i], framesFromAPDU[i])
        self.outputFrames.append(frame.getOutputFrame())
        i += 1
        frame = APDU_Frame('APDU', 'P1', self.totalHexStrings[i][2:4], self.totalHexStrings[i], framesFromAPDU[i])
        self.outputFrames.append(frame.getOutputFrame())
        i += 1
        frame = APDU_Frame('APDU', 'P2', self.totalHexStrings[i][2:4], self.totalHexStrings[i], framesFromAPDU[i])
        self.outputFrames.append(frame.getOutputFrame())
        i += 1

        if case == '1':
            pass
        if case == '2S':
            frame = APDU_Frame('APDU', 'Le', str(b1), self.totalHexStrings[i], framesFromAPDU[i])
            self.outputFrames.append(frame.getOutputFrame())

        elif case == '3S' or case == '4S':
            frame = APDU_Frame('APDU', 'Lc', str(b1), self.totalHexStrings[i], framesFromAPDU[i])
            self.outputFrames.append(frame.getOutputFrame())

            i += 1

            for j in range(b1):
                frame = APDU_Frame('APDU', 'DATA', self.totalHexStrings[i + j], self.totalHexStrings[i + j],
                                   framesFromAPDU[i + j])
                self.outputFrames.append(frame.getOutputFrame())

            if case == '4S':
                i += b1
                frame = APDU_Frame('APDU', 'Le', str(bL), self.totalHexStrings[-1], framesFromAPDU[-1])
                self.outputFrames.append(frame.getOutputFrame())

        elif case == '2E':
            le = binaryToDecimal(apduBinaryStrings[-3] + apduBinaryStrings[-2] + apduBinaryStrings[-1])
            frame = APDU_Frame('APDU', 'Le', str(le), self.totalHexStrings[-1], framesFromAPDU[-3], framesFromAPDU[-1])
            self.outputFrames.append(frame.getOutputFrame())

        elif case == '3E' or case == '4E':
            frame = APDU_Frame('APDU', 'Lc', str(binaryToDecimal(sb2 + sb3)),
                               self.totalHexStrings[i] + self.totalHexStrings[i + 1],
                               framesFromAPDU[i], framesFromAPDU[i + 1])
            self.outputFrames.append(frame.getOutputFrame())

            i += 2

            for j in range(b1):
                frame = APDU_Frame('APDU', 'DATA', self.totalHexStrings[i + j], self.totalHexStrings[i + j],
                                   framesFromAPDU[i + j])
                self.outputFrames.append(frame.getOutputFrame())

            if case == '4E':
                i += b1
                frame = APDU_Frame('APDU', 'Le', str(binaryToDecimal(apduBinaryStrings[-2] + apduBinaryStrings[-1])),
                                   self.totalHexStrings[-2] + self.totalHexStrings[-1], framesFromAPDU[-2],
                                   framesFromAPDU[-1])
                self.outputFrames.append(frame.getOutputFrame())

        print("Switching to APDU Answer.")
        if len(framesFromAPDU) < len(self.messageFrames):
            # The frames contain an answer.
            self.handleAPDUAnswer(framesFromAnswer, apduAnsBinaryStrings)
        else:
            self.clearingProcessForAPDU()
            self.subContext = Title.APDU_ANSWER

    def handleAPDUAnswer(self, framesFromAnswer, binaryString):
        print("Handling APDU Answer...")

        if len(framesFromAnswer) > 2:
            for i in range(len(framesFromAnswer) - 2):
                frame = APDU_Frame('APDU Ans', 'ANSWER DATA', binaryToHex(binaryString[i]),
                                   binaryToHex(binaryString[i]),
                                   framesFromAnswer[i])
                self.outputFrames.append(frame.getOutputFrame())
        if len(framesFromAnswer) >= 2:
            sw1Frame = framesFromAnswer[-2]
            sw2Frame = framesFromAnswer[-1]

            sw1Binary = binaryString[-2]
            sw2Binary = binaryString[-1]

            frame = decodeSWAndGenerateFrame(sw1Frame, sw2Frame, sw1Binary, sw2Binary)
            self.outputFrames.append(frame)

        print("Switching to APDU.")
        self.subContext = Title.APDU
        self.clearingProcessForAPDU()

    def findCuttingPoints(self, dataLen):
        cuttingPoints = []

        print('CWT', self.getCWT())
        for i in reversed(range(1, dataLen + 4)):
            if (self.messageFrames[i].start_time - self.messageFrames[
                i - 1].end_time).__float__() + self.getETU() > self.getCWT() / 2:
                cuttingPoints.append(i)

        return cuttingPoints

    def shrinkMessage(self, cuttingIndex):
        case = getAPDUCase(self.messageFrames[: cuttingIndex], self.totalBinaryString[: cuttingIndex])

        if case != 'INV':
            framesFromAPDU = self.messageFrames[: cuttingIndex]
            apduBinaryStrings = self.totalBinaryString[: cuttingIndex]

            framesFromAnswer = self.messageFrames[cuttingIndex:]
            apduAnsBinaryStrings = self.totalBinaryString[cuttingIndex - 1:-1]

            return {'apduFrames': framesFromAPDU, 'apduBStr': apduBinaryStrings, 'ansFrames': framesFromAnswer,
                    'ansBin': apduAnsBinaryStrings}

        return {'apduFrames': self.messageFrames, 'apduBStr': self.totalBinaryString, 'ansFrames': None, 'ansBin': None}

    def handleT1(self, binaryString):
        self.title = Title.T1EXCHANGE
        print('Count :', self.charCount)
        # First byte: NAD (Node Address)
        if self.charCount == 1:
            self.type = 'NAD'
            self.readData = 'SAD : ' + binaryString[5:] + '; DAD : ' + binaryString[0:3] + "; "
            b8 = int(binaryString[0])
            b4 = int(binaryString[4])

            if b8 == 0 and b4 == 0:
                self.readData += 'Set or maintain pause sate on VPP.'
            elif b8 == 1 and b4 == 0:
                self.readData += 'Set reading state on VPP until PCB.'
            elif b8 == 0 and b4 == 1:
                self.readData += 'Set reading state on VPP until NAD.'
            else:
                self.readData += 'Not allowed...'

        # Second byte: PCB (Protocol Control Byte)
        elif self.charCount == 2:
            self.type = 'PCB'
            self.readData = ''

            # I bloc:
            if binaryString[0] == '0':
                self.readData += 'I bloc; N(S): ' + binaryString[1]
                self.readData += '; bit M : ' + binaryString[2]
                self.readData += '; RUF : ' + binaryString[3:]
            # R bloc:
            elif binaryString[0:2] == '10':
                self.readData += 'R bloc; '
                if self.readData[2] == '0':
                    if self.readData[3] == '1':
                        self.readData += 'Error : '
                        if binaryString[4:] == '0001':
                            self.readData += 'Char parity or EDC error.'
                        elif binaryString[4:] == '0010':
                            self.readData += 'Other error.'
                        else:
                            self.readData += 'RUF.'
                    elif binaryString == '10000000' or binaryString == '10010000':
                        self.readData += 'No error.'
                    else:
                        self.readData += 'RUF.'
                else:
                    self.readData += 'RUF.'

            # S bloc:
            elif binaryString[0:2] == '11':
                self.readData += 'S bloc; '
                b5__b1_meaning = decodePCBB_blocS_b5__b1(binaryString[4:])
                if binaryString[2:] == '100100':
                    self.readData += 'VPP state error.'
                elif binaryString[2] == '0':
                    self.readData += b5__b1_meaning
                    self.readData += ' request.'
                elif binaryString[2] == '1':
                    self.readData += b5__b1_meaning
                    self.readData += ' answer.'
                else:
                    self.readData += 'RUF.'

        # Third byte: len (Length)
        elif self.charCount == 3:
            self.type = 'len'
            self.len = binaryToDecimal(binaryString)
            self.readData = 'len : ' + str(self.len)
        elif self.charCount - 3 <= self.len:
            self.type = 'INF-' + str(self.charCount - 3)

        elif self.charCount - 3 - self.len == 1:
            if self.edc_type == EDC_Type.LRC:
                self.type = 'EDC : ' + EDC_Type.LRC
                transfertOK = self.checkCntrlChar()
                if transfertOK:
                    print("Transfer OK !")
                    self.readData = 'Transfer OK'
                else:
                    print("Error in transfer.")
                    self.readData = 'Error in transfer'
                self.clearingProcess(Title.T1EXCHANGE)
            elif self.edc_type == EDC_Type.CRC:
                self.type = 'EDC : ' + EDC_Type.CRC
                self.holdNeeded = True
                self.bigBeginning = self.frame.start_time
                self.firstHexString = binaryToHex(binaryString)
            else:
                self.type = 'EDC : ' + EDC_Type.NA
                self.readData = 'Please specify EDC.'
                print("\nEDC type specified as NA.")
                print("Please specify EDC type.\n")
        elif self.charCount - 3 - self.len == 2 and self.edc_type == EDC_Type.CRC:
            transfertOK = checkCRCIsOK(self.totalBinaryString)
            if transfertOK:
                print("Transfer OK !")
                self.readData = 'Transfer OK'
            else:
                print("Error in transfer.")
                self.readData = 'Error in transfer'
            self.holdNeeded = False
            self.isEndOfHold = True
            self.clearingProcess(Title.T1EXCHANGE)
        else:
            self.title = Title.UNDEFINED
            self.type = Title.UNDEFINED
            self.readData = Title.UNDEFINED


def getAPDUCase(messageFrames, totalBinaryString):
    dataLen = len(messageFrames) - 4
    print('Message length :', dataLen + 4)

    # SEE: iso7816_4 part 5.3.2 (conditions on L)
    sb2 = ''
    sb3 = ''
    b1 = 0

    if dataLen + 4 > 4:
        b1 = binaryToDecimal(totalBinaryString[4])
        if dataLen + 4 > 5:
            sb2 = totalBinaryString[5]
            if dataLen + 4 > 6:
                sb3 = totalBinaryString[6]

    # Case 1: L=0
    if dataLen == 0:
        case = '1'
    # Case 2S: L = 1
    elif dataLen == 1:
        case = '2S'
    # Case 3S: L = 1+(B1); (B1) != 0
    elif dataLen == 1 + b1 and b1 != 0:
        case = '3S'
    # Case 4S: L = 2+(B1); (B1) != 0
    elif dataLen == 2 + b1 and b1 != 0:
        case = '4S'
    # Case 2E: L = 3; (B1) = 0
    elif dataLen == 3 and b1 == 0:
        case = '2E'
    # Case 3E: L = 3 + (B2 || B3); (B1) = 0; (B2 || B3) != 0
    elif dataLen == 3 + binaryToDecimal(sb2 + sb3) and b1 == 0 and binaryToDecimal(sb2 + sb3) != 0:
        case = '3E'
    # Case 4E: L = 5 + (B2 || B3); (B1) = 0; (B2 || B3) != 0
    elif dataLen == 5 + binaryToDecimal(sb2 + sb3) and b1 == 0 and binaryToDecimal(sb2 + sb3) != 0:
        case = '4S'
    # Not valid cases
    else:
        case = 'INV'

    return case


def invertBits(bits):
    newBits = ""
    for b in bits:
        if b == '1':
            newBits += '0'
        else:
            newBits += '1'
    return newBits


def reverseBits(bits):
    newBits = ""
    for b in bits:
        newBits = b + newBits
    return newBits


def binaryToDecimal(n):
    try:
        out = int(n, 2)
    except:
        out = 0
    return out


def bytesToBinary(bytesData: bytes) -> str:
    return "{:08b}".format(int(bytesData.hex(), 16))


def binaryToHex(binaryString: str) -> str:
    return "{0:0>4X}".format(int(binaryString, 2))[2:5]


def calculate_TCK(binaryData):
    tck = "00000000"

    # First two octets
    for i in range(len(binaryData[0])):
        tck = replacer(tck, charXOR(binaryData[0][i], binaryData[1][i]), i)
    for binary in binaryData[2:-1]:
        for i in range(len(binary)):
            tck = replacer(tck, charXOR(tck[i], binary[i]), i)

    return tck


def replacer(s, newstring, index):
    if index < 0:  # add it to the beginning
        return newstring + s
    if index > len(s):  # add it to the end
        return s + newstring

    # insert the new string between "slices" of the original
    return s[:index] + newstring + s[index + 1:]


def charXOR(a: str, b: str) -> str:
    if a == '1' and b == '0' or a == '0' and b == '1':
        return '1'
    else:
        return '0'


# CRC check using divider (x^16+x^12+x^5+1)
def checkCRCIsOK(binaryStrings):
    div = '10001000000100001'

    # Generate the string
    binaryString = ''
    for string in binaryStrings:
        binaryString += string

    # Compute the division :
    currString = binaryString[0:len(div)]
    nextStr = ''
    if div[0] == 0 or currString[0] == 1:
        for i in range(len(div) - 1):
            nextStr += charXOR(currString[i + 1], div[i + 1])
    currString = nextStr
    nextStr = ''

    for bit in binaryString[len(div):]:
        currString += bit
        for i in range(len(div) - 1):
            nextStr += charXOR(currString[i + 1], div[i + 1])
        currString = nextStr
        nextStr = ''

    if '1' in currString:
        return False
    else:
        return True


def hexStringToHex(hexString: str) -> int:
    return int(hexString, 16)


# SEE: https://cardwerk.com/smart-card-standard-iso7816-4-section-5-basic-organizations/ part 5.4.1
def decodeCLA(hexString, binaryString):
    hexValue = hexStringToHex(hexString)

    # Structure and coding of command and response according to this part of ISO/IEC 7816
    if hexString[0] == '0':
        readData = '0: Structure of command and response, '
        decodeCLA_X(binaryString)

    # RFU
    elif 0x10 <= hexValue <= 0x7F:
        readData = 'RFU: {}'.format(hexString)

    # Structure of command and response according to this part of ISO/IEC 7816. Except for ‘X’ the coding and
    # meaning of command and response are proprietary.
    elif 0x80 <= hexValue <= 0x9F:
        readData = '{}: Structure of command and response, '.format(int(hexString[0]))
        decodeCLA_X(binaryString)

    # Unless otherwise specified by the application context, structure and coding of command and response according
    # to this part of ISO/IEC 7816
    elif hexString[0] == 'A':
        readData = 'A: Structure and coding of command and response, '
        decodeCLA_X(binaryString)

    # Structure of command and response according to this part of ISO/IEC 7816
    elif 0xB0 <= hexValue <= 0xCF:
        readData = 'Structure of command and response: {}'.format(hexString)

    # Proprietary structure and coding of command and response
    elif 0xD0 <= hexValue <= 0xFE:
        readData = 'Proprietary structure and coding of command and response: {}'.format(hexString)

    # Reserved for PTS
    else:
        readData = 'FF: Reserved for PTS.'

    return readData


def decodeCLA_X(binaryString):
    secureMessagingFormat = binaryString[4:6]
    readData = ''

    # No SM or no SM indication
    if secureMessagingFormat == '00':
        readData += 'No SM or no SM indication.'
    # Proprietary SM format
    elif secureMessagingFormat == '01':
        readData += 'Proprietary SM format.'

    # Command header not authenticated
    elif secureMessagingFormat == '10':
        readData += 'Command header not authenticated.'
    # Command header authenticated
    elif secureMessagingFormat == '11':
        readData += 'Command header authenticated.'

    logicalChannelNumber = binaryString[6:8]

    readData += ' Logical Channel Number: {}'.format(logicalChannelNumber)

    return readData


# SEE: https://cardwerk.com/smart-card-standard-iso7816-4-section-5-basic-organizations/ part 5.4.2
def decodeINS(hexString, binaryString, cla):
    readData = ''

    if cla is 'FF':
        if hexString is '82':
            readData = 'LOAD KEY'
        elif hexString is '86':
            readData = 'GENERAL AUTHENTICATE'
        elif hexString is 'B0':
            readData = 'READ BINARY'
        elif hexString is 'B4':
            readData = 'GET CHALLENGE'
        elif hexString is 'CA':
            readData = 'GET DATA'
        elif hexString is 'D6':
            readData = 'UPDATE BINARY'
        elif hexString is 'F0':
            readData = 'CONTROL'
        elif hexString is 'F3':
            readData = 'MIFARE CLASSIC READ'
        elif hexString is 'F4':
            readData = 'MIFARE CLASSIC WRITE'
        elif hexString is 'F5':
            readData = 'MIFARE CLASSIC VALUE'
        elif hexString is 'F6':
            readData = 'RFID'
        elif hexString is 'F7':
            readData = 'HCE'
        elif hexString is 'F9':
            readData = 'SE'
        elif hexString is 'FB':
            readData = 'CT CONTROL'
        elif hexString is 'FD':
            readData = 'ECHO'
        elif hexString is 'FE':
            readData = 'ENCAPSULATE'
        else:
            readData = 'RFU'
    else:
        # Invalid INS codes
        if binaryString[7] == '1' or binaryString[0:4] == '0110' or binaryString[0:4] == '1001':
            readData += 'Invalid Code.'
        else:
            try:
                instructionType = Constants.CONV_INS[hexString]
            except:
                instructionType = 'Unknown type : ' + hexString
            readData += instructionType
            print("Instruction:", instructionType)

    return readData


def decodeSWAndGenerateFrame(sw1Frame, sw2Frame, sw1Binary, sw2Binary):
    sw1 = binaryToHex(sw1Binary)
    sw2 = binaryToHex(sw2Binary)

    readData = ''

    # SEE: ISO7816_4 part 5.4.5
    if sw1 == '61':
        readData = 'Still ' + str(binaryToDecimal(sw2Binary)) + ' available octets.'
    elif sw1 == '62':
        readData = 'Memory unchanged. '
        if sw2 == '00':
            readData += 'No precisions.'
        elif sw2 == '01':
            readData += 'NV-Ram not changed 1.'
        elif sw2 == '81':
            readData += 'Part of returned data may be corrupted'
        elif sw2 == '82':
            readData += 'End of file/record reached before reading Le bytes.'
        elif sw2 == '83':
            readData += 'Selected file invalidated.'
        elif sw2 == '84':
            readData += 'Selected file is not valid. FCI not formated according to ISO'
        elif sw2 == '85':
            readData += 'No input data available from a sensor on the card. No Purse Engine enslaved for R3bc.'
        elif sw2 == 'A2':
            readData += 'Wrong R-MAC.'
        elif sw2 == 'A4':
            readData += 'Card locked (during reset( )).'
        elif sw2 == 'CX':
            readData += 'Counter with value x (command dependent).'
        elif sw2 == 'F1':
            readData += 'Wrong C-MAC.'
        elif sw2 == 'F3':
            readData += 'Internal reset.'
        elif sw2 == 'F5':
            readData += 'Default agent locked.'
        elif sw2 == 'F7':
            readData += 'Cardholder locked.'
        elif sw2 == 'F8':
            readData += 'Basement is current agent.'
        elif sw2 == 'F9':
            readData += 'CALC Key Set not unblocked.'
        elif sw2[0] == 'F':
            pass
        else:
            readData += 'RFU.'
    elif sw1 == '63':
        readData = 'Memory changed. '
        if sw2 == '00':
            readData += 'No precisions.'
        elif sw2 == '81':
            readData += 'File filled up by the last write. Loading/updating is not allowed.'
        elif sw2 == '82':
            readData += 'Card key not supported.'
        elif sw2 == '83':
            readData += 'Reader key not supported.'
        elif sw2 == '84':
            readData += 'Plaintext transmission not supported.'
        elif sw2 == '85':
            readData += 'Secured transmission not supported.'
        elif sw2 == '86':
            readData += 'Volatile memory is not available.'
        elif sw2 == '87':
            readData += 'Non-volatile memory is not available.'
        elif sw2 == '88':
            readData += 'Key number not valid.'
        elif sw2 == '89':
            readData += 'Key length is not correct.'
        elif sw2 == 'C0':
            readData += 'Verify fail, no try left.'
        elif sw2 == 'C1':
            readData += 'Verify fail, 1 try left.'
        elif sw2 == 'C2':
            readData += 'Verify fail, 2 tries left.'
        elif sw2 == 'C3':
            readData += 'Verify fail, 3 tries left.'
        elif sw2[0] == 'C':
            ##
            readData += 'The counter has reached the value ' + str(hexStringToDecimal(sw2[1])) + '.'
        elif sw2 == 'F1':
            readData += 'More data expected.'
        elif sw2 == 'F2':
            readData += 'More data expected and proactive command pending.'
        elif sw2[0] == 'F':
            readData += ''
        else:
            readData += 'RFU'
    elif sw1 == '64':
        readData = 'Memory unchanged. '
        if sw2 == '00':
            readData += 'No information given (NV-Ram not changed).'
        elif sw2 == '01':
            readData += 'Command timeout. Immediate response required by the card.'
        else:
            readData += 'RFU.'
    elif sw1 == '65':
        readData = 'Memory changed. '
        if sw2 == '00':
            readData += 'No precisions.'
        elif sw2 == '01':
            readData += 'Write error. Memory failure. There have been problems in writing or reading the EEPROM. ' \
                        'Other hardware problems may also bring this error.'

        elif sw2 == '81':
            readData += 'Memory failure.'
        elif sw2[0] == 'F':
            pass
        else:
            readData += 'RFU.'
    elif sw1 == '66':
        if sw2 == '00':
            readData += 'Error while receiving (timeout)'
        elif sw2 == '01':
            readData += 'Error while receiving (character parity error'
        elif sw2 == '02':
            readData += 'Wrong checksum'
        elif sw2 == '03':
            readData += 'The current DF file without FCI'
        elif sw2 == '04':
            readData += 'No SF or KF under the current DF'
        elif sw2 == '69':
            readData += 'Incorrect Encryption/Decryption Padding'
        else:
            pass
    elif sw1 == '67':
        readData = 'Incorrect length.'
    elif sw1 == '68':
        readData = 'CLA not assumed. '
        if sw2 == '00':
            readData += 'No precisions.'
        elif sw2 == '81':
            readData += 'Logical channel not supported.'
        elif sw2 == '82':
            readData += 'Secure messaging not supported.'
        elif sw2 == '83':
            readData += 'Last command of the chain expected.'
        elif sw2 == '84':
            readData += 'Command chaining not supported.'
        elif sw2[0] == 'F':
            pass
        else:
            readData += 'RFU.'
    elif sw1 == '69':
        readData = 'Command not allowed. '
        if sw2 == '00':
            readData += 'No precisions.'
        elif sw2 == '01':
            readData += 'Command not accepted (inactive state).'
        elif sw2 == '81':
            readData += 'Incompatibility with file structure.'
        elif sw2 == '82':
            readData += 'Security condition not satisfied.'
        elif sw2 == '83':
            readData += 'Authentication method blocked.'
        elif sw2 == '84':
            readData += 'Referenced data reversibly blocked (invalidated).'
        elif sw2 == '85':
            readData += 'Conditions of use not satisfied.'
        elif sw2 == '86':
            readData += 'Command not allowed (no current EF).'
        elif sw2 == '87':
            readData += 'Expected secure messaging (SM) object missing.'
        elif sw2 == '88':
            readData += 'Incorrect secure messaging (SM) data object'
        elif sw2 == '8D':
            readData += 'Reserved.'
        elif sw2 == '96':
            readData += 'Data must be updated again.'
        elif sw2 == 'E1':
            readData += 'POL1 of the currently Enabled Profile prevents this action.'
        elif sw2 == 'F0':
            readData += 'Permission Denied.'
        elif sw2 == 'F1':
            readData += 'Permission Denied – Missing Privilege'
        elif sw2[0] == 'F':
            pass
        else:
            readData += 'RFU.'

    elif sw1 == '6A':
        readData = 'P1-P2 incorrect. '
        if sw2 == '00':
            readData += 'No precisions.'
        elif sw2 == '80':
            readData += 'The parameters in the data field are incorrect..'
        elif sw2 == '81':
            readData += 'Function not supported.'
        elif sw2 == '82':
            readData += 'File not found.'
        elif sw2 == '83':
            readData += 'Record not found.'
        elif sw2 == '84':
            readData += 'Not enough memory in record or file.'
        elif sw2 == '85':
            readData += 'Lc inconsistent with TLV structure.'
        elif sw2 == '86':
            readData += 'P1-P2 incorrect.'
        elif sw2 == '87':
            readData += 'Lc inconsistent with P1-P2.'
        elif sw2 == '88':
            readData += 'Reference data not found.'
        elif sw2 == '89':
            readData += 'File already exists'
        elif sw2 == '8A':
            readData += 'DF name already exists.'
        elif sw2 == 'F0':
            readData += 'Wrong parameter value'
        elif sw2[0] == 'F':
            pass
        else:
            readData += 'RFU.'

    elif sw1 == '6B':
        if sw2 == '00':
            readData = 'P1-P2 incorrect.'
        else:
            readData = 'Reference incorrect (procedure byte).'
    elif sw1 == '6C':
        if sw2 == '00':
            readData = 'Incorrect P3 length..'
        else:
            readData = 'Wrong Le. Correct : ' + str(binaryToDecimal(sw2Binary)) + '.'
    elif sw1 == '6D':
        if sw2 == '00':
            readData = 'INS not supported or valid.'
        else:
            readData = 'INS not programmed or valid.'
    elif sw1 == '6E':
        readData = 'CLA incorrect.'
    elif sw1 == '6F':
        if sw2 == '00':
            readData = 'Command aborted – more exact diagnosis not possible.'
        elif sw2 == 'FF':
            readData = 'Card dead.'
        else:
            readData = 'No precise diagnosis.'
    elif sw1 == '90':
        if sw2 == '00':
            readData = 'Command successfully executed '
        elif sw2 == '04':
            readData = 'PIN not successfully verified, 3 or more PIN tries left.'
        elif sw2 == '08':
            readData = 'Key/file not found.'
        elif sw2 == '80':
            readData = 'Unblock Try Counter has reached zero.'
        else:
            readData = 'RFU.'

    elif sw1 == '91':
        if sw2 == '00':
            readData = 'OK'
        elif sw2 == '01':
            readData = 'States.activity, States.lock Status or States.lockable has wrong value'
        elif sw2 == '02':
            readData = 'Transaction number reached its limit'
        elif sw2 == '0C':
            readData = 'No changes'
        elif sw2 == '0E':
            readData = 'Insufficient NV-Memory to complete command'
        elif sw2 == '1C':
            readData = 'Command code not supported'
        elif sw2 == '1E':
            readData = 'CRC or MAC does not match data'
        elif sw2 == '40':
            readData = 'Invalid key number specified'
        elif sw2 == '7E':
            readData = 'Length of command string invalid'
        elif sw2 == '9D':
            readData = 'Not allow the requested command'
        elif sw2 == '9E':
            readData = 'Value of the parameter invalid'
        elif sw2 == 'A0':
            readData = 'Requested AID not present on PICC'
        elif sw2 == 'A1':
            readData = 'Unrecoverable error within application'
        elif sw2 == 'AE':
            readData = 'Authentication status does not allow the requested command'
        elif sw2 == 'AF':
            readData = 'Additional data frame is expected to be sent'
        elif sw2 == 'BE':
            readData = 'Out of boundary'
        elif sw2 == 'C1':
            readData = 'Unrecoverable error within PICC'
        elif sw2 == 'CA':
            readData = 'Previous Command was not fully completed'
        elif sw2 == 'CD':
            readData = 'PICC was disabled by an unrecoverable error'
        elif sw2 == 'CE':
            readData = 'Number of Applications limited to 28'
        elif sw2 == 'DE':
            readData = 'File or application already exists '
        elif sw2 == 'EE':
            readData = 'Could not complete NV-write operation due to loss of power'
        elif sw2 == 'F0':
            readData = 'Specified file number does not exist'
        elif sw2 == 'F1':
            readData = 'Unrecoverable error within file'
        else:
            readData = 'RFU.'

    elif sw1 == '92':
        if sw2[0] == 0:
            readData = 'Writing to EEPROM successful after ' + str(hexStringToDecimal(sw2[1])) + ' attempts.'
        elif sw2 == '10':
            readData = 'Insufficient memory. No more storage available.'
        elif sw2 == '40':
            readData = 'Writing to EEPROM not successful.'
        else:
            readData = 'RFU.'
    elif sw1 == '93':
        if sw2 == '01':
            readData = 'Integrity error.'
        elif sw2 == '02':
            readData = 'Candidate S2 invalid.'
        elif sw2 == '03':
            readData = 'Application is permanently locked.'
        else:
            readData = 'RUF.'

    elif sw1 == '94':
        if sw2 == '00':
            readData = 'No EF selected.'
        elif sw2 == '01':
            readData = 'Candidate currency code does not match purse currency'
        elif sw2 == '02':
            readData = 'Address range exceeded.'
        elif sw2 == '03':
            readData = 'Candidate amount too low'
        elif sw2 == '04':
            readData = 'FID not found, record not found or comparison pattern not found.'
        elif sw2 == '05':
            readData = 'Problems in the data field.'
        elif sw2 == '06':
            readData = 'Required MAC unavailable'
        elif sw2 == '07':
            readData = 'Bad currency : purse engine has no slot with R3bc currency'
        elif sw2 == '08':
            readData = 'Selected file type does not match command.'
        else:
            readData = 'RUF.'

    elif sw1 + sw2 == '9500':
        readData = 'Bad sequence.'
    elif sw1 + sw2 == '9680':
        readData = 'Slave not found.'
    elif sw1 == '97':
        if sw2 == '00':
            readData = 'PIN blocked and Unblock Try Counter is 1 or 2.'
        elif sw2 == '02':
            readData = 'Main keys are blocked.'
        elif sw2 == '04':
            readData = 'PIN not successfully verified, 3 or more PIN tries left.'
        elif sw2 == '84':
            readData = 'Base key.'
        elif sw2 == '85':
            readData = 'Limit exceeded – C-MAC key.'
        elif sw2 == '86':
            readData = 'SM error – Limit exceeded – R-MAC key.'
        elif sw2 == '87':
            readData = 'Limit exceeded – sequence counter.'
        elif sw2 == '88':
            readData = 'Limit exceeded – R-MAC length.'
        elif sw2 == '89':
            readData = 'Service not available.'
        else:
            readData = 'RUF.'
    elif sw1 == '98':
        if sw2 == '02':
            readData = 'No PIN defined.'
        elif sw2 == '04':
            readData = 'Access conditions not satisfied, authentication failed.'
        elif sw2 == '35':
            readData = 'ASK RANDOM or GIVE RANDOM not executed.'
        elif sw2 == '40':
            readData = 'PIN verification not successful.'
        elif sw2 == '50':
            readData = 'INCREASE or DECREASE could not be executed because a limit has been reached.'
        elif sw2 == '62':
            readData = 'Authentication Error, application specific (incorrect MAC)'
        else:
            readData = 'RUF.'
    elif sw1 == '99':
        if sw2 == '00':
            readData = '1 PIN try left'
        elif sw2 == '04':
            readData = 'PIN not successfully verified, 1 PIN try left'
        elif sw2 == '85':
            readData = 'Wrong status – Cardholder lock'
        elif sw2 == '86':
            readData = 'Missing privilege'
        elif sw2 == '87':
            readData = 'PIN is not installed'
        elif sw2 == '88':
            readData = 'Wrong status – R-MAC state'
        else:
            readData = 'RUF.'
    elif sw1 == '9A':
        if sw2 == '00':
            readData = '2 PIN try left'
        elif sw2 == '04':
            readData = 'PIN not succesfully verified, 2 PIN try left'
        elif sw2 == '71':
            readData = 'Wrong parameter value – Double agent AID'
        elif sw2 == '72':
            readData = 'Wrong parameter value – Double agent Type'
        else:
            readData = 'RUF.'

    elif sw1 == '9D':
        if sw2 == '05':
            readData = 'Incorrect certificate type'
        elif sw2 == '07':
            readData = 'Incorrect session data size'
        elif sw2 == '08':
            readData = 'Incorrect DIR file record size'
        elif sw2 == '09':
            readData = 'Incorrect FCI record size'
        elif sw2 == '0A':
            readData = 'Incorrect code size'
        elif sw2 == '10':
            readData = 'Insufficient memory to load application'
        elif sw2 == '11':
            readData = 'Invalid AID'
        elif sw2 == '12':
            readData = 'Duplicate AID'
        elif sw2 == '13':
            readData = 'Application previously loaded'
        elif sw2 == '14':
            readData = 'Application history list full'
        elif sw2 == '15':
            readData = 'Application not open'
        elif sw2 == '17':
            readData = 'Invalid offset'
        elif sw2 == '18':
            readData = 'Application already loaded'
        elif sw2 == '19':
            readData = 'Invalid certificate'
        elif sw2 == '1A':
            readData = 'Invalid signature'
        elif sw2 == '1B':
            readData = 'Invalid KTU'
        elif sw2 == '1D':
            readData = 'MSM controls not set'
        elif sw2 == '1E':
            readData = 'Application signature does not exist'
        elif sw2 == '1F':
            readData = 'KTU does not exist'
        elif sw2 == '20':
            readData = 'Application not loaded'
        elif sw2 == '21':
            readData = 'Invalid Open command data length'
        elif sw2 == '30':
            readData = 'Check data parameter is incorrect (invalid start address)'
        elif sw2 == '31':
            readData = 'Check data parameter is incorrect (invalid length)'
        elif sw2 == '32':
            readData = 'Check data parameter is incorrect (illegal memory check area)'
        elif sw2 == '40':
            readData = 'Invalid MSM Controls ciphertext'
        elif sw2 == '41':
            readData = 'MSM controls already set'
        elif sw2 == '42':
            readData = 'Set MSM Controls data length less than 2 bytes'
        elif sw2 == '43':
            readData = 'Invalid MSM Controls data length'
        elif sw2 == '44':
            readData = 'Excess MSM Controls ciphertext'
        elif sw2 == '45':
            readData = 'Verification of MSM Controls data failed'
        elif sw2 == '50':
            readData = 'Invalid MCD Issuer production ID'
        elif sw2 == '51':
            readData = 'Invalid MCD Issuer ID'
        elif sw2 == '52':
            readData = 'Invalid set MSM controls data date'
        elif sw2 == '53':
            readData = 'Invalid MCD number'
        elif sw2 == '54':
            readData = 'Reserved field error'
        elif sw2 == '55':
            readData = 'Reserved field error'
        elif sw2 == '56':
            readData = 'Reserved field error'
        elif sw2 == '57':
            readData = 'Reserved field error'
        elif sw2 == '60':
            readData = 'MAC verification failed'
        elif sw2 == '61':
            readData = 'Maximum number of unblocks reached'
        elif sw2 == '62':
            readData = 'Card was not blocked'
        elif sw2 == '63':
            readData = 'Crypto functions not available'
        elif sw2 == '64':
            readData = 'No application loaded'
        else:
            readData = 'RUF.'

    elif sw1 == '9E':
        if sw2 == '00':
            readData = 'PIN not installed'
        elif sw2 == '04':
            readData = 'PIN not successfully verified, PIN not installed'
        else:
            readData = 'RUF.'

    elif sw1 == '9F':
        if sw2 == '00':
            readData = 'PIN blocked and Unblock Try Counter is 3'
        elif sw2 == '04':
            readData = 'PIN not successfully verified, PIN blocked and Unblock Try Counter is 3'
        else:
            readData = 'Command successfully executed; ' + str(hexStringToDecimal(sw2)) + 'bytes of data are ' \
                                                                                          'available and can be ' \
                                                                                          'requested using GET ' \
                                                                                          'RESPONSE.'

    elif sw1[0] == '9':
        readData = 'Application related status.'

    frame = APDU_Frame('APDU Ans', 'SW1-SW2', readData, sw1 + sw2, sw1Frame, sw2Frame)
    return frame.getOutputFrame()


def decodePCBB_blocS_b5__b1(b5__b1: str) -> str:
    out = ''
    if b5__b1 == '0000':
        out = 'RESYNCH'
    elif b5__b1 == '0001':
        out = 'IFS'
    elif b5__b1 == '0010':
        out = 'ABORT'
    elif b5__b1 == '0011':
        out = 'WTX'
    else:
        out = 'RUF'

    return out


def hexStringToDecimal(hexString: str) -> int:
    return int(hexString, 16)
