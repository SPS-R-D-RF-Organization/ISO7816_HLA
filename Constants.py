import math

CONV_FI = {
    '0000': {
        'Fi': 372,
        'f': 4
    },
    '0001': {
        'Fi': 372,
        'f': 5
    },
    '0010': {
        'Fi': 558,
        'f': 6
    },
    '0011': {
        'Fi': 744,
        'f': 8
    },
    '0100': {
        'Fi': 1116,
        'f': 12
    },
    '0101': {
        "Fi": 1488,
        'f': 16
    },
    '0110': {
        "Fi": 1860,
        'f': 20
    },
    '1001': {
        "Fi": 512,
        'f': 5
    },
    '1010': {
        "Fi": 768,
        'f': 7.5
    },
    '1011': {
        "Fi": 1024,
        'f': 10
    },
    '1100': {
        "Fi": 1536,
        'f': 15
    },
    '1101': {
        'Fi': 2048,
        'f': 20
    }
}

CONV_DI = {
    '0001': 1,
    '0010': 2,
    '0011': 4,
    '0100': 8,
    '0101': 16,
    '0110': 32,
    '1000': 12,
    '1001': 20
}

CONV_II = {
    "00": 25,
    "01": 50
}

# SEE: https://cardwerk.com/smart-card-standard-iso7816-4-section-5-basic-organizations/ part 5.4.2
CONV_INS = {
    '0E': 'ERASE BINARY',
    '20': 'VERIFY',
    '70': 'MANAGE CHANNEL',
    '82': 'EXTERNAL AUTHENTICATE',
    '84': 'GET CHALLENGE',
    '88': 'INTERNAL AUTHENTICATE',
    'A4': 'SELECT FILE',
    'B0': 'READ BINARY',
    'B2': 'READ RECORD(S)',
    'C0': 'GET RESPONSE',
    'C2': 'ENVELOPE',
    'CA': 'GET DATA',
    'D0': 'WRITE BINARY',
    'D2': 'WRITE RECORD',
    'D6': 'UPDATE BINARY',
    'DA': 'PUT DATA',
    'DC': 'UPDATE DATA',
    'E2': 'APPEND RECORD',
}


class INS_title:
    ERR_BIN = 'ERASE BINARY'
    VERIFY = 'VERIFY'
    MANAGE_CHANNEL = 'MANAGE CHANNEL'
    EXTERNAL_AUTHENTICATE = 'EXTERNAL AUTHENTICATE'
    GET_CHALLENGE = 'GET CHALLENGE'
    INTERNAL_AUTHENTICATE = 'INTERNAL AUTHENTICATE'
    SELECT_FILE = 'SELECT FILE'
    READ_BINARY = 'READ BINARY'
    READ_RECORD = 'READ RECORD(S)'
    GET_RESPONSE = 'GET RESPONSE'
    ENVELOPE = 'ENVELOPE'
    GET_DATA = 'GET DATA'
    WRITE_BINARY = 'WRITE BINARY'
    WRITE_RECORD = 'WRITE RECORD'
    UPDATE_BINARY = 'UPDATE BINARY'
    PUT_DATA = 'PUT DATA'
    UPDATE_DATA = 'UPDATE DATA'
    APPEND_RECORD = 'APPEND RECORD'


DEFAULT_Fi = 372
DEFAULT_Di = 1
DEFAULT_N = 0
DEFAULT_f = 4.8 * math.pow(10, 6)


class Title:
    ATR = 'ATR'
    APDU = 'APDU'
    APDU_ANSWER = 'APDU answer'
    HEADER = 'Header'
    DATA = 'Data'
    DATA_ANSWER = 'Data answer'
    PPS = 'PPS'
    PPS_ANSWER = 'PPS Answer'
    LOOKING_FOR_KNOWN_INIT = 'Searching'
    STORING_FRAMES = 'Storing frames'
    T1EXCHANGE = 'Exchange using T=1'
    UNDEFINED = 'Undefined'


class EDC_Type:
    LRC = 'LRC'
    CRC = 'CRC'
    NA = 'Not applicable'


class InitBinary:
    PPS_INIT = '11111111'


class Bits:
    b1 = 'b1'
    b2 = 'b2'
    b3 = 'b3'
    b4 = 'b4'
    b5 = 'b5'
    b6 = 'b6'
    b7 = 'b7'
    b8 = 'b8'
