
  # ISO7816_Hla

This project is an extension for the software Saleae Logic 2. It allows you to decode messages exchanged between a smartcard and its reader, using the ISO7816.
This extension can be used with T=0 and T=1 protocols, but is not able to handle the frequency changes that occur after a PPS exchange. Due to a technical limitation, it can't process the last APDU message in a record.
