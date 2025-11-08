# Attaching 0xC2 Agent

## 0xC2 Side

1. Create an External Listener (default name looked for is ExternalC3)
2. Create an HTTP listener (default name looked for is C3) - set your profile here as normal

## UDVT

1. Compile the UDVT C3 project https://git.reversec/C3/0xC2-C3, add in any additional UDVT to this file.
2. Use extract.py to extract the UDVT base64 string.
3. Note the pipename in settings.h or change as appropriate.

## C3 Side

1. Once loaded you can go back to the C3 interface and run the `TurnOnConnectorOhxC2` command on your chosen Gateway. Provide the listener names, 0xc2 password, UDVT64 (and 32 bit if required), pipename that matches settings.h from the UDVT project, and the path to the 0xC3 Sqlite database (c2.db). 
2. Now click on the Relay you want to bind your Cobalt Strike beacon to and select Command Center, Then select `AddPeripheralOhxC2` and then keep all the default settings and press Send Command.