# Attaching CS Beacon

## Cobalt Strike Side

1. Launch Teamserver as normal
2. Launch Client as normal
3. Create a new text file on your desktop called `c3.cna` and add the following inside:
    
    ```
    externalc2_start("0.0.0.0", 2222);
    ```
    
    *note: can be any port number, no opsec requirements as it’s from Gateway to Teamsever (your infrastructure)*
    
4. Go back to the Client and go to the Script Manager, load this script

## C3 Side

1. Once loaded you can go back to the C3 interface and run the `TurnOnConnectorTeamServer` command on your chosen Gateway, input the IP of the teamserver and then the port number you specified in the `c3.cna` file
2. Now click on the Relay you want to bind your Cobalt Strike beacon to and select Command Center, Then select `AddPeripheralBeacon` and then keep all the default settings and press Send Command
3. After about 10 seconds a beacon should have been built and automatically staged for you on the target machine (Note that this beacon automatically staged into the Relay process)