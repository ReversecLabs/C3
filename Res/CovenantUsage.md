This section demonstrates how to use the new integration of the Covenant C2 framework. The process is described below. These steps assuming an instance of Covenant is running. Users are also required to download and compile the C2Bridge project.

1. Select a running gateway, open its command centre and select TurnOnConnectorCovenant.

2. Fill in the form, these options will be used to create a BridgeListener in Covenant on the specified port.

<image src="UsageImages/figure1.png" />

3. Run the C2Bridge project on the same system as C3’s gateway. If TCP port 8000 was chosen as the C2Bridge port, then the correct arguments for C2Bridge would be “dotnet C2Bridge.dll covenant-host-ip 8000 8000”.

4. In order to stage an SMB Grunt, select a running Node Relay’s command centre and select AddPeripheralGrunt. 

<image src="UsageImages/figure2.png" />



