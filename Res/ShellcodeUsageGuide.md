It is now possible for raw shellcode to be downloaded from the web interface. This binary output can then be used for weaponisation of other payloads. The process of generating Relay shellcode is as follows:

1. Assuming a Gateway is setup and running, create a new Channel (eg. Slack)
    
2. Double click on the channel icon and select the new Relay option under “Interface Options”

3. Within the Relay Setup window, select “shellcode” from the target suffix dropdown. A new set of options will be provided, as shown in the next image.

![figure3.png](./Images/ShellcodeUsageGuide/figure3.png)

1. Select the various options that will be passed to Donut. Note that it is strongly advised to use compression, of which the apLib option is the best.

2. Click on “Generate and Download Relay”.
