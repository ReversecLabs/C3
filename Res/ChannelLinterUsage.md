The Channel Linter makes it possible to test channels without having to start any of C3's infrastructure. The Channel Linter has the following options:
```
Custom Command and Control - Channel linter. BUILD: C3-1.0.manual-build
Usage: ChannelLinter_d64.exe {-h|-l|-n NAME [options]}
Mode:
  -h, --help            Show this message and exit.
  -l, --list            List registered Channels and exit.
  -n <NAME>, --name <NAME>
                        Select channel with given <NAME> for further processing
Options:
  -a [ARGS...], --args [ARGS...]
                        Create channel with given ARGS using the Capability/create/arguments.
  -c [ARGS...], --complementary [ARGS...]
                        Create a complementary channel with given ARGS.
  -i, --test-io         Create a pair of channels and send packets through.
                        If this option is present -a [ARGS...] must be specified.
                        If -c is not present, complementary channel arguments are deduced by swapping
                        parameters from Capability/create/arguments arrays.
  -x <ID> [ARGS... ], --command <ID> [ARGS... ]
                        Execute a command with a given <ID> and arguments [ARGS...]
```

Below is an example of a **Failed** run of a channel, note the exception. This information tells us that an incorrect character was passed to the base64 decoder. The cause of this was lack of URL Encoding.

```
.\ChannelLinter_r86.exe -n Trello -a "input" "output" "KEY" "TOKEN" "linterTest1" -i
Custom Command and Control - Channel linter. BUILD: C3-1.0.manual-build
Channel: Trello
Parsing create arguments ... OK
Parsing command definitions ... OK
Registered commands:
id      name
65534   Set UpdateDelayJitter
65535   Close
Trello's Capability json verified OK.
Creating channel ... OK
Creating complementary channel ... OK
Testing channel with 8 bytes of data ... parse error: character [32 ' '] out of bounds
```

Once fixed, a successful run is observed:

```
 .\ChannelLinter_r86.exe -n Trello -a "input" "output" "KEY" "TOKEN" "linterTest1" -i
Custom Command and Control - Channel linter. BUILD: C3-1.0.manual-build
Channel: Trello
Parsing create arguments ... OK
Parsing command definitions ... OK
Registered commands:
id      name
65534   Set UpdateDelayJitter
65535   Close
Trello's Capability json verified OK.
Creating channel ... OK
Creating complementary channel ... OK
Testing channel with 8 bytes of data ... OK
Testing channel with 64 bytes of data ... OK
Testing channel with 1024 bytes of data ... OK
Testing channel with 1048576 bytes of data ... OK
```