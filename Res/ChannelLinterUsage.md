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