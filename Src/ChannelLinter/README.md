# C3 Channel Linter

Tool to ease the development and debugging of channels.
Main goal is to provide a simple application to test channels without the need of spinning up the whole C3 network.

## Usage

This tool provides console frontend for channel usage.

```
Usage: ChannelLinter.exe {-h|-l|-n NAME [options]}
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

Example workflows:
1. Parse the json returned from `GetCapability()` and validate it against C3 rules:
    `-n ChannelName` 
    `--name ChannelName`
    e.g. `ChannelLinter.exe -n UncShareFile`
    Note: ChannelName is case sensitive and must be same as used for the class name.
2. Create instance of a channel:
    `-a [Argument1 Argument2 ...]` 
    `--args [Argument1 Argument2 ...]` 
   e.g. `ChannelLinter.exe -n UncShareFile --args inputId outputId C:\Temp\C3Store false`
   Note: Messeges logged by calls to `this->Log()` will not be displayed if the channel constructor throws.
3. Test channel permeability - create a complemetary pair of channels and send messages through.
    `-i`
    `--test-io` 
   e.g. `ChannelLinter.exe -n UncShareFile --args inputId outputId C:\Temp\C3Store false -i`
4. Execute channel commmand:
    `-x commandId [Argument1 Argument2 ...]`
    `--command commandId [Argument1 Argument2 ...]` 
   e.g. `ChannelLinter.exe -n UncShareFile --args inputId outputId C:\Temp\C3Store false -x 0`
