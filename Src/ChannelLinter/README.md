# C3 Channel Linter

Standalone tool to ease the development and debugging of channels.

## Usage

This tool provides console frontend for real channel usage

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
3. Test channel permeability - create a complemetary pair of channels and send message through.
    `-i`
    `--test-io` 
   e.g. `ChannelLinter.exe -n UncShareFile --args inputId outputId C:\Temp\C3Store false -i`
4. Execute channel commmand:
    `-x commandId [Argument1 Argument2 ...]`
    `--command commandId [Argument1 Argument2 ...]` 
   e.g. `ChannelLinter.exe -n UncShareFile --args inputId outputId C:\Temp\C3Store false -x 0`
