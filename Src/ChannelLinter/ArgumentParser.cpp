#include "stdafx.h"
#include "ArgumentParser.h"

namespace FSecure::C3::Linter
{
	ArgumentParser::ArgumentParser(int argc, char** argv) : m_ArgParser()
	{
		ConfigureParser();
		m_AppName = argv[0];
		m_ArgParser.parse(argc, argv);
		FillConfig();
		ValidateConfig();
	}

	void ArgumentParser::ConfigureParser()
	{
		m_ArgParser.addArgument("-h", "--help");
		m_ArgParser.addArgument("-l", "--list");
		m_ArgParser.addArgument("-n", "--name", 1);
		m_ArgParser.addArgument("-a", "--args", '*');
		m_ArgParser.addArgument("-c", "--complementary", '*');
		m_ArgParser.addArgument("-i", "--test-io");
		m_ArgParser.addArgument("-x", "--command", '+');
		m_ArgParser.useExceptions(true);
	}

	AppConfig const& ArgumentParser::GetConfig() const
	{
		return m_Config;
	}

	std::string ArgumentParser::GetUsage() const
	{
		return "Usage: " + m_AppName.filename().string() + R"( {-h|-l|-n NAME [options]}
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

Examples:
    1. Parse the json returned from GetCapability and validate it against C3 rules:
        ChannelLinter.exe -n UncShareFile

     2. Create instance of a channel:
         ChannelLinter.exe -n UncShareFile --args inputId outputId C:\Temp\C3Store false

     3. Test channel permeability - create a complementary pair of channels and send messages through.
         ChannelLinter.exe -n UncShareFile --args inputId outputId C:\Temp\C3Store false -i

     4. Execute channel command:
         ChannelLinter.exe -n UncShareFile --args inputId outputId C:\Temp\C3Store false -x 0
)";
	}

	void ArgumentParser::FillConfig()
	{
		m_Config.m_ShowHelp = m_ArgParser.exists("help");
		m_Config.m_ListChannels = m_ArgParser.exists("list");

		if (m_ArgParser.exists("name"))
			m_Config.m_ChannelName = m_ArgParser.retrieve<std::string>("name");

		if (m_ArgParser.exists("args"))
			m_Config.m_ChannelArguments = m_ArgParser.retrieve<std::vector<std::string>>("args");

		if (m_ArgParser.exists("complementary"))
			m_Config.m_ComplementaryChannelArguments = m_ArgParser.retrieve<std::vector<std::string>>("complementary");

		m_Config.m_TestChannelIO = m_ArgParser.exists("test-io");

		if (m_ArgParser.exists("command"))
			m_Config.m_Command = m_ArgParser.retrieve<StringVector>("command");
	}

	void ArgumentParser::ValidateConfig() const
	{
		if(!(m_Config.m_ShowHelp || m_Config.m_ListChannels || m_Config.m_ChannelName))
			throw std::invalid_argument("Argument error: either -h (--help), -l (--list) or -n (--name) must be specified");

		if (m_Config.m_TestChannelIO && !m_Config.m_ChannelArguments)
			throw std::invalid_argument("Argument error: specified -i (--test-io) without -a (--args)");

		if (m_Config.m_Command && !m_Config.m_ChannelArguments)
			throw std::invalid_argument("Argument error: specified -x (--command) without -a (--args)");
	}

}
