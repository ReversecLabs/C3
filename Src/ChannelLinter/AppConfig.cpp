#include "stdafx.h"
#include "AppConfig.h"

namespace MWR::C3::Linter
{
	namespace
	{
		AppConfig::Config CreateConfig(argparse::ArgumentParser const& parser)
		{
			AppConfig::Config config;
			config.m_ChannelName = parser.retrieve<std::string>("name");
			config.m_ChannelArguments = parser.retrieve<std::vector<std::string>>("args");

			if (parser.exists("complementary"))
				config.m_ComplementaryChannelArguments = parser.retrieve<std::vector<std::string>>("complementary");

			config.m_TestChannelIO = parser.exists("test-io");

			if (parser.exists("command"))
				config.m_Command = parser.retrieve<StringVector>("command");

			return config;
		}
	}

	AppConfig::AppConfig(int argc, char** argv) : m_ArgParser()
	{
		ConfigureParser();
		m_ArgParser.parse(argc, argv);
		m_Config = CreateConfig(m_ArgParser);
	}

	void AppConfig::ConfigureParser()
	{
		m_ArgParser.addArgument("-n", "--name", 1, false);
		m_ArgParser.addArgument("-a", "--args", '*', false);
		m_ArgParser.addArgument("-c", "--complementary", '*');
		m_ArgParser.addArgument("-i", "--test-io");
		m_ArgParser.addArgument("-x", "--command", '+');
	}

	std::string AppConfig::GetUsage()
	{
		return m_ArgParser.usage();
	}
}
