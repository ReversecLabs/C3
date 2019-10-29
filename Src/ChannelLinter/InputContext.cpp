#include "stdafx.h"
#include "InputContext.h"

namespace MWR::C3::Linter
{
	namespace
	{
		InputContext::Config CreateConfig(argparse::ArgumentParser const& parser)
		{
			InputContext::Config config;
			config.m_ChannelName = parser.retrieve<std::string>("name");
			config.m_ChannelArguments = parser.retrieve<std::vector<std::string>>("args");
			return config;
		}
	}

	InputContext::InputContext(int argc, char** argv) : m_ArgParser()
	{
		AddOptions();
		m_ArgParser.parse(argc, argv);
		m_Config = CreateConfig(m_ArgParser);
	}

	void InputContext::AddOptions()
	{
		m_ArgParser.addArgument("-n", "--name", 1, false);
		m_ArgParser.addArgument("-a", "--args", '*', false);

	}

	std::string InputContext::GetUsage()
	{
		return m_ArgParser.usage();
	}
}
