#pragma once
#include "argparse.hpp"
#include <optional>

namespace MWR::C3::Linter
{
	using StringVector = std::vector<std::string>;

	class AppConfig
	{
	public:
		AppConfig(int argc, char** argv);

		std::string GetUsage();

		struct Config
		{
			std::string m_ChannelName;
			StringVector m_ChannelArguments;
			std::optional<StringVector> m_ComplementaryChannelArguments;
			bool m_TestChannelIO;
			std::optional<StringVector> m_Command;
		};

		Config const& GetConfig() const { return m_Config; }

	private:
		void AddOptions();
		argparse::ArgumentParser m_ArgParser;
		Config m_Config;
	};
}

