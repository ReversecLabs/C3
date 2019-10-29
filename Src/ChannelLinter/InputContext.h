#pragma once
#include "argparse.hpp"
#include <optional>

namespace MWR::C3::Linter
{
	using StringVector = std::vector<std::string>;

	class InputContext {
	public:
		InputContext(int argc, char** argv);

		std::string GetUsage();

		struct Config {
			std::string m_ChannelName;
			StringVector m_ChannelArguments;
			std::optional<StringVector> m_ComplementaryChannelArguments;
		};

		Config const& GetConfig() const { return m_Config; }

	private:
		void AddOptions();
		argparse::ArgumentParser m_ArgParser;
		Config m_Config;
	};
}

