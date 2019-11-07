#pragma once

namespace MWR::C3::Linter
{
	using StringVector = std::vector<std::string>;

	struct AppConfig
	{
		bool ShouldCreateChannel() const
		{
			return m_ChannelArguments || m_Command || m_TestChannelIO;
		}

		std::string m_ChannelName;
		std::optional<StringVector> m_ChannelArguments;
		std::optional<StringVector> m_ComplementaryChannelArguments;
		bool m_TestChannelIO;
		std::optional<StringVector> m_Command;
	};
}