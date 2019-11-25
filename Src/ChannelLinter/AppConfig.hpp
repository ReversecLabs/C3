#pragma once

namespace MWR::C3::Linter
{
	using StringVector = std::vector<std::string>;

	/// Helper struct that holds Channel linter configuration
	struct AppConfig
	{
		/// @returns true if an instance of a channel should be created
		bool ShouldCreateChannel() const
		{
			return m_ChannelArguments || m_Command || m_TestChannelIO;
		}

		/// Channel name e.g. Slack
		std::string m_ChannelName;

		/// String representation of arguments passed to create a channel
		std::optional<StringVector> m_ChannelArguments;

		/// String representation of arguments passed to create a complementary channel
		std::optional<StringVector> m_ComplementaryChannelArguments;

		/// Whether application channel should test sending and receiving through the channel
		bool m_TestChannelIO;

		/// Command id and its arguments
		std::optional<StringVector> m_Command;
	};
}
