#pragma once

namespace FSecure::C3::Linter
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

		/// Whether -h was set
		bool m_ShowHelp = false;

		/// Whether -l was set
		bool m_ListChannels = false;

		/// Channel name e.g. Slack
		std::optional<std::string> m_ChannelName;

		/// String representation of arguments passed to create a channel
		std::optional<StringVector> m_ChannelArguments;

		/// String representation of arguments passed to create a complementary channel
		std::optional<StringVector> m_ComplementaryChannelArguments;

		/// Whether application channel should test sending and receiving through the channel
		bool m_TestChannelIO;

		/// Change test IO mode to perform Overlapped Read/Write on chunks.
		bool m_OverlappedIO;

		/// Command id and its arguments
		std::optional<StringVector> m_Command;
	};
}
