#pragma once

namespace MWR::C3::Linter
{
	class ChannelLinter
	{
	public:
		/// Create Channel linter
		/// @param config - application config
		/// @throws std::runtime_error, std::invalid_argument
		ChannelLinter(AppConfig config);

		/// Run application with given config
		void Process();

	private:
		/// Translate arguments to binary command
		/// @param args - command input (commandID [command args])
		/// @returns Translated command in binary format
		/// @throws std::runtime_error, std::out_of_range, std::invalid_argument
		ByteVector TranslateCommand(StringVector const& args);

		/// Test Command on channel from configuration
		/// @param channel to run command on
		/// @throws std::runtime_error, std::out_of_range, std::invalid_argument
		void TestCommand(std::shared_ptr<MockDeviceBridge> const& channel);

		/// Test channel pair permeability
		/// @param first of complementary channels
		/// @param second of complementary channels
		/// @throws if Channel::OnSend or Channel::OnReceive throws
		void TestChannelIO(std::shared_ptr<MockDeviceBridge> const& channel, std::shared_ptr<MockDeviceBridge> const& ch2);

		/// Create channel from string channel arguments
		/// @param channel arguments
		/// @returns Device bridge attached to channel
		std::shared_ptr<MockDeviceBridge> MakeChannel(StringVector const& channnelArguments) const;

		/// Create channel from binary channel argument
		/// @param channel arguments
		/// @returns Device bridge attached to channel
		std::shared_ptr<MockDeviceBridge> MakeChannel(ByteView blob) const;

		/// Get arguments to create a complementary channel
		/// @returns arguments to create a complementary channel
		StringVector GetComplementaryChannelArgs() const;

		/// Application config
		AppConfig m_Config;

		/// Selected channel Interface metadata
		InterfaceFactory::InterfaceData<AbstractChannel> const& m_ChannelData;

		/// Selected Channel capability supplemented with build-in capability
		json m_ChannelCapability;

		/// Selected Channel create form
		const Form m_CreateForm;

		struct ChannelCommand
		{
			uint16_t m_Id = 0;
			std::string m_Name = "";
			Form m_ArgumentsForm;

			ChannelCommand(json const& commandDefinition);
		};

		/// Selected Channel command forms
		std::map<uint16_t, ChannelCommand> m_ChannelCommands;
	};
}

