#pragma once

namespace FSecure::C3::Linter
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
		/// @param channel first of channels. Used to send data.
		/// @param complementary second of channels. Used to receive data.
		/// @param overlapped informs if operations should be performed overlapped, or first read must be preceded by write of all chunks .
		/// @throws if Channel::OnSend or Channel::OnReceive throws
		void TestChannelIO(MockDeviceBridge& channel, MockDeviceBridge& complementary, bool overlapped = false);

		/// Test maximal packet size that can be delivered by channel.
		/// @param channel first of channels. Used to send data.
		/// @param complementary second of channels. Used to receive data.
		/// @param overlapped informs if operations should be performed overlapped, or first read must be preceded by write of all chunks .
		/// @throws if Channel::OnSend or Channel::OnReceive throws
		void TestChannelMTU(MockDeviceBridge& channel, MockDeviceBridge& complementary, bool overlapped = false);

		/// Test maximal packet size if read/write operations are overlapped.
		/// @param channel first of channels. Used to send data.
		/// @param complementary second of channels. Used to receive data.
		/// @param overlapped informs if operations should be performed overlapped, or first read must be preceded by write of all chunks .
		/// @throws if Channel::OnSend or Channel::OnReceive throws
		bool TestOverlapped(MockDeviceBridge& channel, MockDeviceBridge& complementary, ByteView data);

		/// Test maximal packet size if all chunks must be written before first read.
		/// @param channel first of channels. Used to send data.
		/// @param complementary second of channels. Used to receive data.
		/// @param overlapped informs if operations should be performed overlapped, or first read must be preceded by write of all chunks .
		/// @throws if Channel::OnSend or Channel::OnReceive throws
		bool TestSequential(MockDeviceBridge& channel, MockDeviceBridge& complementary, ByteView data);

		/// Test if packets are received in the same order as were passed to send.
		/// @param channel first of channels. Used to send data.
		/// @param complementary second of channels. Used to receive data.
		/// @throws if Channel::OnSend or Channel::OnReceive throws
		void TestChannelOrder(MockDeviceBridge& channel, MockDeviceBridge& complementary);

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

