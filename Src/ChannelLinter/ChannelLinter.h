#pragma once

namespace MWR::C3::Linter
{
	class ChannelLinter
	{
	public:
		ChannelLinter(AppConfig config);

		void Process();

		void TestCommand(std::shared_ptr<MockDeviceBridge> const& channel);

		ByteVector TranslateCommand(StringVector const& args);

		void TestChannelIO(std::shared_ptr<MockDeviceBridge> const& channel, std::shared_ptr<MockDeviceBridge> const& ch2);

		std::shared_ptr<MockDeviceBridge> MakeChannel(StringVector const& channnelArguments) const;

		std::shared_ptr<MockDeviceBridge> MakeChannel(ByteView blob) const;

		StringVector GetComplementaryChannelArgs() const;

	private:
		AppConfig m_Config;
		InterfaceFactory::InterfaceData<AbstractChannel> const& m_ChannelData;
		json m_ChannelCapability;
	};
}

