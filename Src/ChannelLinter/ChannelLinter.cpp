#include "stdafx.h"
#include "ChannelLinter.h"

#include "Core/Profiler.h"

namespace MWR::C3::Linter
{
	namespace
	{
		/// @throws std::runtime_error if channel with given name was not registered
		auto const& GetChannelInfo(std::string_view channelName)
		{
			return InterfaceFactory::Instance().Find<AbstractChannel>(channelName)->second;
		}

		auto GetChannelCapability(InterfaceFactory::InterfaceData<AbstractChannel> const& channelInfo)
		{
			try
			{
				auto ret = json::parse(channelInfo.m_Capability);
				C3::Core::Profiler::Gateway::EnsureCreateExists(ret);
				C3::Core::Profiler::Gateway::AddBuildInCommands(ret, true);
				return ret;
			}
			catch (json::parse_error & e)
			{
				throw std::runtime_error("Failed to parse channel's capability json. "s + e.what());
			}
		}

		uint16_t GetCommandId(std::string const& commandId)
		{
			// allow negative inputs
			auto commandIdL = std::stoi(commandId);
			return static_cast<uint16_t>(commandIdL);
		}
	}

	ChannelLinter::ChannelLinter(AppConfig config) :
		m_Config(std::move(config)),
		m_ChannelData(GetChannelInfo(m_Config.m_ChannelName)),
		m_ChannelCapability(GetChannelCapability(m_ChannelData))
	{
	}

	void ChannelLinter::Process()
	{
		std::shared_ptr<MockDeviceBridge> channel;
		if (m_Config.ShouldCreateChannel())
			channel = MakeChannel(*m_Config.m_ChannelArguments);

		if (m_Config.m_TestChannelIO)
		{
			assert(channel); // First channel should already be created
			auto complementaryArgs = GetComplementaryChannelArgs();
			auto complementaryChannel = MakeChannel(complementaryArgs);
			TestChannelIO(channel, complementaryChannel);
		}

		if (m_Config.m_Command)
		{
			assert(channel); // First channel should already be created
			TestCommand(channel);
		}
	}

	std::shared_ptr<MWR::C3::Linter::MockDeviceBridge> ChannelLinter::MakeChannel(StringVector const& channnelArguments) const
	{
		std::cout << "Create channel " << std::endl;
		Form form(m_ChannelCapability.at("/create/arguments"_json_pointer));
		auto createParams = form.FillForm(channnelArguments);
		auto blob = MWR::C3::Core::Profiler::TranslateArguments(createParams);
		return MakeChannel(blob);
	}

	std::shared_ptr<MockDeviceBridge> ChannelLinter::MakeChannel(ByteView blob) const
	{
		auto channelBridge = std::make_shared<MockDeviceBridge>(m_ChannelData.m_Builder(blob));
		channelBridge->OnAttach();
		return channelBridge;
	}

	void ChannelLinter::TestChannelIO(std::shared_ptr<MockDeviceBridge> const& channel, std::shared_ptr<MockDeviceBridge> const& complementary)
	{
		assert(channel);
		assert(complementary);

		auto data = ByteVector(ByteView(MWR::Utils::GenerateRandomString(64)));
		channel->GetDevice()->OnSendToChannelInternal(data);
		auto received = std::static_pointer_cast<C3::AbstractChannel>(complementary->GetDevice())->OnReceiveFromChannelInternal();
		if (data != received.at(0))
			throw std::exception("Data sent and received mismatch");
	}

	void ChannelLinter::TestCommand(std::shared_ptr<MockDeviceBridge> const& channel)
	{
		assert(m_Config.m_Command);
		auto binaryCommand = TranslateCommand(*m_Config.m_Command);
		channel->RunCommand(binaryCommand);
	}

	MWR::ByteVector ChannelLinter::TranslateCommand(StringVector const& commandParams)
	{
		uint16_t commandId = GetCommandId(commandParams.at(0));

		auto& commands = m_ChannelCapability.at("commands");
		auto commandIt = std::find_if(begin(commands), end(commands), [commandId](auto const& c) { return c.contains("id") && c["id"].get<uint16_t>() == commandId; });
		if (commandIt == end(commands))
			throw std::runtime_error("Failed to find a command with id: " + std::to_string(commandId));

		json command = *commandIt;
		Form commandForm(command.at("arguments"));
		command["arguments"] = commandForm.FillForm({begin(commandParams) + 1, end(commandParams)}); // + 1 to omit command id
		return C3::Core::Profiler::TranslateCommand(command);
	}

	StringVector ChannelLinter::GetComplementaryChannelArgs() const
	{
		Form form(m_ChannelCapability.at("/create/arguments"_json_pointer));
		return m_Config.m_ComplementaryChannelArguments ? *m_Config.m_ComplementaryChannelArguments : form.GetComplementaryArgs(*m_Config.m_ChannelArguments);
	}
}
