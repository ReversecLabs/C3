#pragma once

namespace MWR::C3::Linter
{
	class MockDeviceBridge : public MWR::C3::AbstractDeviceBridge, public std::enable_shared_from_this<MockDeviceBridge>
	{
	public:
		MockDeviceBridge(std::shared_ptr<Device> device);

		void OnAttach() override;

		void Detach() override;

		void Close() override;

		void OnReceive() override;

		void PassNetworkPacket(ByteView packet) override;

		void OnPassNetworkPacket(ByteView packet) override;

		void PostCommandToConnector(ByteView command) override;

		void OnCommandFromConnector(ByteView command) override;

		ByteVector RunCommand(ByteView command) override;

		ByteVector WhoAreYou() override;

		void Log(LogMessage const& message) override;

		void SetUpdateFrequency(std::chrono::milliseconds minUpdateFrequencyInMs, std::chrono::milliseconds maxUpdateFrequencyInMs) override;

		void SetUpdateFrequency(std::chrono::milliseconds frequencyInMs) override;

		void SetErrorStatus(std::string_view errorMessage) override;

		std::string GetErrorStatus() override;

		std::shared_ptr<MWR::C3::Device> GetDevice() const;

	private:
		std::shared_ptr<Device> m_Device;
	};
}

