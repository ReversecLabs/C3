#pragma once

namespace MWR::C3::Linter
{
	class ChannelLinter
	{
	public:
		ChannelLinter(AppConfig::Config const& config) : m_Config(config) {}
		void Process();

	private:
		AppConfig::Config const& m_Config;
	};
}

