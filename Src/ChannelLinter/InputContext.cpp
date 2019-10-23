#include "stdafx.h"
#include "InputContext.h"

namespace MWR::C3::Linter
{
	InputContext::InputContext(int argc, char* argv[])
	{
		if (argc < 2)
			throw InputError("No channel name specified");

		m_ChannelName = argv[1];
	}

	std::string_view InputContext::GetChannelName() const
	{
		return m_ChannelName;
	}

	std::string_view InputContext::GetUsage()
	{
		return "TODO";
	}
}
