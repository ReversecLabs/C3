#include "StdAfx.h"
#include "InputContext.h"

namespace MWR::C3::Linter
{
	void OutputDebug(std::string_view output)
	{
#ifdef _DEBUG
		std::cout << output << std::endl;
#endif // _DEBUG
	}

	/// @throws std::runtime_error if channel with given name was not registered
	auto const& GetChannelInfo(std::string_view channelName)
	{
		return InterfaceFactory::Instance().Find<AbstractChannel>(channelName)->second;
	}
}


/// Entry point of the application.
/// @param argc number of program arguments.
/// @param argv vector of program arguments.
int main(DWORD argc, char* argv[])
try
{
	using namespace MWR;
	using json = nlohmann::json;

	std::cout << "Custom Command and Control - Channel linter. BUILD: " << C3_BUILD_VERSION << std::endl;
	C3::Linter::InputContext context(argc, argv);

	// select channel
	auto const& chInfo = C3::Linter::GetChannelInfo(context.GetChannelName());

	// read create and prompt for arguments
	auto capability = json::parse(chInfo.m_Capability);
	C3::Linter::OutputDebug(capability.dump(4));
	return 0;
}
catch (MWR::C3::Linter::InputError & e)
{
	std::cerr << e.what() << std::endl;
	std::cerr << MWR::C3::Linter::InputContext::GetUsage() << std::endl;
	return 1;
}
catch (std::exception & e)
{
	std::cerr << "Error occurred: " << e.what() << std::endl;
	return 1;
}
