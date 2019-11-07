#include "StdAfx.h"


/// Entry point of the application.
/// @param argc number of program arguments.
/// @param argv vector of program arguments.
int main(DWORD argc, char* argv[])
try
{
	using namespace MWR;

	std::cout << "Custom Command and Control - Channel linter. BUILD: " << C3_BUILD_VERSION << std::endl;
	C3::Linter::AppConfig context(argc, argv);
	auto const& config = context.GetConfig();
	C3::Linter::ChannelLinter(config).Process();
}
catch (std::exception & e)
{
	std::cerr << e.what() << std::endl;
	return 1;
}
