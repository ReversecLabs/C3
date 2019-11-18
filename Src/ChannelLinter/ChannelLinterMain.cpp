#include "StdAfx.h"

/// Entry point of the application.
/// @param argc number of program arguments.
/// @param argv vector of program arguments.
int main(DWORD argc, char* argv[])
try
{
	std::cout << "Custom Command and Control - Channel linter. BUILD: " << C3_BUILD_VERSION << std::endl;

	using namespace MWR;
	C3::Linter::ArgumentParser argParser(argc, argv);
	auto const& config = argParser.GetConfig();
	C3::Linter::ChannelLinter(config).Process();
}
catch (std::exception& e)
{
	std::cerr << e.what() << std::endl;
	return 1;
}
