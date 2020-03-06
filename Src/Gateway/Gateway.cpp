#include "StdAfx.h"

/// Entry point of the application.
/// @param argc number of program arguments.
/// @param argv vector of program arguments.
int main(int argc, char * argv[])
{
	std::cout << OBF("Custom Command and Control - GatewayConsoleExe. BUILD: ") << OBF(C3_BUILD_VERSION) << std::endl << std::endl;

	try
	{
		// Helper lambda used to render Log entries on the screen.
		auto Log = [](FSecure::C3::LogMessage const& message, std::string_view sender)
		{
			// Synchronize and print.
			static std::mutex mutex;
			std::lock_guard lock(mutex);
			std::cout << FSecure::C3::Utils::ConvertLogMessageToConsoleText(OBF("Gateway"), message, sender) << std::endl;
		};

		// Simply create a Gateway providing Log lambda, configuration and keys files, then join its threads.
		FSecure::C3::Utils::CreateGatewayFromConfigurationFiles(Log, FSecure::C3::InterfaceFactory::Instance(), OBF("GatewayKeys.json"), OBF("GatewayConfiguration.json"))->Join();
	}
	catch (std::exception const& exception)
	{
		std::cerr << OBF("!> ") << exception.what() << OBF("\nProgram terminates.\n") << std::endl;
	}
	catch (...)
	{
		std::cerr << OBF("!> ") << OBF("\nCaught an unhandled exception.\n") << std::endl;
	}

	return 0;
}
