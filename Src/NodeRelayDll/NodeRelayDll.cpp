#include "StdAfx.h"

/// Entry point of the the library.
BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID)
{
	// Indicate successful load of the library.
	return TRUE;
}

/// Starts a NodeRelay.
/// @param leaveImmediately if false then waits for Relay to be shut down internally by a C3 API Command.
extern "C" __declspec(dllexport) void StartNodeRelay()
{
	FSecure::WinTools::StructuredExceptionHandling::SehWrapper(
	[]()
	{
		try
		{
			auto relay = FSecure::C3::Utils::CreateNodeRelayFromImagePatch(
				[](FSecure::C3::LogMessage const&, std::string_view*) {},
				FSecure::C3::InterfaceFactory::Instance(),
				EmbeddedData::Instance()[0],
				EmbeddedData::Instance()[1],
				EmbeddedData::Instance()[2],
				EmbeddedData::Instance().FindMatching(3));

			relay->Join();
		}
		catch (...)
		{
		}
	}, []() {});
}
