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
	MWR::WinTools::StructuredExceptionHandling::SehWrapper(
	[]()
	{
		try
		{
			auto relay = MWR::C3::Utils::CreateNodeRelayFromImagePatch(
				[](MWR::C3::LogMessage const&, std::string_view*) {},
				MWR::C3::InterfaceFactory::Instance(),
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
