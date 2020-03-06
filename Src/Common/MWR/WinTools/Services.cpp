#include "StdAfx.h"
#include "Services.h"

// Statics.
SERVICE_STATUS_HANDLE MWR::CppCommons::WinTools::Services::s_ServiceStatusHandle;
SERVICE_STATUS MWR::CppCommons::WinTools::Services::s_ServiceStatus;
MWR::CppCommons::WinTools::AbstractService* MWR::CppCommons::WinTools::Services::s_Service;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::pair<MWR::CppCommons::WinTools::Services::ReturnEnum, HRESULT> MWR::CppCommons::WinTools::Services::IsServiceInstalled(std::wstring const& serviceName)
{
	// Open the Service Control Manager with full access.
	SC_HANDLE manager = ::OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
	if (!manager)
		return std::make_pair(ReturnEnum::OpeningServiceManager, XERROR_GETLASTERROR);

	// Try to open the service
	if (SC_HANDLE service = ::OpenService(manager, serviceName.c_str(), SERVICE_QUERY_CONFIG))
		return std::make_pair(ReturnEnum::ClosingHandles, (::CloseServiceHandle(service) && ::CloseServiceHandle(manager) ? S_OK : XERROR_GETLASTERROR));

	// Failed to open the Service. Make sure to return the right error.
	auto retVal = XERROR_GETLASTERROR;
	::CloseServiceHandle(manager);
	return std::make_pair(ReturnEnum::OpenService, retVal);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::pair<MWR::CppCommons::WinTools::Services::ReturnEnum, HRESULT> MWR::CppCommons::WinTools::Services::InstallServiceSimple(std::filesystem::path const& binaryPath, std::wstring const& serviceName)
{
	// Open the Service Control Manager with full access
	SC_HANDLE manager = ::OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
	if (!manager)
		return std::make_pair(ReturnEnum::OpeningServiceManager, XERROR_GETLASTERROR);

	// Create the service
	if (SC_HANDLE service = ::CreateServiceW(manager, serviceName.c_str(), serviceName.c_str(), SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
		binaryPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr))
		return std::make_pair(ReturnEnum::ClosingHandles, (::CloseServiceHandle(service) && ::CloseServiceHandle(manager) ? S_OK : XERROR_GETLASTERROR));

	// Failed to open the Service. Make sure to return right error.
	auto retVal = XERROR_GETLASTERROR;
	::CloseServiceHandle(manager);
	return std::make_pair(ReturnEnum::CreateService, retVal);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::pair<MWR::CppCommons::WinTools::Services::ReturnEnum, HRESULT> MWR::CppCommons::WinTools::Services::UninstallService(std::wstring const& serviceName)
{
	// Open the Service Control Manager with full access
	SC_HANDLE manager = ::OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
	if (!manager)
		return std::make_pair(ReturnEnum::OpeningServiceManager, XERROR_GETLASTERROR);

	// Try to open the service
	if (SC_HANDLE service = ::OpenService(manager, serviceName.c_str(), STANDARD_RIGHTS_REQUIRED))
	{
		if (::DeleteService(service))
			return std::make_pair(ReturnEnum::ClosingHandles, (::CloseServiceHandle(service) && ::CloseServiceHandle(manager) ? S_OK : XERROR_GETLASTERROR));

		// Failed to open the Service. Make sure to return right error.
		auto retVal = XERROR_GETLASTERROR;
		::CloseServiceHandle(service);
		::CloseServiceHandle(manager);
		return std::make_pair(ReturnEnum::DeleteService, retVal);
	}

	// Failed to open the Service. Make sure to return right error.
	auto retVal = XERROR_GETLASTERROR;
	::CloseServiceHandle(manager);
	return std::make_pair(ReturnEnum::OpenService, retVal);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::CppCommons::CppTools::XError<HRESULT> MWR::CppCommons::WinTools::Services::TryStartAsService(AbstractService& theOnlyService, std::wstring const& serviceName)
{
	// Sanity check.
	if (s_Service)
		return HRESULT_FROM_WIN32(ERROR_FILE_EXISTS);

	// Copy Service object and start the Service.
	s_Service = &theOnlyService;
	SERVICE_TABLE_ENTRY table[] = { { const_cast<LPTSTR>(serviceName.c_str()), ServiceMain }, { nullptr, nullptr } };
	return ::StartServiceCtrlDispatcher(table) ? S_OK : XERROR_GETLASTERROR;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::pair<MWR::CppCommons::WinTools::Services::Status, HRESULT> MWR::CppCommons::WinTools::Services::CheckStatus(std::wstring const& serviceName)
{
	// Open the Service Control Manager with full access
	SC_HANDLE manager = ::OpenSCManager(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
	if (!manager)
		return std::make_pair(Status::Unknown, XERROR_GETLASTERROR);

	// Try to open the service
	if (SC_HANDLE service = ::OpenService(manager, serviceName.c_str(), SERVICE_QUERY_STATUS))
	{
		if (!service)
		{
			CloseServiceHandle(manager);
			return std::make_pair(Status::Unknown, XERROR_GETLASTERROR);
		}

		SERVICE_STATUS_PROCESS ssStatus;
		DWORD dwBytesNeeded;
		auto result = QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssStatus), sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded);

		auto retVal = XERROR_GETLASTERROR;
		::CloseServiceHandle(service);
		::CloseServiceHandle(manager);
		return std::make_pair(result ? static_cast<Status>(ssStatus.dwCurrentState) : static_cast<Status>(0), retVal);
	}


	// Failed to open the Service. Make sure to return right error.
	auto retVal = XERROR_GETLASTERROR;
	::CloseServiceHandle(manager);
	return std::make_pair(Status::Unknown, retVal);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void MWR::CppCommons::WinTools::Services::ServiceMain(DWORD argc, LPTSTR* argv)
{
	// Register the control request handler
	if (s_ServiceStatusHandle = RegisterServiceCtrlHandler(OBF(TEXT("AdsaServicePoX")), ControlHandler), !s_ServiceStatusHandle)
	{
		//SvcReportEvent(TEXT("RegisterServiceCtrlHandler")); Windows event viewer
		return;
	}

	// Immediately call the SetServiceStatus function, to notify the Service Control Manager that its status is SERVICE_START_PENDING.
	s_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	s_ServiceStatus.dwServiceSpecificExitCode = 0;
	if (SetServiceStatus(SERVICE_START_PENDING, 1000).IsFailure())
	{
		//SvcReportEvent(TEXT("RegisterServiceCtrlHandler")); Windows event viewer
		return;
	}

	// Perform the actual initialization
	auto xe = s_Service->OnServiceInit(argc, argv);
	if (xe.IsSuccess())
	{
		// Set final state.
		auto xe2 = SetServiceStatus(SERVICE_RUNNING);
		if (xe2.IsFailure())
		{
			//SvcReportEvent(TEXT("RegisterServiceCtrlHandler")); Windows event viewer
			SetServiceStatus(SERVICE_STOPPED, 0, **xe);
			return;
		}

		// Do the real work. When the OnServiceRun function returns, the service stops.
		xe = s_Service->OnServiceRun();
	}

	// Stop the Service.
	SetServiceStatus(SERVICE_STOPPED, 0, **xe);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void MWR::CppCommons::WinTools::Services::ControlHandler(DWORD opcode)
{
	// Handle particular code.
	switch (opcode)
	{
	case SERVICE_CONTROL_STOP: SetServiceStatus(SERVICE_STOP_PENDING, 100, NO_ERROR); SetServiceStatus(SERVICE_STOPPED, 0, **s_Service->OnServiceStop()); break;
	case SERVICE_CONTROL_PAUSE: s_Service->OnServicePause(); break;
	case SERVICE_CONTROL_CONTINUE: s_Service->OnServiceContinue(); break;
	case SERVICE_CONTROL_INTERROGATE: s_Service->OnServiceInterrogate(); break;
	case SERVICE_CONTROL_SHUTDOWN: s_Service->OnServiceShutdown(); break;
	default: if (opcode >= 128) s_Service->OnServiceUserControl(opcode);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::CppCommons::CppTools::XError<MWR::CppCommons::CppTools::SystemErrorCode> MWR::CppCommons::WinTools::Services::SetServiceStatus(DWORD state, DWORD waitHint, DWORD serviveExitCode)
{
	// WinAPI needs a valid, self incremented counter to be passed with each call, so let's make it static.
	static DWORD checkPoint = 1;

	// Fill in the SERVICE_STATUS structure.
	s_ServiceStatus.dwCurrentState = state;
	s_ServiceStatus.dwWaitHint = waitHint;

	// The error code the service uses to report an error that occurs when it is starting or stopping.
	if (serviveExitCode)
	{
		s_ServiceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
		s_ServiceStatus.dwServiceSpecificExitCode = serviveExitCode;
	}

	// The service should not accept any controls, when it's in start pending state. After initialization, it is wise to allow the Service to be stopped.
	s_ServiceStatus.dwControlsAccepted = (state == SERVICE_START_PENDING ? 0 : SERVICE_ACCEPT_STOP);

	// Check point should be reset on stop and run events.
	s_ServiceStatus.dwCheckPoint = (state == SERVICE_RUNNING || state == SERVICE_STOPPED ? 0 : checkPoint++);

	// Report the status of the service to the SCM.
	return ::SetServiceStatus(s_ServiceStatusHandle, &s_ServiceStatus) ? NO_ERROR : GetLastError();
}
