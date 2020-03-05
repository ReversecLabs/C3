#pragma once

#include "AbstractService.h"

namespace FSecure::CppCommons::WinTools
{
	/// Microsoft Windows Services functionality wrapper structure. This is a static structure.
	struct Services
	{
		/// Enumeration type that is used to describe precisely on which phase of particular function call error has occurred.
		enum class ReturnEnum
		{
			OpeningServiceManager,												///< Error happened on call to ::OpenSCManager.
			OpenService,														///< Error happened on call to ::OpenService. Might happen when calling IsServiceInstalled or UninstallService.
			CreateService,														///< Error happened on call to ::CreateService. Might happen when calling InstallServiceSimple.
			DeleteService,														///< Error happened on call to ::DeleteService. Might happen when calling UninstallService.
			ClosingHandles,														///< Error happened on call to ::CloseServiceHandle.
		};

		/// Enumeration type that is used to describe service status.
		enum class Status
		{
			Unknown = 0,
			Stopped,
			StartPending,
			StopPending,
			Running,
			ContinuePending,
			PausePending,
			Paused
		};

		/// Checks if a Service is installed in the system.
		/// @param serviceName name of the Service to check.
		/// @reutrn std::pair of ReturnEnum and HRESULT. If ReturnEnum equals ClosingHandles, it means that the check was successful (the Service exists), but HRESULT part might contain an error that
		///  occurred when cleaning-up. If the Service is not installed then the HRESULT part equals WinTools::SystemErrorToHresult(ERROR_SERVICE_DOES_NOT_EXIST).
		/// @note std::pair is return instead of XError, because there's no clear distinction between a success and a failure here (e.g. error on phase ClosingHandles).
		static std::pair<ReturnEnum, HRESULT> IsServiceInstalled(std::wstring const& serviceName);

		/// Performs simplified installation of a Service that runs in its own process and has the same name and display name.
		/// @param binaryPath path to a binary containing the Service.
		/// @param serviceName name of the Service.
		/// @reutrn std::pair of ReturnEnum and HRESULT. If ReturnEnum equals ClosingHandles, it means that the installation was successful, but HRESULT part might contain an error that occurred when
		///  cleaning-up. If the Service is already installed then the HRESULT part equals WinTools::SystemErrorToHresult(ERROR_SERVICE_EXISTS).
		/// @note std::pair is return instead of XError, because there's no clear distinction between a success and a failure here (e.g. error on phase ClosingHandles).
		static std::pair<ReturnEnum, HRESULT> InstallServiceSimple(std::filesystem::path const& binaryPath, std::wstring const& serviceName);

		/// Uninstalls Service from system.
		/// @param serviceName name of the Service.
		/// @reutrn std::pair of ReturnEnum and HRESULT. If ReturnEnum equals ClosingHandles, it means that the uninstallation was successful, but HRESULT part might contain an error that occurred when
		///  cleaning-up. If the Service is not installed then the HRESULT part equals WinTools::SystemErrorToHresult(ERROR_SERVICE_DOES_NOT_EXIST).
		/// @note std::pair is return instead of XError, because there's no clear distinction between a success and a failure here (e.g. error on phase ClosingHandles).
		static std::pair<ReturnEnum, HRESULT> UninstallService(std::wstring const& serviceName);

		/// If run as a Service, gives control to Service Control Manager (never returns). Otherwise (if run as a "normal" user-land application) returns with HRESULT code.
		/// @param theOnlyService service object singleton.
		/// @param serviceName name of the Service.
		/// @return HRESULT code if not run as a Microsoft Windows Service.
		static CppTools::XError<HRESULT> TryStartAsService(AbstractService& theOnlyService, std::wstring const& serviceName);

		/// Retrieves the service status of the specified service.
		/// @param serviceName name of the Service.
		/// @reutrn std::pair of Status and HRESULT. If Status is equal to Unknown, it means that the HRESULT part might contain an error that occurred.
		/// @note std::pair is return instead of XError
		static std::pair<Status, HRESULT> CheckStatus(std::wstring const& serviceName);

	protected:
		/// Friendships.
		friend void AbstractService::SetServiceStatus(DWORD state, DWORD waitHint, DWORD serviveExitCode);				///< AbstractService::SetStatus internally redirects here.

		/// Sets status of run Service.
		/// @param state new state to set.
		/// @param waitHint the estimated time required for a pending start, stop, pause, or continue operation, in milliseconds.
		/// @param serviveExitCode a service-specific error code that the service returns when an error occurs while the service is starting or stopping.
		static CppTools::XError<CppTools::SystemErrorCode> SetServiceStatus(DWORD state, DWORD waitHint = 0, DWORD serviveExitCode = NO_ERROR);

	private:
		/// Entry point of the Service. Used as a callback by API.
		/// @param argc number of Service command-line arguments that are passed in argv array.
		/// @param argv array of Service command-line arguments.
		static void WINAPI ServiceMain(DWORD argc, LPTSTR* lpszArgv);

		/// Members
		static AbstractService *s_Service;																				///< The only Service object.
		static SERVICE_STATUS_HANDLE s_ServiceStatusHandle;																///< Handle to Service.
		static SERVICE_STATUS s_ServiceStatus;																			///< Service Status structure.

		/// Handles commands from the Service Control Manager. Used as a callback by API.
		/// @param opcode control code.
		static void WINAPI ControlHandler(DWORD opcode);
	};
}
