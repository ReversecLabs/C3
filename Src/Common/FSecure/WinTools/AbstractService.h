#pragma once

#include "Common/FSecure/CppTools/XError.h"

namespace FSecure::CppCommons::WinTools
{
	struct Services;

	/// A structure that should be inherited from and instantiated in order to implement a Microsoft Windows Service.
	struct AbstractService
	{
		/// Declared friendship with WinTools::Services struct, which acts as a manager for Services.
		friend struct WinTools::Services;

		/// Callback function, that is called on initialization of the Service.
		/// @param argc number of Service command-line arguments that are passed in argv array.
		/// @param argv array of Service command-line arguments.
		/// @return this callback should return S_OK to continue initialization of the Service. Any other value will be passed to STOP event as error to stop the Service gracefully.
		/// @note DWORD has to be used instead of HRESULT, because this is the only form accepted by the SERVICE_STOPPED event.
		virtual CppTools::XError<CppTools::SystemErrorCode> OnServiceInit(DWORD argc, LPTSTR* argv);

		/// Callback function, that is called after initialization. This callback should perform the main task of the Service. When it returns, the Service is stopped.
		/// @note DWORD has to be used instead of HRESULT, because this is the only form accepted by the SERVICE_STOPPED event.
		virtual CppTools::XError<CppTools::SystemErrorCode> OnServiceRun() = 0;

		/// Callback function, that is called on stop signal. If the Service requires more time to clean up, it should send STOP_PENDING status messages, along with a wait hint.
		/// @note If a service calls SetServiceStatus with status set to SERVICE_STOPPED and exitCode set to a nonzero value, the following entry is written into the System event log:
		///  Event ID = 7023, Source = Service Control Manager, Type = Error, Description = <ServiceName> terminated with the following error : <ExitCode>.
		/// @return Filled SystemErrorCode object.
		virtual CppTools::XError<CppTools::SystemErrorCode> OnServiceStop();

		/// Callback that notifies a Service that it should report its current status information to the service control manager.
		virtual void OnServiceInterrogate();

		/// Callback function, that is called on pause signal.
		virtual void OnServicePause();

		/// Callback function, that is called on continue signal.
		virtual void OnServiceContinue();

		/// Callback function, that is called on shutdown signal.
		virtual void OnServiceShutdown();

		/// Callback function, that is called on signals of value greater than 128.
		/// @param opcode user defined code.
		virtual void OnServiceUserControl(DWORD opcode);

	protected:
		/// Sets Service state. @see SetServiceStatus MSDN documentation.
		/// @param state new state to set.
		/// @param waitHint the estimated time required for a pending start, stop, pause, or continue operation, in milliseconds.
		/// @param serviveExitCode a service-specific error code that the service returns when an error occurs while the service is starting or stopping.
		void SetServiceStatus(DWORD state, DWORD waitHint = 0, DWORD serviveExitCode = NO_ERROR);
	};
}
