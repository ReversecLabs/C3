#pragma once

namespace FSecure
{
	/// Exception used to indicate and describe WinSockets library errors.
	struct SocketsException : std::runtime_error
	{
		/// Public ctor.
		/// @param message description of error.
		/// @param errorCode Sockets library error code (e.g. returned by WSAGetLastError()).
		SocketsException(std::string const& message, int errorCode)
			: std::runtime_error(message + OBF(" Error code: ") + std::to_string(errorCode)), m_ErrorCode(errorCode)
		{ }

		/// Error code value getter.
		/// @return Sockets library error code value.
		int GetErrorCode() const
		{
			return m_ErrorCode;
		}

		/// Error code value setter.
		/// @param new error code value to set.
		void SetTimeOutValue(int const& errorCode)
		{
			m_ErrorCode = errorCode;
		}

	private:
		int m_ErrorCode;
	};
}
