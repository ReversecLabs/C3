#pragma once
#include <Windows.h>
#include <Winspool.h>

namespace FSecure::C3::Interfaces::Channels
{
	namespace Detail
	{
		/// @brief RAII wrapper around ComPtr to call IUnknown::Release
		struct PrinterHandle
		{
			static PrinterHandle Open(std::string_view printerAddress);

			HANDLE Get() const{ return m_Handle.get(); }

		private:
			PrinterHandle(HANDLE ptr) : m_Handle{ ptr, &Deleter } {}

			static void Deleter(HANDLE ptr)
			{
				ClosePrinter(ptr);
			}

			std::unique_ptr<std::remove_pointer_t<HANDLE>, decltype(&Deleter)> m_Handle;
		};
	}

	///Implementation of the Print Channel.
	struct Print : public Channel<Print>
	{
		/// Public constructor.
		/// @param arguments factory arguments.
		Print(ByteView arguments);

		/// Destructor
		virtual ~Print() = default;

		/// OnSend callback implementation.
		/// @param packet data to send to Channel.
		/// @returns size_t number of bytes successfully written.
		size_t OnSendToChannel(ByteView packet);

		/// Reads a single C3 packet from Channel.
		/// @return packet retrieved from Channel.
		ByteVector OnReceiveFromChannel();

		std::tuple<std::wstring, DWORD> GetC3Job();

		DWORD WriteData(std::string dataToWrite);

		size_t CalculateDataSize(ByteView data);

		static std::string EncodeData(ByteView data, size_t dataSize);
		/// Get channel capability.
		/// @returns Channel capability in JSON format
		static const char* GetCapability();

		/// Values used as default for channel jitter. 30 ms if unset. Current jitter value can be changed at runtime.
		/// Set long delay otherwise slack rate limit will heavily impact channel.
		constexpr static std::chrono::milliseconds s_MinUpdateDelay = 3500ms, s_MaxUpdateDelay = 6500ms;

	protected:
		/// The inbound direction name of data
		std::string m_inboundDirectionName;

		/// The outbound direction name, the opposite of m_inboundDirectionName
		std::string m_outboundDirectionName;

		// ID of the created job on print queue
		std::string m_jobIdentifier;

		// Local or network address of target printer
		std::string m_printerAddress;

		// Handle to local or network printer
		Detail::PrinterHandle m_pHandle;

		/// Maximum packet size
		uint32_t m_maxPacketSize;
	};
}
