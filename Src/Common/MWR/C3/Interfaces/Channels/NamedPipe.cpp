#include "StdAfx.h"
#include "Common/MWR/WinTools/Pipe.h"

namespace MWR::C3::Interfaces::Channels
{
	/// Implementation of the Named Pipe Channel.
	struct NamedPipe : public Channel<NamedPipe>
	{
		/// Public constructor.
		/// @param arguments factory arguments.
		NamedPipe(ByteView arguments)
			: m_Pipe(arguments.Read<ByteVector, ByteVector>())
		{ }

		/// OnSend callback implementation.
		/// @param packet data to send to Channel.
		/// @returns size_t number of bytes successfully written.
		size_t OnSendToChannel(ByteView packet)
		{
			return m_Pipe.Write(packet);
		}

		/// Reads a single C3 packet from Channel.
		/// @return packet retrieved from Channel.
		ByteVector OnReceiveFromChannel()
		{
			return m_Pipe.Read();
		}

		/// Get channel capability.
		/// @returns ByteView view of channel capability.
		static ByteView GetCapability()
		{
			return R"({
				"create":
				{
					"arguments":
					[
						[
							{
								"type": "string",
								"name": "Input ID",
								"min": 4,
								"randomize": true,
								"description": "Used to distinguish packets for the channel"
							},
							{
								"type": "string",
								"name": "Output ID",
								"min": 4,
								"randomize": true,
								"description": "Used to distinguish packets from the channel"
							}
						]
					]
				},
				"commands":	[]
			})";
		}

	protected:
		/// A full-duplex Pipe object
		MWR::WinTools::DuplexPipe m_Pipe;
	};
}
