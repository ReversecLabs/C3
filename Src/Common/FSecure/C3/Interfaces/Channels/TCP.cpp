#include "StdAfx.h"
#include "Common/FSecure/Sockets/InitializeSockets.h"
#include "Common/FSecure/Sockets/Socket.h"

namespace FSecure::C3::Interfaces::Channels
{
    class TCP : public FSecure::C3::Interfaces::Channel<TCP>
    {
    public:
        TCP(FSecure::ByteView arguments)
            : m_IP(arguments.Read<std::string>())
            , m_Port(arguments.Read<std::uint16_t>())
            , m_IsServer(arguments.Read<bool>())
        {
            if (m_IsServer)
            {
                m_ListeningSocket = Socket(AddrInfo{ m_IP, m_Port });
                m_ListeningSocket.Bind(AddrInfo{ m_IP, m_Port });
                m_ListeningSocket.Listen();
            }
            else
            {
                m_Socket = Socket(AddrInfo{ m_IP, m_Port });
                m_Socket.Connect(m_IP, m_Port);
            }
        }

        size_t OnSendToChannel(FSecure::ByteView packet)
        {
            if (m_IsServer && !m_Socket)
                m_Socket = m_ListeningSocket.Accept();

            if (m_Socket)
            {
                m_Socket.Send(packet);
                return packet.size();
            }

            return 0;
        }

        FSecure::ByteVector OnReceiveFromChannel()
        {
            if (m_IsServer && !m_Socket)
                m_Socket = m_ListeningSocket.Accept();

            if (m_Socket && m_Socket.HasReceivedData())
                return m_Socket.Receive();

            return {};
        }

        static const char* GetCapability()
        {
            return R"({
				"create":
				{
					"arguments":
					[
			            {
				            "type": "string",
				            "name": "IP",
				            "defaultValue": "127.0.0.1",
				            "description": "The IP address to bind to on server side or connect to from client side"
			            },
			            {
				            "type": "uint16",
				            "name": "Port",
				            "defaultValue": 4444,
				            "description": "The port to use"
			            },
			            {
				            "type": "boolean",
				            "name": "Server",
				            "defaultValue": false,
				            "description": "Is this the server?"
			            }
					]
				},
				"commands":	[]
			})";
        }


    private:
        std::string m_IP;
        std::uint16_t m_Port;
        bool m_IsServer;
        FSecure::Socket m_Socket;
        FSecure::Socket m_ListeningSocket;
        FSecure::InitializeSockets m_InitializeSockets;
    };
}
