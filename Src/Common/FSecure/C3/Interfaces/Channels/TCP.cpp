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
                m_ListeningSocket.Listen(1); // Defaults to 1 maximum Connection, need to add more logic to handle multiple input/output IDs and share the socket
            }
        }

        size_t OnSendToChannel(FSecure::ByteView packet)
        {
            EnsureConnected();

            if (m_Socket)
            {
                m_Socket.Send(packet);
                return packet.size();
            }

            return 0;
        }

        FSecure::ByteVector OnReceiveFromChannel()
        {
            EnsureConnected();

            try
            {
                if (m_IsServer && !m_Socket)
                    m_Socket = m_ListeningSocket.Accept();

                if (m_Socket && m_Socket.HasReceivedData())
                    return m_Socket.Receive();
            }
            catch (...)
            {
                m_Socket = {};
            }

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
        void EnsureConnected()
        {
            if (m_IsServer)
            {
                if (!m_Socket)
                {
                    try
                    {
                        m_Socket = m_ListeningSocket.Accept();
                    }
                    catch (...) {
                        m_Socket = {};
                    }
                }
            }
            else
            {
                if (!m_Socket)
                {
                    ConnectClient();
                }
            }
        }


        void ConnectClient()
        {
            while (true)
            {
                try
                {
                    m_Socket = Socket(AddrInfo{ m_IP, m_Port });
                    m_Socket.Connect(m_IP, m_Port);
                    break;
                }
                catch (...)
                {
                    m_Socket = {}; // Reset socket
                    std::this_thread::sleep_for(std::chrono::seconds(5)); // Retry after delay
                }
            }
        }

        std::string m_IP;
        std::uint16_t m_Port;
        bool m_IsServer;
        FSecure::Socket m_Socket;
        FSecure::Socket m_ListeningSocket;
        FSecure::InitializeSockets m_InitializeSockets;
    };
}
