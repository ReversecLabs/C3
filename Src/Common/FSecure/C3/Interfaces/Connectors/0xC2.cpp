#include "StdAfx.h"
#include "Common/FSecure/Sockets/SocketsException.h"
#include "Common/json/json.hpp"
#include "Common/CppRestSdk/include/cpprest/http_client.h"
#include "Common/FSecure/Crypto/Base64.h"
#include "Common/FSecure/CppTools/Compression.h"

using json = nlohmann::json;

namespace FSecure::C3::Interfaces::Connectors
{
	/// A class representing communication with 0xC2.
	struct OhxC2 : Connector<OhxC2>
	{
		/// Public constructor.
		/// @param arguments factory arguments.
		OhxC2(ByteView arguments);

		/// A public destructor.
		~OhxC2();

		/// OnCommandFromConnector callback implementation.
		/// @param binderId Identifier of Peripheral who sends the Command.
		/// @param command full Command with arguments.
		void OnCommandFromBinder(ByteView binderId, ByteView command) override;

		/// Processes internal (C3 API) Command.
		/// @param command a buffer containing whole command and it's parameters.
		/// @return command result.
		ByteVector OnRunCommand(ByteView command) override;

		/// Called every time new implant is being created.
		/// @param connectionId adders of 0xC2Agent in C3 network .
		/// @param data parameters used to create implant. If payload is empty, new one will be generated.
		/// @param isX64 indicates if relay staging beacon is x64.
		/// @returns ByteVector correct command that will be used to stage beacon.
		ByteVector PeripheralCreationCommand(ByteView connectionId, ByteView data, bool isX64) override;

		/// Return json with commands.
		/// @return Capability description in JSON format.
		static const char* GetCapability();

	private:
		/// Represents a single C3 <-> 0xC2 connection, as well as each 0xC2Agent in network.
		struct Connection : std::enable_shared_from_this<Connection>
		{
			/// Constructor.
			/// @param listeningPostAddress adders of Bridge.
			/// @param listeningPostPort port of Bridge.
			/// @param owner weak pointer to 0xC2 class.
			/// @param id id used to address 0xC2Agent.
			Connection(std::string_view listeningPostAddress, uint16_t listeningPostPort, std::weak_ptr<OhxC2> owner, std::string_view id = ""sv);

			/// Destructor.
			~Connection();

			/// Sends data directly to 0xC2.
			/// @param data buffer containing blob to send.
			/// @remarks throws FSecure::WinSocketsException on WinSockets error.
			void Send(ByteView data);

			/// Creates the receiving thread.
			/// As long as connection is alive detached thread will pull available data 0xC2.
			void StartUpdatingInSeparateThread();

			/// Reads data from Socket.
			/// @return heartbeat read data.
			ByteVector Receive();

			/// Indicates that receiving thread was already started.
			/// @returns true if receiving thread was started, false otherwise.
			bool SecondThreadStarted();

			/// Received messages from the beacon
			std::deque<ByteVector> m_RecvQueue;

		private:
			/// Pointer to TeamServer instance.
			std::weak_ptr<OhxC2> m_Owner;

			/// A socket object used in communication with the Bridge listener.
			SOCKET m_Socket;

			/// RouteID in binary form. Address of beacon in network.
			ByteVector m_Id;

			/// Indicates that receiving thread was already started.
			bool m_SecondThreadStarted = false;
		};

		/// Retrieves 0xC2Agent payload from 0xC2 using the API.
		/// @param binderId address of beacon in network.
		/// @param pipename name of pipe hosted by the SMB 0xC2Agent.
		/// @param listenerId the id of the Bridge listener for 0xC2
		/// @param isX64 whether to use 64 or x86 arch
		/// @return generated payload.
		FSecure::ByteVector GeneratePayload(ByteView binderId, std::string pipename, uint32_t connectAttempts, bool isX64);

		/// Close desired connection
		/// @arguments arguments for command. connection Id in string form.
		/// @returns ByteVector empty vector.
		FSecure::ByteVector CloseConnection(ByteView arguments);

		bool UpdateListenerId();

		bool UpdateTemplateId();

		/// Initializes Sockets library. Can be called multiple times, but requires corresponding number of calls to DeinitializeSockets() to happen before closing the application.
		/// @return value forwarded from WSAStartup call (zero if successful).
		static int InitializeSockets();

		/// Deinitializes Sockets library.
		/// @return true if successful, otherwise WSAGetLastError might be called to retrieve specific error number.
		static bool DeinitializeSockets();

		/// IP Address of Bridge Listener.
		std::string m_ListeningPostAddress;

		/// Port of Bridge Listener.
		uint16_t m_ListeningPostPort;

		///0xC2 host for web API
		std::string m_webHost;

		///0xC2 username
		std::string m_username;

		///0xC2 password
		std::string m_password;

		///0xC2 profile
		FSecure::json m_profile;

		///API token, generated on logon.
		std::string m_token;

		///member for 0xC2 Listener ID
		int m_ListenerId;

		/// Access mutex for m_ConnectionMap.
		std::mutex m_ConnectionMapAccess;

		/// Access mutex for sending data to 0xC2.
		std::mutex  m_SendMutex;

		/// Map of all connections.
		std::unordered_map<std::string, std::shared_ptr<Connection>> m_ConnectionMap;

	};
}

bool FSecure::C3::Interfaces::Connectors::OhxC2::UpdateListenerId()
{
	std::string url = this->m_webHost + OBF("/v1/listener");
	std::pair<std::string, uint16_t> data;
	json response;

	web::http::client::http_client_config config;
	config.set_validate_certificates(false); //0xC2 framework is unlikely to have a valid cert.

	web::http::client::http_client webClient(utility::conversions::to_string_t(url), config);
	web::http::http_request request;

	request = web::http::http_request(web::http::methods::GET);

	std::string authHeader = OBF("Bearer ") + this->m_token;
	request.headers().add(OBF(L"Authorization"), utility::conversions::to_string_t(authHeader));
	pplx::task<web::http::http_response> task = webClient.request(request);

	web::http::http_response resp = task.get();

	if (resp.status_code() != web::http::status_codes::OK)
		throw std::exception((OBF("[0xC2] Error getting Listeners, HTTP resp: ") + std::to_string(resp.status_code())).c_str());

	//Get the json response
	auto respData = resp.extract_string();
	response = json::parse(respData.get());

	bool retVal = false;
	for (auto& listeners : response)
	{
		if (listeners[OBF("name")] == OBF("0xC2Bridge"))
		{
			this->m_ListenerId = listeners[OBF("listenerID")].get<int>();
			auto prof = listeners[OBF("profile")];
			auto profile_text = prof[OBF("windows_agent")];
			auto text = profile_text.dump();
			this->m_profile = profile_text;
			retVal = true;
		}

		if (listeners[OBF("name")] == OBF("TestC3"))
		{
			this->m_ListeningPostPort = listeners[OBF("port")].get<int>();;
		}
	}

	return retVal;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Connectors::OhxC2::OhxC2(ByteView arguments)
{
	json postData;
	json response;

	std::tie(m_ListeningPostPort, m_webHost, m_username, m_password) = arguments.Read<uint16_t, std::string, std::string, std::string>();

	// if the last character is '/' remove it
	if (this->m_webHost.back() == '/')
		this->m_webHost.pop_back();


	/***Authenticate to Web API ***/
	std::string url = this->m_webHost + OBF("/v1/token");

	postData[OBF("username")] = this->m_username;
	postData[OBF("secret")] = this->m_password;

	web::http::client::http_client_config config;
	config.set_validate_certificates(false); //0xC2 framework is unlikely to have a valid cert.

	web::http::client::http_client webClient(utility::conversions::to_string_t(url), config);
	web::http::http_request request;

	request = web::http::http_request(web::http::methods::POST);
	request.headers().set_content_type(utility::conversions::to_string_t(OBF("application/json")));
	request.set_body(utility::conversions::to_string_t(postData.dump()));

	pplx::task<web::http::http_response> task = webClient.request(request);
	web::http::http_response resp = task.get();

	if (resp.status_code() == web::http::status_codes::OK)
	{
		//Get the json response
		auto respData = resp.extract_string();
		response = json::parse(respData.get());
	}
	else
		throw std::exception((OBF("[0xC2] Error authenticating to web app, HTTP resp: ") + std::to_string(resp.status_code())).c_str());

	this->m_token = response[OBF("access_token")].get<std::string>();

	// TODO: If the listener doesn't already exist create it.
	if (!UpdateListenerId())
	{
		//extract ip address from url
		size_t start = 0, end = 0;
		start = url.find("://") + 3;
		end = url.find(":", start + 1);

		if (start == std::string::npos || end == std::string::npos || end > url.size())
			throw std::exception(OBF("[0xC2] Incorrect URL, must be of the form http|https://hostname|ip:port - eg https://192.168.133.171:7443"));

		this->m_ListeningPostAddress = url.substr(start, end - start);

		///Create the bridge listener
		url = this->m_webHost + OBF("/vi/listener");

		web::http::client::http_client webClientBridge(utility::conversions::to_string_t(url), config);
		request = web::http::http_request(web::http::methods::POST);
		request.headers().set_content_type(utility::conversions::to_string_t(OBF("application/json")));

		std::string authHeader = OBF("Bearer ") + this->m_token;
		request.headers().add(OBF(L"Authorization"), utility::conversions::to_string_t(authHeader));

		//The data to create a bridge listener
		// TODO: Fix for 0xc2
		json postData;
		postData[OBF("name")] = OBF("C3Bridge");
		postData[OBF("guid")] = OBF("b85ea642f2");
		postData[OBF("description")] = OBF("A bridge for custom listeners");
		postData[OBF("bindAddress")] = OBF("0.0.0.0");
		postData[OBF("bindPort")] = this->m_ListeningPostPort;
		postData[OBF("connectAddresses")] = { this->m_ListeningPostAddress };
		postData[OBF("connectPort")] = this->m_ListeningPostPort;
		postData[OBF("status")] = OBF("Active");
		postData[OBF("listenerTypeId")] = 2;
		postData[OBF("profileId")] = 3;

		request.set_body(utility::conversions::to_string_t(postData.dump()));

		task = webClientBridge.request(request);
		resp = task.get();

		if (resp.status_code() != web::http::status_codes::OK)
			throw std::exception((OBF("[0xC2] Error setting up BridgeListener, HTTP resp: ") + std::to_string(resp.status_code())).c_str());

		if (!UpdateListenerId()) //now get the id of the listener
			throw std::exception((OBF("[0xC2] Error getting ListenerID after creation")));
	}

	InitializeSockets();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Connectors::OhxC2::~OhxC2()
{
	DeinitializeSockets();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Connectors::OhxC2::OnCommandFromBinder(ByteView binderId, ByteView command)
{
	std::scoped_lock<std::mutex> lock(m_ConnectionMapAccess);

	auto it = m_ConnectionMap.find(binderId);
	if (it == m_ConnectionMap.end())
		throw std::runtime_error{ OBF("Unknown connection") };

	it->second->Send(command);

	if (!(it->second->SecondThreadStarted()))
		it->second->StartUpdatingInSeparateThread();


}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int FSecure::C3::Interfaces::Connectors::OhxC2::InitializeSockets()
{
	WSADATA wsaData;
	WORD wVersionRequested;
	wVersionRequested = MAKEWORD(2, 2);
	return WSAStartup(wVersionRequested, &wsaData);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool FSecure::C3::Interfaces::Connectors::OhxC2::DeinitializeSockets()
{
	return WSACleanup() == 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Connectors::OhxC2::GeneratePayload(ByteView binderId, std::string pipename, uint32_t connectAttempts, bool arch64)
{
	if (binderId.empty() || pipename.empty())
		throw std::runtime_error{ OBF("Wrong parameters, cannot create payload") };

	std::string authHeader = OBF("Bearer ") + this->m_token;
	ByteVector payload;

	web::http::client::http_client_config config;
	config.set_validate_certificates(false);
	web::http::client::http_client webClient(utility::conversions::to_string_t(this->m_webHost + OBF("/v1/payload/windows/stageless")), config);
	web::http::http_request request;

	
	this->m_profile[OBF("p2p")][OBF("binding")] = "\\\\.\\pipe\\" + pipename;
	//The data to create an 0xC2 payload
	json postData;
	postData[OBF("p2p")] = true;
	postData[OBF("listenerID")] = this->m_ListenerId;
	postData[OBF("arch")] = arch64 ? OBF("x64") : OBF("x86");
	postData[OBF("profile")] = this->m_profile;

	try
	{
		request = web::http::http_request(web::http::methods::POST);
		request.headers().set_content_type(utility::conversions::to_string_t("application/json"));
		request.set_body(utility::conversions::to_string_t(postData.dump()));

		request.headers().add(OBF(L"Authorization"), utility::conversions::to_string_t(authHeader));
		pplx::task<web::http::http_response> task = webClient.request(request);
		web::http::http_response resp = task.get();

		if (resp.status_code() != web::http::status_codes::OK)
		{
			throw std::runtime_error(OBF("[0xC2] Non-200 HTTP code returned generating payload: ") + std::to_string(resp.status_code()));
		}

		auto payload = resp.extract_vector().get();

		//Finally connect to the socket.
		try
		{
			m_ListeningPostAddress = "127.0.0.1";
			auto connection = std::make_shared<Connection>(m_ListeningPostAddress, m_ListeningPostPort, std::static_pointer_cast<OhxC2>(shared_from_this()), binderId);
			m_ConnectionMap.emplace(std::string{ binderId }, std::move(connection));
		}
		catch (std::exception&)
		{
			throw std::exception(OBF("[0xC2] Error connecting to 0xC2 Bridge"));
		}

		return payload;
	}
	catch (std::exception& e)
	{
		throw e;
	}
}

FSecure::ByteVector FSecure::C3::Interfaces::Connectors::OhxC2::CloseConnection(ByteView arguments)
{
	m_ConnectionMap.erase(arguments);
	return {};
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Connectors::OhxC2::OnRunCommand(ByteView command)
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
const char* FSecure::C3::Interfaces::Connectors::OhxC2::GetCapability()
{
	return R"(
	{
	"create":
	{
		"arguments":
		[
			{
				"type": "uint16",
				"name": "0xC2BridgePort",
				"min": 2,
				"defaultValue": 8080,
				"randomize": true,
				"description": "The port for the C2Bridge Listener if it doesn't already exist."
			},
			{
				"type": "string",
				"name": "0xC2 Web Host",
				"min": 1,
				"defaultValue": "https://127.0.0.1:5000/",
				"description": "Host for 0xC2 - eg https://127.0.0.1:5000/"
			},
			{
				"type": "string",
				"name": "Username",
				"min": 1,
				"description": "Username to authenticate"
			},
			{
				"type": "string",
				"name": "Password",
				"min": 1,
				"description": "Password to authenticate"
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

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Connectors::OhxC2::Connection::Connection(std::string_view listeningPostAddress, uint16_t listeningPostPort, std::weak_ptr<OhxC2> owner, std::string_view id)
	: m_Owner(owner)
	, m_Id(ByteView{ id })
{

	/*** Connect to C2Bridge ***/
	sockaddr_in client;
	client.sin_family = AF_INET;
	client.sin_port = htons(listeningPostPort);
	switch (InetPtonA(AF_INET, &listeningPostAddress.front(), &client.sin_addr.s_addr))			//< Mod to solve deprecation issue.
	{
	case 0:
		throw std::invalid_argument(OBF("Provided Listening Post address in not a valid IPv4 dotted - decimal string or a valid IPv6 address."));
	case -1:
		throw FSecure::SocketsException(OBF("Couldn't convert standard text IPv4 or IPv6 address into its numeric binary form. Error code : ") + std::to_string(WSAGetLastError()) + OBF("."), WSAGetLastError());
	}

	// Attempt to connect.
	if (INVALID_SOCKET == (m_Socket = socket(AF_INET, SOCK_STREAM, 0)))
		throw FSecure::SocketsException(OBF("Couldn't create socket."), WSAGetLastError());

	if (SOCKET_ERROR == connect(m_Socket, (struct sockaddr*)&client, sizeof(client)))
		throw FSecure::SocketsException(OBF("Could not connect to ") + std::string{ listeningPostAddress } + OBF(":") + std::to_string(listeningPostPort) + OBF("."), WSAGetLastError());

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Connectors::OhxC2::Connection::~Connection()
{
	closesocket(m_Socket);
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Connectors::OhxC2::Connection::Send(ByteView data)
{
	auto owner = m_Owner.lock();
	if (!owner)
		throw std::runtime_error(OBF("Could not lock pointer to owner "));

	std::unique_lock<std::mutex> lock{ owner->m_SendMutex };
	// Write four bytes indicating the length of the next chunk of data.
	DWORD chunkLength = static_cast<DWORD>(data.size());
	if (SOCKET_ERROR == send(m_Socket, reinterpret_cast<char*>(&chunkLength), 4, 0))
		throw FSecure::SocketsException(OBF("Error sending to Socket : ") + std::to_string(WSAGetLastError()) + OBF("."), WSAGetLastError());

	// Write the chunk to socket.
	if (SOCKET_ERROR == send(m_Socket, reinterpret_cast<const char*>(&data.front()), static_cast<int>(chunkLength), 0))
		throw FSecure::SocketsException(OBF("Error sending to Socket : ") + std::to_string(WSAGetLastError()) + OBF("."), WSAGetLastError());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Connectors::OhxC2::Connection::Receive()
{
	DWORD chunkLength = 0, bytesRead;
	if (SOCKET_ERROR == (bytesRead = recv(m_Socket, reinterpret_cast<char*>(&chunkLength), 4, 0)))
		throw FSecure::SocketsException(OBF("Error receiving from Socket : ") + std::to_string(WSAGetLastError()) + ("."), WSAGetLastError());

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

		case static_cast<DWORD>(SOCKET_ERROR):
			throw FSecure::SocketsException(OBF("Error receiving from Socket : ") + std::to_string(WSAGetLastError()) + OBF("."), WSAGetLastError());
		}

	return buffer;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Connectors::OhxC2::Connection::StartUpdatingInSeparateThread()
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
				std::this_thread::sleep_for(std::chrono::milliseconds{ 10 });
				try
				{
					// Read packet and post it to Binder.
					if (auto packet = Receive(); !packet.empty())
					{
						// Don't forward NoOps over C3
						if (packet.size() == 1u && packet[0] == 0u)
						{
							if (!m_RecvQueue.empty())
							{
								// Just send one message at a time or Beacon gets slowed down from downloads/socks
								auto msg = std::move(m_RecvQueue.front());
								m_RecvQueue.pop_front();
								Send(msg);
							}
						}
						else
						{
							// Send valid Commands over C3
							bridge->PostCommandToBinder(m_Id, packet);
							// Send NoOp on response to all commands.
							//Send("\0"_bv);
						}
					}
				}
				catch (std::exception& e)
				{
					bridge->Log({ e.what(), LogMessage::Severity::Error });
				}
			}
		}).detach();
}

bool FSecure::C3::Interfaces::Connectors::OhxC2::Connection::SecondThreadStarted()
{
	return m_SecondThreadStarted;
}

FSecure::ByteVector FSecure::C3::Interfaces::Connectors::OhxC2::PeripheralCreationCommand(ByteView connectionId, ByteView data, bool isX64)
{
	auto [pipeName, maxConnectionAttempts, delayBetweenConnectionTrials, useSyscalls] = data.Read<std::string, uint16_t, uint16_t, bool>();
	return ByteVector{}.Write(pipeName, maxConnectionAttempts, delayBetweenConnectionTrials, useSyscalls, GeneratePayload(connectionId, pipeName, maxConnectionAttempts, isX64));
}


