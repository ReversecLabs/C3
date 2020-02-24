#include "StdAfx.h"

#ifdef _DEBUG

namespace MWR::C3::Interfaces::Connectors
{
	/// Class that mocks a Connector.
	class MockServer : public Connector<MockServer>
	{
	public:
		/// Constructor.
		/// @param arguments factory arguments.
		MockServer(ByteView);

		/// Destructor
		virtual ~MockServer() = default;

		/// OnCommandFromBinder callback implementation.
		/// @param binderId Identifier of Peripheral who sends the Command.
		/// @param command full Command with arguments.
		void OnCommandFromBinder(ByteView binderId, ByteView command) override;

		/// Returns json with Commands.
		/// @return Capability in JSON format
		static const char* GetCapability();

		/// Processes internal (C3 API) Command.
		/// @param command a buffer containing whole command and it's parameters.
		/// @return command result.
		ByteVector OnRunCommand(ByteView command) override;

		/// Called every time new implant is being created.
		/// @param connectionId unused.
		/// @param data unused. Prints debug information if not empty.
		/// @param isX64 unused.
		/// @returns ByteVector copy of data.
		ByteVector PeripheralCreationCommand(ByteView connectionId, ByteView data, bool isX64) override;

	private:
		/// Example of internal command of Connector. Must be described in GetCapability, and handled in OnRunCommand
		/// @param arg all arguments send to method.
		/// @returns ByteVector response for command.
		ByteVector TestErrorCommand(ByteView arg);

		/// Close desired connection
		/// @param connectionId id of connection (RouteId) in string form.
		/// @returns ByteVector empty vector.
		MWR::ByteVector CloseConnection(ByteView connectionId) override;

		/// Represents a single connection with implant.
		struct Connection : std::enable_shared_from_this<Connection>
		{
			/// Constructor.
			/// @param owner weak pointer to connector object.
			/// @param id of connection.
			Connection(std::weak_ptr<MockServer> owner, std::string_view id = ""sv);

			/// Creates the receiving thread.
			/// Thread will send packet every 3 seconds.
			void StartUpdatingInSeparateThread();

		private:
			/// Pointer to MockServer.
			std::weak_ptr<MockServer> m_Owner;

			/// RouteID in binary form.
			ByteVector m_Id;
		};

		/// Access blocker for m_ConnectionMap.
		std::mutex m_ConnectionMapAccess;

		/// Map of all connections.
		std::unordered_map<std::string, std::shared_ptr<Connection>> m_ConnectionMap;
	};
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::C3::Interfaces::Connectors::MockServer::MockServer(ByteView)
{
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void MWR::C3::Interfaces::Connectors::MockServer::OnCommandFromBinder(ByteView binderId, ByteView command)
{
	std::scoped_lock<std::mutex> lock(m_ConnectionMapAccess);

	auto it = m_ConnectionMap.find(binderId);
	if (it == m_ConnectionMap.end())
	{
		it = m_ConnectionMap.emplace(binderId, std::make_unique<Connection>(std::static_pointer_cast<MockServer>(shared_from_this()), binderId)).first;
		it->second->StartUpdatingInSeparateThread();
	}

	Log({ OBF("MockServer received: ") + std::string{ command.begin(), command.size() < 10 ? command.end() : command.begin() + 10 } + OBF("..."), LogMessage::Severity::DebugInformation });
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::C3::Interfaces::Connectors::MockServer::Connection::Connection(std::weak_ptr<MockServer> owner, std::string_view id)
	: m_Owner(owner)
	, m_Id(ByteView{ id })
{
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void MWR::C3::Interfaces::Connectors::MockServer::Connection::StartUpdatingInSeparateThread()
{
	std::thread([&, id = m_Id]()
		{
			// Lock pointers.
			auto owner = m_Owner.lock();
			auto bridge = owner->GetBridge();
			auto self = shared_from_this();
			while (bridge->IsAlive() && self.use_count() > 1)
			{
				// Post something to Binder and wait a little.
				try
				{
					bridge->PostCommandToBinder(id, ByteView(OBF("Beep")));
				}
				catch (...)
				{
				}
				std::this_thread::sleep_for(3s);
			}
		}).detach();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::ByteVector MWR::C3::Interfaces::Connectors::MockServer::OnRunCommand(ByteView command)
{
	auto commandCopy = command;
	switch (command.Read<uint16_t>())
	{
	case 0:
		return TestErrorCommand(command);
	case 1:
		return CloseConnection(command);
	default:
		return AbstractConnector::OnRunCommand(commandCopy);
	}
}

MWR::ByteVector MWR::C3::Interfaces::Connectors::MockServer::CloseConnection(ByteView arguments)
{
	m_ConnectionMap.erase(arguments);
	return {};
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::ByteVector MWR::C3::Interfaces::Connectors::MockServer::TestErrorCommand(ByteView arg)
{
	GetBridge()->SetErrorStatus(arg.Read<std::string>());
	return {};
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::ByteVector MWR::C3::Interfaces::Connectors::MockServer::PeripheralCreationCommand(ByteView connectionId, ByteView data, bool isX64)
{
	if (!data.empty())
		Log({ OBF("Non empty command for mock peripheral indicating parsing during command creation."), LogMessage::Severity::DebugInformation });

	return data;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const char* MWR::C3::Interfaces::Connectors::MockServer::GetCapability()
{
	return R"(
{
	"create":
	{
		"arguments":[]
	},
	"commands":
	[
		{
			"name": "Test command",
			"description": "Set error on connector.",
			"id": 0,
			"arguments":
			[
				{
					"name": "Error message",
					"description": "Error set on connector. Send empty to clean up error"
				}
			]
		},
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
#endif // _DEBUG
