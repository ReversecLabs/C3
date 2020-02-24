#pragma once

#include "Common/MWR/C3/Internals/BackendCommons.h"

// Forward declarations.
namespace MWR::C3
{
	struct AbstractConnector;
	namespace Core
	{
		struct GateRelay;
	}
}

namespace MWR::C3::Core
{
	/// PIMPL for Connector type.
	struct ConnectorBridge : AbstractConnectorBridge, std::enable_shared_from_this<ConnectorBridge>
	{
		/// Public constructor, used by GateRelays.
		/// @param gateway "parent" GateRelay this Connector is being attached to.
		/// @param connector the Connector this object binds GateRelay with.
		/// @param name of connector
		/// @param nameHash hash of connector.
		ConnectorBridge(std::shared_ptr<GateRelay>&& gateway, std::shared_ptr<AbstractConnector>&& connector, std::string name, HashT nameHash);

		/// Destructor
		virtual ~ConnectorBridge() = default;

		/// Called by GateRelay just after the Connector creation.
		void OnAttach() override;

		/// Detaches the Connector.
		void Detach() override;

		/// Notify the gateway to turn off the connector
		void TurnOff() override;

		/// Called whenever Connector wants to send a Command to its Peripheral Binder.
		/// @param binderId Identifier of Peripheral who sends the Command.
		/// @param command full Command with arguments.
		void PostCommandToBinder(ByteView binderId, ByteView command) override;

		/// Fired by Relay to pass by provided Command from Binder Peripheral.
		/// @param binderId Identifier of Peripheral who sends the Command.
		/// @param command full Command with arguments.
		void OnCommandFromBinder(ByteView binderId, ByteView command) override;

		/// Runs Connector's Command.
		/// @param command Connector's Command to run.
		/// @return Command result.
		ByteVector RunCommand(ByteView command) override;

		/// Logs a message. Used by internal mechanisms to report errors, warnings, informations and debug messages.
		/// @param message information to log.
		void Log(LogMessage const& message) override;

		/// Returns name of connector.
		std::string GetName() const;

		/// Returns hash of connector.
		HashT GetNameHash() const;

		/// Checks Connector status.
		/// @return false if Connector is being turned off.
		bool IsAlive() const override { return m_IsAlive; }

		/// "Parent" GateRelay getter.
		/// @return GateRelay this Connector is attached to.
		std::shared_ptr<GateRelay> GetGateRelay() const;

		/// Set error on connector.
		/// @param errorMessage text of error. Set empty to remove error.
		void SetErrorStatus(std::string_view errorMessage) override;

		/// Get error string.
		std::string GetErrorStatus() override;

		/// Called every time new peripheral is being created.
		/// @param connectionId adders of peripheral in C3 network .
		/// @param data all parameters used to create peripheral. Specific for each connector.
		/// @param isX64 indicates if relay staging peripheral is x64.
		/// @returns ByteVector correct command that will be used to stage peripheral.
		ByteVector PeripheralCreationCommand(ByteView connectionId, ByteView data, bool isX64 = false) override;

		/// Close desired connection
		/// @param connectionId id of connection (RouteId) in string form.
		/// @returns ByteVector empty vector.
		ByteVector CloseConnection(ByteView connectionId) override;

	protected:
		/// Connector object getter.
		/// @return Connector this object binds GateRelay with.
		std::shared_ptr<AbstractConnector> GetConnector() const;

	private:
		bool m_IsAlive = true;																							///< False if detached and about to be destroyed.
		std::string m_Name;																								///< Connector's name.
		HashT m_NameHash;																								///< Hash of Connector's name.
		std::weak_ptr<GateRelay> m_GateRelay;																			///< GateRelay this Connector is attached to.
		std::shared_ptr<AbstractConnector> m_Connector;																	///< Connector this object binds GateRelay with.
		std::string m_Error;																							///< String with error text. No error if empty.
	};
}
