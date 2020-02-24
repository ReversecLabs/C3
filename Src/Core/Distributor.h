#pragma once

#include "Procedures.h"
#include "ProceduresG2X.h"
#include "RouteManager.h"
#include "Common/MWR/Crypto/Crypto.hpp"

// Forward declarations.
namespace MWR::C3
{
	struct LogMessage;
	namespace Core
	{
		struct DeviceBridge;
	}
}

namespace MWR::C3::Core
{
	/// Relay's lowest layer - responsible for managing packet transmission.
	struct Distributor : std::enable_shared_from_this<Distributor>, RouteManager, ProceduresN2N::RequestHandler, ProceduresS2G::RequestHandler
	{
		using LoggerCallback = Utils::LoggerCallback;

		/// Destructor
		virtual ~Distributor() = default;

		/// Logs a message. Used by internal Relay mechanisms and attached Interfaces to report errors, warnings, informations and debug messages.
		/// @param message information to log.
		/// @param sender Interface reporting the message. If sender.IsNull() then the message comes from internal Relay mechanisms.
		virtual void Log(LogMessage const& message, DeviceId sender = DeviceId{}) noexcept;

		/// Callback fired to by a Channel when a C3 packet arrives.
		/// @param packet full C3 packet to interpret.
		/// @param sender Interface passing the packet.
		/// @throws std::runtime_error.
		virtual void OnPacketReceived(ByteView packet, std::shared_ptr<DeviceBridge> sender);

	protected:
		/// Expose all base classes `On` methods.
		using ProceduresN2N::RequestHandler::On;
		using ProceduresS2G::RequestHandler::On;

		/// A protected ctor.
		/// @param callbackOnLog callback fired whenever a new Log entry is being added.
		/// @param decryptionKey Relay's private asymmetric key.
		/// @param broadcastKey Network's symmetric key.
		Distributor(LoggerCallback callbackOnLog, Crypto::PrivateKey const& decryptionKey, Crypto::SymmetricKey const& broadcastKey);

		/// Checks whether particular Agent is banned.
		/// @param agentId ID of the Agent to check.
		virtual bool IsAgentBanned(AgentId agentId);

		/// Fired when a N2N protocol packet arrives.
		/// @param packet0 a buffer that contains whole packet.
		/// @param sender a Channel that provided the packet.
		virtual void OnProtocolN2N(ByteView packet0, std::shared_ptr<DeviceBridge> sender);

		/// Fired when a S2G protocol packet arrives.
		/// @param packet0 a buffer that contains whole packet.
		/// @param sender a Channel that provided the packet.
		virtual void OnProtocolS2G(ByteView packet0, std::shared_ptr<DeviceBridge> sender) = 0;

		/// Fired when a S2G protocol packet arrives.
		/// @param packet0 a buffer that contains whole packet.
		/// @param sender a Channel that provided the packet.
		virtual void OnProtocolG2A(ByteView packet0, std::shared_ptr<DeviceBridge> sender) = 0;

		/// Fired when a S2G protocol packet arrives.
		/// @param packet0 a buffer that contains whole packet.
		/// @param sender a Channel that provided the packet.
		virtual void OnProtocolG2R(ByteView packet0, std::shared_ptr<DeviceBridge> sender) = 0;

		/// Encrypts a packet with the Network key and sends it through specified Channel. This is the last function to be called for a completely built outgoing packet.
		/// @param packet plain-text packet to encrypt.
		/// @param channel Interface used to send the packet.
		/// @throws std::runtime_error.
		virtual void LockAndSendPacket(ByteView packet, std::shared_ptr<DeviceBridge> channel);

		/// Decrypts a packet with the Network key. This is the first thing called before parsing a packet from a Channel (even before QOS).
		/// @param packet encrypted packet to decrypt.
		/// @return decrypted packet.
		/// @throws std::runtime_error.
		virtual ByteVector UnlockPacket(ByteView packet);

	protected:
		LoggerCallback m_CallbackOnLog;																					///< Callback fired whenever a new Log entry is being added.
		Crypto::SymmetricKey m_BroadcastKey;																			///< Network key.
		Crypto::PrivateKey m_DecryptionKey;																				///< Own key used to decrypt messages addressed to me.
	};
}
