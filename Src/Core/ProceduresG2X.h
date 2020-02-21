#pragma once

#include "Procedures.h"

/// Gateway -> X [Agent|Route]
namespace MWR::C3::Core::ProceduresG2X
{
	/// Base for Gateway -> [Agent|Route] Queries.
	struct QueryG2X : BaseQuery
	{
		/// Create Query from received packet.
		/// @param sender device that received query.
		/// @param destinationRid - destination route Id from packet.
		/// @param procedureNo number identifying procedure.
		/// @param packetAfterProcedureNumber body of query.
		QueryG2X(std::weak_ptr<DeviceBridge> sender, RouteId destinationRid, ProceduresUnderlyingType procedureNo, ByteView packetAfterProcedureNumber)
			: BaseQuery{ sender }
			, m_GatewayPrivateSignature{nullptr}
			, m_QueryPacketBody{ packetAfterProcedureNumber }
			, m_ReceiverRid{ destinationRid }
		{
			// In the future - parse packet. Currently it's not used anywhere.
		}

		/// Creates Query that is empty and should be filled then sent.
		/// @param propagation - type of propagation for this query
		/// @param receiverRid - the route to propagate this message through
		/// @param gatewayPrivateSignature - gateway's signature, used to encrypt and sign the message
		/// @param responseType - requested response type [Not used]
		QueryG2X(Propagation propagation, RouteId receiverRid, Crypto::PrivateSignature const& gatewayPrivateSignature, ResponseType responseType = ResponseType::None)
			: BaseQuery{ responseType }
			, m_GatewayPrivateSignature{ &gatewayPrivateSignature }
			, m_Propagation{ propagation }
			, m_ReceiverRid{ receiverRid }
		{
		}

		/// @returns destination route Id
		RouteId GetRecipientRouteId()
		{
			return m_ReceiverRid;
		}

		/// @returns packet body
		ByteVector const& GetPacketBody()
		{
			return m_QueryPacketBody;
		}

		/// Constructs the following header: [G2X|(Signed[AID.IID|ProcedureNo|QueryBody])].
		/// @return buffer containing whole packet.
		ByteVector ComposeQueryPacket() const override
		{
			assert(m_GatewayPrivateSignature);
			return CompileProtocolHeader().Concat(Crypto::SignMessage(m_ReceiverRid.ToByteVector().Concat(GetQueryHeader()).Concat(m_QueryPacketBody), *m_GatewayPrivateSignature));
		}

	protected:
		const Crypto::PrivateSignature* const m_GatewayPrivateSignature;														///< Gateway signature used to sign the query.
		ByteVector m_QueryPacketBody;																					///< Whole Query packet along with all the headers.

	private:
		/// Constructs the following header: [G2A/G2R].
		/// @return buffer containing composed header.
		ByteVector CompileProtocolHeader() const override
		{
			return ByteVector{}.Write(static_cast<ProtocolsUnderlyingType>(GetProtocol()));
		}

		/// @return Protocol type for propagation type.
		Protocols GetProtocol() const
		{
			switch (m_Propagation)
			{
			case Propagation::Agent: return Protocols::G2A;
			case Propagation::Route: return Protocols::G2R;
			default: throw std::logic_error(OBF("Invalid propagation mode"));
			}
		}

		/// @return Buffer with query header appropriate to propagation
		ByteVector GetQueryHeader() const
		{
			switch (m_Propagation)
			{
			case Propagation::Agent: return {};
			case Propagation::Route: return CompileQueryHeader();
			default: throw std::logic_error(OBF("Invalid propagation mode"));
			}
		}

		Propagation m_Propagation;																						///< Propagation type for query
		RouteId m_ReceiverRid;																							///< This Query receiver RouteId
	};

	/// Helper to template creating Queries.
	/// @tparam ProcedureNumber identifier for each query. Assure that only one type inherits from Query<> with unique identifier.
	template<ProceduresUnderlyingType ProcedureNumber>
	struct Query : QueryG2X
	{
		/// Get underlying number of procedure.
		static constexpr ProceduresUnderlyingType GetProcedureNumberConstexpr() { return ProcedureNumber; }

		/// Get underlying number of procedure.
		ProceduresUnderlyingType GetProcedureNumber() const override { return GetProcedureNumberConstexpr(); }

		/// Forwarded constructors.
		using QueryG2X::QueryG2X;
	};

	/// Helper to template creating Queries to Agent
	/// @tparam ProcedureNumber identifier for each query. Assure that only one type inherits from Query<> with unique identifier.
	template<ProceduresUnderlyingType ProcedureNumber>
	struct QueryToAgent : Query<ProcedureNumber>
	{
		/// Encrypts and sets query body
		/// @param queryPacketBody plaintext body of query
		/// @param agentPublicKey - recipient agent's public key
		/// @param gatewayPrivateKey - gateawy private key
		void EncrpytQueryWithBody(ByteView queryPacketBody, Crypto::PublicKey const& agentPublicKey, Crypto::PrivateKey const& gatewayPrivateKey)
		{
			m_QueryPacketBody = Crypto::EncryptAndAuthenticate(CompileQueryHeader().Concat(queryPacketBody), agentPublicKey, gatewayPrivateKey);
		}

		/// Forwarded constructors.
		using Query<ProcedureNumber>::Query;
		using Query<ProcedureNumber>::CompileQueryHeader;
		using Query<ProcedureNumber>::m_QueryPacketBody;
	};

	/// Helper to template creating Queries to Route
	/// @tparam ProcedureNumber identifier for each query. Assure that only one type inherits from Query<> with unique identifier.
	template<ProceduresUnderlyingType ProcedureNumber>
	struct QueryToRoute : Query<ProcedureNumber>
	{

		/// Forwarded constructors.
		using Query<ProcedureNumber>::Query;
	};

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	/// Query agent to run a command
	struct RunCommandOnAgentQuery final : QueryToAgent<0>
	{
		/// Create new instance.
		/// @param receiverRid - destination route id
		/// @param gatewayPrivateSignature - gateway's private signature
		/// @param agentPublicKey - destination agent's public key
		/// @param gatewayPrivateKey - gateway's private key
		/// @param commandWithArguments - plaintext command with it's arguments in binary form
		/// @param responseType - [Not used]
		/// @returns a new query instance
		static std::unique_ptr<RunCommandOnAgentQuery> Create(RouteId receiverRid, Crypto::PrivateSignature const& gatewayPrivateSignature, Crypto::PublicKey const& agentPublicKey, Crypto::PrivateKey const& gatewayPrivateKey, ByteView commandWithArguments, ResponseType responseType = ResponseType::None)
		{
			auto query = std::make_unique<RunCommandOnAgentQuery>(Propagation::Agent, receiverRid, gatewayPrivateSignature, responseType);
			query->EncrpytQueryWithBody(commandWithArguments, agentPublicKey, gatewayPrivateKey);
			return query;
		}

	private:
		/// Inherit Constructors.
		using QueryToAgent::QueryToAgent;
	};

	/// Query to add a new route (eg. to new agent)
	struct AddRoute final : QueryToRoute<1>
	{
		/// Create new instance.
		/// @param receiverRid - destination route id
		/// @param gatewayPrivateSignature - gateway's private signature
		/// @param commandWithArguments - plaintext command with it's arguments in binary form
		/// @param responseType - [Not used]
		/// @returns a new query instance
		static std::unique_ptr<AddRoute> Create(RouteId receiverRid, Crypto::PrivateSignature const& gatewayPrivateSignature, ByteView commandWithArguments, ResponseType responseType = ResponseType::None)
		{
			auto query = std::make_unique<AddRoute>(Propagation::Route, receiverRid, gatewayPrivateSignature, responseType);
			query->m_QueryPacketBody = commandWithArguments;
			return query;
		}

	private:
		/// Inherit Constructors.
		using QueryToRoute::QueryToRoute;
	};

	/// Query agent to run command on it's device
	struct RunCommandOnDeviceQuery final : QueryToAgent<2>
	{
		/// Create new instance.
		/// @param receiverRid - destination route id
		/// @param gatewayPrivateSignature - gateway's private signature
		/// @param agentPublicKey - destination agent's public key
		/// @param gatewayPrivateKey - gateway's private key
		/// @param deviceToRunOn - device which should execute command
		/// @param commandWithArguments - plaintext command with it's arguments in binary form
		/// @param responseType - [Not used]
		/// @returns a new query instance
		static std::unique_ptr<RunCommandOnDeviceQuery> Create(RouteId receiverRid, Crypto::PrivateSignature const& gatewayPrivateSignature, Crypto::PublicKey const& agentPublicKey, Crypto::PrivateKey const& gatewayPrivateKey, DeviceId deviceToRunOn, ByteView commandWithArguments, ResponseType responseType = ResponseType::None)
		{
			auto query = std::make_unique<RunCommandOnDeviceQuery>(Propagation::Agent, receiverRid, gatewayPrivateSignature, responseType);
			query->EncrpytQueryWithBody(deviceToRunOn.ToByteVector().Concat(commandWithArguments), agentPublicKey, gatewayPrivateKey);
			return query;
		}

	private:
		/// Inherit Constructors.
		using QueryToAgent::QueryToAgent;
	};

	/// Query agent to run command on it's device
	struct DeliverToBinder final : QueryToAgent<3>
	{
		/// Create new instance.
		/// @param receiverRid - destination route id
		/// @param gatewayPrivateSignature - gateway's private signature
		/// @param agentPublicKey - destination agent's public key
		/// @param gatewayPrivateKey - gateway's private key
		/// @param deliverTo - device to deliver message to
		/// @param commandWithArguments - message to binder
		/// @param responseType - [Not used]
		/// @returns a new query instance
		static std::unique_ptr<DeliverToBinder> Create(RouteId receiverRid, Crypto::PrivateSignature const& gatewayPrivateSignature, Crypto::PublicKey const& agentPublicKey, Crypto::PrivateKey const& gatewayPrivateKey, DeviceId deliverTo, ByteView commandWithArguments, ResponseType responseType = ResponseType::None)
		{
			auto query = std::make_unique<DeliverToBinder>(Propagation::Agent, receiverRid, gatewayPrivateSignature, responseType);
			query->EncrpytQueryWithBody(deliverTo.ToByteVector().Concat(commandWithArguments), agentPublicKey, gatewayPrivateKey);
			return query;
		}

	private:
		/// Inherit Constructors.
		using QueryToAgent::QueryToAgent;
	};

	/// Base class for G2X queries request handler
	struct RequestHandler
	{
		/// empty RunCommandOnAgentQuery handler
		virtual void On(RunCommandOnAgentQuery) {};
		/// empty AddRoute handler
		virtual void On(AddRoute) {};
		/// empty RunCommandOnDeviceQuery handler
		virtual void On(RunCommandOnDeviceQuery) {};
		/// empty DeliverToBinder handler
		virtual void On(DeliverToBinder) {};

		/// Dispatch the query packet to suitable handler
		/// @param sender - device that originally received packet
		/// @param destinationRoute - destination route of this packet
		/// @param packetAtProcedureNumber - query packet starting with procedure number
		void ParseRequestAndHandleIt(std::weak_ptr<DeviceBridge> sender, RouteId destinationRoute, ByteView packetAtProcedureNumber)
		{
			auto procedureNo = ReadProcedureNo(packetAtProcedureNumber);
			HandleQuery(sender, destinationRoute, procedureNo, packetAtProcedureNumber);
		}

	private:

		/// Dispatch the query packet to suitable handler
		/// @param sender - device that originally received packet
		/// @param destinationRoute - destination route of this packet
		/// @param procedureNo - query procedure number
		/// @param packetAfterProcedureNumber - query packet without procedure number
		void HandleQuery(std::weak_ptr<DeviceBridge> sender, RouteId destinationRoute, ProceduresUnderlyingType procedureNo, ByteView packetAfterProcedureNumber)
		{
			switch (procedureNo)
			{
			case RunCommandOnAgentQuery::GetProcedureNumberConstexpr():
				return On(RunCommandOnAgentQuery{ sender, destinationRoute, procedureNo, packetAfterProcedureNumber });
			case AddRoute::GetProcedureNumberConstexpr():
				return On(AddRoute{sender, destinationRoute, procedureNo, packetAfterProcedureNumber});
			case RunCommandOnDeviceQuery::GetProcedureNumberConstexpr():
				return On(RunCommandOnDeviceQuery{sender, destinationRoute, procedureNo, packetAfterProcedureNumber});
			case DeliverToBinder::GetProcedureNumberConstexpr():
				return On(DeliverToBinder{ sender, destinationRoute, procedureNo, packetAfterProcedureNumber });
			}

			throw std::invalid_argument{ OBF("Unknown G2X Query Procedure number: ") + std::to_string(procedureNo) + '.' };
		}
	};
}
