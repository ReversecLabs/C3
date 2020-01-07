#pragma once

#include "BaseQuery.h"
#include "Common/MWR/Crypto/Crypto.hpp"
#include "Common/MWR/C3/Internals/BackendCommons.h"
#include "RouteId.h"

namespace MWR::C3::Core
{
	// Typedefs.
	using ProtocolsUnderlyingType = std::uint8_t;
	using PropagationUnderlyingType = std::uint8_t;

	/// Protocol types.
	enum class Protocols : ProtocolsUnderlyingType
	{
		N2N,																										///< [NeighborToNeighbor][SENDERS AID.IID][N2N Procedure][FIELDS]...
		S2G,																										///< [SendToGate]|ENCRYPTED ANONYMOUSLY->|[SENDERS AID]|ENCRYPTED AUTHENTICATED->|[N2G Procedure][FIELDS]...
		G2A,																										///< [G2A]|SIGNED->|[RECEIVERS AID]|ENCRYPTED->|[G2N Procedure][FIELDS]...
		G2R,																										///< [G2R]|SIGNED->|[AID][G2N Procedure][FIELDS]...
		//G2B,																										///< [G2B]|SIGNED->|[AID][G2N Procedure][FIELDS]... NOT IMPLEMENTED.
	};

	/// Sub-protocols of S2X.
	enum class Propagation : ProtocolsUnderlyingType
	{
		Agent,																										///< [G2X]|SIGNED->|[G2A][RECEIVERS AID]|ENCRYPTED->|[G2N Procedure][FIELDS]...
		Route,																										///< [G2X]|SIGNED->|[G2R][AID][G2N Procedure][FIELDS]...
		//Branch,																									///< [G2X]|SIGNED->|[G2B][AID][G2N Procedure][FIELDS]... NOT IMPLEMENTED.
	};

	/// Retrieve packet number and move buffer to position after.
	/// @param packetAtProcedureNumber reference to packet buffer.
	static ProceduresUnderlyingType ReadProcedureNo(ByteView& packetAtProcedureNumber)
	{
		// Sanity check.
		if (packetAtProcedureNumber.empty())
			throw std::runtime_error{ OBF("Packet too short.") };

		return packetAtProcedureNumber.Read<ProceduresUnderlyingType>();
	}

	/// Neighbor Relay -> Neighbor Relay Procedures.
	namespace ProceduresN2N
	{
		/// Base for all N2N queries.
		struct QueryN2N : BaseQuery
		{
			/// Public constructor.
			/// @param sender device that received query.
			/// @param neighborRouteId RouteId of query sender.
			/// @param procedureNo number identifying procedure.
			/// @param packetAfterProcedureNumber body of query.
			QueryN2N(std::weak_ptr<DeviceBridge> sender, RouteId neighborRouteId, ProceduresUnderlyingType procedureNo, ByteView packetAfterProcedureNumber)
				: BaseQuery{ sender }
				, m_SendersRid{ neighborRouteId }
				, m_QueryPacketBody{ packetAfterProcedureNumber }
			{

			}

			/// Constructor creating empty query.
			/// Should be  filled then sent.
			/// @param sendersRid RouteId of query sender.
			/// @param responseType indicates if response is required.
			QueryN2N(RouteId sendersRid, ResponseType responseType = ResponseType::None)
				: BaseQuery{ responseType }
				, m_SendersRid{ sendersRid }
			{
			}

			/// Constructs the following header: [N2N|AID.IID|ProcedureNo|Query Field].
			/// Use to send serialized data.
			/// @return buffer containing whole packet.
			ByteVector ComposeQueryPacket() const override
			{
				return CompileProtocolHeader().Concat(CompileQueryHeader(), m_QueryPacketBody);
			}

			/// Get decrypted query body.
			ByteVector GetQueryPacket(Crypto::PublicKey const& authenticationKey, Crypto::PrivateKey const& decrpytionKey)
			{
				return Crypto::DecryptFromAnonymous(m_QueryPacketBody, authenticationKey, decrpytionKey);
			}

			/// Get Query Body.
			ByteView GetQueryPacket()
			{
				return m_QueryPacketBody;
			}

			/// Get Sender RouteId.
			RouteId const& GetSenderRouteId() const { return m_SendersRid; }

		protected:
			ByteVector m_QueryPacketBody;																					///< Whole Query packet along with all the headers.

			/// Constructs the following header: [N2N|AID.IID].
			/// @return buffer containing composed header.
			ByteVector CompileProtocolHeader() const override
			{
				return ByteVector{}.Write(static_cast<ProtocolsUnderlyingType>(Protocols::N2N), m_SendersRid.ToByteArray());
			}

		private:
			RouteId m_SendersRid;																						///< This Query sender's RouteId.
		};

		/// Helper to template creating Queries.
		/// @tparam ProcedureNumber identifier for each query. Assure that only one type inherits from Query<> with unique identifier.
		template<ProceduresUnderlyingType ProcedureNumber>
		struct Query : QueryN2N
		{
			/// Get underlying number of procedure.
			static constexpr ProceduresUnderlyingType GetProcedureNumberConstexpr() { return ProcedureNumber; }

			/// Get underlying number of procedure.
			ProceduresUnderlyingType GetProcedureNumber() const override { return GetProcedureNumberConstexpr(); }

			/// Forwarded constructors.
			using QueryN2N::QueryN2N;
		};

		/// Query type used to join network.
		struct InitializeRouteQuery : Query<0>
		{
			/// Create new instance.
			/// @param sendersRid RouteId created from relay AgentId, and grc DeviceId.
			/// @param buildId id of relay build.
			/// @param gatewayEncryptionKey key used to encrypt package. Only gateway will be able to decrypt package.
			/// @param agentsPublicEncryptionKey gateway will use this key to send encrypted messages to relay.
			/// @param grcHash hash identifying type of first interface.
			/// @param timestamp time of generating message.
			/// @param responseType inform if recipient if response is required.
			static std::unique_ptr<InitializeRouteQuery> Create(RouteId sendersRid, BuildId buildId, Crypto::PublicKey gatewayEncryptionKey, Crypto::PublicKey agentsPublicEncryptionKey, HashT grcHash, int32_t timestamp, ResponseType responseType = ResponseType::None)
			{
				auto query = std::make_unique<InitializeRouteQuery>(sendersRid, responseType);
				query->m_QueryPacketBody = Crypto::EncryptAnonymously(buildId.ToByteVector().Write(agentsPublicEncryptionKey.ToByteVector(), grcHash, timestamp, HostInfo().ToByteVector()), gatewayEncryptionKey);
				return query;
			}

		private:
			/// Inherit Constructors.
			using Query::Query;
		};

		/// Start of negotiation process. New relay request unique connection.
		struct ChannelIdExchangeStep1 : Query<2>
		{
			/// Create query.
			/// @param sendersRid route id of sender.
			/// @param generatedInputId input id of negotiated channel from new relay.
			static std::unique_ptr<ChannelIdExchangeStep1> Create(RouteId sendersRid, ByteView generatedInputId)
			{
				auto query = std::make_unique<ChannelIdExchangeStep1>(sendersRid);
				query->m_QueryPacketBody = ByteVector{}.Write(generatedInputId);
				return query;
			}

		private:
			/// Inherit Constructors.
			using Query::Query;
		};

		/// Closure of negotiation process. Network relay accepts unique connection.
		struct ChannelIdExchangeStep2 : Query<3>
		{
			/// Create query.
			/// @param sendersRid route id of sender.
			/// @param generatedInputId input id of negotiated channel from network relay side.
			static std::unique_ptr<ChannelIdExchangeStep2> Create(RouteId sendersRid, ByteView generatedInputId)
			{
				auto query = std::make_unique<ChannelIdExchangeStep2>(sendersRid);
				query->m_QueryPacketBody = ByteVector{}.Write(generatedInputId);
				return query;
			}

		private:
			/// Inherit Constructors.
			using Query::Query;
		};

		/// Class representing support for C3 N2N Requests.
		struct RequestHandler
		{
			/// Declaration of support for InitializeRouteQuery Request.
			virtual void On(InitializeRouteQuery&&) = 0;

			/// Declaration of support for ChannelIdExchangeStep1 Request.
			virtual void On(ChannelIdExchangeStep1) = 0;

			/// Declaration of support for ChannelIdExchangeStep2 Request.
			virtual void On(ChannelIdExchangeStep2) = 0;

			/// Function responsible interpreting request and calling right handle.
			/// @param sender Device that reported request.
			/// @param neighborRouteId Id of sender relay.
			/// @param packetAtProcedureNumber request with embedded procedure number.
			void ParseRequestAndHandleIt(std::weak_ptr<DeviceBridge> sender, RouteId neighborRouteId, ByteView packetAtProcedureNumber)
			{
				auto procedureNo = ReadProcedureNo(packetAtProcedureNumber);
				HandleQuery(sender, neighborRouteId, procedureNo, packetAtProcedureNumber);
			}

			/// Function responsible interpreting request and calling right handle.
			/// @param sender Device that reported request.
			/// @param neighborRouteId Id of sender relay.
			/// @param procedureNo number of procedure.
			/// @param packetAfterProcedureNumber request in binary form.
			void HandleQuery(std::weak_ptr<DeviceBridge> sender, RouteId neighborRouteId, ProceduresUnderlyingType procedureNo, ByteView packetAfterProcedureNumber)
			{
				switch (procedureNo)
				{
				 case InitializeRouteQuery::GetProcedureNumberConstexpr():
					return On(InitializeRouteQuery{ sender, neighborRouteId, procedureNo, packetAfterProcedureNumber });
				case ChannelIdExchangeStep1::GetProcedureNumberConstexpr():
					return On(ChannelIdExchangeStep1{ sender, neighborRouteId, procedureNo, packetAfterProcedureNumber });
				case ChannelIdExchangeStep2::GetProcedureNumberConstexpr():
					return On(ChannelIdExchangeStep2{ sender, neighborRouteId, procedureNo, packetAfterProcedureNumber });
				}

				throw std::invalid_argument{ OBF("Unknown N2N Query Procedure number: ") + std::to_string(procedureNo) + OBF(".") };
			}
		};
	}

	namespace ProceduresS2G
	{
		/// Base for all S2G queries.
		struct QueryS2G : BaseQuery
		{
			/// Public constructor.
			/// @param sender device that received query.
			/// @param sendersRid RouteId of query sender.
			/// @param timestamp reported time at relay.
			/// @param packetAfterProcedureNumber body of query.
			QueryS2G(std::weak_ptr<DeviceBridge> sender, RouteId sendersRid, int32_t timestamp, ByteView packetAfterProcedureNumber)
				: BaseQuery{ sender }
				, m_SendersRid{ sendersRid }
				, m_Timestamp{timestamp}
				, m_QueryPacketBody{ packetAfterProcedureNumber }
			{

			}

			/// Public constructor.
			/// @param sendersRid RouteId of query sender.
			/// @param timestamp reported time at relay.
			/// @param responseType is response required.
			QueryS2G(RouteId sendersRid, int32_t timestamp, ResponseType responseType = ResponseType::None)
				: BaseQuery{ responseType }
				, m_SendersRid{ sendersRid }
				, m_Timestamp{ timestamp }
			{
			}


			/// Constructs the S2G header.
			/// Use to send serialized data.
			/// @return buffer containing whole packet.
			ByteVector ComposeQueryPacket() const override
			{
				return CompileProtocolHeader().Concat(m_QueryPacketBody);
			}

			/// Get decrypted query body.
			ByteVector GetQueryPacket(Crypto::PublicKey const& authenticationKey, Crypto::PrivateKey const& decrpytionKey)
			{
				return Crypto::DecryptFromAnonymous(m_QueryPacketBody, authenticationKey, decrpytionKey);
			}

			/// Get Query Body.
			ByteVector GetQueryPacket()
			{
				return m_QueryPacketBody;
			}

			/// Get Sender RouteId.
			RouteId const& GetSenderRouteId() const { return m_SendersRid; }

			/// Get timestamp of request.
			int32_t GetTimestamp() const { return m_Timestamp; }

		protected:
			ByteVector m_QueryPacketBody;																					///< Whole Query packet along with all the headers.

			/// Constructs the following header: [S2G].
			/// @return buffer containing composed header.
			ByteVector CompileProtocolHeader() const override
			{
				return ByteVector{}.Write(static_cast<ProtocolsUnderlyingType>(Protocols::S2G));
			}

		private:
			RouteId m_SendersRid;																							///< This Query sender's RouteId.
			int32_t m_Timestamp;																							///< Timestamp of request.

		};

		/// Helper to template creating Queries.
		/// @tparam ProcedureNumber identifier for each query. Assure that only one type inherits from Query<> with unique identifier.
		template<ProceduresUnderlyingType ProcedureNumber>
		struct Query : QueryS2G
		{
			static constexpr ProceduresUnderlyingType GetProcedureNumberConstexpr() { return ProcedureNumber; }
			ProceduresUnderlyingType GetProcedureNumber() const override { return GetProcedureNumberConstexpr(); }

			/// Forwarded constructors.
			using QueryS2G::QueryS2G;
		};


		/// Query used by relay in network, when new relay wants to join.
		/// New Relay can only send N2N::InitializeRouteQuery to direct neigbor, but cannot communicate with wwhole network.
		/// Network relay will send S2G::InitializeRouteQuery to gateway, announcing new relay.
		struct InitializeRouteQuery : Query<0>
		{
			/// Create new instance.
			/// @param rid of relay sending S2G
			/// @param timestamp reported time at relay.
			/// @param sendersRid rid of new relay, sender of N2
			/// @param senderSideDid device id that connects new relay
			/// @param encryptedBlob encrypted message for gateway from N2N packet.
			/// @param gatewayPublicEncryptionKey key used to encrypt package. Only gateway will be able to decrypt package.
			static std::unique_ptr<InitializeRouteQuery> Create(RouteId rid, int32_t timestamp, RouteId senderRid, DeviceId senderSideDid, ByteVector encryptedBlob, Crypto::PublicKey gatewayPublicEncryptionKey)
			{
				auto query = std::make_unique<InitializeRouteQuery>(rid, timestamp, ResponseType::None);
				query->m_QueryPacketBody = Crypto::EncryptAnonymously(query->CompileQueryHeader().Write(rid, timestamp, senderRid, senderSideDid).Concat(encryptedBlob), gatewayPublicEncryptionKey);
				return query;
			}

			/// Create new instance.
			/// @param sender weak reference to device that reported request.
			/// @param rid RouteID of Relay sending S2G.
			/// @param timestamp reported time at relay.
			/// @param encryptedBlob already encrypted packet body.
			static std::unique_ptr<InitializeRouteQuery> Create(std::weak_ptr<DeviceBridge> sender, RouteId rid, int32_t timestamp, ByteView encryptedBlob)
			{
				auto query = std::make_unique<InitializeRouteQuery>(sender, rid, timestamp, encryptedBlob);
				return query;
			}

		private:
			/// Inherit Constructors.
			using Query::Query;
		};

		/// Request to gateway announcing new device in network.
		struct AddDeviceResponse : Query<1>
		{
			/// Create new instance.
			/// @param rid of relay sending S2G
			/// @param timestamp reported time at relay.
			/// @param newDeviceId id of new device.
			/// @param deviceTypeHash type of new device.
			/// @param isChannel informs if device is channel or peripheral.
			/// @param isNegotiationChannel if channel informs if new device can be used for negotiation.
			/// @param gatewayPublicEncryptionKey key used to encrypt package. Only gateway will be able to decrypt package.
			static std::unique_ptr<AddDeviceResponse> Create(RouteId rid, int32_t timestamp, DeviceId newDeviceId, HashT deviceTypeHash, bool isChannel, bool isNegotiationChannel, Crypto::PublicKey gatewayPublicEncryptionKey)
			{
				auto query = std::make_unique<AddDeviceResponse>(rid, timestamp, ResponseType::None);
				std::uint8_t flags = static_cast<std::uint8_t>(isChannel) | (static_cast<std::uint8_t>(isNegotiationChannel) << 1);
				query->m_QueryPacketBody = Crypto::EncryptAnonymously(query->CompileQueryHeader().Write(rid, timestamp, newDeviceId, deviceTypeHash, flags), gatewayPublicEncryptionKey);
				return query;
			}

		private:
			/// Inherit Constructors.
			using Query::Query;
		};

		/// Request to gateway when peripheral received new packet of data
		struct DeliverToBinder : Query<2>
		{
			/// Create new instance.
			/// @param rid of relay sending S2G
			/// @param timestamp reported time at relay.
			/// @param peripheralId id of peripheral sending packet.
			/// @param connectorHash type of connector that should handle message.
			/// @param blobFromPeripheral original message.
			/// @param gatewayPublicEncryptionKey key used to encrypt package. Only gateway will be able to decrypt package.
			static std::unique_ptr<DeliverToBinder> Create(RouteId rid, int32_t timestamp, DeviceId peripheralId, HashT connectorHash, ByteView blobFromPeripheral, Crypto::PublicKey gatewayPublicEncryptionKey)
			{
				auto query = std::make_unique<DeliverToBinder>(rid, timestamp, ResponseType::None);
				query->m_QueryPacketBody = Crypto::EncryptAnonymously(query->CompileQueryHeader().Write(rid, timestamp, peripheralId, connectorHash).Concat(blobFromPeripheral), gatewayPublicEncryptionKey);
				return query;
			}

			/// Create new instance.
			/// @param rid of relay sending S2G
			/// @param timestamp reported time at relay.
			/// @param encryptedBlob already encrypted packet body.
			static std::unique_ptr<DeliverToBinder> Create(RouteId rid, int32_t timestamp, ByteView encryptedBlob)
			{
				auto query = std::make_unique<DeliverToBinder>(rid, timestamp, ResponseType::None);
				query->m_QueryPacketBody = encryptedBlob;
				return query;
			}

		private:
			/// Inherit Constructors.
			using Query::Query;
		};

		/// Request to gateway that new channel was negotiated.
		struct NewNegotiatedChannelNotification : Query<3>
		{
			/// Create new instance.
			/// @param rid of relay sending S2G
			/// @param timestamp reported time at relay.
			/// @param newDeviceId id of new device.
			/// @param negotiatiorId id of channel that was used in negotiation process.
			/// @param inId input id of new channel
			/// @param outId output id of new channel
			/// @param gatewayPublicEncryptionKey key used to encrypt package. Only gateway will be able to decrypt package.
			static std::unique_ptr<NewNegotiatedChannelNotification> Create(RouteId rid, int32_t timestamp, DeviceId newDeviceId, DeviceId negotiatiorId, ByteView inId, ByteView outId, Crypto::PublicKey gatewayPublicEncryptionKey)
			{
				auto query = std::make_unique<NewNegotiatedChannelNotification>(rid, timestamp, ResponseType::None);
				query->m_QueryPacketBody = Crypto::EncryptAnonymously(query->CompileQueryHeader().Write(rid, timestamp, newDeviceId, negotiatiorId, inId, outId), gatewayPublicEncryptionKey);
				return query;
			}

		private:
			/// Inherit Constructors.
			using Query::Query;
		};

		/// Request carrying unspecified blob of data.
		/// Use carefully, creating new request is recommended instead of using Notification.
		struct Notification : Query<4>
		{
			/// Create new instance.
			/// @param rid of relay sending S2G
			/// @param timestamp reported time at relay.
			/// @param blob unspecified data
			/// @param gatewayPublicEncryptionKey key used to encrypt package. Only gateway will be able to decrypt package.
			static std::unique_ptr<Notification> Create(RouteId rid, int32_t timestamp, MWR::ByteView blob, Crypto::PublicKey gatewayPublicEncryptionKey)
			{
				auto query = std::make_unique<Notification>(rid, timestamp, ResponseType::None);
				query->m_QueryPacketBody = Crypto::EncryptAnonymously(query->CompileQueryHeader().Write(rid, timestamp, blob), gatewayPublicEncryptionKey);
				return query;
			}

		private:
			/// Inherit Constructors.
			using Query::Query;
		};

		/// Retrieve packet number and move buffer to position after.
		/// @param packetAtProcedureNumber reference to packet buffer.
		static ProceduresUnderlyingType ReadProcedureNo(ByteView& packetAtProcedureNumber)
		{
			// Sanity check.
			if (packetAtProcedureNumber.empty())
				throw std::runtime_error{ OBF("Packet too short.") };

			return packetAtProcedureNumber.Read<ProceduresUnderlyingType>();;
		}

		/// Class representing support for C3 N2N Requests.
		struct RequestHandler
		{
			/// Declaration of support for InitializeRouteQuery Request.
			virtual void On(InitializeRouteQuery&&) = 0;

			/// Default empty handler for AddDeviceResponse Request.
			virtual void On(AddDeviceResponse) {};

			/// Default empty handler for DeliverToBinder Request.
			virtual void On(DeliverToBinder) {};

			/// Default empty handler for NewNegotiatedChannelNotification Request.
			virtual void On(NewNegotiatedChannelNotification) {};

			/// Default empty handler for Notification Request.
			virtual void On(Notification) {};

			/// Function responsible interpreting request and calling right handle.
			/// @param sender Device that reported request.
			/// @param procedure type of procedure.
			/// @param rid id of device that reported request.
			/// @param timestamp reported time at relay.
			/// @param encryptedData body of request.
			void ParseRequestAndHandleIt(std::weak_ptr<DeviceBridge> sender, ProceduresUnderlyingType procedure, RouteId rid, int32_t timestamp,  ByteView encryptedData)
			{
				switch (procedure)
				{
				case InitializeRouteQuery::GetProcedureNumberConstexpr():
					On(InitializeRouteQuery{ sender, rid, timestamp, encryptedData });
					break;
				case AddDeviceResponse::GetProcedureNumberConstexpr():
					On(AddDeviceResponse{ sender, rid, timestamp, encryptedData });
					break;
				case DeliverToBinder::GetProcedureNumberConstexpr():
					On(DeliverToBinder{ sender, rid, timestamp, encryptedData });
					break;
				case  NewNegotiatedChannelNotification::GetProcedureNumberConstexpr():
					On(NewNegotiatedChannelNotification{ sender, rid, timestamp, encryptedData });
					break;
				case  Notification::GetProcedureNumberConstexpr():
					On(Notification{ sender, rid, timestamp, encryptedData });
					break;
				default:
					throw std::runtime_error{ OBF("Failed to parse S2G packet. ") };
				}
			}
		};
	}
}
