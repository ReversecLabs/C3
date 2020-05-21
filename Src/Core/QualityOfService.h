#pragma once
// TODO
#include <map>
#include <functional>
#include "RouteId.h"

namespace FSecure::C3
{
	/// A structure that handles Quality of Service of C3 protocols.
	class QualityOfService
	{
		/// Struct representing not merged packet.
		struct Packet
		{
			/// Constructor of packet.
			/// @param chunkId handle order of chunks.
			/// @param expectedSize informs how long whole packet should be.
			/// @param chunk fragment of packet.
			Packet(uint32_t chunkId, uint32_t expectedSize, ByteVector chunk);

			/// Add next chunk.
			/// @param chunkId handle order of chunks.
			/// @param expectedSize informs how long whole packet should be.
			/// @param chunk fragment of packet.
			/// @throw QosException if expected size of whole packet is different for any of chunks.
			void PushNextChunk(uint32_t chunkId, uint32_t expectedSize, ByteVector chunk);

			/// Returns merged packet.
			/// @throw QosException if called before packet was ready to be merged. Use IsReady() to check packet.
			ByteVector Read();

			/// Informs that packet can be merged from chunks.
			bool IsReady();

			void SetExpectedSize(uint32_t size);

		private:
			/// Map of chunks
			std::map<uint32_t, ByteVector> m_Chunks;

			/// Size provided by chunk nr. 0. packet must be not empty, 0 means packet nr. 0 was not yet received.
			uint32_t m_ExpectedSize = 0;

			/// Sum of all chunk sizes.
			uint32_t m_Size = 0;
		};

		/// Used to mark order to outgoing packets.
		uint32_t m_OutgouingPacketId = 0u;

		/// Map of received packets. Packets could be not complete, or there could be packet missing.
		std::map<uint32_t, Packet> m_ReciveQueue;

		/// Returns next ids for packets.
		uint32_t GetOutgouingPacketId();

		/// Used to find order in incoming packets. GetNextPacket will hold ready packets if there was gap in numbering.
		// removed, manual route table management means that channels should not wait for missing packets. It will be introduced at the edges of network
		//uint32_t m_IncomigPacketId = 0u;
	public:
		/// Size of QoS header added to each sent chunk.
		static constexpr size_t s_MaxPacketSize = sizeof(uint32_t);
		static constexpr size_t s_PacketIdSize = sizeof(uint32_t);
		static constexpr size_t s_ChunkIdSize = sizeof(uint32_t);
		static constexpr size_t s_HeaderSize = s_MaxPacketSize + s_PacketIdSize + s_ChunkIdSize;
		static constexpr size_t s_MinFrameSize = 64U;
		static constexpr size_t s_MinBodySize = s_MinFrameSize - s_HeaderSize;

		class PacketSplitter
		{
		public:
			PacketSplitter(ByteView data, uint32_t id);
			bool Update(size_t sent);
			ByteVector NextChunk() const;
			bool HasMore() const;

		private:
			ByteView m_Data;
			uint32_t m_PacketId;
			uint32_t m_ChunkId;
		};

		/// Get next packet.
		/// @returns ByteVector whole packet when it's ready or empty buffer otherwise.
		ByteVector GetNextPacket();

		/// Push chunk to QoS storage to handle merging and ordering.
		/// @param chunkWithHeader received packet. Device will add QoS header before sending any chunk.
		void PushReceivedChunk(ByteView chunkWithHeader);

		/// Push chunk to QoS storage to handle merging and ordering.
		/// @param packetId id of the packet.
		/// @param chunkId id of the chunk.
		/// @param expectedSize expected size of whole packet.
		/// @param chunk chunk of packet.
		void PushReceivedChunk(uint32_t packetId, uint32_t chunkId, uint32_t expectedSize, ByteView chunk);

		PacketSplitter GetPacketSplitter(ByteView data);
	};
}

