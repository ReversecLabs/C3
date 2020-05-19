#include "StdAfx.h"
#include "QualityOfService.h"
#include "RouteId.h"
#include "Common/FSecure/CppTools/ScopeGuard.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
uint32_t FSecure::C3::QualityOfService::GetOutgouingPacketId()
{
	return m_OutgouingPacketId++;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::QualityOfService::GetNextPacket()
{
	auto it = std::find_if(m_ReciveQueue.begin(), m_ReciveQueue.end(), [](auto& e) {return e.second.IsReady(); });
	if (it == m_ReciveQueue.end())
		return {};

	auto ret = it->second.Read();
	m_ReciveQueue.erase(it);
	return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::QualityOfService::PushReceivedChunk(ByteView chunkWithHeader)
{
	if (chunkWithHeader.size() <= QualityOfService::s_HeaderSize) // Data is to short to even be chunk of packet.
		return; // skip this chunk. there is nothing that can be done with it. If sender knows it pushed chunk to short it will retransmit it.

	auto [mId, cId, expectedSize] = chunkWithHeader.Read<uint32_t, uint32_t, uint32_t>();
	PushReceivedChunk(mId, cId, expectedSize, chunkWithHeader);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::QualityOfService::PushReceivedChunk(uint32_t packetId, uint32_t chunkId, uint32_t expectedSize, ByteView chunk)
{
	auto it = m_ReciveQueue.find(packetId);
	if (it == m_ReciveQueue.end())
		m_ReciveQueue.emplace(packetId, Packet{ chunkId, expectedSize, ByteVector{ chunk } });
	else
		it->second.PushNextChunk(chunkId, expectedSize, ByteVector{ chunk });
}

FSecure::C3::PacketSplitter FSecure::C3::QualityOfService::GetPacketSplitter(ByteView data)
{
	return { data, GetOutgouingPacketId() };
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::QualityOfService::Packet::Packet(uint32_t chunkId, uint32_t expectedSize, ByteVector chunk)
	: m_ExpectedSize(expectedSize)
{

	if (chunk.size() >= QualityOfService::s_MinBodySize || chunk.size() == expectedSize)
	{
		m_Size += static_cast<uint32_t>(chunk.size());
		m_Chunks.emplace(chunkId, std::move(chunk));
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::QualityOfService::Packet::PushNextChunk(uint32_t chunkId, uint32_t expectedSize, ByteVector chunk)
{
	if (expectedSize != m_ExpectedSize)
		throw std::runtime_error{ OBF("QoS error. Received chunk of packet has wrong expected size") };

	auto it = m_Chunks.find(chunkId);
	if (it != m_Chunks.end())
		throw std::runtime_error{ OBF("QoS error. Received chunk of packet was already set") };

	if (chunk.size() >= QualityOfService::s_MinBodySize || m_Size + chunk.size() == m_ExpectedSize)
	{
		m_Size += static_cast<uint32_t>(chunk.size());
		m_Chunks.emplace(chunkId, std::move(chunk));
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::QualityOfService::Packet::Read()
{
	if (!IsReady())
		throw std::runtime_error{ OBF("QoS error. Packet is not ready") };

	ByteVector ret;
	ret.resize(m_ExpectedSize);
	auto data = ret.data();
	for (auto&& e : m_Chunks)
	{
		memcpy(data, e.second.data(), e.second.size());
		data += e.second.size();
	}

	return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool FSecure::C3::QualityOfService::Packet::IsReady()
{
	if (m_Size > m_ExpectedSize)
		throw std::runtime_error{ OBF("QoS error. Packet size is longer than expected, wrong chunks must been set.") };

	return m_Size == m_ExpectedSize;
}

FSecure::C3::PacketSplitter::PacketSplitter(ByteView data, uint32_t id)
	: m_Data{ data }, m_OryginalDataSize{ static_cast<uint32_t>(data.size()) }, m_PacketId{ id }, m_ChunkId{ 0 }
{

}

bool FSecure::C3::PacketSplitter::Update(size_t sent)
{
	auto dataSent = sent - QualityOfService::s_HeaderSize;
	if (sent < QualityOfService::s_MinFrameSize && dataSent != m_Data.size() )
		return false;

	++m_ChunkId;
	m_Data.remove_prefix(dataSent);
	return true;
}

FSecure::ByteVector FSecure::C3::PacketSplitter::NextChunk() const
{
	return ByteVector::Create(m_PacketId, m_ChunkId, m_OryginalDataSize).Concat(m_Data);
}

bool FSecure::C3::PacketSplitter::HasMore() const
{
	return !m_Data.empty();
}
