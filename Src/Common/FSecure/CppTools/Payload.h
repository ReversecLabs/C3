#pragma once
#include "ByteConverter/ByteConverter.h"
#include "Encryption.h"

#define FSECURE_PAYLOAD_GUID "15e3eda3-74c8-43d5-a4a1-e2e039542240"

namespace FSecure
{
	/// Payload type to be modified by external tool.
	/// @tparam N. Size of payload.
	/// @remarks only one specialization is allowed in the image.
	/// Compiler will try to remove payload if it is not used in executable.
	template <size_t N>
	class Payload
	{
	public:
		/// This friend declaration creates method in FSecure namespace. Two specializations will create compilation error.
		friend void PreventSpecializationOfMoreThenOnePayloadInProject() {}

		/// Get size of payload (sizeof(PAYLOAD_GUID) + N)
		constexpr static size_t RawSize()
		{
			return sizeof(m_Payload);
		}

		/// Get Size of prefix that will be used to find payload in executable.
		/// @returns size_t. Size of prefix.
		constexpr static size_t PrefixSize()
		{
			return sizeof(FSECURE_PAYLOAD_GUID);
		}

		/// Get reference to singleton object.
		/// @return Payload<N>&. Reference to singleton instance.
		static Payload<N>& Instance()
		{
			static Payload<N> self;
			return self;
		}

		/// Get access to underlying data.
		/// @return ByteView. Underlying data.
		ByteView RawData() const
		{
			return { reinterpret_cast<const uint8_t*>(m_Payload), RawSize()};
		}

		/// Get number of elements stored in payload.
		/// @return uint32_t. Number of elements.
		uint32_t Size() const
		{
			static_assert(sizeof(FSECURE_PAYLOAD_GUID) > sizeof(uint32_t));
			return *reinterpret_cast<const uint32_t*>(m_Payload + sizeof(FSECURE_PAYLOAD_GUID) - sizeof(uint32_t) - 1);
		}

		/// Get encryption key of data stored in payload.
		/// @returns ByteView. Encryption key.
		ByteView Key() const
		{
			return { reinterpret_cast<const uint8_t*>(m_Payload), sizeof(FSECURE_PAYLOAD_GUID) - sizeof(uint32_t) - 1 };
		}

		/// Access elements stored in payload.
		/// @param idx. Index of accessed element.
		/// @returns ByteVector. Accessed element.
		ByteVector operator[](uint32_t idx) const
		{
			if (idx >= Size())
				throw std::out_of_range{OBF("Out of range access. Size: ") + std::to_string(Size()) + OBF(" Index: ") + std::to_string(idx)};

			auto bv = ByteView{ reinterpret_cast<const uint8_t*>(m_Payload) + PrefixSize(), RawSize() - PrefixSize() };
			for (uint32_t i = 0; i < Size(); ++i)
			{
				auto currentSize = bv.Read<uint32_t>();
				if (i == idx)
					return Encryption::RC4(bv.SubString(0, currentSize), Key());

				bv.remove_prefix(currentSize);
			}

			throw std::logic_error{ OBF("Function should not reach end of the loop.") };
		}

		/// Find all elements for which unaryPredicate evaluates to true.
		/// @param begin. First element of range that will be checked with unaryPredicate. Function will return empty container if begin is greater or equal than size.
		/// @param end. First element of range that will be checked with unaryPredicate. Function will check only valid elements for end greater than size. Function will return empty container if end is lesser or equal than begin.
		/// @param unaryPredicate. Functor responsible for accepting elements in returned container.
		/// @returns std::vector<ByteVector>. All elements matching conditions.
		std::vector<ByteVector> FindMatching(uint32_t begin = 0, uint32_t end = Instance().Size(), std::function<bool(ByteView)> unaryPredicate = [](ByteView) {return true; })
		{
			std::vector<ByteVector> ret;
			auto bv = ByteView{ reinterpret_cast<const uint8_t*>(m_Payload) + PrefixSize(), RawSize() - PrefixSize() };
			for (uint32_t i = 0; i < std::min(end, Size()); ++i)
			{
				auto currentSize = bv.Read<uint32_t>();
				if (i >= begin)
					if (auto current = Encryption::RC4(bv.SubString(0, currentSize), Key()); unaryPredicate(current))
						ret.push_back(std::move(current));

				bv.remove_prefix(currentSize);
			}

			return ret;
		}

	private:
		/// Private constructor. Use Instance method to get reference to singleton.
		Payload()
		{
			volatile const char* payloadBuffer = m_Payload;
			// When m_Payload is used directly this `if` is optimized away (into branchless throw) in Release builds with enabled InlineFunctionExpansion
			if (!payloadBuffer[PrefixSize() - 1]) // Ensure that payload was set before use.
				throw std::logic_error{ OBF("Payload was declared but never set.") };
		}

		/// Underlying data.
		constexpr static char m_Payload[sizeof(FSECURE_PAYLOAD_GUID) + N] = FSECURE_PAYLOAD_GUID;
	};
}

#undef FSECURE_PAYLOAD_GUID
