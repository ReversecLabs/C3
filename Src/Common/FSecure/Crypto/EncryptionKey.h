#pragma once

#include "Common/FSecure/CppTools/ByteView.h"

namespace FSecure::Crypto
{
	/// Template class for encryption keys.
	/// @tparam size Key length in bytes.
	/// @tparam Tag Token used identify Key and to eliminate conversion between same-size public and private keys.
	template <size_t size, class Tag>
	struct Key
	{
		/// Construct empty key.
		Key() = default;

		/// Construct key from byte view.
		/// @param buffer binary key data .
		/// @throws std::logic_error if data size is not equal to key size.
		Key(ByteView buffer)
		{
			if (buffer.size() != size)
				throw std::logic_error(OBF("Failed to convert data to Key - invalid data size"));

			m_Bytes = buffer;
		}

		/// Construct key from buffer.
		/// @param buffer binary key data .
		/// @throws std::logic_error if data size is not equal to key size.
		Key(ByteVector buffer)
		{
			if (buffer.size() != size)
				throw std::logic_error(OBF("Failed to convert data to Key - invalid data size"));

			m_Bytes = std::move(buffer);
		}

		/// Check if key is valid.
		/// @return false if key is empty
		bool IsValid() const noexcept
		{
			return !m_Bytes.empty();
		}

		/// Check if key is valid.
		/// @return false if key is empty.
		operator bool() const noexcept
		{
			return IsValid();
		}

		/// Get key data.
		/// @return pointer to key bytes.
		/// @throws std::logic_error if key is empty.
		ByteVector const& ToByteVector() const
		{
			if (!IsValid())
				throw std::logic_error(OBF("Failed to access key bytes - key invalid"));

			return m_Bytes;
		}

		/// Get key data.
		/// @return raw pointer to key bytes.
		/// @throws std::logic_error if key is empty.
		uint8_t const* data() const
		{
			return ToByteVector().data();
		}

		/// Represent key as base64 string.
		/// @return base64 string
		/// @throws std::logic_error if key is empty.
		std::string ToBase64() const
		{
			return cppcodec::base64_rfc4648::encode(std::string{ ByteView{ToByteVector()} });
		}

		static constexpr size_t Size = size;																			///< Key size in bytes.

	private:
		ByteVector m_Bytes;																								///< Key bytes buffer.
	};
}
