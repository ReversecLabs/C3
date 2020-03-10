#pragma once

namespace FSecure::Crypto
{
	inline namespace Sodium
	{
		/// A number sequence that is used only once.
		template<bool isForSymmetricEncryption>
		struct Nonce
		{
			/// Public constructor that fill the Nonce with a random sequence.
			Nonce() noexcept
			{
				randombytes_buf(m_Nonce, sizeof(m_Nonce));
			}

			/// Nonce bytes getter.
			/// @return Nonce bytes.
			operator uint8_t const* () const noexcept
			{
				return m_Nonce;
			}

			constexpr static size_t Size = isForSymmetricEncryption ? crypto_secretbox_NONCEBYTES : crypto_box_NONCEBYTES;	///< Size of nonce in bytes.
		private:
			uint8_t m_Nonce[Nonce::Size];																					///< Nonce buffer.
		};
	}
}