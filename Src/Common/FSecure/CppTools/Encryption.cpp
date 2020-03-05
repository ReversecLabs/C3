#include "StdAfx.h"

#include "Encryption.h"

namespace
{
	// Functions in this anonymous namespace are from https://gist.github.com/rverton/a44fc8ca67ab9ec32089
	// The author did not publish the license.
	// Updates ware made to avoid access violation.

	/// @Brief size of pseudo random keystream used by RC4.
	constexpr auto N = 256u;

	/// @Brief Initialization of pseudo random keystream with key.
	///
	/// @param key IN argument. Used to create keystream.
	/// @param len IN argument. Size of key in bytes.
	/// @param keystream OUT argument. Generated keystream.
	void KeySchedulingAlgorithm(const char* key, size_t len, unsigned char* keystream)
	{
		for (auto i = 0u; i < N; i++)
			keystream[i] = static_cast<unsigned char>(i);

		for (auto i = 0u, j = 0u; i < N; i++)
		{
			j = (j + keystream[i] + key[i % len]) % N;
			std::swap(keystream[i], keystream[j]);
		}
	}

	/// @brief Encrypting data with usage of keystream.
	///
	/// @param keystream IN/OUT argument. Keystream used for encryption. With each iteration keystream is modified.
	/// @param plainText IN argument. Data to encrypt.
	/// @param cipherText OUT argument. Calculated from input data and keystream.
	/// @param textSize. Determines number of bytes read from plainText, and written to cipherText.
	void PseudoRandomGenerationAlgorithm(unsigned char* keystream, const char* plainText, char* cipherText, size_t textSize)
	{
		for (auto n = 0u, i = 0u, j = 0u; n < textSize; n++)
		{
			i = (i + 1) % N;
			j = (j + keystream[i]) % N;

			std::swap(keystream[i], keystream[j]);
			auto rnd = keystream[(keystream[i] + keystream[j]) % N];

			cipherText[n] = rnd ^ plainText[n];
		}
	}


	/// @brief Implementation of RC4 algorithm.
	///
	/// @note RC4 is a symmetric algorithm. Use this function to decipher text previously encrypted with same key.
	/// @param key IN argument. Key used to calculate cipherText.
	/// @param keySize IN argument. Size of key in bytes.
	/// @plainText IN argument. Data to encrypt.
	/// @cipherText OUT argument. Encrypted message, result of RC4 algorithm.
	/// @param textSize. Determines number of bytes read from plainText, and written to cipherText.
	void RC4(const char* key, size_t keySize, const char* plainText, char* cipherText, size_t textSize)
	{
		unsigned char keystream[N];
		KeySchedulingAlgorithm(key, keySize, keystream);
		PseudoRandomGenerationAlgorithm(keystream, plainText, cipherText, textSize);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::Encryption::RC4(ByteView data, ByteView key)
{
	auto transformed = ByteVector{};
	transformed.resize(data.size());
	::RC4(reinterpret_cast<const char*>(key.data()), key.size(), reinterpret_cast<const char*>(data.data()), reinterpret_cast<char*>(transformed.data()), transformed.size());

	return transformed;
}
