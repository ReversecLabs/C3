#include "StdAfx.h"
#include "AESCTR.h"

#ifdef C3_IS_GATEWAY
FSecure::ByteVector FSecure::Crypto::AES_CTR_Process(FSecure::ByteView key, FSecure::ByteView iv, FSecure::ByteView input)
{
	if (key.size() != 16 && key.size() != 24 && key.size() != 32)
		throw std::invalid_argument(OBF("Invalid AES key size"));

	if (iv.size() != 16)
		throw std::invalid_argument(OBF("CTR IV must be 16 bytes"));

	BCRYPT_ALG_HANDLE hAlg = nullptr;
	BCRYPT_KEY_HANDLE hKey = nullptr;
	NTSTATUS status;

	// Open AES algorithm provider
	status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
	if (status != 0)
		throw std::runtime_error(OBF("Failed to open AES algorithm provider"));

	// Set chaining mode to ECB
	status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
		(PUCHAR)BCRYPT_CHAIN_MODE_ECB,
		(ULONG)(wcslen(BCRYPT_CHAIN_MODE_ECB) + 1) * sizeof(wchar_t),
		0);
	if (status != 0) {
		BCryptCloseAlgorithmProvider(hAlg, 0);
		throw std::runtime_error(OBF("Failed to set chaining mode to ECB"));
	}

	// Generate symmetric key
	status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
		const_cast<PUCHAR>(key.data()), (ULONG)key.size(), 0);
	if (status != 0) {
		BCryptCloseAlgorithmProvider(hAlg, 0);
		throw std::runtime_error(OBF("Failed to generate symmetric key"));
	}

	const size_t blockSize = 16;
	FSecure::ByteVector counter{ iv.begin(), iv.end() };
	FSecure::ByteVector output(input.size());

	for (size_t i = 0; i < input.size(); i += blockSize) {
		BYTE encryptedCounter[blockSize] = { 0 };
		ULONG resultSize = 0;

		// Encrypt the counter block
		status = BCryptEncrypt(hKey, counter.data(), (ULONG)blockSize, nullptr,
			nullptr, 0, encryptedCounter, blockSize, &resultSize, 0);
		if (status != 0) {
			BCryptDestroyKey(hKey);
			BCryptCloseAlgorithmProvider(hAlg, 0);
			throw std::runtime_error(OBF("Failed to encrypt counter block"));
		}

		// XOR with input
		for (size_t j = 0; j < blockSize && (i + j) < input.size(); ++j) {
			output[i + j] = input[i + j] ^ encryptedCounter[j];
		}

		// Increment counter (big-endian)
		for (int j = blockSize - 1; j >= 0; --j) {
			if (++counter[j]) break;
		}
	}

	BCryptDestroyKey(hKey);
	BCryptCloseAlgorithmProvider(hAlg, 0);
	return output;
}
#endif