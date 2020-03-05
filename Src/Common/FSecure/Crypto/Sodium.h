#pragma once

// Details.
#include "Nonce.h"
#include "EncryptionKey.h"

namespace FSecure::Crypto
{
	/// Wrappers for libsodium
	inline namespace Sodium
	{
		// Helper aliases.
		using PublicKey = Key<crypto_box_PUBLICKEYBYTES, struct PublicKeyTag>;
		using PrivateKey = Key<crypto_box_SECRETKEYBYTES, struct PrivateKeyTag>;
		using AsymmetricKeys = std::pair<PrivateKey, PublicKey>;
		using PublicSignature = Key<crypto_sign_PUBLICKEYBYTES, struct PublicSignatureKeyTag>;
		using PrivateSignature = Key<crypto_sign_SECRETKEYBYTES, struct PrivateSignatureKeyTag>;
		using SignatureKeys = std::pair<PrivateSignature, PublicSignature>;
		using SymmetricKey = Key<crypto_secretbox_KEYBYTES, struct SymmetricKeyTag>;
		using ExchangePublicKey = Key<crypto_kx_PUBLICKEYBYTES, struct ExchangePublicKeyTag>;
		using ExchangePrivateKey = Key<crypto_kx_SECRETKEYBYTES, struct ExchangePrivateKeyTag>;
		using ExchangeKeys = std::pair<ExchangePrivateKey, ExchangePublicKey>;
		using SessionTxKey = Key< crypto_kx_SESSIONKEYBYTES, struct SessionTxKeyTag>;
		using SessionRxKey = Key< crypto_kx_SESSIONKEYBYTES, struct SessionRxKeyTag>;
		using SessionKeys = std::pair<SessionRxKey, SessionTxKey>;

		/// Generate a key pair for asymmetric encryption.
		/// @return a pair of encryption keys (public and private).
		/// @throws std::runtime_error if keys couldn't be generated
		AsymmetricKeys GenerateAsymmetricKeys();

		/// Generate a key pair for asymmetric signature.
		/// @return a pair of signature keys (public and private).
		/// @throws std::runtime_error if keys couldn't be generated
		SignatureKeys GenerateSignatureKeys();

		/// Generate a key for asymmetric signature.
		/// @return a symmetric encryption key.
		SymmetricKey GenerateSymmetricKey() noexcept;

		/// Generate a key pair for key exchange.
		/// @returns a pair of keys to perform a key exchange (public and private).
		/// @throws std::runtime_error if keys couldn't be generated
		ExchangeKeys GenerateExchangeKeys();

		/// Generate a session keys on client side.
		/// @returns a pair of session keys to use in symmetric encryption
		/// @throws std::runtime_error if keys couldn't be generated
		SessionKeys GenerateClientSessionKeys(ExchangeKeys const& selfKeys, ExchangePublicKey const& serverKey);

		/// Generate a session keys on server side.
		/// @returns a pair of session keys to use in symmetric encryption
		/// @throws std::runtime_error if keys couldn't be generated
		SessionKeys GenerateServerSessionKeys(ExchangeKeys const& selfKeys, ExchangePublicKey const& clientKey);

		/// Decrypt a message using provided SessionTx key.
		/// @param plaintext message to encrypt.
		/// @param key session tx key.
		/// @returns Encrypted message prefixed with nonce.
		/// @throws std::runtime_error.
		ByteVector Encrypt(ByteView plaintext, SessionTxKey const& key);

		/// Decrypt a message using provided SessionRx key.
		/// @param ciphertext message to decrypt (must be prefixed with nonce used to encrypt that message).
		/// @param key session rx key.
		/// @returns Decrypted message.
		/// @throws std::invalid_argument, std::runtime_error.
		ByteVector Decrypt(ByteView message, SessionRxKey const& key);

		/// Encrypt a message using provided symmetric key.
		/// @param plaintext message to encrypt.
		/// @param key symmetric key.
		/// @return Encrypted message prefixed with nonce.
		/// @throws std::runtime_error.
		ByteVector EncryptAnonymously(ByteView plaintext, SymmetricKey const& key);

		/// Decrypt a message using provided symmetric key.
		/// @param ciphertext message to decrypt (must be prefixed with nonce used to encrypt that message).
		/// @param key symmetric key.
		/// @return Decrypted message.
		/// @throws std::invalid_argument, std::runtime_error.
		ByteVector DecryptFromAnonymous(ByteView message, SymmetricKey const& key);

		/// Encrypt a message anonymously.
		/// @param plaintext message to encrypt.
		/// @param key recipient public key.
		/// @return Encrypted message prefixed with a nonce.
		/// @throws std::runtime_error.
		ByteVector EncryptAnonymously(ByteView plaintext, PublicKey const& encryptionKey);

		/// Decrypt a message from an anonymous sender.
		/// @param ciphertext message to decrypt (must be prefixed with a nonce used to encrypt that message).
		/// @param myEncryptionKey recipients public key.
		/// @param myDecryptionKey recipients private key.
		/// @return Decrypted message.
		/// @throws std::invalid_argument, std::runtime_error.
		ByteVector DecryptFromAnonymous(ByteView ciphertext, PublicKey const& myEncryptionKey, PrivateKey const& myDecryptionKey);

		/// Encrypt a message using provided symmetric key and signs the message.
		/// @param plaintext message to encrypt.
		/// @param key symmetric key.
		/// @return Encrypted message prefixed with nonce.
		/// @throws std::runtime_error.
		ByteVector EncryptAndSign(ByteView plaintext, SymmetricKey const& key, PrivateSignature const& signature);

		/// Decrypt a message using provided symmetric key and checks sender signature.
		/// @param ciphertext message to decrypt (must be prefixed with nonce used to encrypt that message).
		/// @param key symmetric key.
		/// @return Decrypted message.
		/// @throws std::invalid_argument, std::runtime_error.
		ByteVector DecryptAndVerify(ByteView ciphertext, SymmetricKey const& key, PublicSignature const& signature);

		/// Encrypt a message and authenticates it.
		/// @param plaintext message to encrypt.
		/// @param theirPublicKey recipient's public key.
		/// @param myPrivateKey sender's private key.
		/// @return Encrypted message prefixed with a nonce.
		/// @throws std::runtime_error.
		ByteVector EncryptAndAuthenticate(ByteView plaintext, PublicKey const& theirPublicKey, PrivateKey const& myPrivateKey);

		/// Decrypt a message and verifies identity of the sender.
		/// @param message message to decrypt (must be prefixed with a nonce used to encrypt that message).
		/// @param theirPublicKey sender's public key.
		/// @param myPrivateKey recipient's private key.
		/// @return Decrypted message.
		/// @throws std::invalid_argument, std::runtime_error.
		ByteVector DecryptAndAuthenticate(ByteView message, PublicKey const& theirPublicKey, PrivateKey const& myPrivateKey);

		/// Signs a message.
		/// @param message to sign.
		/// @param signature private signature key.
		/// @return Signed message.
		/// @throws std::runtime_error.
		ByteVector SignMessage(ByteView message, PrivateSignature const& signature);

		/// Verifies a signed message.
		/// @param signedMessage message to check against signature.
		/// @param signature public signature used to verify the message.
		/// @return message without signature.
		/// @throws std::invalid_argument, std::runtime_error.
		ByteVector VerifyMessage(ByteView signedMessage, PublicSignature const& signature);

		/// Converts a public signature key to a public encryption key.
		/// @param signature public signature to convert.
		/// @return converted public encryption key.
		/// @throws std::runtime_error.
		PublicKey ConvertToKey(PublicSignature const& signature);

		/// Converts a private signature key to a private encryption key.
		/// @param signature private signature to convert.
		/// @return converted private encryption key.
		/// @throws std::runtime_error.
		PrivateKey ConvertToKey(PrivateSignature const& signature);

		/// Converts a private signature key to a public signature key.
		/// @param signature private signature to convert.
		/// @return converted public signature key.
		/// @throws std::runtime_error.
		PublicSignature ExtractPublic(PrivateSignature const& signature);
	}
}
