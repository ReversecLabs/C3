#include "StdAfx.h"
#include "Sodium.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::Crypto::Sodium::AsymmetricKeys FSecure::Crypto::Sodium::GenerateAsymmetricKeys()
{
	ByteVector publicKey(PublicKey::Size), privateKey(PrivateKey::Size);
	if (crypto_box_keypair(publicKey.data(), privateKey.data()))
		throw std::runtime_error{ OBF("Asymmetric keys generation failed.") };

	return std::make_pair(privateKey, publicKey);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::Crypto::Sodium::SignatureKeys FSecure::Crypto::Sodium::GenerateSignatureKeys()
{
	ByteVector publicSignature(PublicSignature::Size), privateSignature(PrivateSignature::Size);
	if (crypto_sign_keypair(publicSignature.data(), privateSignature.data()))
		throw std::runtime_error{ OBF("Signature keys generation failed.") };

	return std::make_pair(privateSignature, publicSignature);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::Crypto::Sodium::SymmetricKey FSecure::Crypto::Sodium::GenerateSymmetricKey() noexcept
{
	ByteVector key(SymmetricKey::Size);
	crypto_secretbox_keygen(key.data());
	return key;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::Crypto::Sodium::EncryptAnonymously(ByteView plaintext, SymmetricKey const& key)
{
	Nonce<true> nonce;
	ByteVector encryptedMessage(plaintext.size() + crypto_secretbox_MACBYTES + Nonce<true>::Size);

	// Perpend ciphertext with nonce.
	memcpy(encryptedMessage.data(), nonce, Nonce<true>::Size);
	if (crypto_secretbox_easy(encryptedMessage.data() + Nonce<true>::Size, plaintext.data(), plaintext.size(), nonce, key.data()))
		throw std::runtime_error{ OBF("Encryption failed.") };

	return encryptedMessage;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::Crypto::Sodium::DecryptFromAnonymous(ByteView message, SymmetricKey const& key)
{
	// Sanity check.
	if (message.size() < Nonce<true>::Size + crypto_secretbox_MACBYTES)
		throw std::invalid_argument{ OBF("Ciphertext too short.") };

	// Retrieve nonce.
	auto nonce = message.SubString(0, Nonce<true>::Size), ciphertext = message.SubString(Nonce<true>::Size);

	// Decrypt.
	ByteVector decryptedMessage(ciphertext.size() - crypto_secretbox_MACBYTES);
	if (crypto_secretbox_open_easy(decryptedMessage.data(), ciphertext.data(), ciphertext.size(), nonce.data(), key.data()))
		throw std::runtime_error{ OBF("Message forged.") };

	return decryptedMessage;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::Crypto::Sodium::EncryptAnonymously(ByteView plaintext, PublicKey const& encryptionKey)
{
	ByteVector ciphertext(plaintext.size() + crypto_box_SEALBYTES);
	if (crypto_box_seal(ciphertext.data(), plaintext.data(), plaintext.size(), encryptionKey.data()))
		throw std::runtime_error{ OBF("Encryption failed.") };

	return ciphertext;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::Crypto::Sodium::DecryptFromAnonymous(ByteView ciphertext, PublicKey const& myEncryptionKey, PrivateKey const& myDecryptionKey)
{
	// Sanity check.
	if (ciphertext.size() < crypto_box_SEALBYTES)
		throw std::invalid_argument{ "Ciphertext too short." };

	ByteVector decryptedMesage(ciphertext.size() - crypto_box_SEALBYTES);
	if (crypto_box_seal_open(decryptedMesage.data(), ciphertext.data(), ciphertext.size(), myEncryptionKey.data(), myDecryptionKey.data()))
		throw std::runtime_error{ OBF("Message corrupted or not intended for this recipient.") };

	return decryptedMesage;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::Crypto::Sodium::EncryptAndSign(ByteView plaintext, SymmetricKey const& key, PrivateSignature const& signature)
{
	return EncryptAnonymously(SignMessage(plaintext, signature), key);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::Crypto::Sodium::DecryptAndVerify(ByteView ciphertext, SymmetricKey const& key, PublicSignature const& signature)
{
	return VerifyMessage(DecryptFromAnonymous(ciphertext, key), signature);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::Crypto::Sodium::EncryptAndAuthenticate(ByteView plaintext, PublicKey const& theirPublicKey, PrivateKey const& myPrivateKey)
{
	Nonce<false> nonce;
	ByteVector encryptedMessage(plaintext.size() + crypto_box_MACBYTES + Nonce<false>::Size);

	// Perpend ciphertext with nonce.
	memcpy(encryptedMessage.data(), nonce, Nonce<false>::Size);
	if (crypto_box_easy(encryptedMessage.data() + Nonce<false>::Size, plaintext.data(), plaintext.size(), nonce, theirPublicKey.data(), myPrivateKey.data()))
		throw std::runtime_error{ OBF("Encryption failed.") };

	return encryptedMessage;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::Crypto::Sodium::DecryptAndAuthenticate(ByteView message, PublicKey const& theirPublicKey, PrivateKey const& myPrivateKey)
{
	// Sanity check.
	if (message.size() < Nonce<false>::Size + crypto_box_MACBYTES)
		throw std::invalid_argument{ OBF("Ciphertext too short.") };

	// Retrieve nonce.
	auto nonce = message.SubString(0, Nonce<false>::Size), ciphertext = message.SubString(Nonce<false>::Size);

	// Decrypt.
	ByteVector decryptedMessage(ciphertext.size() - crypto_box_MACBYTES);
	if (crypto_box_open_easy(decryptedMessage.data(), ciphertext.data(), ciphertext.size(), nonce.data(), theirPublicKey.data(), myPrivateKey.data()))
		throw std::runtime_error{ OBF("Message forged.") };

	return decryptedMessage;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::Crypto::Sodium::SignMessage(ByteView message, PrivateSignature const& signature)
{
	ByteVector signedMessage(message.size() + crypto_sign_BYTES);
	if (crypto_sign(signedMessage.data(), nullptr, message.data(), message.size(), signature.data()))
		throw std::runtime_error{ OBF("Couldn't sign message.") };

	return signedMessage;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::Crypto::Sodium::VerifyMessage(ByteView signedMessage, PublicSignature const& signature)
{
	// Sanity check.
	if (signedMessage.size() < crypto_sign_BYTES)
		throw std::invalid_argument{ OBF("Signed message too short.") };

	// Verify.
	ByteVector verifiedMessage(signedMessage.size() - crypto_sign_BYTES);
	if (crypto_sign_open(verifiedMessage.data(), nullptr, signedMessage.data(), signedMessage.size(), signature.data()))
		throw std::runtime_error{ OBF("Signature verification failed.") };

	// TODO: using crypto_sign_open_detached it could return a ByteView of signedMessage without copy.
	return verifiedMessage;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::Crypto::Sodium::PublicKey FSecure::Crypto::Sodium::ConvertToKey(PublicSignature const& signature)
{
	ByteVector convertedKey(crypto_scalarmult_curve25519_BYTES);
	if (crypto_sign_ed25519_pk_to_curve25519(convertedKey.data(), signature.data()))
		throw std::runtime_error{ OBF("Signature to Key (public) Conversion failed.") };

	return convertedKey;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::Crypto::Sodium::PrivateKey FSecure::Crypto::Sodium::ConvertToKey(PrivateSignature const& signature)
{
	ByteVector convertedKey(crypto_scalarmult_curve25519_BYTES);
	if (crypto_sign_ed25519_sk_to_curve25519(convertedKey.data(), signature.data()))
		throw std::runtime_error{ OBF("Signature to Key (secret) conversion failed.") };

	return convertedKey;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::Crypto::Sodium::PublicSignature FSecure::Crypto::Sodium::ExtractPublic(PrivateSignature const& signature)
{
	ByteVector publicSignature(crypto_scalarmult_curve25519_BYTES);
	if (crypto_sign_ed25519_sk_to_pk(publicSignature.data(), signature.data()))
		throw std::runtime_error{ OBF("Signature (secret to public) conversion failed.") };

	return publicSignature;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::Crypto::Sodium::ExchangeKeys FSecure::Crypto::Sodium::GenerateExchangeKeys()
{
	ByteVector publicKey(ExchangePublicKey::Size);
	ByteVector privateKey(ExchangePrivateKey::Size);
	if (crypto_kx_keypair(publicKey.data(), privateKey.data()))
		throw std::runtime_error{ OBF("Exchange keys generation failed.") };

	return { privateKey, publicKey };
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::Crypto::Sodium::SessionKeys FSecure::Crypto::Sodium::GenerateClientSessionKeys(ExchangeKeys const& selfKeys, ExchangePublicKey const& serverKey)
{
	ByteVector rxKey(SessionRxKey::Size);
	ByteVector txKey(SessionTxKey::Size);
	if(crypto_kx_client_session_keys(rxKey.data(), txKey.data(), selfKeys.second.data(), selfKeys.first.data(), serverKey.data()))
		throw std::runtime_error{ OBF("Session keys generation failed.") };

	return { rxKey, txKey };
}

FSecure::Crypto::Sodium::SessionKeys FSecure::Crypto::Sodium::GenerateServerSessionKeys(ExchangeKeys const& selfKeys, ExchangePublicKey const& clientKey)
{
	ByteVector rxKey(SessionRxKey::Size);
	ByteVector txKey(SessionTxKey::Size);
	if (crypto_kx_server_session_keys(rxKey.data(), txKey.data(), selfKeys.second.data(), selfKeys.first.data(), clientKey.data()))
		throw std::runtime_error{ OBF("Session keys generation failed.") };

	return { rxKey, txKey };
}

FSecure::ByteVector FSecure::Crypto::Sodium::Encrypt(ByteView plaintext, SessionTxKey const& key)
{
	Nonce<true> nonce;
	ByteVector encryptedMessage(plaintext.size() + crypto_secretbox_MACBYTES + Nonce<true>::Size);

	// Perpend ciphertext with nonce.
	memcpy(encryptedMessage.data(), nonce, Nonce<true>::Size);
	if (crypto_secretbox_easy(encryptedMessage.data() + Nonce<true>::Size, plaintext.data(), plaintext.size(), nonce, key.data()))
		throw std::runtime_error{ OBF("Encryption failed.") };

	return encryptedMessage;
}

FSecure::ByteVector FSecure::Crypto::Sodium::Decrypt(ByteView message, SessionRxKey const& key)
{
	// Sanity check.
	if (message.size() < Nonce<true>::Size + crypto_secretbox_MACBYTES)
		throw std::invalid_argument{ OBF("Ciphertext too short.") };

	// Retrieve nonce.
	auto nonce = message.SubString(0, Nonce<true>::Size), ciphertext = message.SubString(Nonce<true>::Size);

	// Decrypt.
	ByteVector decryptedMessage(ciphertext.size() - crypto_secretbox_MACBYTES);
	if (crypto_secretbox_open_easy(decryptedMessage.data(), ciphertext.data(), ciphertext.size(), nonce.data(), key.data()))
		throw std::runtime_error{ OBF("Message forged.") };

	return decryptedMessage;
}
