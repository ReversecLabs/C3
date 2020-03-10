using System;
using System.Linq;
using Sodium;

namespace FSecure.C3.WebController.Comms.Crypto
{
    public class KeyExchange
    {
        public const int KeyBytes = 32;
        public const int crypto_secretbox_NONCEBYTES = 24;
        public const int crypto_kx_SESSIONKEYBYTES = 32;

        public static KeyPair GenerateKeyPair()
        {
            return PublicKeyBox.GenerateKeyPair();
        }

        public static byte[] Encrypt(byte[] plaintext, byte[] txKey)
        {
            var nonce = SecretBox.GenerateNonce();
            return nonce.Concat(SecretBox.Create(plaintext, nonce, txKey)).ToArray();
        }

        public static byte[] Decrypt(byte[] message, byte[] rxKey)
        {

            var nonce = message.Take(crypto_secretbox_NONCEBYTES).ToArray();
            var cipher = message.Skip(crypto_secretbox_NONCEBYTES).ToArray();
            return SecretBox.Open(cipher, nonce, rxKey);
        }

        public static Tuple<byte[], byte[]> GenerateServerSessionKeys(KeyPair serverKeys, byte[] clientPublicKey)
        {
            var junk = new byte[Math.Max(crypto_kx_SESSIONKEYBYTES, serverKeys.PublicKey.Length)];
            var serverSecret = ScalarMult.Mult(serverKeys.PrivateKey, clientPublicKey);
            using (var serverHash = new GenericHash.GenericHashAlgorithm((byte[])null, 2 * crypto_kx_SESSIONKEYBYTES))
            {
                serverHash.Initialize();
                serverHash.TransformBlock(serverSecret, 0, serverSecret.Length, junk, 0);
                serverHash.TransformBlock(clientPublicKey, 0, serverSecret.Length, junk, 0);
                serverHash.TransformFinalBlock(serverKeys.PublicKey, 0, serverSecret.Length);
                var tx = serverHash.Hash.Take(crypto_kx_SESSIONKEYBYTES);
                var rx = serverHash.Hash.Skip(crypto_kx_SESSIONKEYBYTES);
                return Tuple.Create(rx.ToArray(), tx.ToArray());
            }
        }

        public static Tuple<byte[], byte[]> GenerateClientSessionKeys(KeyPair clientKeys, byte[] serverPublicKey)
        {
            var junk = new byte[Math.Max(crypto_kx_SESSIONKEYBYTES, clientKeys.PublicKey.Length)];
            var clientSecret = ScalarMult.Mult(clientKeys.PrivateKey, serverPublicKey);
            using (var clientHash = new GenericHash.GenericHashAlgorithm((byte[])null, 2 * crypto_kx_SESSIONKEYBYTES))
            {
                clientHash.Initialize();
                clientHash.TransformBlock(clientSecret, 0, clientSecret.Length, junk, 0);
                clientHash.TransformBlock(clientKeys.PublicKey, 0, clientSecret.Length, junk, 0);
                clientHash.TransformFinalBlock(serverPublicKey, 0, clientSecret.Length);
                var rx = clientHash.Hash.Take(crypto_kx_SESSIONKEYBYTES);
                var tx = clientHash.Hash.Skip(crypto_kx_SESSIONKEYBYTES);
                return Tuple.Create(rx.ToArray(), tx.ToArray());
            }
        }
    }
}
