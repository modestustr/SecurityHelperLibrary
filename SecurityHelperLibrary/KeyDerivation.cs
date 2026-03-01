using System;
using System.Security.Cryptography;
using System.Text;

namespace SecurityHelperLibrary
{
    /// <summary>
    /// Advanced key derivation utilities for secure cryptographic key generation.
    /// Provides HKDF (HMAC-based Key Derivation Function) implementation.
    /// </summary>
    public class KeyDerivation
    {
        /// <summary>
        /// HKDF key derivation as per RFC 5869 (Extract + Expand).
        /// Suitable for deriving multiple cryptographic keys from a single master secret.
        /// </summary>
        /// <param name="algorithm">Hash algorithm (SHA256, SHA384, SHA512)</param>
        /// <param name="inputKeyMaterial">Input key material (master secret)</param>
        /// <param name="salt">Optional salt (random value recommended)</param>
        /// <param name="info">Optional context/application-specific info</param>
        /// <param name="outputLength">Desired output key length in bytes</param>
        /// <returns>Derived key material</returns>
        public static byte[] DeriveKeyMaterial(
            HashAlgorithmName algorithm,
            byte[] inputKeyMaterial,
            byte[] salt = null,
            byte[] info = null,
            int outputLength = 32)
        {
            if (inputKeyMaterial == null || inputKeyMaterial.Length == 0)
                throw new ArgumentNullException(nameof(inputKeyMaterial), "Input key material cannot be empty");
            if (outputLength < 1 || outputLength > 255 * GetHashLength(algorithm))
                throw new ArgumentOutOfRangeException(nameof(outputLength), $"Output length must be 1-{255 * GetHashLength(algorithm)} bytes");

#if NET8_0_OR_GREATER
            byte[] output = new byte[outputLength];
            HKDF.DeriveKey(
                algorithm,
                inputKeyMaterial,
                output,
                salt ?? Array.Empty<byte>(),
                info ?? Array.Empty<byte>());

            return output;
#else
            // Step 1: Extract
            salt = salt ?? new byte[GetHashLength(algorithm)];
            byte[] prk = HkdfExtract(algorithm, salt, inputKeyMaterial);

            // Step 2: Expand
            return HkdfExpandCore(algorithm, prk, info ?? new byte[0], outputLength);
#endif
        }

        /// <summary>
        /// Backward-compatible alias for HKDF key derivation.
        /// </summary>
        public static byte[] HkdfExpand(
            HashAlgorithmName algorithm,
            byte[] inputKeyMaterial,
            byte[] salt = null,
            byte[] info = null,
            int outputLength = 32)
        {
            return DeriveKeyMaterial(algorithm, inputKeyMaterial, salt, info, outputLength);
        }

        /// <summary>
        /// HKDF Extract step (RFC 5869 Section 2.1).
        /// </summary>
        private static byte[] HkdfExtract(HashAlgorithmName algorithm, byte[] salt, byte[] inputKeyMaterial)
        {
            if (algorithm.Name == "SHA256" || algorithm == HashAlgorithmName.SHA256)
            {
                using (var sha256Hmac = new HMACSHA256(salt))
                {
                    return sha256Hmac.ComputeHash(inputKeyMaterial);
                }
            }
            else if (algorithm.Name == "SHA384" || algorithm == HashAlgorithmName.SHA384)
            {
                using (var sha384Hmac = new HMACSHA384(salt))
                {
                    return sha384Hmac.ComputeHash(inputKeyMaterial);
                }
            }
            else if (algorithm.Name == "SHA512" || algorithm == HashAlgorithmName.SHA512)
            {
                using (var sha512Hmac = new HMACSHA512(salt))
                {
                    return sha512Hmac.ComputeHash(inputKeyMaterial);
                }
            }
            else
            {
                throw new NotSupportedException($"Algorithm {algorithm.Name} not supported. Use SHA256, SHA384, or SHA512.");
            }
        }

        /// <summary>
        /// HKDF Expand step (RFC 5869 Section 2.3).
        /// </summary>
        private static byte[] HkdfExpandCore(HashAlgorithmName algorithm, byte[] prk, byte[] info, int outputLength)
        {
            int hashLen = GetHashLength(algorithm);
            int n = (outputLength + hashLen - 1) / hashLen; // Ceiling division
            byte[] okm = new byte[outputLength];
            byte[] t = new byte[0];
            byte[] buffer = new byte[hashLen + info.Length + 1];

            for (int i = 1; i <= n; i++)
            {
                // T(i) = HMAC-Hash(PRK, T(i-1) | info | counter)
                int offset = 0;
                if (t.Length > 0)
                {
                    Array.Copy(t, 0, buffer, 0, t.Length);
                    offset = t.Length;
                }
                Array.Copy(info, 0, buffer, offset, info.Length);
                buffer[offset + info.Length] = (byte)i;

                HMAC hmac = CreateHmac(algorithm, prk);
                using (hmac)
                {
                    t = hmac.ComputeHash(buffer, 0, offset + info.Length + 1);
                }

                int copyLength = Math.Min(hashLen, outputLength - (i - 1) * hashLen);
                Array.Copy(t, 0, okm, (i - 1) * hashLen, copyLength);
            }

            return okm;
        }

        /// <summary>
        /// Create appropriate HMAC instance for algorithm.
        /// </summary>
        private static HMAC CreateHmac(HashAlgorithmName algorithm, byte[] key)
        {
            if (algorithm.Name == "SHA256" || algorithm == HashAlgorithmName.SHA256)
                return new HMACSHA256(key);
            else if (algorithm.Name == "SHA384" || algorithm == HashAlgorithmName.SHA384)
                return new HMACSHA384(key);
            else if (algorithm.Name == "SHA512" || algorithm == HashAlgorithmName.SHA512)
                return new HMACSHA512(key);
            else
                throw new NotSupportedException($"Algorithm {algorithm.Name} not supported");
        }

        /// <summary>
        /// Get hash output length for given algorithm.
        /// </summary>
        private static int GetHashLength(HashAlgorithmName algorithm)
        {
            if (algorithm.Name == "SHA256" || algorithm == HashAlgorithmName.SHA256)
                return 32;
            else if (algorithm.Name == "SHA384" || algorithm == HashAlgorithmName.SHA384)
                return 48;
            else if (algorithm.Name == "SHA512" || algorithm == HashAlgorithmName.SHA512)
                return 64;
            else
                throw new NotSupportedException($"Algorithm {algorithm.Name} not supported");
        }

        /// <summary>
        /// Derive multiple keys from a single master key.
        /// Useful for deriving separate keys for different purposes (encryption, signing, etc).
        /// </summary>
        /// <param name="algorithm">Hash algorithm</param>
        /// <param name="masterKey">Master key material</param>
        /// <param name="keyCount">Number of keys to derive</param>
        /// <param name="keyLength">Length of each derived key</param>
        /// <param name="salt">Optional salt</param>
        /// <param name="context">Context string (purpose identifier)</param>
        /// <returns>Array of derived keys</returns>
        public static byte[][] DeriveMultipleKeys(
            HashAlgorithmName algorithm,
            byte[] masterKey,
            int keyCount,
            int keyLength,
            byte[] salt = null,
            string context = "")
        {
            if (masterKey == null || masterKey.Length == 0)
                throw new ArgumentNullException(nameof(masterKey));
            if (keyCount < 1 || keyCount > 255)
                throw new ArgumentOutOfRangeException(nameof(keyCount), "Must be 1-255");
            if (keyLength < 1)
                throw new ArgumentOutOfRangeException(nameof(keyLength), "Must be at least 1");

            byte[] contextBytes = Encoding.UTF8.GetBytes(context ?? "");
            int totalLength = keyCount * keyLength;

            byte[] derivedMaterial = DeriveKeyMaterial(algorithm, masterKey, salt, contextBytes, totalLength);

            byte[][] keys = new byte[keyCount][];
            for (int i = 0; i < keyCount; i++)
            {
                keys[i] = new byte[keyLength];
                Array.Copy(derivedMaterial, i * keyLength, keys[i], 0, keyLength);
            }

            // Securely clear derived material
            Array.Clear(derivedMaterial, 0, derivedMaterial.Length);

            return keys;
        }
    }
}
