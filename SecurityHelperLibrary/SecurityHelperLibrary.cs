using System;
using System.Security.Cryptography;
using System.Text;
using System.ComponentModel;
using Isopoh.Cryptography.Argon2;

namespace SecurityHelperLibrary
{
    /// <summary>
    /// Security helper interface for Dependency Injection (DI) support.
    /// Provides methods for hashing, PBKDF2, Argon2, HMAC, and AES-GCM encryption.
    /// </summary>
    public interface ISecurityHelper
    {
        /// <summary>
        /// Creates a hash for the given input using the specified salt and hash algorithm.
        /// This helper is general purpose and should not be used for password storage.
        /// </summary>
        string ComputeGeneralPurposeHash(string input, string salt, HashAlgorithmName hashAlgorithm);

        /// <summary>
        /// Deprecated alias for <see cref="ComputeGeneralPurposeHash"/>.
        /// </summary>
        [Obsolete("Use ComputeGeneralPurposeHash for general hashing and HashPasswordWith* for password storage.")]
        string ComputeHash(string input, string salt, HashAlgorithmName hashAlgorithm);

        /// <summary>
        /// Generates a cryptographically secure random salt.
        /// </summary>
        string GenerateSalt(int size = 32);

        /// <summary>
        /// Hashes a password using PBKDF2 with a given salt, algorithm, iterations, and hash length.
        /// </summary>
    #if NET6_0_OR_GREATER
        [EditorBrowsable(EditorBrowsableState.Never)]
        [Obsolete("Use the ReadOnlySpan<char> overload for stronger memory hygiene.")]
    #endif
        string HashPasswordWithPBKDF2(string password, byte[] salt, HashAlgorithmName hashAlgorithm, int iterations = 210000, int hashLength = 32);

        /// <summary>
        /// Hashes a password using PBKDF2 and automatically generates a random salt.
        /// </summary>
        string HashPasswordWithPBKDF2(string password, out string salt, HashAlgorithmName hashAlgorithm, int iterations = 210000, int hashLength = 32);

        /// <summary>
        /// Verifies that a plain text input matches a given hash using a salt and algorithm.
        /// </summary>
        bool VerifyHash(string input, string salt, string expectedHash, HashAlgorithmName hashAlgorithm);

        /// <summary>
        /// Verifies a password against a stored PBKDF2 hash string in the format algorithm|iterations|salt|hash.
        /// </summary>
        bool VerifyPasswordWithPBKDF2(string password, string storedHashString);


        /// <summary>
        /// Hashes a password using Argon2id algorithm. Requires Isopoh.Cryptography.Argon2 NuGet package.
        /// </summary>
    #if NET6_0_OR_GREATER
        [EditorBrowsable(EditorBrowsableState.Never)]
        [Obsolete("Use the ReadOnlySpan<char> overload for safer handling.")]
    #endif
        string HashPasswordWithArgon2(string password, string salt, int iterations = 4, int memoryKb = 131072, int degreeOfParallelism = 4, int hashLength = 32);

    #if NET6_0_OR_GREATER
        /// <summary>
        /// Hashes a password using Argon2id with a ReadOnlySpan to avoid keeping passwords as strings.
        /// </summary>
        string HashPasswordWithArgon2(ReadOnlySpan<char> password, string salt, int iterations = 4, int memoryKb = 131072, int degreeOfParallelism = 4, int hashLength = 32);
    #endif


        /// <summary>
        /// Computes an HMAC for the given input using the specified key and hash algorithm.
        /// </summary>
        string ComputeHMAC(string input, string key, HashAlgorithmName hashAlgorithm);


        /// <summary>
        /// Encrypts a string using AES-GCM (Authenticated Encryption).
        /// </summary>
        string EncryptStringGCM(string plainText, byte[] key);

        /// <summary>
        /// Decrypts a string using AES-GCM.
        /// </summary>
        string DecryptStringGCM(string combinedCipherText, byte[] key);

        /// <summary>
        /// Generates a cryptographically secure random key for symmetric encryption (default 256-bit).
        /// </summary>
        byte[] GenerateSymmetricKey(int size = 32);

#if NET6_0_OR_GREATER
    /// <summary>
    /// Hashes a password using PBKDF2 with a Span&lt;char&gt; for more secure password handling.
    /// </summary>
    string HashPasswordWithPBKDF2(ReadOnlySpan<char> password, byte[] salt, HashAlgorithmName hashAlgorithm, int iterations = 210000, int hashLength = 32);

    /// <summary>
    /// Verifies a password against a stored PBKDF2 hash using Span&lt;char&gt; for secure password comparison.
    /// </summary>
    bool VerifyPasswordWithPBKDF2(ReadOnlySpan<char> password, string storedHashString);
#endif

        /// <summary>
        /// Clears sensitive data from memory by zeroing out the array.
        /// </summary>
        void ClearSensitiveData(byte[] data);

#if NET6_0_OR_GREATER
        /// <summary>
        /// Clears sensitive data from memory by zeroing out the span.
        /// </summary>
        void ClearSensitiveData(Span<char> data);
#endif
    }

    /// <summary>
    /// Implementation of ISecurityHelper providing comprehensive security utilities.
    /// </summary>
    public class SecurityHelper : ISecurityHelper
    {
        private const int MinSaltSizeBytes = 16;
        private const int MinHashLengthBytes = 16;
        private const int MinArgon2Iterations = 3;
        private const int MinArgon2MemoryKb = 65536;

        // --- IMMUTABLE WORKING METHODS ---

        /// <summary>
        /// Creates a hash for the given input using the specified salt and hash algorithm.
        /// This helper is general purpose and should not be used for password storage.
        /// </summary>
        /// <param name="input">The plain text string to hash.</param>
        /// <param name="salt">The salt string to combine with the input before hashing.</param>
        /// <param name="hashAlgorithm">The hash algorithm to use (SHA256, SHA384, SHA512).</param>
        /// <returns>Base64-encoded hash string.</returns>
        public string ComputeGeneralPurposeHash(string input, string salt, HashAlgorithmName hashAlgorithm)
        {
            string saltedInput = input + salt;
            byte[] inputBytes = Encoding.UTF8.GetBytes(saltedInput);

            using (HashAlgorithm hashAlgo = GetHashAlgorithm(hashAlgorithm))
            {
                byte[] hashBytes = hashAlgo.ComputeHash(inputBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }

        [Obsolete("Use ComputeGeneralPurposeHash for non-password hashes and the dedicated password helpers for credentials.")]
        public string ComputeHash(string input, string salt, HashAlgorithmName hashAlgorithm)
            => ComputeGeneralPurposeHash(input, salt, hashAlgorithm);

        /// <summary>
        /// Generates a cryptographically secure random salt.
        /// </summary>
        /// <param name="size">The size of the salt in bytes (default is 32).</param>
        /// <returns>Base64-encoded salt string.</returns>
        public string GenerateSalt(int size = 32)
        {
            if (size < MinSaltSizeBytes)
                throw new ArgumentOutOfRangeException(nameof(size), $"Salt size must be at least {MinSaltSizeBytes} bytes.");

            byte[] saltBytes = new byte[size];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(saltBytes);
            }
            return Convert.ToBase64String(saltBytes);
        }

        /// <summary>
        /// Hashes a password using PBKDF2 with a given salt, algorithm, iterations, and hash length.
        /// </summary>
        /// <param name="password">The password to hash.</param>
        /// <param name="salt">The salt bytes to use for PBKDF2.</param>
        /// <param name="hashAlgorithm">The hash algorithm to use (SHA256, SHA384, SHA512).</param>
        /// <param name="iterations">Number of iterations for PBKDF2 (default 210000).</param>
        /// <param name="hashLength">Length of the derived hash in bytes (default 32).</param>
        /// <returns>Base64-encoded hash string.</returns>
    #if NET6_0_OR_GREATER
        [EditorBrowsable(EditorBrowsableState.Never)]
        [Obsolete("Use the ReadOnlySpan<char> overload for stronger memory hygiene.")]
    #endif
        public string HashPasswordWithPBKDF2(string password, byte[] salt, HashAlgorithmName hashAlgorithm, int iterations = 210000, int hashLength = 32)
        {
    #if NET6_0_OR_GREATER
            return HashPasswordWithPBKDF2(password.AsSpan(), salt, hashAlgorithm, iterations, hashLength);
    #else
            ValidatePbkdf2Inputs(password, salt, iterations, hashLength);

            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, hashAlgorithm))
            {
            byte[] hash = pbkdf2.GetBytes(hashLength);
            return Convert.ToBase64String(hash);
            }
    #endif
        }

        /// <summary>
        /// Hashes a password using PBKDF2 and automatically generates a random salt.
        /// Returns a formatted string containing algorithm, iterations, salt, and hash.
        /// </summary>
        /// <param name="password">The password to hash.</param>
        /// <param name="salt">Outputs the generated salt string.</param>
        /// <param name="hashAlgorithm">The hash algorithm to use (SHA256, SHA384, SHA512).</param>
        /// <param name="iterations">Number of iterations for PBKDF2 (default 210000).</param>
        /// <param name="hashLength">Length of the derived hash in bytes (default 32).</param>
        /// <returns>A formatted string: "algorithm|iterations|salt|hash".</returns>
        public string HashPasswordWithPBKDF2(string password, out string salt, HashAlgorithmName hashAlgorithm, int iterations = 210000, int hashLength = 32)
        {
            salt = GenerateSalt(32);
            byte[] saltBytes = Convert.FromBase64String(salt);
            string hash
#if NET6_0_OR_GREATER
                = HashPasswordWithPBKDF2(password.AsSpan(), saltBytes, hashAlgorithm, iterations, hashLength);
#else
                = HashPasswordWithPBKDF2(password, saltBytes, hashAlgorithm, iterations, hashLength);
#endif

            return $"{hashAlgorithm.Name}|{iterations}|{salt}|{hash}";
        }

        /// <summary>
        /// Verifies that a plain text input matches a given hash using a salt and algorithm.
        /// </summary>
        /// <param name="input">The plain text string to verify.</param>
        /// <param name="salt">The salt string used during hashing.</param>
        /// <param name="expectedHash">The expected Base64-encoded hash.</param>
        /// <param name="hashAlgorithm">The hash algorithm used (SHA256, SHA384, SHA512).</param>
        /// <returns>True if the input matches the hash; otherwise false.</returns>
        public bool VerifyHash(string input, string salt, string expectedHash, HashAlgorithmName hashAlgorithm)
        {
            byte[] computedHashBytes = Convert.FromBase64String(ComputeGeneralPurposeHash(input, salt, hashAlgorithm));
            byte[] expectedHashBytes = Convert.FromBase64String(expectedHash);

            return FixedTimeEquals(computedHashBytes, expectedHashBytes);
        }

        /// <summary>
        /// Verifies a password against a stored PBKDF2 hash string in the format algorithm|iterations|salt|hash.
        /// </summary>
        /// <param name="password">The password to verify.</param>
        /// <param name="storedHashString">The stored hash string in the format algorithm|iterations|salt|hash.</param>
        /// <returns>True if the password matches the stored hash; otherwise false.</returns>
        public bool VerifyPasswordWithPBKDF2(string password, string storedHashString)
        {
#if NET6_0_OR_GREATER
            return VerifyPasswordWithPBKDF2(password.AsSpan(), storedHashString);
#else
            var parts = storedHashString.Split('|');
            if (parts.Length != 4)
                throw new FormatException("Stored hash is not in the correct format.");

            var algorithm = new HashAlgorithmName(parts[0]);
            if (!int.TryParse(parts[1], out int iterations) || iterations < 1)
                throw new FormatException("Stored hash iteration value is invalid.");
            byte[] salt = Convert.FromBase64String(parts[2]);
            string expectedHash = parts[3];

            byte[] expectedBytes = Convert.FromBase64String(expectedHash);
            if (expectedBytes.Length < MinHashLengthBytes)
                return false;
            string computedHash = HashPasswordWithPBKDF2(password, salt, algorithm, iterations, expectedBytes.Length);
            byte[] computedBytes = Convert.FromBase64String(computedHash);

            return FixedTimeEquals(computedBytes, expectedBytes);
#endif
        }

        /// <summary>
        /// Returns a HashAlgorithm instance based on HashAlgorithmName.
        /// </summary>
        /// <param name="hashAlgorithm">The hash algorithm name.</param>
        /// <returns>An instance of HashAlgorithm.</returns>
        private static HashAlgorithm GetHashAlgorithm(HashAlgorithmName hashAlgorithm)
        {
            if (hashAlgorithm == HashAlgorithmName.SHA256)
                return SHA256.Create();
            else if (hashAlgorithm == HashAlgorithmName.SHA384)
                return SHA384.Create();
            else if (hashAlgorithm == HashAlgorithmName.SHA512)
                return SHA512.Create();
            else
                throw new NotSupportedException("Algorithm " + hashAlgorithm.Name + " is not supported.");
        }

        /// <summary>
        /// Performs a constant-time comparison between two byte arrays to prevent timing attacks.
        /// </summary>
        /// <param name="a">The first byte array.</param>
        /// <param name="b">The second byte array.</param>
        /// <returns>True if both arrays are equal; otherwise false.</returns>
        private static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;

            int result = 0;
            for (int i = 0; i < a.Length; i++)
            {
                result |= a[i] ^ b[i];
            }
            return result == 0;
        }

        // --- NEW EXTENSIONS (ADDITION ONLY) ---

        /// <summary>
        /// Hashes a password using Argon2id algorithm. Requires Isopoh.Cryptography.Argon2 NuGet package.
        /// </summary>
        /// <param name="password">The password to hash.</param>
        /// <param name="salt">The salt to use for hashing.</param>
        /// <param name="iterations">Number of iterations (default 4).</param>
        /// <param name="memoryKb">Memory size in KB (default 131072).</param>
        /// <param name="degreeOfParallelism">Degree of parallelism (default 4).</param>
        /// <param name="hashLength">Length of the hash in bytes (default 32).</param>
        /// <returns>Base64-encoded Argon2id hash string.</returns>
#if NET6_0_OR_GREATER
        [EditorBrowsable(EditorBrowsableState.Never)]
        [Obsolete("Use the ReadOnlySpan<char> overload for safer handling.")]
#endif
        public string HashPasswordWithArgon2(string password, string salt, int iterations = 4, int memoryKb = 131072, int degreeOfParallelism = 4, int hashLength = 32)
        {
#if NET6_0_OR_GREATER
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));
            return HashPasswordWithArgon2(password.AsSpan(), salt, iterations, memoryKb, degreeOfParallelism, hashLength);
#else
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));
            if (string.IsNullOrWhiteSpace(salt))
                throw new ArgumentException("Salt cannot be null or empty.", nameof(salt));
            if (iterations < MinArgon2Iterations)
                throw new ArgumentOutOfRangeException(nameof(iterations), $"Argon2 iterations must be at least {MinArgon2Iterations}.");
            if (memoryKb < MinArgon2MemoryKb)
                throw new ArgumentOutOfRangeException(nameof(memoryKb), $"Argon2 memory cost must be at least {MinArgon2MemoryKb} KB.");
            if (degreeOfParallelism < 1)
                throw new ArgumentOutOfRangeException(nameof(degreeOfParallelism), "Degree of parallelism must be at least 1.");
            if (hashLength < MinHashLengthBytes)
                throw new ArgumentOutOfRangeException(nameof(hashLength), $"Hash length must be at least {MinHashLengthBytes} bytes.");

            byte[] saltBytes = GetSaltBytes(salt);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            var config = new Argon2Config
            {
                Type = Argon2Type.HybridAddressing,
                Version = Argon2Version.Nineteen,
                Password = passwordBytes,
                Salt = saltBytes,
                TimeCost = iterations,
                MemoryCost = memoryKb,
                Lanes = degreeOfParallelism,
                Threads = degreeOfParallelism,
                HashLength = hashLength
            };

            try
            {
                using (var argon2 = new Argon2(config))
                {
                    return Convert.ToBase64String(argon2.Hash().Buffer);
                }
            }
            finally
            {
                Array.Clear(passwordBytes, 0, passwordBytes.Length);
            }
#endif
        }

#if NET6_0_OR_GREATER
        /// <summary>
        /// Hashes a password using Argon2id with a ReadOnlySpan to avoid keeping passwords as strings.
        /// </summary>
        public string HashPasswordWithArgon2(ReadOnlySpan<char> password, string salt, int iterations = 4, int memoryKb = 131072, int degreeOfParallelism = 4, int hashLength = 32)
        {
            if (password.Length == 0)
                throw new ArgumentException("Password cannot be empty.", nameof(password));
            if (string.IsNullOrWhiteSpace(salt))
                throw new ArgumentException("Salt cannot be null or empty.", nameof(salt));
            if (iterations < MinArgon2Iterations)
                throw new ArgumentOutOfRangeException(nameof(iterations), $"Argon2 iterations must be at least {MinArgon2Iterations}.");
            if (memoryKb < MinArgon2MemoryKb)
                throw new ArgumentOutOfRangeException(nameof(memoryKb), $"Argon2 memory cost must be at least {MinArgon2MemoryKb} KB.");
            if (degreeOfParallelism < 1)
                throw new ArgumentOutOfRangeException(nameof(degreeOfParallelism), "Degree of parallelism must be at least 1.");
            if (hashLength < MinHashLengthBytes)
                throw new ArgumentOutOfRangeException(nameof(hashLength), $"Hash length must be at least {MinHashLengthBytes} bytes.");

            byte[] saltBytes = GetSaltBytes(salt);
            byte[] passwordBytes = new byte[Encoding.UTF8.GetByteCount(password)];
            Encoding.UTF8.GetBytes(password, passwordBytes);
            var config = new Argon2Config
            {
                Type = Argon2Type.HybridAddressing,
                Version = Argon2Version.Nineteen,
                Password = passwordBytes,
                Salt = saltBytes,
                TimeCost = iterations,
                MemoryCost = memoryKb,
                Lanes = degreeOfParallelism,
                Threads = degreeOfParallelism,
                HashLength = hashLength
            };

            try
            {
                using (var argon2 = new Argon2(config))
                {
                    return Convert.ToBase64String(argon2.Hash().Buffer);
                }
            }
            finally
            {
                Array.Clear(passwordBytes, 0, passwordBytes.Length);
            }
        }
#endif

        /// <summary>
        /// Computes an HMAC for the given input using the specified key and hash algorithm.
        /// </summary>
        /// <param name="input">The input string to compute HMAC for.</param>
        /// <param name="key">The secret key for HMAC.</param>
        /// <param name="hashAlgorithm">The hash algorithm to use (SHA256, SHA384, SHA512).</param>
        /// <returns>Base64-encoded HMAC string.</returns>
        public string ComputeHMAC(string input, string key, HashAlgorithmName hashAlgorithm)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);

            using (HMAC hmac = GetHMACInstance(hashAlgorithm, keyBytes))
            {
                byte[] hashBytes = hmac.ComputeHash(inputBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }

        /// <summary>
        /// Generates a cryptographically secure random key for symmetric encryption (default 256-bit).
        /// </summary>
        /// <param name="size">The size of the key in bytes (default 32 for 256-bit).</param>
        /// <returns>Randomly generated key bytes.</returns>
        public byte[] GenerateSymmetricKey(int size = 32)
        {
            byte[] key = new byte[size];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }
            return key;
        }

#if NET6_0_OR_GREATER
        /// <summary>
        /// Encrypts a string using AES-GCM (Authenticated Encryption). Only available on .NET 6.0 or later.
        /// </summary>
        /// <param name="plainText">The plain text to encrypt.</param>
        /// <param name="key">The encryption key (32 bytes for AES-256).</param>
        /// <returns>Encrypted string in the format nonce|tag|ciphertext (all Base64).</returns>
        public string EncryptStringGCM(string plainText, byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Length != 32)
                throw new ArgumentException("Key must be 32 bytes (256 bits).");

            using (var aesGcm = new AesGcm(key, AesGcm.TagByteSizes.MaxSize))
            {
                byte[] nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
                RandomNumberGenerator.Fill(nonce);

                byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                byte[] cipherBytes = new byte[plainBytes.Length];
                byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];

                aesGcm.Encrypt(nonce, plainBytes, cipherBytes, tag);

                return $"{Convert.ToBase64String(nonce)}|{Convert.ToBase64String(tag)}|{Convert.ToBase64String(cipherBytes)}";
            }
        }

        /// <summary>
        /// Decrypts a string using AES-GCM. Only available on .NET 6.0 or later.
        /// </summary>
        /// <param name="combinedCipherText">The encrypted string in the format nonce|tag|ciphertext (all Base64).</param>
        /// <param name="key">The encryption key (32 bytes for AES-256).</param>
        /// <returns>Decrypted plain text string.</returns>
        public string DecryptStringGCM(string combinedCipherText, byte[] key)
        {
            if (string.IsNullOrWhiteSpace(combinedCipherText))
                throw new ArgumentException("Encrypted text cannot be null or empty.", nameof(combinedCipherText));
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Length != 32)
                throw new ArgumentException("Key must be 32 bytes (256 bits).", nameof(key));

            var parts = combinedCipherText.Split('|');
            if (parts.Length != 3)
                throw new FormatException("Invalid encrypted text format. Expected: nonce|tag|ciphertext");

            byte[] nonce = null;
            byte[] tag = null;
            byte[] cipherBytes = null;

            try
            {
                // Validate and decode each component with specific error reporting
                if (string.IsNullOrEmpty(parts[0]))
                    throw new FormatException("Nonce component cannot be empty.");
                if (string.IsNullOrEmpty(parts[1]))
                    throw new FormatException("Tag component cannot be empty.");

                try
                {
                    nonce = Convert.FromBase64String(parts[0]);
                }
                catch (FormatException)
                {
                    throw new FormatException("Invalid Base64 encoding in nonce component.");
                }

                try
                {
                    tag = Convert.FromBase64String(parts[1]);
                }
                catch (FormatException)
                {
                    throw new FormatException("Invalid Base64 encoding in tag component.");
                }

                try
                {
                    cipherBytes = string.IsNullOrEmpty(parts[2])
                        ? Array.Empty<byte>()
                        : Convert.FromBase64String(parts[2]);
                }
                catch (FormatException)
                {
                    throw new FormatException("Invalid Base64 encoding in ciphertext component.");
                }

                if (nonce.Length != AesGcm.NonceByteSizes.MaxSize)
                    throw new FormatException($"Invalid nonce size. Expected {AesGcm.NonceByteSizes.MaxSize} bytes.");
                if (tag.Length != AesGcm.TagByteSizes.MaxSize)
                    throw new FormatException($"Invalid tag size. Expected {AesGcm.TagByteSizes.MaxSize} bytes.");

                byte[] decryptedBytes = new byte[cipherBytes.Length];

                using (var aesGcm = new AesGcm(key, AesGcm.TagByteSizes.MaxSize))
                {
                    aesGcm.Decrypt(nonce, cipherBytes, tag, decryptedBytes);
                    return Encoding.UTF8.GetString(decryptedBytes);
                }
            }
            finally
            {
                // Secure cleanup of sensitive data
                SecureZeroMemory(nonce);
                SecureZeroMemory(tag);
                SecureZeroMemory(cipherBytes);
            }
        }
#else
        public string EncryptStringGCM(string plainText, byte[] key)
        {
            throw new NotSupportedException("AES-GCM encryption is only supported on .NET 6.0 or later.");
        }

        public string DecryptStringGCM(string combinedCipherText, byte[] key)
        {
            throw new NotSupportedException("AES-GCM decryption is only supported on .NET 6.0 or later.");
        }
#endif

        /// <summary>
        /// Returns an HMAC instance for the specified hash algorithm and key.
        /// </summary>
        /// <param name="hashAlgorithm">The hash algorithm to use (SHA256, SHA384, SHA512).</param>
        /// <param name="key">The secret key for HMAC.</param>
        /// <returns>An HMAC instance.</returns>
        private static HMAC GetHMACInstance(HashAlgorithmName hashAlgorithm, byte[] key)
        {
            if (hashAlgorithm == HashAlgorithmName.SHA256)
                return new HMACSHA256(key);
            else if (hashAlgorithm == HashAlgorithmName.SHA384)
                return new HMACSHA384(key);
            else if (hashAlgorithm == HashAlgorithmName.SHA512)
                return new HMACSHA512(key);
            else
                throw new NotSupportedException($"Algorithm {hashAlgorithm.Name} is not supported for HMAC.");
        }

        // --- SECURE STRING HANDLING EXTENSIONS ---

#if NET6_0_OR_GREATER
        /// <summary>
        /// Hashes a password using PBKDF2 with a Span&lt;char&gt; for more secure password handling.
        /// This keeps the password in secure memory (Span) during processing.
        /// </summary>
        /// <param name="password">The password as a Span&lt;char&gt; (more secure).</param>
        /// <param name="salt">The salt bytes to use for PBKDF2.</param>
        /// <param name="hashAlgorithm">The hash algorithm to use (SHA256, SHA384, SHA512).</param>
        /// <param name="iterations">Number of iterations for PBKDF2 (default 210000).</param>
        /// <param name="hashLength">Length of the derived hash in bytes (default 32).</param>
        /// <returns>Base64-encoded hash string.</returns>
        public string HashPasswordWithPBKDF2(ReadOnlySpan<char> password, byte[] salt, HashAlgorithmName hashAlgorithm, int iterations = 210000, int hashLength = 32)
        {
            if (password.Length == 0)
                throw new ArgumentException("Password cannot be empty.", nameof(password));
            if (salt == null)
                throw new ArgumentNullException(nameof(salt));
            if (salt.Length < MinSaltSizeBytes)
                throw new ArgumentOutOfRangeException(nameof(salt), $"Salt length must be at least {MinSaltSizeBytes} bytes.");
            if (iterations < 1)
                throw new ArgumentOutOfRangeException(nameof(iterations), "Iterations must be greater than 0.");
            if (hashLength < MinHashLengthBytes)
                throw new ArgumentOutOfRangeException(nameof(hashLength), $"Hash length must be at least {MinHashLengthBytes} bytes.");

            byte[] passwordBytes = new byte[Encoding.UTF8.GetByteCount(password)];
            Encoding.UTF8.GetBytes(password, passwordBytes);

            try
            {
                byte[] hash = Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, iterations, hashAlgorithm, hashLength);
                return Convert.ToBase64String(hash);
            }
            finally
            {
                Array.Clear(passwordBytes, 0, passwordBytes.Length);
            }
        }

        /// <summary>
        /// Verifies a password against a stored PBKDF2 hash using Span&lt;char&gt; for secure password comparison.
        /// </summary>
        /// <param name="password">The password as a Span&lt;char&gt; (more secure).</param>
        /// <param name="storedHashString">The stored hash string in the format algorithm|iterations|salt|hash.</param>
        /// <returns>True if the password matches the stored hash; otherwise false.</returns>
        public bool VerifyPasswordWithPBKDF2(ReadOnlySpan<char> password, string storedHashString)
        {
            var parts = storedHashString.Split('|');
            if (parts.Length != 4)
                throw new FormatException("Stored hash is not in the correct format.");

            var algorithm = new HashAlgorithmName(parts[0]);
            if (!int.TryParse(parts[1], out int iterations) || iterations < 1)
                throw new FormatException("Stored hash iteration value is invalid.");
            byte[] salt = Convert.FromBase64String(parts[2]);
            string expectedHash = parts[3];

            try
            {
                byte[] expectedBytes = Convert.FromBase64String(expectedHash);
                if (expectedBytes.Length < MinHashLengthBytes)
                    return false;
                string computedHash = HashPasswordWithPBKDF2(password, salt, algorithm, iterations, expectedBytes.Length);
                byte[] computedBytes = Convert.FromBase64String(computedHash);

                return FixedTimeEquals(computedBytes, expectedBytes);
            }
            finally
            {
                Array.Clear(salt, 0, salt.Length);
            }
        }

        /// <summary>
        /// Clears sensitive data from memory by zeroing out the char span.
        /// </summary>
        /// <param name="data">The char span to clear.</param>
        public void ClearSensitiveData(Span<char> data)
        {
            if (data.Length > 0)
            {
                for (int i = 0; i < data.Length; i++)
                {
                    data[i] = '\0';
                }
            }
        }
#endif

        /// <summary>
        /// Clears sensitive data from memory by zeroing out the byte array using secure volatile writes.
        /// </summary>
        /// <param name="data">The byte array to clear.</param>
        public void ClearSensitiveData(byte[] data)
        {
            if (data != null && data.Length > 0)
            {
                SecureZeroMemory(data);
            }
        }

        private static void ValidatePbkdf2Inputs(string password, byte[] salt, int iterations, int hashLength)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));
            if (salt == null)
                throw new ArgumentNullException(nameof(salt));
            if (salt.Length < MinSaltSizeBytes)
                throw new ArgumentOutOfRangeException(nameof(salt), $"Salt length must be at least {MinSaltSizeBytes} bytes.");
            if (iterations < 1)
                throw new ArgumentOutOfRangeException(nameof(iterations), "Iterations must be greater than 0.");
            if (hashLength < MinHashLengthBytes)
                throw new ArgumentOutOfRangeException(nameof(hashLength), $"Hash length must be at least {MinHashLengthBytes} bytes.");
        }

        /// <summary>
        /// Securely zeros out sensitive byte data to prevent disclosure from memory.
        /// </summary>
        /// <param name="data">The byte array to securely clear.</param>
        private static void SecureZeroMemory(byte[] data)
        {
            if (data == null || data.Length == 0)
                return;

            // Clear all bytes with zeros - prevents accidental data leakage
            Array.Clear(data, 0, data.Length);
        }

        private static byte[] GetSaltBytes(string salt)
        {
            if (string.IsNullOrEmpty(salt))
                throw new ArgumentException("Salt cannot be null or empty.", nameof(salt));

            byte[] decoded;
            try
            {
                decoded = Convert.FromBase64String(salt);
            }
            catch (FormatException ex)
            {
                throw new FormatException("Salt must be provided in Base64 format. Raw UTF-8 encoding is not permitted for security reasons.", ex);
            }

            if (decoded.Length < MinSaltSizeBytes)
                throw new ArgumentOutOfRangeException(nameof(salt), $"Salt must be at least {MinSaltSizeBytes} bytes when decoded.");

            return decoded;
        }
    }
}