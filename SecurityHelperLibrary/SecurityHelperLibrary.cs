using System;
using System.Security.Cryptography;
using System.Text;
using System.ComponentModel;
using System.Threading;
using Isopoh.Cryptography.Argon2;

namespace SecurityHelperLibrary
{
    /// <summary>
    /// Implementation of ISecurityHelper providing comprehensive security utilities.
    /// </summary>
    public class SecurityHelper : ISecurityHelper
    {
        private const string GenericSecurityErrorMessage = "Invalid security parameters";
        private const int MinSaltSizeBytes = 16;
        private const int MinHashLengthBytes = 16;
        private const int MinArgon2Iterations = 3;
        private const int MinArgon2MemoryKb = 65536;
        private const int BaselineArgon2Iterations = 4;
        private const int BaselineArgon2MemoryKb = 131072;
        private const int BaselineArgon2DegreeOfParallelism = 4;
        private const int BaselineArgon2HashLength = 32;
        private const int MaxArgon2DegreeOfParallelism = 64;
        private readonly Action<string> _securityIncidentLogger;
        private readonly int _defaultArgon2Iterations;
        private readonly int _defaultArgon2MemoryKb;
        private readonly int _defaultArgon2DegreeOfParallelism;
        private readonly int _defaultArgon2HashLength;

        public SecurityHelper()
            : this((Action<string>)null)
        {
        }

        public SecurityHelper(Action<string> securityIncidentLogger)
            : this(securityIncidentLogger, null)
        {
        }

        public SecurityHelper(SecurityHelperOptions options)
            : this(null, options)
        {
        }

        public SecurityHelper(Action<string> securityIncidentLogger, SecurityHelperOptions options)
        {
            _securityIncidentLogger = securityIncidentLogger;
            if (options == null)
            {
                _defaultArgon2Iterations = BaselineArgon2Iterations;
                _defaultArgon2MemoryKb = BaselineArgon2MemoryKb;
                _defaultArgon2DegreeOfParallelism = BaselineArgon2DegreeOfParallelism;
                _defaultArgon2HashLength = BaselineArgon2HashLength;
                return;
            }

            _defaultArgon2Iterations = options.Argon2DefaultIterations >= MinArgon2Iterations
                ? options.Argon2DefaultIterations
                : MinArgon2Iterations;

            _defaultArgon2MemoryKb = options.Argon2DefaultMemoryKb >= MinArgon2MemoryKb
                ? options.Argon2DefaultMemoryKb
                : MinArgon2MemoryKb;

            _defaultArgon2DegreeOfParallelism = options.Argon2DefaultDegreeOfParallelism >= 1
                ? options.Argon2DefaultDegreeOfParallelism
                : 1;

            if (_defaultArgon2DegreeOfParallelism > MaxArgon2DegreeOfParallelism)
                _defaultArgon2DegreeOfParallelism = MaxArgon2DegreeOfParallelism;

            _defaultArgon2HashLength = options.Argon2DefaultHashLength >= MinHashLengthBytes
                ? options.Argon2DefaultHashLength
                : BaselineArgon2HashLength;
        }

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

            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            try
            {
                using (var pbkdf2 = new Rfc2898DeriveBytes(passwordBytes, salt, iterations, hashAlgorithm))
                {
                    byte[] hash = pbkdf2.GetBytes(hashLength);
                    return Convert.ToBase64String(hash);
                }
            }
            finally
            {
                SecureZeroMemory(passwordBytes);
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
            try
            {
                string hash
#if NET6_0_OR_GREATER
                    = HashPasswordWithPBKDF2(password.AsSpan(), saltBytes, hashAlgorithm, iterations, hashLength);
#else
                    = HashPasswordWithPBKDF2(password, saltBytes, hashAlgorithm, iterations, hashLength);
#endif

                return $"{hashAlgorithm.Name}|{iterations}|{salt}|{hash}";
            }
            finally
            {
                SecureZeroMemory(saltBytes);
            }
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

            return FixedTimeCompare(computedHashBytes, expectedHashBytes);
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
            try
            {
                var parts = storedHashString.Split('|');
                if (parts.Length != 4)
                    throw CreateInvalidSecurityParametersException("PBKDF2_FORMAT_PARTS");

                var algorithm = new HashAlgorithmName(parts[0]);
                if (!int.TryParse(parts[1], out int iterations) || iterations < 1)
                    throw CreateInvalidSecurityParametersException("PBKDF2_ITERATION_INVALID");

                byte[] salt = Convert.FromBase64String(parts[2]);
                string expectedHash = parts[3];

                byte[] expectedBytes = Convert.FromBase64String(expectedHash);
                if (expectedBytes.Length < MinHashLengthBytes)
                    return false;
                string computedHash = HashPasswordWithPBKDF2(password, salt, algorithm, iterations, expectedBytes.Length);
                byte[] computedBytes = Convert.FromBase64String(computedHash);

                return FixedTimeCompare(computedBytes, expectedBytes);
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex) when (ex is FormatException || ex is ArgumentException || ex is OverflowException)
            {
                throw CreateInvalidSecurityParametersException("PBKDF2_VERIFY_PARSE", ex);
            }
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
            ApplyArgon2Defaults(ref iterations, ref memoryKb, ref degreeOfParallelism, ref hashLength);
#if NET6_0_OR_GREATER
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));
            return HashPasswordWithArgon2(password.AsSpan(), salt, iterations, memoryKb, degreeOfParallelism, hashLength);
#else
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));
            if (string.IsNullOrWhiteSpace(salt))
                throw CreateInvalidSecurityParametersException("ARGON2_SALT_EMPTY");
            if (iterations < MinArgon2Iterations)
                throw new ArgumentOutOfRangeException(nameof(iterations), $"Argon2 iterations must be at least {MinArgon2Iterations}.");
            if (memoryKb < MinArgon2MemoryKb)
                throw new ArgumentOutOfRangeException(nameof(memoryKb), $"Argon2 memory cost must be at least {MinArgon2MemoryKb} KB.");
            if (degreeOfParallelism < 1)
                throw new ArgumentOutOfRangeException(nameof(degreeOfParallelism), "Degree of parallelism must be at least 1.");
            if (degreeOfParallelism > MaxArgon2DegreeOfParallelism)
                throw new ArgumentOutOfRangeException(nameof(degreeOfParallelism), $"Degree of parallelism must be at most {MaxArgon2DegreeOfParallelism}.");
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
                SecureZeroMemory(passwordBytes);
                SecureZeroMemory(saltBytes);
            }
#endif
        }

#if NET6_0_OR_GREATER
        /// <summary>
        /// Hashes a password using Argon2id with a ReadOnlySpan to avoid keeping passwords as strings.
        /// </summary>
        public string HashPasswordWithArgon2(ReadOnlySpan<char> password, string salt, int iterations = 4, int memoryKb = 131072, int degreeOfParallelism = 4, int hashLength = 32)
        {
            ApplyArgon2Defaults(ref iterations, ref memoryKb, ref degreeOfParallelism, ref hashLength);
            if (password.Length == 0)
                throw new ArgumentException("Password cannot be empty.", nameof(password));
            if (string.IsNullOrWhiteSpace(salt))
                throw CreateInvalidSecurityParametersException("ARGON2_SPAN_SALT_EMPTY");
            if (iterations < MinArgon2Iterations)
                throw new ArgumentOutOfRangeException(nameof(iterations), $"Argon2 iterations must be at least {MinArgon2Iterations}.");
            if (memoryKb < MinArgon2MemoryKb)
                throw new ArgumentOutOfRangeException(nameof(memoryKb), $"Argon2 memory cost must be at least {MinArgon2MemoryKb} KB.");
            if (degreeOfParallelism < 1)
                throw new ArgumentOutOfRangeException(nameof(degreeOfParallelism), "Degree of parallelism must be at least 1.");
            if (degreeOfParallelism > MaxArgon2DegreeOfParallelism)
                throw new ArgumentOutOfRangeException(nameof(degreeOfParallelism), $"Degree of parallelism must be at most {MaxArgon2DegreeOfParallelism}.");
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
                SecureZeroMemory(passwordBytes);
                SecureZeroMemory(saltBytes);
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

            try
            {
                using (HMAC hmac = GetHMACInstance(hashAlgorithm, keyBytes))
                {
                    byte[] hashBytes = hmac.ComputeHash(inputBytes);
                    return Convert.ToBase64String(hashBytes);
                }
            }
            finally
            {
                SecureZeroMemory(keyBytes);
                SecureZeroMemory(inputBytes);
            }
        }

        public byte[][] DeriveMultipleKeys(HashAlgorithmName algorithm, byte[] masterKey, int keyCount, int keyLength, byte[] salt = null, string context = "")
        {
            return KeyDerivation.DeriveMultipleKeys(algorithm, masterKey, keyCount, keyLength, salt, context);
        }

        public byte[][] DeriveMultipleKeys(byte[] masterKey, int keyCount, int keyLength, byte[] salt = null, string context = "")
        {
            return KeyDerivation.DeriveMultipleKeys(HashAlgorithmName.SHA256, masterKey, keyCount, keyLength, salt, context);
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
            if (key == null || key.Length != 32)
                throw CreateInvalidSecurityParametersException("AES_GCM_KEY_INVALID");

            byte[] nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
            byte[] purePlainText = Encoding.UTF8.GetBytes(plainText ?? string.Empty);
            byte[] cipherBytes = new byte[purePlainText.Length];
            byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];
            try
            {
                RandomNumberGenerator.Fill(nonce);
                using (var aesGcm = new AesGcm(key, AesGcm.TagByteSizes.MaxSize))
                {
                    aesGcm.Encrypt(nonce, purePlainText, cipherBytes, tag);
                }
                return $"{Convert.ToBase64String(nonce)}|{Convert.ToBase64String(tag)}|{Convert.ToBase64String(cipherBytes)}";
            }
            catch (CryptographicException ex)
            {
                throw CreateInvalidSecurityParametersException("AES_GCM_ENCRYPT_FAILED", ex);
            }
            finally
            {
                SecureZeroMemory(purePlainText);
                SecureZeroMemory(cipherBytes);
                SecureZeroMemory(nonce);
                SecureZeroMemory(tag);
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
            if (string.IsNullOrWhiteSpace(combinedCipherText) || key == null || key.Length != 32)
                throw CreateInvalidSecurityParametersException("AES_GCM_INPUT_INVALID");

            var parts = combinedCipherText.Split('|');
            if (parts.Length != 3)
                throw CreateInvalidSecurityParametersException("AES_GCM_FORMAT_PARTS");

            byte[] nonce = null;
            byte[] tag = null;
            byte[] cipherBytes = null;
            byte[] decryptedBytes = null;

            try
            {
                nonce = Convert.FromBase64String(parts[0]);
                tag = Convert.FromBase64String(parts[1]);
                cipherBytes = string.IsNullOrEmpty(parts[2]) ? Array.Empty<byte>() : Convert.FromBase64String(parts[2]);

                if (nonce.Length != AesGcm.NonceByteSizes.MaxSize || tag.Length != AesGcm.TagByteSizes.MaxSize)
                    throw CreateInvalidSecurityParametersException("AES_GCM_NONCE_TAG_SIZE");

                decryptedBytes = new byte[cipherBytes.Length];
                using (var aesGcm = new AesGcm(key, AesGcm.TagByteSizes.MaxSize))
                {
                    aesGcm.Decrypt(nonce, cipherBytes, tag, decryptedBytes);
                }
                return Encoding.UTF8.GetString(decryptedBytes);
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CreateInvalidSecurityParametersException("AES_GCM_DECRYPT_PARSE", ex);
            }
            finally
            {
                SecureZeroMemory(nonce);
                SecureZeroMemory(tag);
                SecureZeroMemory(cipherBytes);
                SecureZeroMemory(decryptedBytes);
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
                SecureZeroMemory(passwordBytes);
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
            byte[] salt = null;
            try
            {
                var parts = storedHashString.Split('|');
                if (parts.Length != 4)
                    throw CreateInvalidSecurityParametersException("PBKDF2_SPAN_FORMAT_PARTS");

                var algorithm = new HashAlgorithmName(parts[0]);
                if (!int.TryParse(parts[1], out int iterations) || iterations < 1)
                    throw CreateInvalidSecurityParametersException("PBKDF2_SPAN_ITERATION_INVALID");

                salt = Convert.FromBase64String(parts[2]);
                string expectedHash = parts[3];

                byte[] expectedBytes = Convert.FromBase64String(expectedHash);
                if (expectedBytes.Length < MinHashLengthBytes)
                    return false;
                string computedHash = HashPasswordWithPBKDF2(password, salt, algorithm, iterations, expectedBytes.Length);
                byte[] computedBytes = Convert.FromBase64String(computedHash);

                return FixedTimeCompare(computedBytes, expectedBytes);
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex) when (ex is FormatException || ex is ArgumentException || ex is OverflowException)
            {
                throw CreateInvalidSecurityParametersException("PBKDF2_SPAN_PARSE", ex);
            }
            finally
            {
                SecureZeroMemory(salt);
            }
        }

        /// <summary>
        /// Clears sensitive data from memory by zeroing out the char span.
        /// </summary>
        /// <param name="data">The char span to clear.</param>
        public void ClearSensitiveData(Span<char> data)
        {
            data.Clear();
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

#if NET6_0_OR_GREATER
            CryptographicOperations.ZeroMemory(data);
#else
            Array.Clear(data, 0, data.Length);
#endif
        }

        private static bool FixedTimeCompare(byte[] a, byte[] b)
        {
#if NET6_0_OR_GREATER
            return CryptographicOperations.FixedTimeEquals(a, b);
#else
            if (a == null || b == null || a.Length != b.Length)
                return false;

            int result = 0;
            for (int i = 0; i < a.Length; i++)
            {
                result |= a[i] ^ b[i];
            }

            return result == 0;
#endif
        }

        private byte[] GetSaltBytes(string salt)
        {
            if (string.IsNullOrWhiteSpace(salt))
                throw CreateInvalidSecurityParametersException("SALT_EMPTY");

            byte[] decoded;
            try
            {
                decoded = Convert.FromBase64String(salt);
            }
            catch (FormatException ex)
            {
                throw CreateInvalidSecurityParametersException("SALT_NOT_BASE64", ex);
            }

            if (decoded.Length < MinSaltSizeBytes)
                throw CreateInvalidSecurityParametersException("SALT_TOO_SHORT");

            return decoded;
        }

        private CryptographicException CreateInvalidSecurityParametersException(string incidentCode, Exception exception = null)
        {
            LogSecurityIncident(incidentCode, exception);
            return new CryptographicException(GenericSecurityErrorMessage);
        }

        private void ApplyArgon2Defaults(ref int iterations, ref int memoryKb, ref int degreeOfParallelism, ref int hashLength)
        {
            if (iterations == BaselineArgon2Iterations)
                iterations = _defaultArgon2Iterations;

            if (memoryKb == BaselineArgon2MemoryKb)
                memoryKb = _defaultArgon2MemoryKb;

            if (degreeOfParallelism == BaselineArgon2DegreeOfParallelism)
                degreeOfParallelism = _defaultArgon2DegreeOfParallelism;

            if (hashLength == BaselineArgon2HashLength)
                hashLength = _defaultArgon2HashLength;
        }

        private void LogSecurityIncident(string incidentCode, Exception exception)
        {
            if (_securityIncidentLogger == null)
                return;

            string payload = exception == null
                ? $"SEC_EVT|code={incidentCode}|exception=None"
                : $"SEC_EVT|code={incidentCode}|exception={exception.GetType().Name}";

            try
            {
                ThreadPool.QueueUserWorkItem(_ =>
                {
                    try
                    {
                        _securityIncidentLogger.Invoke(payload);
                    }
                    catch
                    {
                    }
                });
            }
            catch
            {
            }
        }
    }
}