using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

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
        /// </summary>
        string ComputeHash(string input, string salt, HashAlgorithmName hashAlgorithm);

        /// <summary>
        /// Generates a cryptographically secure random salt.
        /// </summary>
        string GenerateSalt(int size = 32);

        /// <summary>
        /// Hashes a password using PBKDF2 with a given salt, algorithm, iterations, and hash length.
        /// </summary>
        string HashPasswordWithPBKDF2(string password, byte[] salt, HashAlgorithmName hashAlgorithm, int iterations = 100000, int hashLength = 32);

        /// <summary>
        /// Hashes a password using PBKDF2 and automatically generates a random salt.
        /// </summary>
        string HashPasswordWithPBKDF2(string password, out string salt, HashAlgorithmName hashAlgorithm, int iterations = 100000, int hashLength = 32);

        /// <summary>
        /// Verifies that a plain text input matches a given hash using a salt and algorithm.
        /// </summary>
        bool VerifyHash(string input, string salt, string expectedHash, HashAlgorithmName hashAlgorithm);

        /// <summary>
        /// Verifies a password against a stored PBKDF2 hash string in the format algorithm|iterations|salt|hash.
        /// </summary>
        bool VerifyPasswordWithPBKDF2(string password, string storedHashString);

        /// <summary>
        /// Asynchronously hashes a password using PBKDF2.
        /// </summary>
        Task<string> HashPasswordWithPBKDF2Async(string password, byte[] salt, HashAlgorithmName hashAlgorithm, int iterations = 100000, int hashLength = 32);

        /// <summary>
        /// Hashes a password using Argon2id algorithm. Requires Isopoh.Cryptography.Argon2 NuGet package.
        /// </summary>
        string HashPasswordWithArgon2(string password, string salt, int iterations = 3, int memoryKb = 65536, int degreeOfParallelism = 2, int hashLength = 32);

        /// <summary>
        /// Asynchronously hashes a password using Argon2id algorithm.
        /// </summary>
        Task<string> HashPasswordWithArgon2Async(string password, string salt, int iterations = 3, int memoryKb = 65536, int degreeOfParallelism = 2, int hashLength = 32);

        /// <summary>
        /// Computes an HMAC for the given input using the specified key and hash algorithm.
        /// </summary>
        string ComputeHMAC(string input, string key, HashAlgorithmName hashAlgorithm);

        /// <summary>
        /// Asynchronously computes an HMAC for the given input.
        /// </summary>
        Task<string> ComputeHMACAsync(string input, string key, HashAlgorithmName hashAlgorithm);

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
        string HashPasswordWithPBKDF2Span(ReadOnlySpan<char> password, byte[] salt, HashAlgorithmName hashAlgorithm, int iterations = 100000, int hashLength = 32);

        /// <summary>
        /// Verifies a password against a stored PBKDF2 hash using Span&lt;char&gt; for secure password comparison.
        /// </summary>
        bool VerifyPasswordWithPBKDF2Span(ReadOnlySpan<char> password, string storedHashString);
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
        // --- IMMUTABLE WORKING METHODS ---

        /// <summary>
        /// Creates a hash for the given input using the specified salt and hash algorithm.
        /// </summary>
        /// <param name="input">The plain text string to hash.</param>
        /// <param name="salt">The salt string to combine with the input before hashing.</param>
        /// <param name="hashAlgorithm">The hash algorithm to use (SHA256, SHA384, SHA512).</param>
        /// <returns>Base64-encoded hash string.</returns>
        public string ComputeHash(string input, string salt, HashAlgorithmName hashAlgorithm)
        {
            string saltedInput = input + salt;
            byte[] inputBytes = Encoding.UTF8.GetBytes(saltedInput);

            using (HashAlgorithm hashAlgo = GetHashAlgorithm(hashAlgorithm))
            {
                byte[] hashBytes = hashAlgo.ComputeHash(inputBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }

        /// <summary>
        /// Generates a cryptographically secure random salt.
        /// </summary>
        /// <param name="size">The size of the salt in bytes (default is 32).</param>
        /// <returns>Base64-encoded salt string.</returns>
        public string GenerateSalt(int size = 32)
        {
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
        /// <param name="iterations">Number of iterations for PBKDF2 (default 100000).</param>
        /// <param name="hashLength">Length of the derived hash in bytes (default 32).</param>
        /// <returns>Base64-encoded hash string.</returns>
        public string HashPasswordWithPBKDF2(string password, byte[] salt, HashAlgorithmName hashAlgorithm, int iterations = 100000, int hashLength = 32)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, hashAlgorithm))
            {
                byte[] hash = pbkdf2.GetBytes(hashLength);
                return Convert.ToBase64String(hash);
            }
        }

        /// <summary>
        /// Hashes a password using PBKDF2 and automatically generates a random salt.
        /// Returns a formatted string containing algorithm, iterations, salt, and hash.
        /// </summary>
        /// <param name="password">The password to hash.</param>
        /// <param name="salt">Outputs the generated salt string.</param>
        /// <param name="hashAlgorithm">The hash algorithm to use (SHA256, SHA384, SHA512).</param>
        /// <param name="iterations">Number of iterations for PBKDF2 (default 100000).</param>
        /// <param name="hashLength">Length of the derived hash in bytes (default 32).</param>
        /// <returns>A formatted string: "algorithm|iterations|salt|hash".</returns>
        public string HashPasswordWithPBKDF2(string password, out string salt, HashAlgorithmName hashAlgorithm, int iterations = 100000, int hashLength = 32)
        {
            salt = GenerateSalt(32);
            byte[] saltBytes = Convert.FromBase64String(salt);
            string hash = HashPasswordWithPBKDF2(password, saltBytes, hashAlgorithm, iterations, hashLength);

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
            byte[] computedHashBytes = Convert.FromBase64String(ComputeHash(input, salt, hashAlgorithm));
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
            var parts = storedHashString.Split('|');
            if (parts.Length != 4)
                throw new FormatException("Stored hash is not in the correct format.");

            var algorithm = new HashAlgorithmName(parts[0]);
            int iterations = int.Parse(parts[1]);
            byte[] salt = Convert.FromBase64String(parts[2]);
            string expectedHash = parts[3];

            string computedHash = HashPasswordWithPBKDF2(password, salt, algorithm, iterations);

            byte[] computedBytes = Convert.FromBase64String(computedHash);
            byte[] expectedBytes = Convert.FromBase64String(expectedHash);

            return FixedTimeEquals(computedBytes, expectedBytes);
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
        /// Asynchronously hashes a password using PBKDF2.
        /// </summary>
        /// <param name="password">The password to hash.</param>
        /// <param name="salt">The salt bytes to use for PBKDF2.</param>
        /// <param name="hashAlgorithm">The hash algorithm to use (SHA256, SHA384, SHA512).</param>
        /// <param name="iterations">Number of iterations for PBKDF2 (default 100000).</param>
        /// <param name="hashLength">Length of the derived hash in bytes (default 32).</param>
        /// <returns>Base64-encoded hash string.</returns>
        public async Task<string> HashPasswordWithPBKDF2Async(string password, byte[] salt, HashAlgorithmName hashAlgorithm, int iterations = 100000, int hashLength = 32)
        {
            return await Task.Run(() => HashPasswordWithPBKDF2(password, salt, hashAlgorithm, iterations, hashLength));
        }

        /// <summary>
        /// Hashes a password using Argon2id algorithm. Requires Isopoh.Cryptography.Argon2 NuGet package.
        /// </summary>
        /// <param name="password">The password to hash.</param>
        /// <param name="salt">The salt to use for hashing.</param>
        /// <param name="iterations">Number of iterations (default 3).</param>
        /// <param name="memoryKb">Memory size in KB (default 65536).</param>
        /// <param name="degreeOfParallelism">Degree of parallelism (default 2).</param>
        /// <param name="hashLength">Length of the hash in bytes (default 32).</param>
        /// <returns>Base64-encoded Argon2id hash string.</returns>
        public string HashPasswordWithArgon2(string password, string salt, int iterations = 3, int memoryKb = 65536, int degreeOfParallelism = 2, int hashLength = 32)
        {
            var config = new Isopoh.Cryptography.Argon2.Argon2Config
            {
                Type = Isopoh.Cryptography.Argon2.Argon2Type.HybridAddressing,
                Version = Isopoh.Cryptography.Argon2.Argon2Version.Nineteen,
                Password = Encoding.UTF8.GetBytes(password),
                Salt = Encoding.UTF8.GetBytes(salt),
                TimeCost = iterations,
                MemoryCost = memoryKb,
                Lanes = degreeOfParallelism,
                Threads = degreeOfParallelism,
                HashLength = hashLength
            };

            using (var argon2 = new Isopoh.Cryptography.Argon2.Argon2(config))
            {
                return Convert.ToBase64String(argon2.Hash().Buffer);
            }
        }

        /// <summary>
        /// Asynchronously hashes a password using Argon2id algorithm.
        /// </summary>
        /// <param name="password">The password to hash.</param>
        /// <param name="salt">The salt to use for hashing.</param>
        /// <param name="iterations">Number of iterations (default 3).</param>
        /// <param name="memoryKb">Memory size in KB (default 65536).</param>
        /// <param name="degreeOfParallelism">Degree of parallelism (default 2).</param>
        /// <param name="hashLength">Length of the hash in bytes (default 32).</param>
        /// <returns>Base64-encoded Argon2id hash string.</returns>
        public async Task<string> HashPasswordWithArgon2Async(string password, string salt, int iterations = 3, int memoryKb = 65536, int degreeOfParallelism = 2, int hashLength = 32)
        {
            return await Task.Run(() => HashPasswordWithArgon2(password, salt, iterations, memoryKb, degreeOfParallelism, hashLength));
        }

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
        /// Asynchronously computes an HMAC for the given input using the specified key and hash algorithm.
        /// </summary>
        /// <param name="input">The input string to compute HMAC for.</param>
        /// <param name="key">The secret key for HMAC.</param>
        /// <param name="hashAlgorithm">The hash algorithm to use (SHA256, SHA384, SHA512).</param>
        /// <returns>Base64-encoded HMAC string.</returns>
        public async Task<string> ComputeHMACAsync(string input, string key, HashAlgorithmName hashAlgorithm)
        {
            return await Task.Run(() => ComputeHMAC(input, key, hashAlgorithm));
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
#if NET6_0_OR_GREATER
        public string EncryptStringGCM(string plainText, byte[] key)
        {
            if (key.Length != 32)
                throw new ArgumentException("Key must be 32 bytes (256 bits).");

            using (var aesGcm = new AesGcm(key,16))
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
            var parts = combinedCipherText.Split('|');
            if (parts.Length != 3)
                throw new FormatException("Invalid encrypted text format. Expected: nonce|tag|ciphertext");

            byte[] nonce = Convert.FromBase64String(parts[0]);
            byte[] tag = Convert.FromBase64String(parts[1]);
            byte[] cipherBytes = Convert.FromBase64String(parts[2]);
            byte[] decryptedBytes = new byte[cipherBytes.Length];

            using (var aesGcm = new AesGcm(key,16))
            {
                aesGcm.Decrypt(nonce, cipherBytes, tag, decryptedBytes);
                return Encoding.UTF8.GetString(decryptedBytes);
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
        /// <param name="iterations">Number of iterations for PBKDF2 (default 100000).</param>
        /// <param name="hashLength">Length of the derived hash in bytes (default 32).</param>
        /// <returns>Base64-encoded hash string.</returns>
        public string HashPasswordWithPBKDF2Span(ReadOnlySpan<char> password, byte[] salt, HashAlgorithmName hashAlgorithm, int iterations = 100000, int hashLength = 32)
        {
            // Convert span to bytes securely
            byte[] passwordBytes = new byte[Encoding.UTF8.GetByteCount(password)];
            Encoding.UTF8.GetBytes(password, passwordBytes);

            try
            {
                using (var pbkdf2 = new Rfc2898DeriveBytes(Encoding.UTF8.GetString(passwordBytes), salt, iterations, hashAlgorithm))
                {
                    byte[] hash = pbkdf2.GetBytes(hashLength);
                    return Convert.ToBase64String(hash);
                }
            }
            finally
            {
                // Clear password bytes from memory
                Array.Clear(passwordBytes, 0, passwordBytes.Length);
            }
        }

        /// <summary>
        /// Verifies a password against a stored PBKDF2 hash using Span&lt;char&gt; for secure password comparison.
        /// </summary>
        /// <param name="password">The password as a Span&lt;char&gt; (more secure).</param>
        /// <param name="storedHashString">The stored hash string in the format algorithm|iterations|salt|hash.</param>
        /// <returns>True if the password matches the stored hash; otherwise false.</returns>
        public bool VerifyPasswordWithPBKDF2Span(ReadOnlySpan<char> password, string storedHashString)
        {
            var parts = storedHashString.Split('|');
            if (parts.Length != 4)
                throw new FormatException("Stored hash is not in the correct format.");

            var algorithm = new HashAlgorithmName(parts[0]);
            int iterations = int.Parse(parts[1]);
            byte[] salt = Convert.FromBase64String(parts[2]);
            string expectedHash = parts[3];

            try
            {
                string computedHash = HashPasswordWithPBKDF2Span(password, salt, algorithm, iterations);

                byte[] computedBytes = Convert.FromBase64String(computedHash);
                byte[] expectedBytes = Convert.FromBase64String(expectedHash);

                return FixedTimeEquals(computedBytes, expectedBytes);
            }
            finally
            {
                // Clear sensitive arrays from memory
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
        /// Clears sensitive data from memory by zeroing out the byte array.
        /// </summary>
        /// <param name="data">The byte array to clear.</param>
        public void ClearSensitiveData(byte[] data)
        {
            if (data != null && data.Length > 0)
            {
                Array.Clear(data, 0, data.Length);
            }
        }
    }
}