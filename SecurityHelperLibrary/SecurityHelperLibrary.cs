using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

#if NET6_0_OR_GREATER
using System.Buffers;
#endif

namespace SecurityHelperLibrary
{
    /// <summary>
    /// Defines cryptographic helper methods for hashing, key derivation,
    /// encryption, verification, and secure memory handling.
    /// </summary>
    public interface ISecurityHelper
    {
        /// <summary>
        /// Generates a cryptographically secure random salt.
        /// </summary>
        /// <param name="size">Salt size in bytes. Default is 32 bytes.</param>
        /// <returns>Base64-encoded salt string.</returns>
        string GenerateSalt(int size = 32);

        /// <summary>
        /// Computes a hash for the given input and salt using the specified algorithm.
        /// </summary>
        /// <param name="input">Input string to hash.</param>
        /// <param name="salt">Salt value (Base64 string).</param>
        /// <param name="algorithm">Hash algorithm to use.</param>
        /// <returns>Base64-encoded hash.</returns>
        string ComputeHash(string input, string salt, HashAlgorithmName algorithm);

        /// <summary>
        /// Verifies an input against an expected hash using the same salt and algorithm.
        /// </summary>
        /// <param name="input">Input string to verify.</param>
        /// <param name="salt">Salt used during hashing.</param>
        /// <param name="expectedHash">Expected Base64 hash.</param>
        /// <param name="algorithm">Hash algorithm.</param>
        /// <returns>True if hashes match; otherwise false.</returns>
        bool VerifyHash(string input, string salt, string expectedHash, HashAlgorithmName algorithm);

        /// <summary>
        /// Hashes a password using PBKDF2 with an explicit salt.
        /// </summary>
        /// <param name="password">Password string.</param>
        /// <param name="salt">Salt bytes.</param>
        /// <param name="algorithm">Underlying hash algorithm.</param>
        /// <param name="iterations">Iteration count.</param>
        /// <returns>Base64-encoded derived key.</returns>
        string HashPasswordWithPBKDF2(string password, byte[] salt, HashAlgorithmName algorithm, int iterations = 100000);

        /// <summary>
        /// Hashes a password using PBKDF2 and generates a new salt.
        /// </summary>
        /// <param name="password">Password string.</param>
        /// <param name="salt">Generated Base64 salt.</param>
        /// <param name="algorithm">Underlying hash algorithm.</param>
        /// <param name="iterations">Iteration count.</param>
        /// <returns>
        /// Formatted string: Algorithm|Iterations|Salt|Hash
        /// </returns>
        string HashPasswordWithPBKDF2(string password, out string salt, HashAlgorithmName algorithm, int iterations = 100000);

        /// <summary>
        /// Verifies a password against a stored PBKDF2 hash string.
        /// </summary>
        /// <param name="password">Password to verify.</param>
        /// <param name="storedHash">Stored hash in Algorithm|Iterations|Salt|Hash format.</param>
        /// <returns>True if password matches; otherwise false.</returns>
        bool VerifyPasswordWithPBKDF2(string password, string storedHash);

        /// <summary>
        /// Computes an HMAC for the given input using the specified key and algorithm.
        /// </summary>
        /// <param name="input">Input string.</param>
        /// <param name="key">Secret key.</param>
        /// <param name="algorithm">HMAC algorithm.</param>
        /// <returns>Base64-encoded HMAC.</returns>
        string ComputeHMAC(string input, string key, HashAlgorithmName algorithm);

        /// <summary>
        /// Generates a cryptographically secure symmetric key.
        /// </summary>
        /// <param name="size">Key size in bytes. Default is 32.</param>
        /// <returns>Random key bytes.</returns>
        byte[] GenerateSymmetricKey(int size = 32);

        /// <summary>
        /// Encrypts a string using AES-GCM.
        /// </summary>
        /// <param name="plainText">Plain text to encrypt.</param>
        /// <param name="key">32-byte symmetric key.</param>
        /// <returns>Pipe-delimited encrypted string.</returns>
        string EncryptStringGCM(string plainText, byte[] key);

        /// <summary>
        /// Decrypts an AES-GCM encrypted string.
        /// </summary>
        /// <param name="encryptedText">Encrypted data.</param>
        /// <param name="key">32-byte symmetric key.</param>
        /// <returns>Decrypted plain text.</returns>
        string DecryptStringGCM(string encryptedText, byte[] key);

        /// <summary>
        /// Hashes a password using a simplified Argon2-compatible placeholder.
        /// </summary>
        /// <param name="password">Password string.</param>
        /// <param name="salt">Salt value.</param>
        /// <returns>Base64-encoded hash.</returns>
        string HashPasswordWithArgon2(string password, string salt);

        /// <summary>
        /// Asynchronously hashes a password using PBKDF2.
        /// </summary>
        Task<string> HashPasswordWithPBKDF2Async(string password, byte[] salt, HashAlgorithmName algorithm, int iterations = 100000);

        /// <summary>
        /// Asynchronously computes an HMAC.
        /// </summary>
        Task<string> ComputeHMACAsync(string input, string key, HashAlgorithmName algorithm);

        /// <summary>
        /// Asynchronously hashes a password using Argon2 placeholder logic.
        /// </summary>
        Task<string> HashPasswordWithArgon2Async(string password, string salt);

#if NET6_0_OR_GREATER
        /// <summary>
        /// Hashes a password using PBKDF2 from a character span.
        /// </summary>
        string HashPasswordWithPBKDF2Span(ReadOnlySpan<char> password, byte[] salt, HashAlgorithmName algorithm, int iterations = 100000);

        /// <summary>
        /// Verifies a password from a character span against a PBKDF2 hash.
        /// </summary>
        bool VerifyPasswordWithPBKDF2Span(ReadOnlySpan<char> password, string storedHash);

        /// <summary>
        /// Clears sensitive character data from memory.
        /// </summary>
        void ClearSensitiveData(Span<char> data);
#endif

        /// <summary>
        /// Clears sensitive byte data from memory.
        /// </summary>
        void ClearSensitiveData(byte[] data);
    }

    /// <summary>
    /// Default implementation of <see cref="ISecurityHelper"/>.
    /// </summary>
    public sealed class SecurityHelper : ISecurityHelper
    {
        /* ===================== SALT ===================== */

        public string GenerateSalt(int size = 32)
        {
            byte[] buffer = new byte[size];
#if NET6_0_OR_GREATER
            RandomNumberGenerator.Fill(buffer);
#else
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(buffer);
            }
#endif
            return Convert.ToBase64String(buffer);
        }

        /* ===================== HASH ===================== */

        public string ComputeHash(string input, string salt, HashAlgorithmName algorithm)
        {
            var hashAlg = HashAlgorithm.Create(algorithm.Name);
            if (hashAlg == null) throw new ArgumentException(nameof(algorithm));

            try
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(input + salt);
                byte[] hash = hashAlg.ComputeHash(inputBytes);
                return Convert.ToBase64String(hash);
            }
            finally
            {
                hashAlg.Dispose();
            }
        }

        public bool VerifyHash(string input, string salt, string expectedHash, HashAlgorithmName algorithm)
        {
            string computed = ComputeHash(input, salt, algorithm);
            byte[] a = Convert.FromBase64String(computed);
            byte[] b = Convert.FromBase64String(expectedHash);
            return FixedTimeEquals(a, b);
        }

        /* ===================== PBKDF2 ===================== */

        public string HashPasswordWithPBKDF2(string password, byte[] salt, HashAlgorithmName algorithm, int iterations = 100000)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, algorithm))
            {
                byte[] hash = pbkdf2.GetBytes(32);
                return Convert.ToBase64String(hash);
            }
        }

        public string HashPasswordWithPBKDF2(string password, out string salt, HashAlgorithmName algorithm, int iterations = 100000)
        {
            salt = GenerateSalt();
            byte[] saltBytes = Convert.FromBase64String(salt);

            string hash = HashPasswordWithPBKDF2(password, saltBytes, algorithm, iterations);
            return $"{algorithm.Name}|{iterations}|{salt}|{hash}";
        }

        public bool VerifyPasswordWithPBKDF2(string password, string storedHash)
        {
            var parts = storedHash.Split('|');
            if (parts.Length != 4)
                throw new FormatException();

            var algorithm = new HashAlgorithmName(parts[0]);
            int iterations = int.Parse(parts[1]);
            byte[] salt = Convert.FromBase64String(parts[2]);
            byte[] expected = Convert.FromBase64String(parts[3]);

            byte[] actual = Convert.FromBase64String(
                HashPasswordWithPBKDF2(password, salt, algorithm, iterations)
            );

            return FixedTimeEquals(actual, expected);
        }

#if NET6_0_OR_GREATER
        public string HashPasswordWithPBKDF2Span(ReadOnlySpan<char> password, byte[] salt, HashAlgorithmName algorithm, int iterations = 100000)
        {
            char[] rented = ArrayPool<char>.Shared.Rent(password.Length);
            password.CopyTo(rented);

            try
            {
                return HashPasswordWithPBKDF2(new string(rented, 0, password.Length), salt, algorithm, iterations);
            }
            finally
            {
                Array.Clear(rented, 0, rented.Length);
                ArrayPool<char>.Shared.Return(rented);
            }
        }

        public bool VerifyPasswordWithPBKDF2Span(ReadOnlySpan<char> password, string storedHash)
        {
            char[] rented = ArrayPool<char>.Shared.Rent(password.Length);
            password.CopyTo(rented);

            try
            {
                return VerifyPasswordWithPBKDF2(new string(rented, 0, password.Length), storedHash);
            }
            finally
            {
                Array.Clear(rented, 0, rented.Length);
                ArrayPool<char>.Shared.Return(rented);
            }
        }
#endif

        /* ===================== HMAC ===================== */

        public string ComputeHMAC(string input, string key, HashAlgorithmName algorithm)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            HMAC hmac;
            switch (algorithm.Name)
            {
                case "SHA256": hmac = new HMACSHA256(keyBytes); break;
                case "SHA384": hmac = new HMACSHA384(keyBytes); break;
                case "SHA512": hmac = new HMACSHA512(keyBytes); break;
                default: throw new ArgumentException(nameof(algorithm));
            }

            using (hmac)
            {
                byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(input));
                return Convert.ToBase64String(hash);
            }
        }

        /* ===================== SYMMETRIC ===================== */

        public byte[] GenerateSymmetricKey(int size = 32)
        {
            byte[] key = new byte[size];
#if NET6_0_OR_GREATER
            RandomNumberGenerator.Fill(key);
#else
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }
#endif
            return key;
        }

        public string EncryptStringGCM(string plainText, byte[] key)
        {
#if NET6_0_OR_GREATER
            if (key.Length != 32)
                throw new ArgumentException();

            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] cipher = new byte[plaintextBytes.Length];
            byte[] tag = new byte[16];

            using (var aes = new AesGcm(key, 16))
            {
                aes.Encrypt(nonce, plaintextBytes, cipher, tag);
            }

            return $"{Convert.ToBase64String(nonce)}|{Convert.ToBase64String(tag)}|{Convert.ToBase64String(cipher)}";
#else
            throw new NotSupportedException();
#endif
        }

        public string DecryptStringGCM(string encryptedText, byte[] key)
        {
#if NET6_0_OR_GREATER
            var parts = encryptedText.Split('|');
            if (parts.Length != 3)
                throw new FormatException();

            byte[] nonce = Convert.FromBase64String(parts[0]);
            byte[] tag = Convert.FromBase64String(parts[1]);
            byte[] cipher = Convert.FromBase64String(parts[2]);
            byte[] plain = new byte[cipher.Length];

            using (var aes = new AesGcm(key, 16))
            {
                aes.Decrypt(nonce, cipher, tag, plain);
            }

            return Encoding.UTF8.GetString(plain);
#else
            throw new NotSupportedException();
#endif
        }

        /* ===================== ARGON2 (STABLE) ===================== */

        public string HashPasswordWithArgon2(string password, string salt)
        {
            using (var sha = SHA256.Create())
            {
                byte[] data = Encoding.UTF8.GetBytes(password + salt);
                return Convert.ToBase64String(sha.ComputeHash(data));
            }
        }

        /* ===================== ASYNC ===================== */

        public Task<string> HashPasswordWithPBKDF2Async(string password, byte[] salt, HashAlgorithmName algorithm, int iterations = 100000)
            => Task.Run(() => HashPasswordWithPBKDF2(password, salt, algorithm, iterations));

        public Task<string> ComputeHMACAsync(string input, string key, HashAlgorithmName algorithm)
            => Task.Run(() => ComputeHMAC(input, key, algorithm));

        public Task<string> HashPasswordWithArgon2Async(string password, string salt)
            => Task.Run(() => HashPasswordWithArgon2(password, salt));

        /* ===================== CLEAR ===================== */

#if !NETSTANDARD1_3
        private static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null) return false;
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }
#endif

#if NET6_0_OR_GREATER
        public void ClearSensitiveData(Span<char> data)
        {
            if (data == default) return;
            data.Clear();
        }
#endif

        public void ClearSensitiveData(byte[] data)
        {
            if (data == null || data.Length == 0) return;
            Array.Clear(data, 0, data.Length);
        }
    }
}
