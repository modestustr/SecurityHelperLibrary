using System;
using System.ComponentModel;
using System.Security.Cryptography;

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
        /// Derives multiple keys from a single master key using HKDF.
        /// </summary>
        byte[][] DeriveMultipleKeys(HashAlgorithmName algorithm, byte[] masterKey, int keyCount, int keyLength, byte[] salt = null, string context = "");

        /// <summary>
        /// Derives multiple keys from a single master key using the default SHA256 HKDF policy.
        /// </summary>
        byte[][] DeriveMultipleKeys(byte[] masterKey, int keyCount, int keyLength, byte[] salt = null, string context = "");


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
        /// Hashes a password using PBKDF2 with a Span<char> for more secure password handling.
        /// </summary>
        string HashPasswordWithPBKDF2(ReadOnlySpan<char> password, byte[] salt, HashAlgorithmName hashAlgorithm, int iterations = 210000, int hashLength = 32);

        /// <summary>
        /// Verifies a password against a stored PBKDF2 hash using Span<char> for secure password comparison.
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
}
