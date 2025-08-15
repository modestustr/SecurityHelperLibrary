using System;
using System.Security.Cryptography;
using System.Text;

public static class SecurityHelperLibrary
{
    /// <summary>
    /// Creates a hash for the given input using the specified salt and hash algorithm.
    /// </summary>
    /// <param name="input">The plain text string to hash.</param>
    /// <param name="salt">The salt string to combine with the input before hashing.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use (SHA256, SHA384, SHA512).</param>
    /// <returns>Base64-encoded hash string.</returns>
    public static string ComputeHash(string input, string salt, HashAlgorithmName hashAlgorithm)
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
    /// Generates a cryptographically secure random salt.
    /// </summary>
    /// <param name="size">The size of the salt in bytes (default is 32).</param>
    /// <returns>Base64-encoded salt string.</returns>
    public static string GenerateSalt(int size = 32)
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
    public static string HashPasswordWithPBKDF2(string password, byte[] salt,
        HashAlgorithmName hashAlgorithm, int iterations = 100000, int hashLength = 32)
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
    public static string HashPasswordWithPBKDF2(string password, out string salt,
        HashAlgorithmName hashAlgorithm, int iterations = 100000, int hashLength = 32)
    {
        salt = GenerateSalt(32);
        byte[] saltBytes = Convert.FromBase64String(salt);
        string hash = HashPasswordWithPBKDF2(password, saltBytes, hashAlgorithm, iterations, hashLength);

        // Format: algorithm|iterations|salt|hash
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
    public static bool VerifyHash(string input, string salt, string expectedHash, HashAlgorithmName hashAlgorithm)
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
    public static bool VerifyPasswordWithPBKDF2(string password, string storedHashString)
    {
        // Parse format: algorithm|iterations|salt|hash
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
}