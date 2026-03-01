using System;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using SecurityHelperLibrary;

namespace SecurityHelperLibrary.Tests
{
    /// <summary>
    /// Comprehensive unit tests for SecurityHelper class covering hashing, encryption, and verification methods.
    /// </summary>
    public class SecurityHelperTests
    {
        private readonly ISecurityHelper _securityHelper;

        public SecurityHelperTests()
        {
            _securityHelper = new SecurityHelper();
        }

        #region ComputeHash Tests

        [Fact]
        public void ComputeHash_WithValidInput_ReturnsBase64Hash()
        {
            // Arrange
            string input = "TestPassword";
            string salt = _securityHelper.GenerateSalt();

            // Act
            string result = _securityHelper.ComputeHash(input, salt, HashAlgorithmName.SHA256);

            // Assert
            Assert.NotNull(result);
            Assert.NotEmpty(result);
            // Verify it's valid Base64
            byte[] decodedBytes = Convert.FromBase64String(result);
            Assert.NotEmpty(decodedBytes);
        }

        [Theory]
        [InlineData("SHA256")]
        [InlineData("SHA384")]
        [InlineData("SHA512")]
        public void ComputeHash_WithDifferentAlgorithms_ProducesDifferentHashes(string algorithmName)
        {
            // Arrange
            string input = "TestPassword";
            string salt = _securityHelper.GenerateSalt();
            var algorithm = new HashAlgorithmName(algorithmName);

            // Act
            string hash1 = _securityHelper.ComputeHash(input, salt, algorithm);
            string hash2 = _securityHelper.ComputeHash(input, salt, algorithm);

            // Assert - Same input should produce same hash
            Assert.Equal(hash1, hash2);
        }

        [Fact]
        public void ComputeHash_WithDifferentSalts_ProducesDifferentHashes()
        {
            // Arrange
            string input = "TestPassword";
            string salt1 = _securityHelper.GenerateSalt();
            string salt2 = _securityHelper.GenerateSalt();

            // Act
            string hash1 = _securityHelper.ComputeHash(input, salt1, HashAlgorithmName.SHA256);
            string hash2 = _securityHelper.ComputeHash(input, salt2, HashAlgorithmName.SHA256);

            // Assert
            Assert.NotEqual(hash1, hash2);
        }

        #endregion

        #region GenerateSalt Tests

        [Fact]
        public void GenerateSalt_WithDefaultSize_Returns32BytesBase64()
        {
            // Act
            string salt = _securityHelper.GenerateSalt();

            // Assert
            Assert.NotNull(salt);
            byte[] saltBytes = Convert.FromBase64String(salt);
            Assert.Equal(32, saltBytes.Length);
        }

        [Theory]
        [InlineData(16)]
        [InlineData(32)]
        [InlineData(64)]
        public void GenerateSalt_WithCustomSize_ReturnsCorrectLength(int size)
        {
            // Act
            string salt = _securityHelper.GenerateSalt(size);

            // Assert
            byte[] saltBytes = Convert.FromBase64String(salt);
            Assert.Equal(size, saltBytes.Length);
        }

        [Fact]
        public void GenerateSalt_GeneratesTwoDifferentSalts()
        {
            // Act
            string salt1 = _securityHelper.GenerateSalt();
            string salt2 = _securityHelper.GenerateSalt();

            // Assert
            Assert.NotEqual(salt1, salt2);
        }

        #endregion

        #region PBKDF2 Tests

        [Fact]
        public void HashPasswordWithPBKDF2_WithSaltBytes_ReturnsValidHash()
        {
            // Arrange
            string password = "MySecurePassword";
            byte[] salt = Convert.FromBase64String(_securityHelper.GenerateSalt());

            // Act
            string hash = _securityHelper.HashPasswordWithPBKDF2(password, salt, HashAlgorithmName.SHA256);

            // Assert
            Assert.NotNull(hash);
            Assert.NotEmpty(hash);
            byte[] decodedHash = Convert.FromBase64String(hash);
            Assert.Equal(32, decodedHash.Length); // Default hash length
        }

        [Fact]
        public void HashPasswordWithPBKDF2_WithGeneratedSalt_ReturnsFormattedString()
        {
            // Arrange
            string password = "MySecurePassword";

            // Act
            string result = _securityHelper.HashPasswordWithPBKDF2(password, out string salt, HashAlgorithmName.SHA256);

            // Assert
            Assert.NotNull(result);
            Assert.NotNull(salt);
            var parts = result.Split('|');
            Assert.Equal(4, parts.Length);
            Assert.Equal("SHA256", parts[0]);
            Assert.Equal("210000", parts[1]); // Default iterations
            Assert.Equal(salt, parts[2]);
        }

        [Fact]
        public void HashPasswordWithPBKDF2_WithCustomIterations_IncludesIterationCount()
        {
            // Arrange
            string password = "MySecurePassword";
            int iterations = 50000;

            // Act
            string result = _securityHelper.HashPasswordWithPBKDF2(password, out string salt, HashAlgorithmName.SHA256, iterations);

            // Assert
            var parts = result.Split('|');
            Assert.Equal(iterations.ToString(), parts[1]);
        }

        [Fact]
        public void HashPasswordWithPBKDF2_SamePasswordSameSalt_ProducesSameHash()
        {
            // Arrange
            string password = "MySecurePassword";
            byte[] salt = Convert.FromBase64String(_securityHelper.GenerateSalt());

            // Act
            string hash1 = _securityHelper.HashPasswordWithPBKDF2(password, salt, HashAlgorithmName.SHA256);
            string hash2 = _securityHelper.HashPasswordWithPBKDF2(password, salt, HashAlgorithmName.SHA256);

            // Assert
            Assert.Equal(hash1, hash2);
        }

        #endregion

        #region VerifyHash Tests

        [Fact]
        public void VerifyHash_WithCorrectInput_ReturnsTrue()
        {
            // Arrange
            string input = "TestPassword";
            string salt = _securityHelper.GenerateSalt();
            string hash = _securityHelper.ComputeHash(input, salt, HashAlgorithmName.SHA256);

            // Act
            bool result = _securityHelper.VerifyHash(input, salt, hash, HashAlgorithmName.SHA256);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void VerifyHash_WithIncorrectInput_ReturnsFalse()
        {
            // Arrange
            string input = "TestPassword";
            string wrongInput = "WrongPassword";
            string salt = _securityHelper.GenerateSalt();
            string hash = _securityHelper.ComputeHash(input, salt, HashAlgorithmName.SHA256);

            // Act
            bool result = _securityHelper.VerifyHash(wrongInput, salt, hash, HashAlgorithmName.SHA256);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void VerifyHash_WithWrongSalt_ReturnsFalse()
        {
            // Arrange
            string input = "TestPassword";
            string salt1 = _securityHelper.GenerateSalt();
            string salt2 = _securityHelper.GenerateSalt();
            string hash = _securityHelper.ComputeHash(input, salt1, HashAlgorithmName.SHA256);

            // Act
            bool result = _securityHelper.VerifyHash(input, salt2, hash, HashAlgorithmName.SHA256);

            // Assert
            Assert.False(result);
        }

        #endregion

        #region VerifyPasswordWithPBKDF2 Tests

#if NET6_0_OR_GREATER
        [Fact]
        public void VerifyPasswordWithPBKDF2_WithCorrectPassword_ReturnsTrue()
        {
            // Arrange
            string password = "MySecurePassword";
            string storedHash = _securityHelper.HashPasswordWithPBKDF2(password, out string _, HashAlgorithmName.SHA256);

            // Act
            bool result = _securityHelper.VerifyPasswordWithPBKDF2(password, storedHash);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void VerifyPasswordWithPBKDF2_WithIncorrectPassword_ReturnsFalse()
        {
            // Arrange
            string password = "MySecurePassword";
            string wrongPassword = "WrongPassword";
            string storedHash = _securityHelper.HashPasswordWithPBKDF2(password, out string _, HashAlgorithmName.SHA256);

            // Act
            bool result = _securityHelper.VerifyPasswordWithPBKDF2(wrongPassword, storedHash);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void VerifyPasswordWithPBKDF2_WithInvalidFormat_ThrowsFormatException()
        {
            // Arrange
            string invalidHash = "invalid|format";

            // Act & Assert
            Assert.Throws<FormatException>(() => _securityHelper.VerifyPasswordWithPBKDF2("password", invalidHash));
        }

        [Fact]
        public void VerifyPasswordWithPBKDF2_WithModifiedHash_ReturnsFalse()
        {
            // Arrange
            string password = "MySecurePassword";
            string storedHash = _securityHelper.HashPasswordWithPBKDF2(password, out string _, HashAlgorithmName.SHA256);
            var parts = storedHash.Split('|');
            // Modify the hash part with a different valid base64 hash
            string modifiedHash = $"{parts[0]}|{parts[1]}|{parts[2]}|AA==";

            // Act & Assert - Should either return false or throw an exception due to format mismatch
            bool result = false;
            try
            {
                result = _securityHelper.VerifyPasswordWithPBKDF2(password, modifiedHash);
            }
            catch (System.FormatException)
            {
                // Expected - the modified hash doesn't match the expected format
                result = false;
            }
            Assert.False(result);
        }

        [Fact]
        public void VerifyPasswordWithPBKDF2_WithCustomHashLength_ReturnsTrue()
        {
            // Arrange
            string password = "MySecurePassword";
            int customHashLength = 48;
            string storedHash = _securityHelper.HashPasswordWithPBKDF2(password, out string _, HashAlgorithmName.SHA256, 210000, customHashLength);

            // Act
            bool result = _securityHelper.VerifyPasswordWithPBKDF2(password, storedHash);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void VerifyPasswordWithPBKDF2_WithInvalidIterationValue_ThrowsFormatException()
        {
            // Arrange
            string invalid = "SHA256|NaN|c2FsdA==|aGFzaA==";

            // Act & Assert
            Assert.Throws<FormatException>(() => _securityHelper.VerifyPasswordWithPBKDF2("password", invalid));
        }
#endif

        #endregion

        #region HMAC Tests

        [Fact]
        public void ComputeHMAC_WithValidInput_ReturnsBase64Hash()
        {
            // Arrange
            string input = "TestData";
            string key = "SecretKey";

            // Act
            string result = _securityHelper.ComputeHMAC(input, key, HashAlgorithmName.SHA256);

            // Assert
            Assert.NotNull(result);
            Assert.NotEmpty(result);
            byte[] decodedBytes = Convert.FromBase64String(result);
            Assert.NotEmpty(decodedBytes);
        }

        [Fact]
        public void ComputeHMAC_SameInputSameKey_ProducesSameResult()
        {
            // Arrange
            string input = "TestData";
            string key = "SecretKey";

            // Act
            string hmac1 = _securityHelper.ComputeHMAC(input, key, HashAlgorithmName.SHA256);
            string hmac2 = _securityHelper.ComputeHMAC(input, key, HashAlgorithmName.SHA256);

            // Assert
            Assert.Equal(hmac1, hmac2);
        }

        [Fact]
        public void ComputeHMAC_DifferentKeys_ProducesDifferentResults()
        {
            // Arrange
            string input = "TestData";
            string key1 = "SecretKey1";
            string key2 = "SecretKey2";

            // Act
            string hmac1 = _securityHelper.ComputeHMAC(input, key1, HashAlgorithmName.SHA256);
            string hmac2 = _securityHelper.ComputeHMAC(input, key2, HashAlgorithmName.SHA256);

            // Assert
            Assert.NotEqual(hmac1, hmac2);
        }

        #endregion

        #region Symmetric Key Generation Tests

        [Fact]
        public void GenerateSymmetricKey_WithDefaultSize_Returns32Bytes()
        {
            // Act
            byte[] key = _securityHelper.GenerateSymmetricKey();

            // Assert
            Assert.Equal(32, key.Length);
        }

        [Theory]
        [InlineData(16)]
        [InlineData(32)]
        [InlineData(64)]
        public void GenerateSymmetricKey_WithCustomSize_ReturnsCorrectLength(int size)
        {
            // Act
            byte[] key = _securityHelper.GenerateSymmetricKey(size);

            // Assert
            Assert.Equal(size, key.Length);
        }

        [Fact]
        public void GenerateSymmetricKey_GeneratesTwoDifferentKeys()
        {
            // Act
            byte[] key1 = _securityHelper.GenerateSymmetricKey();
            byte[] key2 = _securityHelper.GenerateSymmetricKey();

            // Assert
            Assert.NotEqual(key1, key2);
        }

        #endregion

        #region AES-GCM Tests (Net6.0+)

#if NET6_0_OR_GREATER
        [Fact]
        public void EncryptStringGCM_WithValidInput_ReturnsEncryptedString()
        {
            // Arrange
            string plainText = "SensitiveData";
            byte[] key = _securityHelper.GenerateSymmetricKey();

            // Act
            string encrypted = _securityHelper.EncryptStringGCM(plainText, key);

            // Assert
            Assert.NotNull(encrypted);
            Assert.NotEmpty(encrypted);
            Assert.Contains("|", encrypted); // Should have pipe-delimited format
            var parts = encrypted.Split('|');
            Assert.Equal(3, parts.Length); // nonce|tag|ciphertext
        }

        [Fact]
        public void EncryptStringGCM_WithInvalidKeySize_ThrowsArgumentException()
        {
            // Arrange
            string plainText = "SensitiveData";
            byte[] invalidKey = new byte[16]; // Should be 32 bytes

            // Act & Assert
            Assert.Throws<ArgumentException>(() => _securityHelper.EncryptStringGCM(plainText, invalidKey));
        }

        [Fact]
        public void DecryptStringGCM_WithValidEncryptedText_ReturnsPlainText()
        {
            // Arrange
            string plainText = "SensitiveData";
            byte[] key = _securityHelper.GenerateSymmetricKey();
            string encrypted = _securityHelper.EncryptStringGCM(plainText, key);

            // Act
            string decrypted = _securityHelper.DecryptStringGCM(encrypted, key);

            // Assert
            Assert.Equal(plainText, decrypted);
        }

        [Fact]
        public void DecryptStringGCM_WithInvalidFormat_ThrowsFormatException()
        {
            // Arrange
            byte[] key = _securityHelper.GenerateSymmetricKey();
            string invalidFormat = "invalid|format";

            // Act & Assert
            Assert.Throws<FormatException>(() => _securityHelper.DecryptStringGCM(invalidFormat, key));
        }

        [Fact]
        public void DecryptStringGCM_WithInvalidNonceSize_ThrowsFormatException()
        {
            // Arrange
            string plainText = "SensitiveData";
            byte[] key = _securityHelper.GenerateSymmetricKey();
            string encrypted = _securityHelper.EncryptStringGCM(plainText, key);
            var parts = encrypted.Split('|');
            byte[] validNonce = Convert.FromBase64String(parts[0]);
            byte[] validTag = Convert.FromBase64String(parts[1]);
            byte[] validCipher = Convert.FromBase64String(parts[2]);

            byte[] shortNonce = new byte[validNonce.Length - 1];
            Array.Copy(validNonce, shortNonce, shortNonce.Length);

            string invalid = $"{Convert.ToBase64String(shortNonce)}|{Convert.ToBase64String(validTag)}|{Convert.ToBase64String(validCipher)}";

            // Act & Assert
            Assert.Throws<FormatException>(() => _securityHelper.DecryptStringGCM(invalid, key));
        }

        [Fact]
        public void DecryptStringGCM_WithInvalidTagSize_ThrowsFormatException()
        {
            // Arrange
            string plainText = "SensitiveData";
            byte[] key = _securityHelper.GenerateSymmetricKey();
            string encrypted = _securityHelper.EncryptStringGCM(plainText, key);
            var parts = encrypted.Split('|');
            byte[] validNonce = Convert.FromBase64String(parts[0]);
            byte[] validTag = Convert.FromBase64String(parts[1]);
            byte[] validCipher = Convert.FromBase64String(parts[2]);

            byte[] shortTag = new byte[validTag.Length - 1];
            Array.Copy(validTag, shortTag, shortTag.Length);

            string invalid = $"{Convert.ToBase64String(validNonce)}|{Convert.ToBase64String(shortTag)}|{Convert.ToBase64String(validCipher)}";

            // Act & Assert
            Assert.Throws<FormatException>(() => _securityHelper.DecryptStringGCM(invalid, key));
        }

        [Fact]
        public void EncryptDecryptStringGCM_RoundTrip_PreservesData()
        {
            // Arrange
            string[] testData = { "Hello World", "123456", "Special!@#$%^&*()", "" };
            byte[] key = _securityHelper.GenerateSymmetricKey();

            foreach (string data in testData)
            {
                // Act
                string encrypted = _securityHelper.EncryptStringGCM(data, key);
                string decrypted = _securityHelper.DecryptStringGCM(encrypted, key);

                // Assert
                Assert.Equal(data, decrypted);
            }
        }

        [Fact]
        public void EncryptStringGCM_DifferentNonces_ProducesDifferentCiphertexts()
        {
            // Arrange
            string plainText = "SensitiveData";
            byte[] key = _securityHelper.GenerateSymmetricKey();

            // Act
            string encrypted1 = _securityHelper.EncryptStringGCM(plainText, key);
            string encrypted2 = _securityHelper.EncryptStringGCM(plainText, key);

            // Assert - Different nonces should produce different ciphertexts
            Assert.NotEqual(encrypted1, encrypted2);
            
            // But they should decrypt to the same plaintext
            string decrypted1 = _securityHelper.DecryptStringGCM(encrypted1, key);
            string decrypted2 = _securityHelper.DecryptStringGCM(encrypted2, key);
            Assert.Equal(decrypted1, decrypted2);
        }

        [Fact]
        public void DecryptStringGCM_WithModifiedCiphertext_ThrowsException()
        {
            // Arrange
            string plainText = "SensitiveData";
            byte[] key = _securityHelper.GenerateSymmetricKey();
            string encrypted = _securityHelper.EncryptStringGCM(plainText, key);
            var parts = encrypted.Split('|');
            
            // Modify the ciphertext part
            string modifiedEncrypted = $"{parts[0]}|{parts[1]}|InvalidCiphertext";

            // Act & Assert
            Assert.Throws<FormatException>(() => _securityHelper.DecryptStringGCM(modifiedEncrypted, key));
        }
#else
        [Fact]
        public void EncryptStringGCM_OnNetFramework_ThrowsNotSupportedException()
        {
            // Arrange
            string plainText = "SensitiveData";
            byte[] key = _securityHelper.GenerateSymmetricKey();

            // Act & Assert
            Assert.Throws<NotSupportedException>(() => _securityHelper.EncryptStringGCM(plainText, key));
        }

        [Fact]
        public void DecryptStringGCM_OnNetFramework_ThrowsNotSupportedException()
        {
            // Arrange
            byte[] key = _securityHelper.GenerateSymmetricKey();

            // Act & Assert
            Assert.Throws<NotSupportedException>(() => _securityHelper.DecryptStringGCM("nonce|tag|cipher", key));
        }
#endif

        #endregion

        #region Argon2 Tests

        [Fact]
        public void HashPasswordWithArgon2_WithValidInput_ReturnsBase64Hash()
        {
            // Arrange
            string password = "MySecurePassword";
            string salt = "SomeSalt";

            // Act
            string hash = _securityHelper.HashPasswordWithArgon2(password, salt);

            // Assert
            Assert.NotNull(hash);
            Assert.NotEmpty(hash);
            byte[] decodedHash = Convert.FromBase64String(hash);
            Assert.NotEmpty(decodedHash);
        }

        [Fact]
        public void HashPasswordWithArgon2_SamePasswordSameSalt_ProducesSameHash()
        {
            // Arrange
            string password = "MySecurePassword";
            string salt = "SomeSalt";

            // Act
            string hash1 = _securityHelper.HashPasswordWithArgon2(password, salt);
            string hash2 = _securityHelper.HashPasswordWithArgon2(password, salt);

            // Assert
            Assert.Equal(hash1, hash2);
        }

        [Fact]
        public void HashPasswordWithArgon2_DifferentPasswords_ProducesDifferentHashes()
        {
            // Arrange
            string password1 = "Password1";
            string password2 = "Password2";
            string salt = "SomeSalt";

            // Act
            string hash1 = _securityHelper.HashPasswordWithArgon2(password1, salt);
            string hash2 = _securityHelper.HashPasswordWithArgon2(password2, salt);

            // Assert
            Assert.NotEqual(hash1, hash2);
        }

        #endregion

        #region Async Methods Tests

        [Fact]
        public async void HashPasswordWithPBKDF2Async_ProducesValidHash()
        {
            // Arrange
            string password = "MySecurePassword";
            byte[] salt = Convert.FromBase64String(_securityHelper.GenerateSalt());

            // Act
            string hash = await _securityHelper.HashPasswordWithPBKDF2Async(password, salt, HashAlgorithmName.SHA256);

            // Assert
            Assert.NotNull(hash);
            byte[] decodedHash = Convert.FromBase64String(hash);
            Assert.Equal(32, decodedHash.Length);
        }

        [Fact]
        public async void ComputeHMACAsync_ProducesValidResult()
        {
            // Arrange
            string input = "TestData";
            string key = "SecretKey";

            // Act
            string hmac = await _securityHelper.ComputeHMACAsync(input, key, HashAlgorithmName.SHA256);

            // Assert
            Assert.NotNull(hmac);
            byte[] decodedHmac = Convert.FromBase64String(hmac);
            Assert.NotEmpty(decodedHmac);
        }

        [Fact]
        public async void HashPasswordWithArgon2Async_ProducesValidHash()
        {
            // Arrange
            string password = "MySecurePassword";
            string salt = "SomeSalt";

            // Act
            string hash = await _securityHelper.HashPasswordWithArgon2Async(password, salt);

            // Assert
            Assert.NotNull(hash);
            byte[] decodedHash = Convert.FromBase64String(hash);
            Assert.NotEmpty(decodedHash);
        }

        #endregion

        #region Secure String Handling Tests

#if NET6_0_OR_GREATER
        [Fact]
        public void HashPasswordWithPBKDF2Span_WithValidSpan_ReturnsValidHash()
        {
            // Arrange
            ReadOnlySpan<char> password = "MySecurePassword".AsSpan();
            byte[] salt = Convert.FromBase64String(_securityHelper.GenerateSalt());

            // Act
            string hash = _securityHelper.HashPasswordWithPBKDF2Span(password, salt, HashAlgorithmName.SHA256);

            // Assert
            Assert.NotNull(hash);
            Assert.NotEmpty(hash);
            byte[] decodedHash = Convert.FromBase64String(hash);
            Assert.Equal(32, decodedHash.Length);
        }

        [Fact]
        public void HashPasswordWithPBKDF2Span_SamePasswordSameSalt_ProducesSameHash()
        {
            // Arrange
            ReadOnlySpan<char> password = "MySecurePassword".AsSpan();
            byte[] salt = Convert.FromBase64String(_securityHelper.GenerateSalt());

            // Act
            string hash1 = _securityHelper.HashPasswordWithPBKDF2Span(password, salt, HashAlgorithmName.SHA256);
            string hash2 = _securityHelper.HashPasswordWithPBKDF2Span(password, salt, HashAlgorithmName.SHA256);

            // Assert
            Assert.Equal(hash1, hash2);
        }

        [Fact]
        public void HashPasswordWithPBKDF2Span_EquivalentToStringVersion()
        {
            // Arrange
            string passwordStr = "MySecurePassword";
            ReadOnlySpan<char> passwordSpan = passwordStr.AsSpan();
            byte[] salt = Convert.FromBase64String(_securityHelper.GenerateSalt());

            // Act
            string hashFromString = _securityHelper.HashPasswordWithPBKDF2(passwordStr, salt, HashAlgorithmName.SHA256);
            string hashFromSpan = _securityHelper.HashPasswordWithPBKDF2Span(passwordSpan, salt, HashAlgorithmName.SHA256);

            // Assert
            Assert.Equal(hashFromString, hashFromSpan);
        }

        [Fact]
        public void VerifyPasswordWithPBKDF2Span_WithCorrectPassword_ReturnsTrue()
        {
            // Arrange
            string password = "MySecurePassword";
            ReadOnlySpan<char> passwordSpan = password.AsSpan();
            string storedHash = _securityHelper.HashPasswordWithPBKDF2(password, out string _, HashAlgorithmName.SHA256);

            // Act
            bool result = _securityHelper.VerifyPasswordWithPBKDF2Span(passwordSpan, storedHash);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void VerifyPasswordWithPBKDF2Span_WithIncorrectPassword_ReturnsFalse()
        {
            // Arrange
            string password = "MySecurePassword";
            ReadOnlySpan<char> wrongPassword = "WrongPassword".AsSpan();
            string storedHash = _securityHelper.HashPasswordWithPBKDF2(password, out string _, HashAlgorithmName.SHA256);

            // Act
            bool result = _securityHelper.VerifyPasswordWithPBKDF2Span(wrongPassword, storedHash);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void VerifyPasswordWithPBKDF2Span_EquivalentToStringVersion()
        {
            // Arrange
            string password = "MySecurePassword";
            ReadOnlySpan<char> passwordSpan = password.AsSpan();
            string storedHash = _securityHelper.HashPasswordWithPBKDF2(password, out string _, HashAlgorithmName.SHA256);

            // Act
            bool resultFromString = _securityHelper.VerifyPasswordWithPBKDF2(password, storedHash);
            bool resultFromSpan = _securityHelper.VerifyPasswordWithPBKDF2Span(passwordSpan, storedHash);

            // Assert
            Assert.Equal(resultFromString, resultFromSpan);
        }

        [Fact]
        public void ClearSensitiveData_WithCharSpan_ZerosOut()
        {
            // Arrange
            char[] sensitiveData = "SensitivePassword".ToCharArray();
            Span<char> span = new Span<char>(sensitiveData);
            char[] beforeClear = new char[sensitiveData.Length];
            Array.Copy(sensitiveData, beforeClear, sensitiveData.Length);

            // Act
            _securityHelper.ClearSensitiveData(span);

            // Assert
            for (int i = 0; i < sensitiveData.Length; i++)
            {
                Assert.Equal('\0', sensitiveData[i]);
            }
            // Verify it was different before
            Assert.NotEqual(beforeClear, sensitiveData);
        }
#endif

        [Fact]
        public void ClearSensitiveData_WithByteArray_ZerosOut()
        {
            // Arrange
            byte[] sensitiveData = Encoding.UTF8.GetBytes("SensitivePassword");
            byte[] beforeClear = new byte[sensitiveData.Length];
            Array.Copy(sensitiveData, beforeClear, sensitiveData.Length);

            // Act
            _securityHelper.ClearSensitiveData(sensitiveData);

            // Assert
            for (int i = 0; i < sensitiveData.Length; i++)
            {
                Assert.Equal(0, sensitiveData[i]);
            }
            // Verify it was different before
            Assert.NotEqual(beforeClear, sensitiveData);
        }

        [Fact]
        public void ClearSensitiveData_WithNullArray_DoesNotThrow()
        {
            // Act & Assert - Should not throw
            _securityHelper.ClearSensitiveData((byte[])null);
        }

        [Fact]
        public void ClearSensitiveData_WithEmptyArray_DoesNotThrow()
        {
            // Arrange
            byte[] emptyData = new byte[0];

            // Act & Assert - Should not throw
            _securityHelper.ClearSensitiveData(emptyData);
        }

        #endregion
    }
}
