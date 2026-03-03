using Xunit;
using System;
using System.Security.Cryptography;
using SecurityHelperLibrary;

namespace SecurityHelperLibrary.Tests
{
    public class KeyDerivationTests
    {
        [Fact]
        [Trait("Category", "KeyDerivation")]
        public void KeyDerivation_DeriveKeyMaterial_BasicFunctionality()
        {
            byte[] ikm = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            byte[] salt = new byte[] { 9, 10, 11, 12 };

            byte[] key = KeyDerivation.DeriveKeyMaterial(
                HashAlgorithmName.SHA256,
                ikm,
                salt,
                info: null,
                outputLength: 32);

            Assert.NotNull(key);
            Assert.Equal(32, key.Length);
        }

        [Fact]
        [Trait("Category", "KeyDerivation")]
        public void KeyDerivation_DeriveKeyMaterial_ThrowsOnNullInputMaterial()
        {
            Assert.Throws<ArgumentNullException>(() =>
                KeyDerivation.DeriveKeyMaterial(HashAlgorithmName.SHA256, null, salt: null, info: null, outputLength: 32));
        }

        [Fact]
        [Trait("Category", "KeyDerivation")]
        public void KeyDerivation_MatchesRfc5869TestVectors()
        {
            byte[] ikm = new byte[22];
            for (int i = 0; i < ikm.Length; i++)
            {
                ikm[i] = 0x0b;
            }

            byte[] salt = HexToBytes("000102030405060708090a0b0c");
            byte[] info = HexToBytes("f0f1f2f3f4f5f6f7f8f9");
            byte[] expectedOkm = HexToBytes("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

            byte[] derived = KeyDerivation.DeriveKeyMaterial(
                HashAlgorithmName.SHA256,
                ikm,
                salt,
                info,
                outputLength: 42);

            Assert.Equal(expectedOkm, derived);
        }

        [Fact]
        [Trait("Category", "KeyDerivation")]
        public void KeyDerivation_LegacyHkdfExpand_CompatibleWithDeriveKeyMaterial()
        {
            byte[] ikm = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            byte[] salt = new byte[] { 9, 10, 11, 12 };
            byte[] info = System.Text.Encoding.UTF8.GetBytes("context");

            byte[] modern = KeyDerivation.DeriveKeyMaterial(HashAlgorithmName.SHA256, ikm, salt, info, 32);
            byte[] legacy = KeyDerivation.HkdfExpand(HashAlgorithmName.SHA256, ikm, salt, info, 32);

            Assert.Equal(modern, legacy);
        }

        [Fact]
        [Trait("Category", "KeyDerivation")]
        public void KeyDerivation_HkdfExpand_BasicFunctionality()
        {
            byte[] ikm = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            byte[] salt = new byte[] { 9, 10, 11, 12 };

            byte[] key1 = KeyDerivation.HkdfExpand(
                HashAlgorithmName.SHA256,
                ikm,
                salt,
                info: null,
                outputLength: 32);

            Assert.NotNull(key1);
            Assert.Equal(32, key1.Length);
            Assert.DoesNotContain<byte>(0, key1); // Should be random-looking
        }

        [Fact]
        [Trait("Category", "KeyDerivation")]
        public void KeyDerivation_HkdfExpand_DeterministicOutput()
        {
            byte[] ikm = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            byte[] salt = new byte[] { 9, 10, 11, 12 };
            byte[] info = System.Text.Encoding.UTF8.GetBytes("context");

            byte[] key1 = KeyDerivation.HkdfExpand(
                HashAlgorithmName.SHA256,
                ikm, salt, info, outputLength: 32);

            byte[] key2 = KeyDerivation.HkdfExpand(
                HashAlgorithmName.SHA256,
                ikm, salt, info, outputLength: 32);

            // Same inputs should produce same output (deterministic)
            Assert.Equal(key1, key2);
        }

        [Fact]
        [Trait("Category", "KeyDerivation")]
        public void KeyDerivation_HkdfExpand_DifferentInfo()
        {
            byte[] ikm = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            byte[] salt = new byte[] { 9, 10, 11, 12 };

            byte[] key1 = KeyDerivation.HkdfExpand(
                HashAlgorithmName.SHA256,
                ikm, salt,
                info: System.Text.Encoding.UTF8.GetBytes("context1"),
                outputLength: 32);

            byte[] key2 = KeyDerivation.HkdfExpand(
                HashAlgorithmName.SHA256,
                ikm, salt,
                info: System.Text.Encoding.UTF8.GetBytes("context2"),
                outputLength: 32);

            // Different context should produce different keys
            Assert.NotEqual(key1, key2);
        }

        [Fact]
        [Trait("Category", "KeyDerivation")]
        public void KeyDerivation_HkdfExpand_VariousOutputLengths()
        {
            byte[] ikm = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            byte[] salt = new byte[] { 9, 10, 11, 12 };

            // Test various output lengths
            foreach (int length in new[] { 16, 32, 48, 64, 96, 128 })
            {
                byte[] key = KeyDerivation.HkdfExpand(
                    HashAlgorithmName.SHA256,
                    ikm, salt, info: null, outputLength: length);

                Assert.Equal(length, key.Length);
            }
        }

        [Fact]
        [Trait("Category", "KeyDerivation")]
        public void KeyDerivation_HkdfExpand_DifferentAlgorithms()
        {
            byte[] ikm = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            byte[] salt = new byte[] { 9, 10, 11, 12 };

            var key1 = KeyDerivation.HkdfExpand(HashAlgorithmName.SHA256, ikm, salt, null, 32);
            var key2 = KeyDerivation.HkdfExpand(HashAlgorithmName.SHA384, ikm, salt, null, 32);
            var key3 = KeyDerivation.HkdfExpand(HashAlgorithmName.SHA512, ikm, salt, null, 32);

            // Different algorithms should produce different keys
            Assert.NotEqual(key1, key2);
            Assert.NotEqual(key1, key3);
            Assert.NotEqual(key2, key3);
        }

        [Fact]
        [Trait("Category", "KeyDerivation")]
        public void KeyDerivation_DeriveMultipleKeys()
        {
            byte[] masterKey = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
            
            byte[][] keys = KeyDerivation.DeriveMultipleKeys(
                HashAlgorithmName.SHA256,
                masterKey,
                keyCount: 4,
                keyLength: 32,
                salt: null,
                context: "encryption_keys");

            Assert.NotNull(keys);
            Assert.Equal(4, keys.Length);

            // All keys should be unique
            for (int i = 0; i < keys.Length; i++)
            {
                Assert.Equal(32, keys[i].Length);
                for (int j = i + 1; j < keys.Length; j++)
                {
                    Assert.NotEqual(keys[i], keys[j]);
                }
            }
        }

        [Fact]
        [Trait("Category", "KeyDerivation")]
        public void KeyDerivation_DeriveMultipleKeys_Deterministic()
        {
            byte[] masterKey = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
            
            byte[][] keys1 = KeyDerivation.DeriveMultipleKeys(
                HashAlgorithmName.SHA256,
                masterKey, keyCount: 3, keyLength: 32, context: "test");

            byte[][] keys2 = KeyDerivation.DeriveMultipleKeys(
                HashAlgorithmName.SHA256,
                masterKey, keyCount: 3, keyLength: 32, context: "test");

            // Same inputs should produce same keys
            for (int i = 0; i < keys1.Length; i++)
            {
                Assert.Equal(keys1[i], keys2[i]);
            }
        }

        [Fact]
        [Trait("Category", "KeyDerivation")]
        public void KeyDerivation_DeriveMultipleKeys_ThrowsOnKeyCountBoundary()
        {
            byte[] masterKey = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            Assert.Throws<ArgumentOutOfRangeException>(() =>
                KeyDerivation.DeriveMultipleKeys(HashAlgorithmName.SHA256, masterKey, keyCount: 0, keyLength: 32));

            Assert.Throws<ArgumentOutOfRangeException>(() =>
                KeyDerivation.DeriveMultipleKeys(HashAlgorithmName.SHA256, masterKey, keyCount: 256, keyLength: 32));
        }

        [Fact]
        [Trait("Category", "KeyDerivation")]
        public void KeyDerivation_InvalidInput()
        {
            byte[] validKey = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            // Null IKM
            Assert.Throws<ArgumentNullException>(() => 
                KeyDerivation.HkdfExpand(HashAlgorithmName.SHA256, null, null, null, 32));

            // Empty IKM
            Assert.Throws<ArgumentNullException>(() => 
                KeyDerivation.HkdfExpand(HashAlgorithmName.SHA256, new byte[0], null, null, 32));

            // Invalid output length
            Assert.Throws<ArgumentOutOfRangeException>(() => 
                KeyDerivation.HkdfExpand(HashAlgorithmName.SHA256, validKey, null, null, 0));

            Assert.Throws<ArgumentOutOfRangeException>(() => 
                KeyDerivation.HkdfExpand(HashAlgorithmName.SHA256, validKey, null, null, 10000));
        }

        [Fact]
        [Trait("Category", "KeyDerivation")]
        public void KeyDerivation_SeparationExample()
        {
            // Realistic scenario: derive separate keys for different purposes
            byte[] masterSecret = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(masterSecret);
            }

            byte[][] keys = KeyDerivation.DeriveMultipleKeys(
                HashAlgorithmName.SHA256,
                masterSecret,
                keyCount: 3,
                keyLength: 32,
                context: "application-secrets");

            // Keys are: encryption key, signing key, integrity key
            byte[] encryptionKey = keys[0];
            byte[] signingKey = keys[1];
            byte[] integrityKey = keys[2];

            Assert.Equal(32, encryptionKey.Length);
            Assert.Equal(32, signingKey.Length);
            Assert.Equal(32, integrityKey.Length);
            Assert.NotEqual(encryptionKey, signingKey);
            Assert.NotEqual(signingKey, integrityKey);
        }

        private static byte[] HexToBytes(string hex)
        {
            if (hex == null)
                throw new ArgumentNullException(nameof(hex));
            if (hex.Length % 2 != 0)
                throw new ArgumentException("Hex string length must be even", nameof(hex));

            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }

            return bytes;
        }
    }
}
