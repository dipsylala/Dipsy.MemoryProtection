namespace Dipsy.MemoryProtection.Tests;

using System.Security.Cryptography;
using System.Text;

public class SecureKeyManagerTests
{
    [Fact]
    public void Constructor_WithInvalidKeyLength_ThrowsArgumentException()
    {
        var invalidKey = new byte[16]; // Only 16 bytes instead of 32

        Assert.Throws<ArgumentException>(() => new SecureKeyManager(invalidKey));
    }

    [Fact]
    public void Encrypt_WithValidData_ReturnsEncryptedBytes()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        
        using var keyManager = new SecureKeyManager(key);
        var plaintext = Encoding.UTF8.GetBytes("test secret");
        
        var encrypted = keyManager.Encrypt(plaintext);
        
        Assert.NotNull(encrypted);
        Assert.NotEmpty(encrypted);
        Assert.NotEqual(plaintext, encrypted);
    }

    [Fact]
    public void Decrypt_WithValidData_ReturnsOriginalPlaintext()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        
        using var keyManager = new SecureKeyManager(key);
        var originalText = "test secret 123";
        var plaintext = Encoding.UTF8.GetBytes(originalText);
        
        var encrypted = keyManager.Encrypt(plaintext);
        var decrypted = keyManager.Decrypt(encrypted);
        var decryptedText = Encoding.UTF8.GetString(decrypted);
        
        Assert.Equal(originalText, decryptedText);
    }

    [Fact]
    public void Encrypt_SameData_ProducesDifferentCiphertext()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        
        using var keyManager = new SecureKeyManager(key);
        var plaintext = Encoding.UTF8.GetBytes("test secret");
        
        var encrypted1 = keyManager.Encrypt(plaintext);
        var encrypted2 = keyManager.Encrypt(plaintext);
        
        Assert.NotEqual(encrypted1, encrypted2);
    }

    [Fact]
    public void Encrypt_AfterDispose_ThrowsObjectDisposedException()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        
        var keyManager = new SecureKeyManager(key);
        keyManager.Dispose();
        
        Assert.Throws<ObjectDisposedException>(() => keyManager.Encrypt(new byte[] { 1, 2, 3 }));
    }

    [Fact]
    public void Decrypt_AfterDispose_ThrowsObjectDisposedException()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        
        var keyManager = new SecureKeyManager(key);
        var encrypted = keyManager.Encrypt(new byte[] { 1, 2, 3 });
        keyManager.Dispose();
        
        Assert.Throws<ObjectDisposedException>(() => keyManager.Decrypt(encrypted));
    }

    [Fact]
    public void Decrypt_WithWrongKey_ThrowsCryptographicException()
    {
        var key1 = new byte[32];
        var key2 = new byte[32];
        RandomNumberGenerator.Fill(key1);
        RandomNumberGenerator.Fill(key2);
        
        byte[] encrypted;
        using (var keyManager1 = new SecureKeyManager(key1))
        {
            encrypted = keyManager1.Encrypt(Encoding.UTF8.GetBytes("secret"));
        }
        
        using var keyManager2 = new SecureKeyManager(key2);
        Assert.Throws<AuthenticationTagMismatchException>(() => keyManager2.Decrypt(encrypted));
    }

    [Fact]
    public void Encrypt_EmptyData_SuccessfullyEncryptsAndDecrypts()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        
        using var keyManager = new SecureKeyManager(key);
        var plaintext = Array.Empty<byte>();
        
        var encrypted = keyManager.Encrypt(plaintext);
        var decrypted = keyManager.Decrypt(encrypted);
        
        Assert.Empty(decrypted);
    }

    [Fact]
    public void Decrypt_WithTooShortData_ThrowsCryptographicException()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        
        using var keyManager = new SecureKeyManager(key);
        
        // Data too short (less than nonce + tag = 28 bytes)
        var tooShortData = new byte[20];
        
        var ex = Assert.Throws<CryptographicException>(() => keyManager.Decrypt(tooShortData));
        Assert.Contains("at least 28 bytes", ex.Message);
    }

    [Fact]
    public void Decrypt_WithNullData_ThrowsCryptographicException()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        
        using var keyManager = new SecureKeyManager(key);
        
        var ex = Assert.Throws<CryptographicException>(() => keyManager.Decrypt(null!));
        Assert.Contains("at least 28 bytes", ex.Message);
    }

    [Fact]
    public void Decrypt_WithCorruptedData_ThrowsAndClearsPlaintext()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        
        using var keyManager = new SecureKeyManager(key);
        var plaintext = Encoding.UTF8.GetBytes("secret data");
        
        // Encrypt valid data
        var encrypted = keyManager.Encrypt(plaintext);
        
        // Corrupt the tag (bytes 12-27)
        encrypted[15] ^= 0xFF;
        
        // Decryption should fail due to authentication tag mismatch
        Assert.Throws<AuthenticationTagMismatchException>(() => keyManager.Decrypt(encrypted));
    }
}

public class SecretEncryptionTests
{
    [Fact]
    public void Instance_ReturnsSameInstance()
    {
        var instance1 = SecretEncryption.Instance;
        var instance2 = SecretEncryption.Instance;
        
        Assert.Same(instance1, instance2);
    }

    [Fact]
    public void ProtectInMemory_WithValidsecret_ReturnsEncryptedData()
    {
        var secret = "MySecuresecret123!".ToCharArray();
        
        var encrypted = SecretEncryption.Instance.ProtectInMemory(secret);
        
        Assert.NotNull(encrypted);
        Assert.NotEmpty(encrypted);
    }

    [Fact]
    public void ProtectInMemory_ClearsOriginalsecretArray()
    {
        var secret = "MySecuresecret123!".ToCharArray();
        var originalsecret = secret.ToArray();
        
        SecretEncryption.Instance.ProtectInMemory(secret);
        
        Assert.All(secret, c => Assert.Equal('\0', c));
    }

    [Fact]
    public void UnprotectFromMemory_ReturnsOriginalsecret()
    {
        var originalsecret = "MySecuresecret123!";
        var secret = originalsecret.ToCharArray();
        
        var encrypted = SecretEncryption.Instance.ProtectInMemory(secret);
        var decrypted = SecretEncryption.Instance.UnprotectFromMemory(encrypted);
        
        try
        {
            Assert.Equal(originalsecret, new string(decrypted));
        }
        finally
        {
            Array.Clear(decrypted, 0, decrypted.Length);
        }
    }

    [Fact]
    public void ProtectInMemory_WithEmptysecret_WorksCorrectly()
    {
        var secret = Array.Empty<char>();
        
        var encrypted = SecretEncryption.Instance.ProtectInMemory(secret);
        var decrypted = SecretEncryption.Instance.UnprotectFromMemory(encrypted);
        
        try
        {
            Assert.Empty(decrypted);
        }
        finally
        {
            if (decrypted.Length > 0)
            {
                Array.Clear(decrypted, 0, decrypted.Length);
            }
        }
    }

    [Fact]
    public void ProtectInMemory_WithUnicodeCharacters_WorksCorrectly()
    {
        var originalsecret = "????????????";
        var secret = originalsecret.ToCharArray();
        
        var encrypted = SecretEncryption.Instance.ProtectInMemory(secret);
        var decrypted = SecretEncryption.Instance.UnprotectFromMemory(encrypted);
        
        try
        {
            Assert.Equal(originalsecret, new string(decrypted));
        }
        finally
        {
            Array.Clear(decrypted, 0, decrypted.Length);
        }
    }

    [Fact]
    public void ProtectInMemory_CalledTwiceWithSamesecret_ProducesDifferentCiphertext()
    {
        var secret1 = "Samesecret".ToCharArray();
        var secret2 = "Samesecret".ToCharArray();
        
        var encrypted1 = SecretEncryption.Instance.ProtectInMemory(secret1);
        var encrypted2 = SecretEncryption.Instance.ProtectInMemory(secret2);
        
        Assert.NotEqual(encrypted1, encrypted2);
    }
}

public class ProtectedSecretTests
{
    [Fact]
    public void Constructor_WithValidsecret_CreatesInstance()
    {
        var secret = "Testsecret123!".ToCharArray();
        
        using var protectedSecret = ProtectedSecret.Consume(secret);
        
        Assert.NotNull(protectedSecret);
    }

    [Fact]
    public void Constructor_ClearsOriginalsecretArray()
    {
        var secret = "Testsecret123!".ToCharArray();
        
        using var protectedSecret = ProtectedSecret.Consume(secret);
        
        Assert.All(secret, c => Assert.Equal('\0', c));
    }

    [Fact]
    public void Consume_ClearsOriginalsecretArray()
    {
        var secret = "Testsecret123!".ToCharArray();
        
        using var protectedSecret = ProtectedSecret.Consume(secret);
        
        Assert.All(secret, c => Assert.Equal('\0', c));
    }

    [Fact]
    public void Consume_CreatesWorkingprotectedSecret()
    {
        var originalsecret = "Testsecret123!";
        var secret = originalsecret.ToCharArray();
        
        using var protectedSecret = ProtectedSecret.Consume(secret);
        
        string? retrieved = null;
        protectedSecret.UseSecret(pwd => { retrieved = new string(pwd); });
        
        Assert.Equal(originalsecret, retrieved);
    }

    [Fact]
    public void Usesecret_WithAction_ExecutesCallbackAndClearssecret()
    {
        var originalsecret = "Testsecret123!";
        var secret = originalsecret.ToCharArray();
        
        using var protectedSecret = ProtectedSecret.Consume(secret);
        
        string? capturedsecret = null;
        protectedSecret.UseSecret(pwd =>
        {
            capturedsecret = new string(pwd);
        });
        
        Assert.Equal(originalsecret, capturedsecret);
    }

    [Fact]
    public void Usesecret_WithFunc_ExecutesCallbackAndReturnsResult()
    {
        var originalsecret = "Testsecret123!";
        var secret = originalsecret.ToCharArray();
        
        using var protectedSecret = ProtectedSecret.Consume(secret);
        
        var result = protectedSecret.UseSecret(pwd =>
        {
            return new string(pwd).Length;
        });
        
        Assert.Equal(originalsecret.Length, result);
    }

    [Fact]
    public void Usesecret_CalledMultipleTimes_ReturnsCorrectsecret()
    {
        var originalsecret = "Testsecret123!";
        var secret = originalsecret.ToCharArray();
        
        using var protectedSecret = ProtectedSecret.Consume(secret);
        
        string? result1 = null;
        protectedSecret.UseSecret(pwd => { result1 = new string(pwd); });
        Assert.Equal(originalsecret, result1);
        
        string? result2 = null;
        protectedSecret.UseSecret(pwd => { result2 = new string(pwd); });
        Assert.Equal(originalsecret, result2);
    }

    [Fact]
    public void Usesecret_AfterDispose_ThrowsObjectDisposedException()
    {
        var secret = "Testsecret123!".ToCharArray();
        var protectedSecret = ProtectedSecret.Consume(secret);
        
        protectedSecret.Dispose();
        
        Assert.Throws<ObjectDisposedException>(() =>
            protectedSecret.UseSecret(pwd => { }));
    }

    [Fact]
    public void Usesecret_WithNullAction_ThrowsArgumentNullException()
    {
        var secret = "Testsecret123!".ToCharArray();
        
        using var protectedSecret = ProtectedSecret.Consume(secret);
        
        Assert.Throws<ArgumentNullException>(() =>
            protectedSecret.UseSecret((Action<ReadOnlySpan<char>>)null!));
    }

    [Fact]
    public void Usesecret_WithNullFunc_ThrowsArgumentNullException()
    {
        var secret = "Testsecret123!".ToCharArray();
        
        using var protectedSecret = ProtectedSecret.Consume(secret);
        
        Assert.Throws<ArgumentNullException>(() =>
            protectedSecret.UseSecret((Func<ReadOnlySpan<char>, int>)null!));
    }

    [Fact]
    public void Usesecret_WithExceptionInCallback_StillClearssecret()
    {
        var secret = "Testsecret123!".ToCharArray();
        
        using var protectedSecret = ProtectedSecret.Consume(secret);
        
        // Even if callback throws, secret should be cleared
        Assert.Throws<InvalidOperationException>(() =>
            protectedSecret.UseSecret(pwd =>
            {
                throw new InvalidOperationException("Test exception");
            }));
        
        // Can still use it again after exception
        var canStillUse = false;
        protectedSecret.UseSecret(pwd => { canStillUse = true; });
        Assert.True(canStillUse);
    }

    [Fact]
    public void Usesecret_secretIsReadOnly_CannotModifySpan()
    {
        var originalsecret = "Testsecret123!";
        var secret = originalsecret.ToCharArray();
        
        using var protectedSecret = ProtectedSecret.Consume(secret);
        
        // ReadOnlySpan prevents modification
        protectedSecret.UseSecret(pwd =>
        {
            // This line would not compile:
            // pwd[0] = 'X';  // Error: cannot assign to readonly span
            
            Assert.Equal(originalsecret[0], pwd[0]);
        });
    }
}
