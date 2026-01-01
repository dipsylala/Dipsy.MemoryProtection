namespace Dipsy.MemoryProtection
{
    using System;
    using System.Security.Cryptography;
    using System.Text;

    // LAYER 1: Low-level encryption utility
    public class SecureKeyManager(byte[] key) : IDisposable
    {
        // Use explicit standard sizes for AES-GCM
        private const int NonceSize = 12;  // 96 bits - standard for GCM
        private const int TagSize = 16;    // 128 bits - standard authentication tag
        
        // Associated data for binding ciphertext to context
        private static readonly byte[] DefaultAad = Encoding.UTF8.GetBytes("Dipsy.MemoryProtection:v1");
        
        private byte[]? _keyBytes = InitializeKey(key);
        private bool _disposed = false;

        private static byte[] InitializeKey(byte[] key)
        {
            // Store key in byte array (must be 32 bytes for AES-256)
            if (key.Length != 32)
            {
                throw new ArgumentException("Key must be 32 bytes for AES-256-GCM");
            }

            var keyBytes = new byte[key.Length];
            Array.Copy(key, keyBytes, key.Length);
            return keyBytes;
        }

        public byte[] Encrypt(byte[] plaintext)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("SecureKeyManager");
            }

            // Use AesGcm class for authenticated encryption (.NET Core 3.0+)
            using var aesGcm = new AesGcm(_keyBytes!, TagSize);

            // Generate random nonce (12 bytes - standard for GCM)
            var nonce = new byte[NonceSize];
            RandomNumberGenerator.Fill(nonce);

            // Allocate space for ciphertext and auth tag
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[TagSize];

            try
            {
                // Encrypt with authentication and associated data (AAD)
                // AAD binds ciphertext to context, prevents mix-and-match attacks
                aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, DefaultAad);

                // Return: nonce + tag + ciphertext
                var result = new byte[nonce.Length + tag.Length + ciphertext.Length];
                Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
                Buffer.BlockCopy(tag, 0, result, nonce.Length, tag.Length);
                Buffer.BlockCopy(ciphertext, 0, result, nonce.Length + tag.Length, ciphertext.Length);

                return result;
            }
            finally
            {
                // Clear intermediate buffers for defense in depth
                Array.Clear(nonce, 0, nonce.Length);
                Array.Clear(tag, 0, tag.Length);
                Array.Clear(ciphertext, 0, ciphertext.Length);
            }
        }

        public byte[] Decrypt(byte[] encryptedData)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("SecureKeyManager");
            }

            // Validate minimum length before slicing
            int minLength = NonceSize + TagSize;
            if (encryptedData == null || encryptedData.Length < minLength)
            {
                throw new CryptographicException(
                    $"Encrypted data must be at least {minLength} bytes (nonce + tag). Received: {encryptedData?.Length ?? 0} bytes");
            }

            // Extract nonce, tag, and ciphertext
            var nonce = new byte[NonceSize];
            var tag = new byte[TagSize];
            var ciphertext = new byte[encryptedData.Length - NonceSize - TagSize];

            Buffer.BlockCopy(encryptedData, 0, nonce, 0, NonceSize);
            Buffer.BlockCopy(encryptedData, NonceSize, tag, 0, TagSize);
            Buffer.BlockCopy(encryptedData, NonceSize + TagSize, ciphertext, 0, ciphertext.Length);

            // Decrypt and verify authentication tag
            using var aesGcm = new AesGcm(_keyBytes!, TagSize);
            var plaintext = new byte[ciphertext.Length];

            try
            {
                // Decrypt with AAD verification - ensures ciphertext hasn't been moved between contexts
                aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, DefaultAad);
                return plaintext;
            }
            catch
            {
                // Clear plaintext buffer on decryption failure (bad tag, etc.)
                Array.Clear(plaintext, 0, plaintext.Length);
                throw;
            }
            finally
            {
                // Clear intermediate buffers for defense in depth
                Array.Clear(nonce, 0, nonce.Length);
                Array.Clear(tag, 0, tag.Length);
                Array.Clear(ciphertext, 0, ciphertext.Length);
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (_keyBytes != null)
            {
                // Clear key from memory
                Array.Clear(_keyBytes, 0, _keyBytes.Length);
                _keyBytes = null;
            }

            _disposed = true;
        }

        ~SecureKeyManager()
        {
            Dispose(false);
        }
    }
}
