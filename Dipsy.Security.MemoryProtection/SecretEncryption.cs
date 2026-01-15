namespace Dipsy.Security.MemoryProtection
{
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// Singleton for encrypting/decrypting sensitive data in memory.
    /// The session key is randomly generated on first use and cleared on application shutdown (best-effort).
    /// 
    /// LIMITATIONS:
    /// - Cleanup hooks are best-effort and won't run on hard termination/crash
    /// - Encoding conversions may create transient runtime buffers that can't be reliably wiped in managed environments
    /// - Key material is stored in managed memory (subject to GC movement)
    /// </summary>
    public sealed class SecretEncryption
    {
        private static readonly Lazy<SecretEncryption> _instance = new(() => new SecretEncryption());

        public static SecretEncryption Instance => _instance.Value;

        private readonly SecureKeyManager _keyManager;
        private volatile bool _disposed = false;

        private SecretEncryption()
        {
            // Generate random session key and create single SecureKeyManager instance
            byte[] sessionKey = new byte[32];
            RandomNumberGenerator.Fill(sessionKey);
            
            try
            {
                _keyManager = new SecureKeyManager(sessionKey);
            }
            finally
            {
                // Clear the temporary session key array
                Array.Clear(sessionKey, 0, sessionKey.Length);
            }

            // Multiple cleanup hooks for different shutdown scenarios
            try
            {
                AppDomain.CurrentDomain.ProcessExit += OnProcessExit;
                AppDomain.CurrentDomain.DomainUnload += OnProcessExit;

                // For console apps - handle Ctrl+C
                Console.CancelKeyPress += OnCancelKeyPress;
            }
            catch
            {
                // Event registration failed - still continue
                // Key will be cleared by finalizer if needed
            }
        }

        private void OnProcessExit(object? sender, EventArgs e)
        {
            try
            {
                Cleanup();
            }
            catch
            {
                // Suppress exceptions during shutdown
                // Don't prevent other cleanup handlers from running
            }
        }

        private void OnCancelKeyPress(object? sender, ConsoleCancelEventArgs e)
        {
            try
            {
                Cleanup();
            }
            catch
            {
                // Suppress exceptions
            }
        }

        public byte[] ProtectInMemory(char[] secret)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("SecretEncryption");
            }

            try
            {
                // Convert char[] to bytes
                byte[] secretBytes = Encoding.UTF8.GetBytes(secret);

                try
                {
                    // Encrypt using shared session key manager
                    // No lock needed - SecureKeyManager creates new AesGcm per call
                    return _keyManager.Encrypt(secretBytes);
                }
                finally
                {
                    // Clear plaintext secret bytes
                    Array.Clear(secretBytes, 0, secretBytes.Length);
                }
            }
            finally
            {
                // Clear original char array
                Array.Clear(secret, 0, secret.Length);
            }
        }

        public char[] UnprotectFromMemory(byte[] encryptedData)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("SecretEncryption");
            }

            // Decrypt using shared session key manager
            // No lock needed - SecureKeyManager creates new AesGcm per call
            byte[] secretBytes = _keyManager.Decrypt(encryptedData);

            try
            {
                // Decode UTF-8 bytes directly to char[] without creating intermediate string
                int charCount = Encoding.UTF8.GetCharCount(secretBytes);
                char[] result = new char[charCount];
                Encoding.UTF8.GetChars(secretBytes, 0, secretBytes.Length, result, 0);
                return result;
            }
            finally
            {
                // Clear decrypted bytes
                Array.Clear(secretBytes, 0, secretBytes.Length);
            }
        }

        private void Cleanup()
        {
            if (_disposed) return;

            _disposed = true;
            _keyManager?.Dispose();
        }
    }
}
