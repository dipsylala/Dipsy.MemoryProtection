namespace Dipsy.MemoryProtection
{
    /// <summary>
    /// Stores a secret encrypted in memory. The secret is only decrypted temporarily when accessed via UseSecret callbacks.
    /// Use ProtectedSecret.Consume() to create an instance.
    /// </summary>
    public class ProtectedSecret : IDisposable
    {
        private byte[]? _encryptedData;
        private bool _disposed = false;

        /// <summary>
        /// Private constructor - use Consume() factory method instead.
        /// </summary>
        private ProtectedSecret(byte[] encryptedData)
        {
            _encryptedData = encryptedData;
        }

        /// <summary>
        /// Creates a new ProtectedSecret by consuming and encrypting the provided secret.
        /// The input secret array is cleared (zeroed) for security after encryption.
        /// </summary>
        /// <param name="secret">Secret as char array. This array will be cleared (zeroed) after encryption.</param>
        /// <returns>A new ProtectedSecret with the encrypted secret.</returns>
        public static ProtectedSecret Consume(char[] secret)
        {
            byte[] encryptedData = SecretEncryption.Instance.ProtectInMemory(secret);
            // Note: secret array is now cleared (all zeros) by ProtectInMemory
            return new ProtectedSecret(encryptedData);
        }

        /// <summary>
        /// Safely use the secret within a callback. The secret is automatically cleared after the callback completes.
        /// Callers must not copy the secret (e.g., new string(secret) or secret.ToArray()) as copies won't be cleared.
        /// </summary>
        /// <param name="action">Callback that receives the secret as a ReadOnlySpan. Do not store or copy this span - work with it directly.</param>
        /// <exception cref="ObjectDisposedException">Thrown if this ProtectedSecret has been disposed.</exception>
        /// <exception cref="ArgumentNullException">Thrown if action is null.</exception>
        public void UseSecret(Action<ReadOnlySpan<char>> action)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("ProtectedSecret");
            }

            if (action == null)
            {
                throw new ArgumentNullException(nameof(action));
            }

            char[]? tempSecret = null;
            try
            {
                tempSecret = SecretEncryption.Instance.UnprotectFromMemory(_encryptedData!);
                // Pass as ReadOnlySpan to prevent caller from modifying
                action(tempSecret.AsSpan());
            }
            finally
            {
                // Plaintext is auto-cleared after callback; callers must not copy it
                if (tempSecret != null)
                {
                    Array.Clear(tempSecret, 0, tempSecret.Length);
                }
            }
        }

        /// <summary>
        /// Safely use the secret within a callback that returns a result. The secret is automatically cleared after the callback completes.
        /// Callers must not copy the secret (e.g., new string(secret) or secret.ToArray()) as copies won't be cleared.
        /// </summary>
        /// <typeparam name="TResult">The type of result returned by the callback.</typeparam>
        /// <param name="func">Callback that receives the secret as a ReadOnlySpan and returns a result. Do not store or copy the span - work with it directly.</param>
        /// <returns>The result from the callback.</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this ProtectedSecret has been disposed.</exception>
        /// <exception cref="ArgumentNullException">Thrown if func is null.</exception>
        public TResult UseSecret<TResult>(Func<ReadOnlySpan<char>, TResult> func)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("ProtectedSecret");
            }

            if (func == null)
            {
                throw new ArgumentNullException(nameof(func));
            }

            char[]? tempSecret = null;
            try
            {
                tempSecret = SecretEncryption.Instance.UnprotectFromMemory(_encryptedData!);
                // Pass as ReadOnlySpan to prevent caller from modifying
                return func(tempSecret.AsSpan());
            }
            finally
            {
                // Plaintext is auto-cleared after callback; callers must not copy it
                if (tempSecret != null)
                {
                    Array.Clear(tempSecret, 0, tempSecret.Length);
                }
            }
        }

        /// <summary>
        /// Disposes this ProtectedSecret, clearing the encrypted data from memory.
        /// </summary>
        public void Dispose()
        {
            if (_disposed) return;

            // Clear encrypted data
            if (_encryptedData != null)
            {
                Array.Clear(_encryptedData, 0, _encryptedData.Length);
                _encryptedData = null;
            }

            _disposed = true;
        }
    }
}
