# Dipsy.MemoryProtection

A modern .NET library for **reducing plaintext exposure of sensitive data in memory** using AES-256-GCM encryption. Designed as a replacement for the deprecated `SecureString` class.

[![.NET 10](https://img.shields.io/badge/.NET-10-blue)](https://dotnet.microsoft.com/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

> **⚠️ IMPORTANT: IN-MEMORY ONLY**  
> This library is designed for **runtime memory protection only**. The encryption key changes each time your application starts, making it **unsuitable for persistent storage** (files, databases, etc.). Use this for protecting sensitive data **while your application is running**, not for encrypting data at rest.

## 🤔 Why This Library?

- **`SecureString` is deprecated** - Microsoft recommends against using it
- **Memory dumps can expose passwords** - encrypted storage provides defense in depth
- **Replacement for plaintext storage** - better than storing as `string` or `char[]` in memory

## ✨ Features

- 🔒 **AES-256-GCM encryption** - authenticated encryption with additional data (AAD)
- ⚡ **Zero-configuration** - automatic session key generation
- 🎯 **Singleton pattern** - one encryption key per application lifetime
- 🧹 **Automatic cleanup** - session key cleared on app shutdown (best-effort)
- 🛡️ **Memory safety** - clears plaintext immediately after use
- 🔄 **Thread-safe** for concurrent encryption/decryption; no shared plaintext state.
- 📦 **No external dependencies** - pure .NET implementation

## 📦 Installation

### Option 1: Download NuGet Package from Releases

Download the latest `.nupkg` file from the [Releases page](https://github.com/dipsylala/Dipsy.MemoryProtection/releases):

```bash
# Install from downloaded package
dotnet add package Dipsy.MemoryProtection --source /path/to/downloaded/package

# Or add it to a local NuGet source
nuget add Dipsy.MemoryProtection.{version}.nupkg -source C:\MyLocalNuGetSource
dotnet add package Dipsy.MemoryProtection --source C:\MyLocalNuGetSource
```

### Option 2: Clone and Build from Source

```bash
git clone https://github.com/dipsylala/Dipsy.MemoryProtection.git
cd Dipsy.MemoryProtection
dotnet build
```

### Option 3: Add Project Reference

Add a reference to the `Dipsy.MemoryProtection` project in your application:

```bash
dotnet add reference path/to/Dipsy.MemoryProtection/Dipsy.MemoryProtection.csproj
```

Or manually edit your `.csproj` file:

```xml
<ItemGroup>
  <ProjectReference Include="..\Dipsy.MemoryProtection\Dipsy.MemoryProtection.csproj" />
</ItemGroup>
```

> **Note:** This library is not yet published to NuGet.org. Download releases from GitHub or build from source.

## 🚀 Quick Start

### Basic Usage

```csharp
using Dipsy.MemoryProtection;

// Create password as char array (never use string for passwords!)
char[] password = "MySecurePassword123!".ToCharArray();

// Create ProtectedSecret - this consumes and clears the password array
using var ProtectedSecret = ProtectedSecret.Consume(password);
// password[] is now all zeros - it was consumed!

// Use password safely with automatic cleanup
ProtectedSecret.UseSecret(pwd => 
{
    // Use password briefly for authentication
    // pwd is a ReadOnlySpan<char> - should not be stored or copied
    AuthenticateUser(pwd);
    // Plaintext automatically cleared when callback completes!
});

// Or use with return value
bool isValid = ProtectedSecret.UseSecret(pwd => 
{
    return ValidatePassword(pwd);
});
```

## 🏗️ Architecture

### Design Overview

```
┌───────────────────────────────────────────────────────┐
│  SecretEncryption.Instance (Singleton)                │
│  • Generates 32-byte random AES-256 key on first use  │
│  • Key lives in memory for entire app lifetime        │
│  • Automatically cleared on app shutdown              │
└───────────────────────────────────────────────────────┘
                          ↓
                          ↓
        ┌───────────────────────────────────┐
        │    ProtectedSecret                │
        │  • Stores encrypted byte[]        │
        │  • Temporary decryption on demand │
        └───────────────────────────────────┘
                          ↓
                          ↓
        ┌────────────────────────────────────┐
        │   SecureKeyManager                 │
        │  • AES-256-GCM encryption          │
        │  • Random nonce per encryption     │
        │  • Authentication tag verification │
        └────────────────────────────────────┘
```

### Data Flow

1. **Password arrives** as `char[]` (never use `string`!)
2. **ProtectedSecret** encrypts it with session key → stored as encrypted `byte[]` in RAM
3. **When needed:** `UseSecret()` temporarily decrypts to `ReadOnlySpan<char>`
4. **Use within callback** → plaintext automatically cleared when callback completes
5. **Result:** Password exists in cleartext only during callback execution

### Security Layers

| Layer | Component | Role |
|-------|-----------|------------|
| **Layer 1** | `SecureKeyManager` | AES-256-GCM encryption with random nonces |
| **Layer 2** | `MemoryProtection` | Session key management & auto-cleanup |
| **Layer 3** | `ProtectedSecret` | High-level API with automatic memory clearing |

## 🔑 How It Works

### Session Key

- `SecretEncryption.Instance` is a **singleton** - one instance per application
- On first use, generates **32-byte random encryption key** automatically
- Key lives in memory for entire app lifetime
- Cleared on app shutdown (handles `ProcessExit`, `DomainUnload`, `Ctrl+C`)
- You **never handle the key directly** - just call `ProtectInMemory()` / `UnprotectFromMemory()`

### Encryption Details

- **Algorithm:** AES-256-GCM (Galois/Counter Mode)
- **Key size:** 256 bits (32 bytes)
- **Nonce:** 96 bits (12 bytes) - randomly generated per encryption
- **Tag size:** 128 bits (16 bytes) - for authentication
- **AAD (Associated Data):** `"Dipsy.MemoryProtection:v1"` - binds ciphertext to context
- **Result:** Each encryption produces different ciphertext (even for same plaintext)

**AAD Benefits:**
- Prevents ciphertext from being moved between different contexts
- Provides additional integrity verification
- Protects against mix-and-match attacks if library is extended

### Memory Safety

```csharp
// ❌ WRONG - password stays in memory
string password = "secret";  // String is immutable, can't be cleared!!

// ✅ CORRECT - password can be cleared
char[] password = "secret".ToCharArray();
var protected = new ProtectedSecret(password);
// password[] is now all zeros
```

## 💡 Use Cases

- **Desktop applications** - protecting user passwords in memory
- **Service applications** - storing API keys, connection strings
- **Password managers** – protecting vault master password in memory during unlock
- **Authentication systems** - protecting credentials during login
- **Any scenario** where sensitive data must live in RAM

## 🔐 Security Best Practices

### ✅ DO

- Use `char[]` instead of `string` for password input
- Use `ProtectedSecret.Consume()` to make intent clear
- Use `UseSecret()` callback API for automatic cleanup
- Work with `ReadOnlySpan<char>` directly - don't copy it
- Keep password operations within the callback scope

### ❌ DON'T

- Don't create strings from password spans (`new string(pwd)`)
- Don't copy spans to arrays (`pwd.ToArray()`)
- Don't use string interpolation with passwords
- Don't log or serialize `ProtectedSecret` instances
- Don't assume this prevents all attacks - it's defense in depth, not a silver bullet

## 🧪 Testing

The library includes comprehensive unit tests:

```bash
dotnet test
```

**Test Coverage:**
- ✅ 30 unit tests
- ✅ All encryption/decryption scenarios
- ✅ Memory clearing verification
- ✅ Unicode support (emoji, Chinese, Cyrillic)
- ✅ Edge cases (empty passwords, very long passwords)
- ✅ Exception handling
- ✅ Disposal patterns

## 📋 Requirements

- **.NET 10** or later (uses AES-GCM API)
- Supported platforms:
  - Windows
  - Linux
  - macOS

## ⚠️ Important Limitations

### What This Does NOT Protect Against

**This library provides defense in depth, but it is NOT a solution for:**

❌ **Attackers with code execution in your process**
- If malware is running in your application's memory space, it can access the decrypted password during callbacks

❌ **Debuggers or injected DLLs**
- Debuggers can pause execution during `UseSecret()` callbacks and inspect plaintext
- Injected code can hook into your process and capture passwords

❌ **Malware running as the same user**
- Process memory can be dumped by other processes running with the same privileges
- User-mode malware can inspect your application's memory

❌ **OS-level memory inspection**
- Kernel-mode drivers or system administrators can inspect process memory
- Hibernation files and crash dumps may contain decrypted passwords if captured during callbacks

**What it DOES help with:**
- ✅ Reduces exposure window (password in cleartext only during callbacks)
- ✅ Defense against casual memory dumps when password is not being used
- ✅ Better than storing passwords as plaintext `string` or `char[]`
- ✅ Automatic cleanup reduces risk of developer mistakes

**Remember:** This is **one layer** of security. Use it as part of a comprehensive security strategy, not as your only defense.

### NOT for Persistent Storage

**This library generates a NEW random encryption key every time your application starts.** This means:

❌ **DO NOT use for:**
- Encrypting passwords to save to disk
- Storing encrypted data in databases
- Persisting encrypted configuration files
- Any scenario where data must survive app restart

✅ **DO use for:**
- Protecting passwords in RAM during application runtime
- Temporary storage of API keys/tokens while app is running
- In-memory credential caching
- Replacing `SecureString` for runtime password protection

**If you need to encrypt data for storage at rest**, use a different library with persistent key management (e.g., ASP.NET Core Data Protection, Azure Key Vault, or similar).

### Other Limitations

⚠️ **Cleanup is Best-Effort**
- Shutdown hooks won't run on hard termination/crash
- Application must exit normally for cleanup to occur
- Consider this defense-in-depth, not absolute protection

⚠️ **Managed Memory Constraints**
- Key material is stored in managed memory (subject to GC movement)
- Encoding conversions may create transient runtime buffers
- Not all runtime-created buffers can be reliably wiped
- Protection is against casual memory dumps, not in-process attackers

⚠️ **Callers Must Cooperate**
- `UseSecret()` auto-clears the password after the callback
- BUT callers can still leak if they copy the password (e.g., `new string(pwd)`)
- Follow the anti-patterns guidance in the demo

## 🆚 Compared to SecureString

`SecureString` is deprecated/discouraged for new development and often provides less real-world protection than people assume.

**How Dipsy.MemoryProtection differs:**
- Stores the secret **encrypted in memory by default**, reducing plaintext exposure during normal runtime.
- Uses a **callback-based API (`UseSecret`)** so plaintext exists only briefly and is **automatically cleared** after use (best-effort).
- Behaves consistently across **Windows/Linux/macOS** (within managed-runtime limitations).

**What is the same (important):**
- Neither this library nor `SecureString` protects against **attackers with code execution in your process**, debuggers, injected DLLs, or OS-level memory inspection.
- If you ever convert secrets to `string` (e.g., `new string(pwd)`), you defeat the benefit—strings are immutable and can’t be reliably wiped.

**Rule of thumb:**
Use this library to reduce accidental plaintext exposure and shorten the cleartext window during runtime.
Use an OS secret store / key vault / hardware-backed keys for secrets that must be protected at rest or across restarts.

## 🔁 Migrating from SecureString

If you are currently using `SecureString`, see  
👉 **[MIGRATE.md](MIGRATE.md)** for copy-paste examples and common patterns.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 🐛 Issues

Found a bug or have a suggestion? Please [open an issue](https://github.com/dipsylala/Dipsy.MemoryProtection/issues).

## 📚 Additional Resources

- [Microsoft: SecureString shouldn't be used](https://github.com/dotnet/platform-compat/blob/master/docs/DE0001.md)
- [NIST: AES-GCM Specification](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [.NET Cryptography Best Practices](https://docs.microsoft.com/en-us/dotnet/standard/security/cryptography-model)

---

**Built with ❤️ for secure .NET applications**
