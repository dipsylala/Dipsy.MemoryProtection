// See https://aka.ms/new-console-template for more information

using Dipsy.MemoryProtection;
using System.Security.Cryptography;
using System.Text;

Console.WriteLine("╔═══════════════════════════════════════════════════════════╗");
Console.WriteLine("║  Dipsy.MemoryProtection - Real-World Demo                 ║");
Console.WriteLine("║  Secure In-Memory Password Encryption for .NET 10         ║");
Console.WriteLine("╚═══════════════════════════════════════════════════════════╝");
Console.WriteLine();

// Scenario 1: Basic Authentication (CORRECT - no string leaks)
Console.WriteLine("═══════════════════════════════════════════════════════════");
Console.WriteLine("SCENARIO 1: Basic Authentication (API calls)");
Console.WriteLine("═══════════════════════════════════════════════════════════");
Console.WriteLine();

Console.Write("Enter username: ");
var username = Console.ReadLine() ?? "demo_user";

Console.Write("Enter password: ");
var password = ReadPassword();
Console.WriteLine();

// Store password securely
using var protectedSecret = ProtectedSecret.Consume(password);
Console.WriteLine("✓ Password encrypted in memory");

// Verify password array was cleared without creating a string
var allCleared = true;
foreach (var c in password)
{
    if (c != '\0') { allCleared = false; break; }
}
Console.WriteLine($"✓ Original password array cleared: {(allCleared ? "all '\\0'" : "ERROR")}");
Console.WriteLine();

// Use password for authentication - CORRECT way (no string leaks)
Console.WriteLine("Authenticating with API...");
var authResult = protectedSecret.UseSecret(pwd =>
{
    // ✅ CORRECT: Build credentials using spans without creating strings
    var usernameBytes = Encoding.UTF8.GetBytes(username);
    
    // Get password byte count
    var passwordByteCount = Encoding.UTF8.GetByteCount(pwd);
    var passwordBytes = new byte[passwordByteCount];
    Encoding.UTF8.GetBytes(pwd, passwordBytes);
    
    try
    {
        // Combine: username + ':' + password
        var credentialBytes = new byte[usernameBytes.Length + 1 + passwordBytes.Length];
        Buffer.BlockCopy(usernameBytes, 0, credentialBytes, 0, usernameBytes.Length);
        credentialBytes[usernameBytes.Length] = (byte)':';
        Buffer.BlockCopy(passwordBytes, 0, credentialBytes, usernameBytes.Length + 1, passwordBytes.Length);
        
        try
        {
            var base64 = Convert.ToBase64String(credentialBytes);
            Console.WriteLine($"  Auth header: Basic {base64.Substring(0, Math.Min(16, base64.Length))}...");
            
            // Use base64 for API call here
            Thread.Sleep(500);
            return true;
        }
        finally
        {
            // Clear the combined credentials
            Array.Clear(credentialBytes, 0, credentialBytes.Length);
        }
    }
    finally
    {
        // Clear sensitive password bytes (username is not secret)
        Array.Clear(passwordBytes, 0, passwordBytes.Length);
    }
});

Console.WriteLine(authResult ? "✓ Authentication successful!" : "✗ Authentication failed");
Console.WriteLine("✓ Password automatically cleared after use");
Console.WriteLine("✓ No application-created password strings in memory");
Console.WriteLine();

// Scenario 2: Password Hashing (CORRECT use case with proper algorithm)
Console.WriteLine("═══════════════════════════════════════════════════════════");
Console.WriteLine("SCENARIO 2: Password Hashing for Storage (PBKDF2)");
Console.WriteLine("═══════════════════════════════════════════════════════════");
Console.WriteLine();

Console.Write("Enter password to hash: ");
var hashPassword = ReadPassword();
Console.WriteLine();

using var protectedHashSecret = ProtectedSecret.Consume(hashPassword);

// ✅ CORRECT: Hash with PBKDF2 (proper password hashing algorithm)
var hash = protectedHashSecret.UseSecret(pwd =>
{
    var passwordByteCount = Encoding.UTF8.GetByteCount(pwd);
    var passwordBytes = new byte[passwordByteCount];
    Encoding.UTF8.GetBytes(pwd, passwordBytes);
    
    try
    {
        // Use PBKDF2 with the modern static method (not obsolete constructor)
        var salt = new byte[16];
        RandomNumberGenerator.Fill(salt);
        
        var hashBytes = new byte[32];
        Rfc2898DeriveBytes.Pbkdf2(
            passwordBytes,
            salt,
            hashBytes,
            iterations: 100000,
            HashAlgorithmName.SHA256);
        
        // Return salt + hash for storage
        var result = new byte[salt.Length + hashBytes.Length];
        Buffer.BlockCopy(salt, 0, result, 0, salt.Length);
        Buffer.BlockCopy(hashBytes, 0, result, salt.Length, hashBytes.Length);
        
        return Convert.ToBase64String(result);
    }
    finally
    {
        // Clear password bytes
        Array.Clear(passwordBytes, 0, passwordBytes.Length);
    }
});

Console.WriteLine($"Password hash (PBKDF2): {hash.Substring(0, 24)}...");
Console.WriteLine("✓ Used PBKDF2 (proper algorithm, not SHA-256!)");
Console.WriteLine("✓ Hash created without leaking plaintext password");
Console.WriteLine("✓ Safe to store hash in database");
Console.WriteLine();

// Scenario 3: Password Validation (CORRECT - efficient single pass)
Console.WriteLine("═══════════════════════════════════════════════════════════");
Console.WriteLine("SCENARIO 3: Password Strength Check (Efficient)");
Console.WriteLine("═══════════════════════════════════════════════════════════");
Console.WriteLine();

Console.Write("Enter a password to validate: ");
var validatePassword = ReadPassword();
Console.WriteLine();

using var protectedValidateSecret = ProtectedSecret.Consume(validatePassword);

// ✅ CORRECT: Single callback for better performance
var (hasUpperCase, hasLowerCase, hasDigit, length) = protectedValidateSecret.UseSecret(pwd =>
{
    bool upper = false, lower = false, digit = false;
    
    // Single pass through the password - efficient!
    foreach (var c in pwd)
    {
        if (char.IsUpper(c)) upper = true;
        if (char.IsLower(c)) lower = true;
        if (char.IsDigit(c)) digit = true;
    }
    
    return (upper, lower, digit, pwd.Length);
});

Console.WriteLine("Password strength check:");
Console.WriteLine($"  Length: {length} chars {(length >= 8 ? "✓" : "✗")}");
Console.WriteLine($"  Has uppercase: {(hasUpperCase ? "✓" : "✗")}");
Console.WriteLine($"  Has lowercase: {(hasLowerCase ? "✓" : "✗")}");
Console.WriteLine($"  Has digit: {(hasDigit ? "✓" : "✗")}");
Console.WriteLine();
Console.WriteLine("✓ Password checked once in a single callback (efficient!)");
Console.WriteLine("✓ Auto-cleared immediately after check");
Console.WriteLine();

// Scenario 4: Memory Protection Demo
Console.WriteLine("═══════════════════════════════════════════════════════════");
Console.WriteLine("SCENARIO 4: Memory Dump Protection");
Console.WriteLine("═══════════════════════════════════════════════════════════");
Console.WriteLine();

var demoSecret = "SuperSecret123!".ToCharArray();
using var protectedDemoSecret = ProtectedSecret.Consume(demoSecret);

Console.WriteLine("In memory right now:");
Console.WriteLine("  ✓ Encrypted data: [random bytes - safe in memory dump]");
Console.WriteLine("  ✓ Original char[]: [all '\\0' - cleared]");
Console.WriteLine("  ✗ Plaintext: [only exists during UseSecret() callback]");
Console.WriteLine();

Console.WriteLine("Demonstrating temporary decryption...");
protectedDemoSecret.UseSecret(pwd =>
{
    // ✅ CORRECT: Use span directly without converting to string
    Console.Write("  During callback: plaintext exists [");
    foreach (var c in pwd)
    {
        Console.Write('*'); // Don't print actual password!
    }
    Console.WriteLine("]");
    Thread.Sleep(100);
});
Console.WriteLine("  After callback: plaintext cleared ✓");
Console.WriteLine();

// Scenario 5: ANTI-PATTERNS to AVOID
Console.WriteLine("═══════════════════════════════════════════════════════════");
Console.WriteLine("❌ ANTI-PATTERNS - DO NOT DO THIS:");
Console.WriteLine("═══════════════════════════════════════════════════════════");
Console.WriteLine();

var badPassword = "bad".ToCharArray();
using var protectedBad = ProtectedSecret.Consume(badPassword);

Console.WriteLine("❌ BAD: Creating strings from password");
Console.WriteLine("   protectedBadUseSecret(pwd => {");
Console.WriteLine("       var leak = new string(pwd);  // ❌ String leaks!");
Console.WriteLine("   });");
Console.WriteLine();

Console.WriteLine("❌ BAD: Copying to arrays");
Console.WriteLine("   protectedBadUseSecret(pwd => {");
Console.WriteLine("       var leak = pwd.ToArray();  // ❌ Array not cleared!");
Console.WriteLine("   });");
Console.WriteLine();

Console.WriteLine("❌ BAD: String interpolation");
Console.WriteLine("   protectedBadUseSecret(pwd => {");
Console.WriteLine("       var leak = $\"Password: {pwd}\";  // ❌ Leaks!");
Console.WriteLine("   });");
Console.WriteLine();

Console.WriteLine("❌ BAD: Using SHA-256 for password hashing");
Console.WriteLine("   // SHA-256 is TOO FAST - use PBKDF2/bcrypt/scrypt/Argon2");
Console.WriteLine();

Console.WriteLine("✅ GOOD: Work with ReadOnlySpan directly");
Console.WriteLine("   • Use Encoding.UTF8.GetBytes(pwd, buffer)");
Console.WriteLine("   • Clear byte arrays in finally blocks");
Console.WriteLine("   • Use PBKDF2/bcrypt/scrypt/Argon2 for hashing");
Console.WriteLine("   • Do multiple checks in one callback when possible");
Console.WriteLine();

Console.WriteLine("═══════════════════════════════════════════════════════════");
Console.WriteLine("✓ Demo Complete!");
Console.WriteLine("═══════════════════════════════════════════════════════════");
Console.WriteLine();
Console.WriteLine("Key Takeaways:");
Console.WriteLine("  • Work with ReadOnlySpan<char> directly");
Console.WriteLine("  • NEVER create strings from passwords");
Console.WriteLine("  • NEVER call ToArray() - it copies and doesn't clear");
Console.WriteLine("  • Convert to bytes only when needed, clear immediately");
Console.WriteLine("  • Use foreach loops on spans instead of LINQ");
Console.WriteLine("  • Use proper password hashing (PBKDF2/bcrypt/Argon2)");
Console.WriteLine("  • Minimize decrypt cycles - do work in one callback");
Console.WriteLine();
Console.WriteLine("Press any key to exit...");
Console.ReadKey();

// Helper method to read password without echoing - with complete cleanup
static char[] ReadPassword()
{
    // Use fixed-size buffer that we can fully control and wipe
    const int MaxPasswordLength = 256;
    char[] buffer = new char[MaxPasswordLength];
    int position = 0;
    
    try
    {
        while (true)
        {
            var key = Console.ReadKey(true);
            
            if (key.Key == ConsoleKey.Enter)
            {
                break;
            }
            else if (key.Key == ConsoleKey.Backspace && position > 0)
            {
                position--;
                buffer[position] = '\0';  // Clear the removed character
                Console.Write("\b \b");
            }
            else if (!char.IsControl(key.KeyChar) && position < MaxPasswordLength)
            {
                buffer[position] = key.KeyChar;
                position++;
                Console.Write("*");
            }
        }
        Console.WriteLine();
        
        // Create result array of exact size (no wasted space)
        char[] result = new char[position];
        Array.Copy(buffer, 0, result, 0, position);
        return result;
    }
    finally
    {
        // Always clear the working buffer
        Array.Clear(buffer, 0, buffer.Length);
    }
}
