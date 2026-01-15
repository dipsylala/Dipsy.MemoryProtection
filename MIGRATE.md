# Migrating from `SecureString`

This guide shows how to replace common `SecureString` usage patterns with  
**Dipsy.Security.MemoryProtection** using short, practical examples.

The goal is to **reduce plaintext exposure**, centralize cleanup, and make the
*safe path the easy path* — not to provide protection against in-process attackers.

---

## Why migrate?

`SecureString` is deprecated / discouraged for new development.  
In practice, many applications still end up converting it back into `string`
to call APIs, which defeats its purpose.

`Dipsy.Security.MemoryProtection` replaces this with a **callback-based model**:

- secrets are **encrypted in memory by default**
- plaintext exists **only briefly**
- cleanup happens automatically (best-effort)

---

## Migration principles (read once)

- Encrypted-by-default is the steady state
- Plaintext should exist **only inside a callback**
- Avoid creating `string` from secrets
- Clear any derived buffers (`byte[]`) in `finally`

---

## Example 1: Basic authentication

### Before: `SecureString`

```csharp
SecureString securePassword = ReadSecureString();

IntPtr ptr = IntPtr.Zero;
try
{
    ptr = Marshal.SecureStringToBSTR(securePassword);
    string password = Marshal.PtrToStringBSTR(ptr)!;

    Authenticate(username, password);
}
finally
{
    if (ptr != IntPtr.Zero)
        Marshal.ZeroFreeBSTR(ptr);
}
```

### After: `ProtectedSecret`

```csharp
char[] password = ReadPassword();

using var ProtectedSecret = ProtectedSecret.Consume(password);

ProtectedSecret.UseSecret(pwd =>
{
    Authenticate(username, pwd);
});
```

---

## Example 2: When an API needs `byte[]`

```csharp
ProtectedSecret.UseSecret(pwd =>
{
    int byteCount = Encoding.UTF8.GetByteCount(pwd);
    byte[] passwordBytes = new byte[byteCount];

    try
    {
        Encoding.UTF8.GetBytes(pwd, passwordBytes);
        Authenticate(passwordBytes);
    }
    finally
    {
        Array.Clear(passwordBytes, 0, passwordBytes.Length);
    }
});
```

---

## Example 3: Validation logic

```csharp
ProtectedSecret.UseSecret(pwd =>
{
    bool hasUpper = false;
    bool hasDigit = false;

    foreach (char c in pwd)
    {
        if (char.IsUpper(c)) hasUpper = true;
        if (char.IsDigit(c)) hasDigit = true;
    }

    return hasUpper && hasDigit;
});
```

---

## Common migration traps

- Creating `string` from secrets
- Copying spans without wiping
- Embedding secrets in connection strings

---

## Migration checklist

- Replace `SecureString` fields with `ProtectedSecret`
- Remove `SecureStringToBSTR` conversions
- Replace `string` password flows with `UseSecret(...)`
- Clear derived buffers in `finally`
- Audit logs and telemetry

---

## When not to migrate

Do not use this library if you need:

- encryption across restarts
- storage at rest
- protection against in-process attackers

Use OS secret stores, key vaults, or hardware-backed solutions instead.
