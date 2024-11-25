### What It Does:

**Encrypt/Decrypt Files**:
Encrypt the contents of a file and its name.
Keep the original filename private so the encrypted file doesn’t reveal how long the filename is.
Crash Protection:
This technique uses reliable Write-Ahead Logging (WAL) to ensure that files will not be corrupted if the process stops unexpectedly.
Use WAL in an intelligent way for encrypting in place.
When encrypting in place, I order not to leave the file in an inconsistent state. If the process is terminated while performing the operation, when you run again, resume the operation. For example, when encrypting, if it fails in the middle, the file is corrupted. To avoid this, when starting again, we continue the encryption.
Try to resolve this flow when encrypting inline
- you read 128k
- you encrypt, and it's 132k
- you write 129b
- you overwrite 1b from block2, which is decrypted
- process dies
- you run again
- you cannot recover that byte
=> broken file, unrecoverable
Show File Info:
Without decrypting the whole file, it lets users see details about the encrypted file (such as its name, size, and encryption method).

How It Works:
#### Encryption Algorithms:
Choose between two secure methods:
AES-GCM (a type of AES encryption)
ChaCha20-Poly1305 (another widely used encryption method).
Both are solid options for keeping files safe.
#### CLI Commands:
encrypt: Lock a file (turn it into an unreadable, encrypted version).
decrypt: Unlock a file (restore it to its original readable form).
show: View information about an encrypted file without unlocking it.
#### Command Options:
Choose the algorithm: Use—-alg (or—a) to select an encryption method, such as AES-GCM-128, AES-GCM-196, AES-GCM-256, or ChaCha20Poly1305.
Input and output files:
Specify the file to process with --in (or -i).
Optionally, use --out (or -o) to define where the result should go. If skipped, the input file is replaced directly.
Secure Passphrase:
The tool will ask you for a passphrase (like a password) when it starts.
The passphrase isn’t stored anywhere, and it’s converted into a strong key to lock/unlock the file.
