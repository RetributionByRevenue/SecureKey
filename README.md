# SecureKey - Secure Secrets &amp; Encrypted Storage for Android

<img src="https://raw.githubusercontent.com/RetributionByRevenue/SecureKey/refs/heads/main/screenshots/showcase.png" height="800" >

A secure, encrypted, offline secrets manager Android application built with Kivy that allows users to safely store and manage sensitive information like cryptocurrency keys, passwords, and other secrets.

## How to Use

1. Build the Android APK:
```bash
buildozer android debug
```

2. Install the generated APK on your Android device

3. Launch the app:
   - Enter the default PIN: 1984 (can be customized during compilation)
   - Set your AES encryption key when prompted (store this safely!)

4. Main Screen Operations:
   - Menu Button (top left):
     - Import: Restore previous encrypted databases
     - Export: Save current encrypted database
     - Add New: Create new encrypted entry
     - Clear Screen: Remove all entries from view
   - Each entry has:
     - Copy button: Copy content to clipboard
     - Remove button: Delete entry from view
   - View AES Key: Displays current encryption key

## Features

- **PIN Protection**: Customizable numeric PIN (modifiable in source code)
- **AES Encryption**: All stored data is encrypted using AES encryption
- **Portable Database**: Encrypted data can be exported and imported across devices
- **Secure Storage**: 
  - Individual entries are encrypted before storage
  - Database files are created in a portable format
  - Export/import functionality for backup and transfer
- **User-Friendly Interface**:
  - Copy-to-clipboard functionality for each entry
  - Easy addition and removal of entries
  - Clear screen functionality
  - Scrollable content view
  - Menu-driven operations

## Security Features

- AES encryption for all stored content
- Encrypted database export format
- No plaintext storage of sensitive data
- Secure clipboard operations
- Customizable numeric PIN access

## Installation

1. Ensure you have Python and buildozer installed
2. Clone this repository
3. Run `buildozer android debug` to create the APK
4. Install the APK on your Android device

The buildozer configuration already includes all required dependencies.

## File Storage

- Files are stored in `/storage/emulated/0/Documents/`
- Exported files are named with UTC timestamps
- Databases are encrypted using AES encryption

## Security Recommendations

1. Change the default PIN (1984) by modifying the source code before compilation
2. Store your AES key securely - it's required for decryption
3. Regularly backup your encrypted databases
4. Clear screen after use
5. Don't share your AES key or PIN with anyone

## Technical Details

- Implements AES encryption for all stored content
- Utilizes pysos for portable database management
- Secure clipboard operations for sensitive data
- Custom PIN length supported (must be numeric)
- Designed specifically for Android platform

## Contributing

Feel free to submit issues and enhancement requests!
