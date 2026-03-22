# TLU Digital Signature System - Changelog

All notable changes to this project will be documented in this file.

---

## [1.0.0] - 2026-03-12

### 🆕 New Features

#### Cryptography
- ✅ Added RSA-PSS 2048-bit (256-byte keys) support
- ✅ Added RSA-PSS 4096-bit (512-byte keys) support
- ✅ Added SHAKE128 variable-length hash function
- ✅ Added SHAKE256 variable-length hash function
- ✅ Full Dilithium2 (Post-Quantum) support with proper error handling

#### User Interface
- ✅ Fixed footer layout - logo and text no longer overlap
- ✅ Fixed header responsiveness for mobile devices
- ✅ Fixed logo display issues
- ✅ Improved responsive design for fullscreen mode
- ✅ Better CSS grid for footer on different screen sizes

#### System Tools
- ✅ Created `run_system.bat` for Windows (setup, run, test commands)
- ✅ Created `run_system.sh` for Linux/macOS (setup, run, test commands)
- ✅ Created `test_all_algorithms.py` for comprehensive algorithm testing
- ✅ Created `test_system_complete.py` for full system testing
- ✅ Added tampering detection tests
- ✅ Added file signature testing

#### Documentation
- ✅ Created `QUICKSTART.md` - Quick 5-minute setup guide
- ✅ Created `INSTALLATION.md` - Detailed installation instructions
- ✅ Updated `DILITHIUM_SETUP.md` - Comprehensive PQC setup guide
- ✅ Updated `README.md` - Better structure and documentation
- ✅ Created this `CHANGELOG.md` file

### 🔧 Improvements

#### Code Quality
- ✅ Improved `rsa_impl.py` with key size validation
- ✅ Enhanced error messages for unsupported algorithms
- ✅ Better structured signature artifact format
- ✅ Improved crypto utils with SHAKE functions

#### Backend
- ✅ Updated `signatures.py` to handle RSA variants
- ✅ Updated `verify_artifact()` for RSA variant compatibility
- ✅ Enhanced algorithm status reporting with groups
- ✅ Added static directory existence check in Flask app

#### Frontend
- ✅ Fixed header layout for mobile responsiveness
- ✅ Changed footer flex direction to column on small screens
- ✅ Reduced logo size on mobile devices
- ✅ Added better text sizing for responsive design
- ✅ Improved login page responsiveness

#### Testing
- ✅ Complete algorithm test coverage (RSA, ECDSA, Ed25519, Dilithium2)
- ✅ Hash function testing (SHA-256, SHAKE128, SHAKE256)
- ✅ File signature testing with different MIME types
- ✅ Artifact structure validation
- ✅ Tampering detection verification
- ✅ Audit logging verification

### 📊 Algorithm Coverage

Now supports:

| Algorithm | Key Size | Status | Notes |
|-----------|----------|--------|-------|
| RSA-PSS | 2048-bit | ✅ New | 256-byte keys |
| RSA-PSS | 3072-bit | ✅ Existing | Default |
| RSA-PSS | 4096-bit | ✅ New | 512-byte keys |
| ECDSA P-256 | Standard | ✅ Existing | Modern |
| Ed25519 | 256-bit | ✅ Existing | High speed |
| Dilithium2 | N/A | ✅ Improved | Post-Quantum |

### 🔐 Security Enhancements

- ✅ Better RSA key size handling (3 variants supported)
- ✅ Post-quantum cryptography fully functional
- ✅ Improved error messages for debugging
- ✅ Better tampering detection in tests
- ✅ Complete audit trail for all operations

### 📁 File Structure

New files added:
```
TLU_Digital_Signature_PQC_/
├── run_system.bat              ✅ NEW - Windows launcher
├── run_system.sh               ✅ NEW - Linux/macOS launcher
├── test_all_algorithms.py      ✅ NEW - Algorithm tests
├── test_system_complete.py     ✅ NEW - Full system test
├── QUICKSTART.md               ✅ NEW - Quick start guide
├── INSTALLATION.md             ✅ NEW - Installation guide
├── CHANGELOG.md                ✅ NEW - This file
└── (updated docs)              ✅ UPDATED
```

### 🐛 Bug Fixes

- ✅ Fixed footer text overlapping with logo on small screens
- ✅ Fixed logo not displaying properly in headers
- ✅ Fixed header layout breaking on mobile
- ✅ Fixed responsive breakpoints in CSS
- ✅ Fixed Flask static file serving configuration

### ⚙️ Dependencies

Updated `requirements.txt`:
```
cryptography>=41.0.0
flask>=3.0.0
flask-cors>=4.0.0
```

Updated `requirements-pqc.txt`:
```
liboqs-python>=0.12.0
```

### 📖 Documentation Updates

- ✅ Complete rewrite of README.md
- ✅ Enhanced DILITHIUM_SETUP.md with more details
- ✅ Added QUICKSTART.md for quick setup
- ✅ Added INSTALLATION.md for detailed setup
- ✅ Better troubleshooting guides

### 🧪 Testing

New test coverage:
- ✅ RSA (2048/3072/4096-bit) signing and verification
- ✅ ECDSA P-256 operations
- ✅ Ed25519 operations
- ✅ Dilithium2 operations (when available)
- ✅ Hash functions (SHA-256, SHAKE128, SHAKE256)
- ✅ File uploads with different content types
- ✅ Tampering detection
- ✅ Artifact structure validation

### 🎯 User Experience

- ✅ Better quick start experience
- ✅ Clearer error messages
- ✅ More algorithm options to choose from
- ✅ Responsive design for all devices
- ✅ Better footer presentation

### 🚀 Performance

- ✅ No significant performance changes
- ✅ RSA key generation optimized (smaller keys available)
- ✅ Better memory management in tests

---

## Installation & Running

### Quick Start
```powershell
# Windows
.\run_system.bat setup
.\run_system.bat

# Linux/macOS
chmod +x run_system.sh
./run_system.sh setup
./run_system.sh
```

### Testing
```powershell
# Windows
python test_all_algorithms.py
python test_system_complete.py
run_system.bat test

# Linux/macOS
python3 test_all_algorithms.py
python3 test_system_complete.py
./run_system.sh test
```

---

## Breaking Changes

⚠️ None - Fully backward compatible with previous versions

---

## Known Issues

None - All known issues have been resolved

---

## Future Improvements (Planned)

- [ ] Dilithium3 and Dilithium5 support
- [ ] Additional post-quantum algorithms
- [ ] Database encryption at rest
- [ ] SAML/OAuth authentication
- [ ] Multi-signature support
- [ ] Hardware security module (HSM) integration
- [ ] REST API v2.0
- [ ] Mobile app
- [ ] Docker deployment

---

## Removed/Deprecated

- Removed: Old slider implementation remnants
- Changed: Logo handling (now auto-detected)

---

## Upgrade Instructions

No migration needed - v1.0.0 is fully compatible with previous versions.

Simply update your files and restart the system:
```powershell
# Windows
python main.py

# Linux/macOS
python3 main.py
```

---

## Contributors

- TLU Team
- Department of Information Technology

---

## Support & Issues

1. Check [QUICKSTART.md](QUICKSTART.md)
2. Review [INSTALLATION.md](INSTALLATION.md)
3. Run tests: `python test_system_complete.py`
4. See [DILITHIUM_SETUP.md](DILITHIUM_SETUP.md) for PQC issues

---

**Release Date**: 2026-03-12
**Status**: Production Ready ✅
**Version**: 1.0.0
