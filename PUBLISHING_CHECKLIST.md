# Pre-Publishing Checklist for Qasa v0.1.0

This checklist must be completed before publishing to crates.io.

## ✅ Code Quality

- [x] All code compiles without errors
- [ ] All tests pass: `cargo test --all-features`
- [ ] No clippy warnings: `cargo clippy --all-features -- -D warnings`
- [ ] Code is properly formatted: `cargo fmt -- --check`
- [ ] No security vulnerabilities: `cargo audit`
- [ ] Benchmarks run successfully: `cargo bench`

## ✅ Documentation

- [x] README.md has crates.io badges
- [x] README.md has installation instructions
- [x] README.md includes breaking change warning for v0.1.0
- [x] CHANGELOG.md is updated with v0.1.0 release notes
- [x] DEPLOYMENT.md includes publishing instructions
- [ ] API documentation builds: `cargo doc --no-deps --all-features`
- [ ] All public APIs are documented
- [ ] Code examples in docs compile and work

## ✅ Version Management

- [x] Version updated to 0.1.0 in Cargo.toml
- [x] Version updated in all documentation files
- [x] Version matches across:
  - [x] Cargo.toml
  - [x] README.md
  - [x] Documentation.md
  - [x] CHANGELOG.md
  - [x] docs/guides/getting_started.md
  - [x] docs/api/crypto_api.md
  - [x] docs/api/security_guide.md
  - [x] docs/api/threat_model.md

## ✅ Package Configuration

- [x] Cargo.toml metadata is complete:
  - [x] name = "qasa"
  - [x] version = "0.1.0"
  - [x] description
  - [x] authors
  - [x] license = "MIT"
  - [x] repository URL
  - [x] homepage URL
  - [x] documentation URL
  - [x] keywords (5 max)
  - [x] categories
  - [x] exclude list for unnecessary files

- [x] No `publish = false` in Cargo.toml
- [ ] All dependencies are from crates.io (no path dependencies)
- [ ] No unpublished dependencies

## ✅ Testing

- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] RFC 8439 test vectors pass
- [ ] Test coverage is adequate
- [ ] Security tests pass

## ✅ Git

- [x] All changes committed
- [ ] Working directory is clean: `git status`
- [ ] Pushed to GitHub
- [ ] Git tag v0.1.0 created: `git tag -a v0.1.0 -m "Release version 0.1.0"`
- [ ] Tag pushed: `git push origin v0.1.0`

## ✅ Pre-Publish Verification

- [ ] Run pre-publish script: `./scripts/pre-publish.sh`
- [ ] Package builds: `cargo package --allow-dirty`
- [ ] Verify package contents: `cargo package --list`
- [ ] Check package size (should be reasonable)
- [ ] Dry run successful: `cargo publish --dry-run`

## ✅ Crates.io Account

- [ ] Crates.io account created
- [ ] Email verified
- [ ] API token generated
- [ ] Logged in: `cargo login <token>`

## ✅ Final Checks

- [ ] Review INVESTIGATION_REPORT.md for any security concerns
- [ ] Confirm ChaCha20-Poly1305 is RFC 8439 compliant
- [ ] Breaking changes are clearly documented
- [ ] Migration guide is available for v0.0.3 users
- [ ] No sensitive information in codebase
- [ ] License file is included

## 🚀 Publishing Commands

Once all checks pass:

```bash
# 1. Final verification
cargo publish --dry-run

# 2. Publish to crates.io
cargo publish

# 3. Verify publication
cargo search qasa

# 4. Test installation in a new project
mkdir -p /tmp/test-qasa
cd /tmp/test-qasa
cargo init
cargo add qasa@0.1.0
cargo build
```

## 📢 Post-Publishing Tasks

- [ ] Create GitHub Release for v0.1.0
- [ ] Include CHANGELOG.md content in release notes
- [ ] Verify crate appears on crates.io
- [ ] Verify docs.rs builds successfully
- [ ] Test installation from crates.io
- [ ] Announce release (if applicable)
- [ ] Update project website (if applicable)

## ⚠️ Important Notes

### Breaking Changes in v0.1.0

Version 0.1.0 includes critical fixes to ChaCha20-Poly1305 implementation:

1. **Order of Operations**: Fixed from `(h * r) + block` to `(h + block) * r`
2. **Key Clamping**: Fixed from word-level to byte-level per RFC 8439

**Impact**: Data encrypted with v0.0.3 **cannot** be decrypted with v0.1.0.

### If v0.0.3 Was Published

If v0.0.3 was previously published to crates.io:

```bash
# Yank the buggy version
cargo yank --version 0.0.3

# File a security advisory
# Document the security issue
```

## 🆘 Troubleshooting

### Issue: Tests fail due to network restrictions

**Solution**: Tests need to be run on a machine with internet access before publishing.

### Issue: `cargo publish --dry-run` fails

**Solution**: Review the error message and fix issues. Common problems:
- Missing dependencies
- Documentation errors
- Invalid Cargo.toml metadata

### Issue: Package size too large

**Solution**: Review the exclude list in Cargo.toml and ensure test data, benchmarks, and other non-essential files are excluded.

---

**Prepared by**: Claude Code Investigation Team
**Date**: 2025-10-21
**Version**: 0.1.0
