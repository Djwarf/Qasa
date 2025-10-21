#!/bin/bash
# Qasa v0.1.0 - Complete Publishing Script
# Run this script on a machine with internet access to publish to crates.io

set -e  # Exit on any error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo ""
echo "=========================================="
echo "  Qasa v0.1.0 Publishing Script"
echo "=========================================="
echo ""

# Get version from Cargo.toml
VERSION=$(grep -m 1 "^version" Cargo.toml | cut -d '"' -f 2)
echo -e "${BLUE}📦 Package: qasa v${VERSION}${NC}"
echo ""

# Step 1: Push git tag
echo -e "${YELLOW}Step 1: Pushing git tag v${VERSION}${NC}"
if git rev-parse "v${VERSION}" >/dev/null 2>&1; then
    echo "  Tag v${VERSION} exists locally"

    # Check if tag exists on remote
    if git ls-remote --tags origin | grep -q "refs/tags/v${VERSION}"; then
        echo -e "  ${GREEN}✓ Tag already pushed to remote${NC}"
    else
        echo "  Pushing tag to remote..."
        git push origin "v${VERSION}"
        echo -e "  ${GREEN}✓ Tag pushed${NC}"
    fi
else
    echo -e "  ${RED}✗ Tag v${VERSION} not found locally${NC}"
    echo "  Creating tag..."
    git tag -a "v${VERSION}" -m "Release version ${VERSION}"
    git push origin "v${VERSION}"
    echo -e "  ${GREEN}✓ Tag created and pushed${NC}"
fi
echo ""

# Step 2: Run tests
echo -e "${YELLOW}Step 2: Running tests${NC}"
echo "  Running: cargo test --all-features"
if cargo test --all-features --quiet; then
    echo -e "  ${GREEN}✓ All tests passed${NC}"
else
    echo -e "  ${RED}✗ Tests failed${NC}"
    echo ""
    echo "Please fix test failures before publishing."
    exit 1
fi
echo ""

# Step 3: Verify RFC 8439 compliance
echo -e "${YELLOW}Step 3: Verifying RFC 8439 compliance${NC}"
echo "  Running RFC 8439 test vector..."
if cargo test test_chacha20poly1305_rfc8439_test_vector --lib --quiet; then
    echo -e "  ${GREEN}✓ RFC 8439 test vector passed${NC}"
else
    echo -e "  ${RED}✗ RFC 8439 test vector failed${NC}"
    echo ""
    echo "CRITICAL: RFC 8439 compliance is required for this release."
    echo "Please investigate and fix before publishing."
    exit 1
fi
echo ""

# Step 4: Run clippy
echo -e "${YELLOW}Step 4: Running clippy${NC}"
if cargo clippy --all-features -- -D warnings --quiet 2>&1 | grep -q "warning:"; then
    echo -e "  ${RED}✗ Clippy warnings found${NC}"
    cargo clippy --all-features -- -D warnings
    echo ""
    echo "Please fix clippy warnings before publishing."
    exit 1
else
    echo -e "  ${GREEN}✓ No clippy warnings${NC}"
fi
echo ""

# Step 5: Check formatting
echo -e "${YELLOW}Step 5: Checking code formatting${NC}"
if cargo fmt -- --check >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓ Code is properly formatted${NC}"
else
    echo -e "  ${YELLOW}! Code formatting issues found${NC}"
    echo "  Run 'cargo fmt' to fix formatting"
fi
echo ""

# Step 6: Build documentation
echo -e "${YELLOW}Step 6: Building documentation${NC}"
if cargo doc --no-deps --all-features --quiet; then
    echo -e "  ${GREEN}✓ Documentation builds successfully${NC}"
else
    echo -e "  ${RED}✗ Documentation build failed${NC}"
    exit 1
fi
echo ""

# Step 7: Dry run
echo -e "${YELLOW}Step 7: Running cargo publish --dry-run${NC}"
if cargo publish --dry-run --quiet 2>&1; then
    echo -e "  ${GREEN}✓ Dry run successful${NC}"
else
    echo -e "  ${RED}✗ Dry run failed${NC}"
    echo ""
    echo "Please fix the issues above before publishing."
    exit 1
fi
echo ""

# Step 8: Confirm publication
echo -e "${YELLOW}Step 8: Ready to publish${NC}"
echo ""
echo "All pre-publish checks passed!"
echo ""
echo -e "${BLUE}Package details:${NC}"
echo "  Name:     qasa"
echo "  Version:  ${VERSION}"
echo "  License:  MIT"
echo "  Repo:     https://github.com/Djwarf/Qasa"
echo ""
echo -e "${YELLOW}⚠️  BREAKING CHANGES WARNING ⚠️${NC}"
echo "This version includes breaking changes to ChaCha20-Poly1305."
echo "Data encrypted with v0.0.3 cannot be decrypted with v0.1.0."
echo "See CHANGELOG.md for details."
echo ""

read -p "Do you want to publish to crates.io? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo ""
    echo "Publishing cancelled."
    echo ""
    echo "To publish later, run:"
    echo "  cargo publish"
    exit 0
fi

echo ""
echo -e "${YELLOW}Step 9: Publishing to crates.io${NC}"

# Check if logged in
if ! cargo login --help >/dev/null 2>&1; then
    echo -e "${RED}Cargo login not available${NC}"
    exit 1
fi

echo "  Publishing package..."
if cargo publish; then
    echo -e "  ${GREEN}✓ Successfully published to crates.io!${NC}"
else
    echo -e "  ${RED}✗ Publishing failed${NC}"
    exit 1
fi

echo ""
echo "=========================================="
echo -e "${GREEN}✓ Publication Complete!${NC}"
echo "=========================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Verify publication:"
echo "   cargo search qasa"
echo ""
echo "2. Check documentation:"
echo "   https://docs.rs/qasa/${VERSION}"
echo ""
echo "3. View on crates.io:"
echo "   https://crates.io/crates/qasa"
echo ""
echo "4. Create GitHub Release:"
echo "   https://github.com/Djwarf/Qasa/releases/new?tag=v${VERSION}"
echo ""
echo "5. Test installation:"
echo "   mkdir test-install && cd test-install"
echo "   cargo init"
echo "   cargo add qasa@${VERSION}"
echo "   cargo build"
echo ""
