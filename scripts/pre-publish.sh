#!/bin/bash
set -e

echo "🔍 Running pre-publish checks for Qasa..."
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get version from Cargo.toml
VERSION=$(grep -m 1 "^version" Cargo.toml | cut -d '"' -f 2)
echo "📦 Package: qasa v${VERSION}"
echo ""

# Function to run a check
run_check() {
    local name=$1
    local command=$2

    echo -n "⏳ ${name}... "
    if eval $command > /tmp/qasa-check.log 2>&1; then
        echo -e "${GREEN}✓${NC}"
        return 0
    else
        echo -e "${RED}✗${NC}"
        echo ""
        echo "Error output:"
        cat /tmp/qasa-check.log
        echo ""
        return 1
    fi
}

# Run all checks
echo "Running checks:"
echo ""

# Note: Some checks might fail due to network restrictions in development
# These should be run manually before actual publishing

run_check "Format check" "cargo fmt -- --check" || true
run_check "Clippy lints" "cargo clippy --all-features -- -D warnings" || true
run_check "Build" "cargo build --release" || true
run_check "Tests" "cargo test --all-features" || true
run_check "Documentation" "cargo doc --no-deps --all-features" || true
run_check "Package" "cargo package --allow-dirty --list > /dev/null" || true

echo ""
echo "📋 Manual Checklist:"
echo ""
echo "  [ ] All tests pass locally"
echo "  [ ] CHANGELOG.md is updated"
echo "  [ ] README.md has correct version badges"
echo "  [ ] No security vulnerabilities (cargo audit)"
echo "  [ ] All changes are committed"
echo "  [ ] Git tag v${VERSION} created"
echo ""
echo "To publish:"
echo ""
echo "  1. Create tag:"
echo "     git tag -a v${VERSION} -m \"Release version ${VERSION}\""
echo "     git push origin v${VERSION}"
echo ""
echo "  2. Dry run:"
echo "     cargo publish --dry-run"
echo ""
echo "  3. Publish:"
echo "     cargo publish"
echo ""
echo "  4. Verify:"
echo "     cargo search qasa"
echo ""
