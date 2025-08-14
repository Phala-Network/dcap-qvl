# Publishing Guide

This document explains how to publish dcap-qvl to various package repositories.

## Python Package (PyPI)

### Automated Publishing

The project includes GitHub Actions workflows for automated publishing:

#### 1. Via Git Tags (Automatic)
When you push a git tag starting with `v`, the `python-wheels.yml` workflow automatically:
- Builds wheels for all supported platforms
- Publishes to PyPI if the tag matches a version

```bash
git tag v0.3.1
git push origin v0.3.1
```

#### 2. Manual Publishing
Use the `publish-pypi.yml` workflow for manual control:

1. Go to GitHub Actions → "Publish to PyPI"
2. Click "Run workflow"
3. Choose environment (testpypi or pypi)
4. Optionally specify version
5. Click "Run workflow"

### Supported Platforms

The automated builds create wheels for:

**Linux (manylinux)**:
- x86_64
- x86 (32-bit)
- aarch64 (ARM64)

**Windows**:
- x64 (64-bit)
- x86 (32-bit)

**macOS**:
- x86_64 (Intel)
- aarch64 (Apple Silicon)

### ABI3 Compatibility

All wheels are built with abi3 (stable ABI) enabled, meaning:
- One wheel works across multiple Python versions (3.8+)
- Smaller distribution size
- Better compatibility

### Test Before Publishing

1. **Test on TestPyPI first**:
   ```bash
   # Use the manual workflow with environment: testpypi
   pip install -i https://test.pypi.org/simple/ dcap-qvl
   ```

2. **Local testing**:
   ```bash
   cd python-bindings
   ./tests/test_python_versions.sh
   ```

## Rust Crate (crates.io)

### Automated Publishing

When you create a git tag, the `release.yml` workflow automatically publishes to crates.io.

### Manual Publishing

```bash
# Main library
cargo publish

# CLI tool
cd cli
cargo publish
```

## GitHub Releases

The `release.yml` workflow automatically creates GitHub releases with:
- Pre-built CLI binaries for multiple platforms
- Changelog generated from git commits
- Links to PyPI and crates.io packages

## Environment Setup

### Required Secrets

Configure these secrets in your GitHub repository:

1. **CRATES_IO_TOKEN**: Token for publishing to crates.io
   - Get from https://crates.io/settings/tokens
   - Add to repository secrets

2. **PyPI Publishing**: Uses OpenID Connect (no token needed)
   - Configured with `id-token: write` permission
   - Uses trusted publishing via GitHub Actions

### Environments

Set up these GitHub Environments for PyPI publishing:

1. **testpypi**: For testing releases
   - URL: https://test.pypi.org/p/dcap-qvl
   - Protection rules: None

2. **pypi**: For production releases
   - URL: https://pypi.org/p/dcap-qvl
   - Protection rules: Required reviewers, deployment branches

## Version Management

### Python Package Version

Update version in `python-bindings/pyproject.toml`:
```toml
[project]
version = "0.3.1"
```

### Rust Crate Version

Update version in root `Cargo.toml`:
```toml
[package]
version = "0.3.1"
```

### CLI Version

Update version in `cli/Cargo.toml`:
```toml
[package]
version = "0.3.1"
```

## Troubleshooting

### Build Failures

1. **Cross-compilation issues**: Check the maturin-action logs
2. **Missing dependencies**: Ensure all features are properly configured
3. **Test failures**: Run tests locally first

### Publishing Issues

1. **Duplicate version**: Use `skip-existing: true` in workflows
2. **Permission denied**: Check GitHub environment protection rules
3. **Missing wheels**: Verify all build jobs completed successfully

### Testing Issues

1. **Import errors**: Check that the wheel is compatible with the test environment
2. **Async function failures**: Ensure tokio runtime is properly configured
3. **ABI compatibility**: Test with multiple Python versions locally

## Best Practices

1. **Always test on TestPyPI first**
2. **Use semantic versioning**
3. **Update all version numbers consistently**
4. **Test locally before pushing tags**
5. **Review the generated changelog before release**
6. **Monitor PyPI download statistics**
7. **Keep dependencies up to date with Dependabot**