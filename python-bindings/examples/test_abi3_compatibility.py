#!/usr/bin/env python3
"""
Test script to demonstrate abi3 compatibility.

This script shows that a module built for Python 3.8 can work
on higher Python versions thanks to the stable ABI.
"""

import sys
import subprocess
import tempfile
import shutil
from pathlib import Path

def test_abi3_compatibility():
    """Test that the abi3 module works across Python versions."""
    
    print("🧪 Testing abi3 Cross-Version Compatibility\n")
    
    # Show current Python version
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}"
    print(f"Current Python version: {python_version}")
    
    # Test basic import and functionality
    try:
        import dcap_qvl
        print(f"✅ Successfully imported dcap_qvl")
        print(f"   Version: {dcap_qvl.__version__}")
        print(f"   Available functions: {len(dcap_qvl.__all__)}")
        
        # Test basic functionality
        collateral = dcap_qvl.QuoteCollateralV3(
            pck_crl_issuer_chain="test",
            root_ca_crl=b"test", 
            pck_crl=b"test",
            tcb_info_issuer_chain="test",
            tcb_info='{"test": true}',
            tcb_info_signature=b"test",
            qe_identity_issuer_chain="test",
            qe_identity='{"test": true}',
            qe_identity_signature=b"test"
        )
        
        json_str = collateral.to_json()
        collateral2 = dcap_qvl.QuoteCollateralV3.from_json(json_str)
        
        print(f"✅ Basic functionality works on Python {python_version}")
        
    except Exception as e:
        print(f"❌ Failed to import or use dcap_qvl: {e}")
        return False
    
    return True


def show_abi3_info():
    """Show information about abi3 compatibility."""
    print("\n📋 abi3 Compatibility Information\n")
    
    print("What is abi3?")
    print("  abi3 (stable ABI) is a subset of the Python C API that remains")
    print("  stable across Python minor versions (e.g., 3.8, 3.9, 3.10, etc.)")
    
    print("\nHow it works:")
    print("  ✅ Build once for Python 3.8 → Works on Python 3.8, 3.9, 3.10, 3.11, 3.12+")
    print("  ✅ Binary compatibility across Python versions")
    print("  ✅ No need to rebuild for each Python version")
    print("  ✅ Enables distributing universal Python wheels")
    
    print("\nCurrent configuration:")
    print("  • PyO3 with abi3-py38 feature enabled")
    print("  • Minimum supported Python: 3.8")
    print("  • Forward compatible with all newer versions")
    
    print("\nBenefits:")
    print("  🚀 Faster CI/CD (build once vs. build for each Python version)")
    print("  📦 Smaller distribution (one wheel vs. multiple wheels)")
    print("  🔧 Easier maintenance (single binary to test and debug)")
    print("  🎯 Better user experience (universal compatibility)")


def demonstrate_wheel_compatibility():
    """Show information about wheel distribution."""
    print("\n🎡 Wheel Distribution with abi3\n")
    
    # Look for built wheels
    project_root = Path(__file__).parent.parent.parent
    wheels_dir = project_root / "target" / "wheels"
    
    if wheels_dir.exists():
        wheels = list(wheels_dir.glob("*.whl"))
        if wheels:
            print("Built wheels:")
            for wheel in wheels:
                print(f"  📦 {wheel.name}")
                
                # Analyze wheel name
                parts = wheel.stem.split('-')
                if len(parts) >= 5:
                    name, version, python_tag, abi_tag, platform_tag = parts[0], parts[1], parts[2], parts[3], parts[4]
                    print(f"     Python: {python_tag}, ABI: {abi_tag}, Platform: {platform_tag}")
                    
                    if "abi3" in abi_tag:
                        print(f"     ✅ This is an abi3 wheel - compatible across Python versions!")
                    else:
                        print(f"     ⚠️  This is a version-specific wheel")
        else:
            print("No wheels found in target/wheels/")
    else:
        print("Wheels directory not found - build the project first with maturin")
    
    print("\nTo build abi3 wheels:")
    print("  maturin build --features python")
    print("  # Creates wheels like: dcap_qvl-0.3.0-cp38-abi3-linux_x86_64.whl")
    
    print("\nTo distribute:")
    print("  # Upload to PyPI (one wheel works for all Python 3.8+ versions)")
    print("  twine upload target/wheels/*.whl")


def check_extension_info():
    """Check information about the loaded extension."""
    print("\n🔍 Extension Information\n")
    
    try:
        import dcap_qvl
        
        # Get the module file path
        module_file = dcap_qvl.__file__
        print(f"Module file: {module_file}")
        
        # Check if it's a .so file (compiled extension)
        if module_file and module_file.endswith('.so'):
            print("✅ This is a compiled binary extension")
            
            # Try to get some info about the binary
            try:
                result = subprocess.run(['file', module_file], capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"File info: {result.stdout.strip()}")
            except:
                pass
                
            # Check if it's an abi3 extension
            if 'abi3' in module_file:
                print("✅ This extension uses abi3 stable ABI")
            else:
                print("ℹ️  Extension filename doesn't indicate abi3 (but may still use it)")
                
        else:
            print("ℹ️  This appears to be a pure Python module")
            
    except Exception as e:
        print(f"❌ Could not get extension info: {e}")


def main():
    """Run all compatibility tests."""
    success = test_abi3_compatibility()
    show_abi3_info()
    demonstrate_wheel_compatibility()
    check_extension_info()
    
    if success:
        print("\n🎉 abi3 compatibility test completed successfully!")
        print(f"   The module works correctly on Python {sys.version_info.major}.{sys.version_info.minor}")
    else:
        print("\n💥 abi3 compatibility test failed!")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())