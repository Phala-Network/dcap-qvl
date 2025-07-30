#!/usr/bin/env python3
"""
Test script for DCAP-QVL Python bindings across multiple Python versions.

This script tests the Python bindings with different Python versions to ensure
compatibility across the supported range (Python 3.8+).
"""

import subprocess
import sys
import os
from pathlib import Path
from typing import List, Tuple, Dict, Any
import json
import tempfile
import shutil

# Supported Python versions (matching pyproject.toml)
PYTHON_VERSIONS = [
    "3.8",
    "3.9", 
    "3.10",
    "3.11",
    "3.12",
]

# Colors for output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def run_command(cmd: List[str], cwd: str = None, capture_output: bool = True) -> Tuple[int, str, str]:
    """Run a command and return exit code, stdout, stderr."""
    try:
        result = subprocess.run(
            cmd, 
            cwd=cwd,
            capture_output=capture_output,
            text=True,
            timeout=300  # 5 minute timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out after 5 minutes"
    except Exception as e:
        return -1, "", str(e)

def print_header(text: str):
    """Print a colored header."""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}")

def print_success(text: str):
    """Print success message."""
    print(f"{Colors.GREEN}✅ {text}{Colors.END}")

def print_error(text: str):
    """Print error message."""
    print(f"{Colors.RED}❌ {text}{Colors.END}")

def print_warning(text: str):
    """Print warning message."""
    print(f"{Colors.YELLOW}⚠️  {text}{Colors.END}")

def print_info(text: str):
    """Print info message."""
    print(f"{Colors.CYAN}ℹ️  {text}{Colors.END}")

def check_python_version_available(version: str) -> bool:
    """Check if a Python version is available via uv."""
    print_info(f"Checking if Python {version} is available...")
    
    # Try to create a temporary project with this Python version
    with tempfile.TemporaryDirectory() as temp_dir:
        test_project = Path(temp_dir) / "test_project"
        test_project.mkdir()
        
        # Create a minimal pyproject.toml
        pyproject_content = f"""
[project]
name = "test"
version = "0.1.0"
requires-python = ">={version}"
"""
        (test_project / "pyproject.toml").write_text(pyproject_content)
        
        # Try to sync with this Python version
        code, stdout, stderr = run_command([
            "uv", "sync", "--python", version
        ], cwd=str(test_project))
        
        if code == 0:
            print_success(f"Python {version} is available")
            return True
        else:
            print_warning(f"Python {version} is not available: {stderr.strip()}")
            return False

def test_python_version(version: str, project_root: Path) -> Dict[str, Any]:
    """Test the Python bindings with a specific Python version."""
    result = {
        "version": version,
        "available": False,
        "build_success": False,
        "import_success": False,
        "basic_test_success": False,
        "unit_test_success": False,
        "errors": []
    }
    
    print_header(f"Testing Python {version}")
    
    # Check if version is available
    if not check_python_version_available(version):
        result["errors"].append(f"Python {version} not available")
        return result
    
    result["available"] = True
    
    # Create a temporary virtual environment for this version
    with tempfile.TemporaryDirectory() as temp_dir:
        venv_dir = Path(temp_dir) / f"venv-{version}"
        print_info(f"Creating temporary environment for Python {version}...")
        
        # Create virtual environment
        code, stdout, stderr = run_command([
            "uv", "venv", str(venv_dir), "--python", version
        ])
        
        if code != 0:
            result["errors"].append(f"Failed to create venv: {stderr}")
            return result
        
        # Install maturin in the venv
        print_info("Installing maturin...")
        code, stdout, stderr = run_command([
            "uv", "pip", "install", "maturin", "--python", str(venv_dir / "bin" / "python")
        ])
        
        if code != 0:
            result["errors"].append(f"Failed to install maturin: {stderr}")
            return result
        
        # Build the extension
        print_info("Building Python extension...")
        env = os.environ.copy()
        env["VIRTUAL_ENV"] = str(venv_dir)
        env["PATH"] = f"{venv_dir / 'bin'}:{env.get('PATH', '')}"
        
        code, stdout, stderr = run_command([
            str(venv_dir / "bin" / "python"), "-m", "maturin", "develop", 
            "--features", "python", "--skip-install"
        ], cwd=str(project_root / "python-bindings"))
        
        if code != 0:
            result["errors"].append(f"Build failed: {stderr}")
            return result
        
        result["build_success"] = True
        print_success("Build successful")
        
        # Install the built wheel
        print_info("Installing built package...")
        wheel_files = list(Path(project_root / "target" / "wheels").glob("*.whl"))
        if not wheel_files:
            # Try to build and install directly
            code, stdout, stderr = run_command([
                str(venv_dir / "bin" / "python"), "-m", "maturin", "develop", 
                "--features", "python"
            ], cwd=str(project_root / "python-bindings"))
            
            if code != 0:
                result["errors"].append(f"Install failed: {stderr}")
                return result
        
        # Test import
        print_info("Testing import...")
        test_import_code = """
import dcap_qvl
print(f"Import successful! Version: {dcap_qvl.__version__}")
print(f"Available: {dcap_qvl.__all__}")
"""
        
        code, stdout, stderr = run_command([
            str(venv_dir / "bin" / "python"), "-c", test_import_code
        ])
        
        if code != 0:
            result["errors"].append(f"Import failed: {stderr}")
            return result
        
        result["import_success"] = True
        print_success("Import successful")
        
        # Test basic functionality
        print_info("Testing basic functionality...")
        basic_test_code = """
import dcap_qvl

# Test creating collateral
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

# Test JSON serialization
json_str = collateral.to_json()
collateral2 = dcap_qvl.QuoteCollateralV3.from_json(json_str)

# Test verify with invalid data (should fail gracefully)
try:
    dcap_qvl.verify(b"invalid", collateral, 1234567890)
    print("ERROR: Should have failed")
    exit(1)
except ValueError:
    print("Basic functionality test passed!")
"""
        
        code, stdout, stderr = run_command([
            str(venv_dir / "bin" / "python"), "-c", basic_test_code
        ])
        
        if code != 0:
            result["errors"].append(f"Basic test failed: {stderr}")
            return result
        
        result["basic_test_success"] = True
        print_success("Basic functionality test passed")
        
        # Install pytest and run unit tests
        print_info("Installing pytest and running unit tests...")
        code, stdout, stderr = run_command([
            "uv", "pip", "install", "pytest", "--python", str(venv_dir / "bin" / "python")
        ])
        
        if code == 0:
            # Run unit tests (excluding sample data tests)
            code, stdout, stderr = run_command([
                str(venv_dir / "bin" / "python"), "-m", "pytest", 
                "tests/test_python_bindings.py::TestQuoteCollateralV3",
                "tests/test_python_bindings.py::TestVerify",
                "-v"
            ], cwd=str(project_root / "python-bindings"))
            
            if code == 0:
                result["unit_test_success"] = True
                print_success("Unit tests passed")
            else:
                result["errors"].append(f"Unit tests failed: {stderr}")
        else:
            result["errors"].append(f"Failed to install pytest: {stderr}")
    
    return result

def main():
    """Main test function."""
    project_root = Path(__file__).parent.parent.parent
    
    print_header("DCAP-QVL Python Version Compatibility Test")
    print_info(f"Project root: {project_root}")
    print_info(f"Testing Python versions: {', '.join(PYTHON_VERSIONS)}")
    
    # Check if uv is available
    code, stdout, stderr = run_command(["uv", "--version"])
    if code != 0:
        print_error("uv is not available. Please install uv first.")
        sys.exit(1)
    
    print_success(f"Using uv: {stdout.strip()}")
    
    # Test each Python version
    results = []
    for version in PYTHON_VERSIONS:
        try:
            result = test_python_version(version, project_root)
            results.append(result)
        except Exception as e:
            print_error(f"Unexpected error testing Python {version}: {e}")
            results.append({
                "version": version,
                "available": False,
                "build_success": False,
                "import_success": False,
                "basic_test_success": False,
                "unit_test_success": False,
                "errors": [str(e)]
            })
    
    # Print summary
    print_header("Test Summary")
    
    successful_versions = []
    failed_versions = []
    
    for result in results:
        version = result["version"]
        if not result["available"]:
            print_warning(f"Python {version}: Not available")
            failed_versions.append(version)
        elif result["unit_test_success"]:
            print_success(f"Python {version}: All tests passed ✅")
            successful_versions.append(version)
        else:
            status_parts = []
            if result["build_success"]:
                status_parts.append("build ✅")
            else:
                status_parts.append("build ❌")
            
            if result["import_success"]:
                status_parts.append("import ✅")
            else:
                status_parts.append("import ❌")
            
            if result["basic_test_success"]:
                status_parts.append("basic ✅")
            else:
                status_parts.append("basic ❌")
            
            if result["unit_test_success"]:
                status_parts.append("tests ✅")
            else:
                status_parts.append("tests ❌")
            
            print_error(f"Python {version}: {' | '.join(status_parts)}")
            failed_versions.append(version)
            
            if result["errors"]:
                for error in result["errors"]:
                    print(f"    {Colors.RED}↳ {error}{Colors.END}")
    
    print_header("Final Results")
    print_success(f"Successful versions: {', '.join(successful_versions) if successful_versions else 'None'}")
    
    if failed_versions:
        print_error(f"Failed versions: {', '.join(failed_versions)}")
    
    # Create a detailed report
    report_file = project_root / "python_version_test_report.json"
    with open(report_file, "w") as f:
        json.dump({
            "test_summary": {
                "total_versions": len(PYTHON_VERSIONS),
                "successful_versions": successful_versions,
                "failed_versions": failed_versions,
                "success_rate": f"{len(successful_versions)}/{len(PYTHON_VERSIONS)}"
            },
            "detailed_results": results
        }, f, indent=2)
    
    print_info(f"Detailed report saved to: {report_file}")
    
    # Exit with appropriate code
    if len(successful_versions) == len(PYTHON_VERSIONS):
        print_success("🎉 All Python versions passed!")
        sys.exit(0)
    elif successful_versions:
        print_warning("⚠️  Some Python versions failed, but at least one passed")
        sys.exit(1)
    else:
        print_error("💥 All Python versions failed!")
        sys.exit(2)

if __name__ == "__main__":
    main()