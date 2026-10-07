"""Fail the release gate when Linux integrations silently skip."""
import subprocess
import sys
import xml.etree.ElementTree as ET

result=subprocess.run([sys.executable,'-m','pytest','-q','--tb=short','-p','no:cacheprovider','--junitxml=/tmp/ha-tunnel-tests.xml'])
if result.returncode: raise SystemExit(result.returncode)
report=ET.parse('/tmp/ha-tunnel-tests.xml')
if report.findall('.//skipped'): raise SystemExit('Security gate requires all Linux integrations, no skips allowed')
