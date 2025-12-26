# Testinfra CIS Benchmark Auditing (EL9/EL10, Ubuntu, Debian)
CIS Benchmarks are industry best practices published by the Center for Internet Security (CIS) for securely configuring systems, software, and networks. This repository provides Testinfra-based audit checks targeting Enterprise Linux 8/9/10 (RHEL/Alma/Rocky), Ubuntu, and Debian.

## Requirements
- Python 3.8+
- `pytest` and `testinfra`
- SSH access for remote auditing

Install dependencies:
```
pip install pytest testinfra
```

## Usage
- Local auditing:
```
pytest -v testinfra-cis-el8.py
pytest -v testinfra-cis-el9.py
pytest -v testinfra-cis-el10.py
pytest -v testinfra-cis-ubuntu.py
pytest -v testinfra-cis-debian.py
```
- Remote auditing (SSH):
```
pytest -v --hosts=ssh://user@hostname --ssh-config=~/.ssh/config testinfra-cis-el9.py
```
- Run with elevated privileges when needed:
```
pytest -v --sudo testinfra-cis-el9.py
```

## Choosing a suite
- `testinfra-cis-el9.py`: RHEL/AlmaLinux/Rocky 9 and other EL9 derivatives
- `testinfra-cis-el10.py`: RHEL/AlmaLinux/Rocky 10 and other EL10 derivatives
- `testinfra-cis-ubuntu.py`: Ubuntu LTS releases
- `testinfra-cis-debian.py`: Debian stable releases

## Outputs
- `PASSED`: the check is compliant
- `FAILED`: the check is non-compliant

## Notes
- RHEL 8 reached end-of-life; the original CentOS/RHEL 8 suite remains for reference.
- Service names and package identifiers differ across distributions; the suites are tailored accordingly.
- Some services and modules may be present due to specific workloads. Adjust or skip tests to fit your environment.
