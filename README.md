# Testinfra CIS Benchmark Auditing (CentOS/RHEL 8)
CIS Benchmarks are industry best practices published by the Center for Internet Security (CIS) for securely configuring systems, software, and networks. This repository provides Testinfra-based audit checks targeting CentOS 8 and compatible RHEL 8 derivatives (e.g., AlmaLinux 8, Rocky Linux 8).

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
pytest -v testinfra-cis-centos8.py
```
- Remote auditing (SSH):
```
pytest -v --hosts=ssh://user@hostname --ssh-config=~/.ssh/config testinfra-cis-centos8.py
```
- Run with elevated privileges when needed:
```
pytest -v --sudo testinfra-cis-centos8.py
```

## Outputs
- `PASSED`: the check is compliant
- `FAILED`: the check is non-compliant

## Notes
- CentOS 8 reached end-of-life. These tests are maintained to align with RHEL 8-compatible distributions.
- Some services and modules may be present due to specific workloads. Disable or adjust tests as appropriate for your environment.
