# About Testinfra CIS Benchmark Auditing
CIS Benchmarks, published by the Center for Internet Security (CIS), are documented industry best practices for securely configuring IT systems, software, and networks. 
With Testinfra you can write unit tests in Python to test actual state of your servers configured by management tools like Salt, Ansible, Puppet, Cheft and so on.

## Quick Installation 
```
bash
$ pip install testinfra
```

## Auditing CIS Benchmark with Testinfra
you can use testinfra to test local or remote servers.
For local server auditing 
```
bash
python -m pytest -v testinfra-cis-centos8.py
```
For remote server auditing
```
bash
python -m pytest -v --ssh-config=/Users/username/.ssh/config --hosts='ssh://hosts' testinfra-cis-centos8.py
```
## Audit Result
If you see PASSED that check is compliance
If you see FAILED that check is non-compliance. For the non-compliance, you can see more detail on below 
