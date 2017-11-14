# Cider

### Purpose

This is a Python program I wrote that was originally intended for calculating CIDR IP information for PostgreSQL's pg_hba.conf file. Now it does... a lot more.

### Usage

```usage: cidr.py [-h] [-l] [--ic 0.0.0.0/0] [--nm 0.0.0.0 0.0.0.0] [--hosts n]

optional arguments:
  -h, --help            show this help message and exit
  -l                    List all CIDR/Subnet Mask combinations
  --ic 0.0.0.0/0        Get info on a valid IP/CIDR combination
  --nm 0.0.0.0 0.0.0.0  Find minimum net mask which contains two IPs
  --hosts n             Calculate CIDR to contain n hosts```
