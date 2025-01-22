# ShadowSight

A client to gather vulnerability-related information from the
[Shadowserver Foundation](https://www.shadowserver.org).
The collected data is then sent to the
[Vulnerability-Lookup](https://github.com/cve-search/vulnerability-lookup) API as sightings.


## Installation

[pipx](https://github.com/pypa/pipx) is an easy way to install and run Python applications in isolated environments.
It's easy to [install](https://github.com/pypa/pipx?tab=readme-ov-file#on-linux).

```bash
$ pipx install ShadowSight
$ export SHADOWSIGHT_CONFIG=~/.ShadowSight/conf.py
```

The configuration should be defined in a Python file (e.g., ``~/.ShadowSight/conf.py``).
You must then set an environment variable (``SHADOWSIGHT_CONFIG``) with the full path to this file.

You can have a look at [this example](https://github.com/CIRCL/ShadowSight/blob/main/shadowsight/conf_sample.py) of configuration.


## Usage

### Publishing sightings to Vulnerability-Lookup

```bash
$ ShadowSight --help
usage: ShadowSight [-h] [--method {exploited,common}] [--since SINCE] [--limit LIMIT]

ShadowSight Query Script

options:
  -h, --help            show this help message and exit
  --method {exploited,common}
                        The set of vulnerabilities (honeypot/exploited-vulnerabilities or honeypot/common-vulnerabilities) from the honeypot group.
  --since SINCE         Query for exploited vulnerabilities from Shadow Server (back until) this date inclusive (yyyy-mm-dd), or specify an integer to represent days in the past.
  --limit LIMIT         Limit number of results.


$ ShadowSight --since 2025-01-21 --limit 10

$ ShadowSight --since 3d --limit 10

$ ShadowSight --since 30d --limit 10 --method common
```


## Example of collected sightings

Sets of sightings available on Vulnerability-Lookup thanks to the Shadowserver foundation:

- [sightings of type exploited](https://vulnerability.circl.lu/sightings/?query=honeypot%2Fexploited-vulnerabilities)
- [sightings of type seen](https://vulnerability.circl.lu/sightings/?query=honeypot%2Fcommon-vulnerabilities)


## License

[ShadowSight](https://github.com/CIRCL/ShadowSight) is licensed under
[GNU General Public License version 3](https://www.gnu.org/licenses/gpl-3.0.html)

~~~
Copyright (c) 2025 Computer Incident Response Center Luxembourg (CIRCL)
Copyright (C) 2025 Cédric Bonhomme - https://github.com/cedricbonhomme
~~~
