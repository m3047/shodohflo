### Installation

**1) The first step in installation is to clone or unpack the repository somewhere..**

One suggestion would be `/usr/local/share/`.

**2) Make it so _Python 3_ will find it.**

By "the package" we're referring to the `shodohflo` directory at the toplevel of the 
this repository.

One suggestion would be to create a symlink to the package in `/usr/local/lib/python3.6/site-packages/`. So for example,
and assuming that you unpacked the repository in `/usr/local/share/`:

```
cd /usr/local/lib/python3.6/site-packages/
ln -s ../../../share/shodohflo/shodohflo
```

If you're not sure where python is going to look, you can find out this way:

```
# python3
>>> import sys
>>> sys.path
['', '/usr/lib/python36.zip', '/usr/lib64/python3.6', '/usr/lib64/python3.6/lib-dynload', '/usr/lib64/python3.6/site-packages', '/usr/lib64/python3.6/site-packages/PIL', '/usr/lib64/python3.6/_import_failed', '/usr/lib/python3.6/site-packages', '/usr/local/lib/python3.6/site-packages']
```
Another option would be to add the location of the package to `PYTHONPATH`.

For the agents and `dnstap2json.py` I modify `sys.path` within the applications themselves, you can do that too.

**3) Run `create_shodohflo.py` to create `__pycache__`**

This script will also validate the correctness of your symlink.

### Post installation

If you are installing to run agents or the app, then you need to create `configuration.py`. There should be
a `configuration_sample.py` in the appropriate directories. (`dnstap2json` just takes command line args.)

Look in the `install/systemd/` directory for _systemd_ service scripts.

### Upgrades

Upgrading should be as simple as running `git pull`. You may need to re-run `create_shodohflo_pycache.py` and restart services.
