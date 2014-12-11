payutcli
========

Payutcli will drop you in a funny shell to interact with payutc server,
the shell support autocompletion so feel free to hurt the tab key.

Install
-------

    pip install -r requirements.txt
    pip install ipython # optional but more fun

Run
---

    ./payutcli -l 'http://localhost/payutc'
    >>> client.POSS3.getCasUrl()
    'http://cas.utc.fr'

Login by CAS
------------

An utility funciton is provided to login by CAS, the function will open the default browser.

    >>> client.loginCas()
    # browser open
    myutclogin

Notes
-----

The following packages are required to make ssl works smoothly on python2:

  ndg-httpsclient
  pyasn1
  pyOpenSSL

