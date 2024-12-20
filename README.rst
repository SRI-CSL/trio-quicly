Trio QUIC -- an implementation of the QUIC protocol using the async Python Trio library
=======================================================================================

What is ``trio-quic``?
--------------------

``trio-quic`` is a library for the QUIC network protocol in Python using the popular async library `Trio`_.

QUIC v1 was standardized in May in `RFC 9000`_ and accompanied by `RFC 9001`_ ("Using TLS to Secure QUIC") and
`RFC 9002`_ ("QUIC Loss Detection and Congestion Control").  It is used as transport for HTTP/3 (see `RFC 9114`_).

To learn more about ``trio-quic`` please `read the documentation`_.

Requirements
------------

``trio-quic`` requires Python 3.9 or better, and the OpenSSL development headers.

License
-------

``trio-quic`` is released under the `BSD license`_.

QLOG
----

We are embracing `QLOG main`_ and `QUIC events`_ that together define a "qlog event schema containing concrete qlog
event definitions and their metadata for the core QUIC protocol and selected extensions."  In our example HTTP/3
implementation, we are extending our structured logging to include `HTTP3 events`_.

.. _cryptography: https://cryptography.io/
.. _Trio: https://trio.readthedocs.io/en/stable/
.. _RFC 9000: https://datatracker.ietf.org/doc/html/rfc9000
.. _RFC 9001: https://datatracker.ietf.org/doc/html/rfc9001
.. _RFC 9002: https://datatracker.ietf.org/doc/html/rfc9002
.. _RFC 9114: https://datatracker.ietf.org/doc/html/rfc9114
.. _QLOG main: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-10
.. _QUIC events: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-quic-events-09
.. _HTTP3 events: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-h3-events-09
