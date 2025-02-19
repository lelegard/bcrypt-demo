# Microsoft BCrypt Library Demo

This project contains one single program which demonstrates the usage of the
Microsoft BCrypt library on Windows.

The following algorithms are demonstrated:

- PBKDF2
- AES-ECB
- AES-CBC
- AES-GCM

The source code encapsulates the complex calls to the BCrypt library into C++
classes. The main program tests these implementations using test vectors,
either public reference test vectors or generated with an `openssl` command
line.

## About the Microsoft BCrypt library

BCrypt, a.k.a. CNG (Cryptographic API Next Generation), is the native cryptographic
library on Windows systems. The library can be called from user mode or kernel mode.
It is embedded in all Windows systems, for all architectures. Using BCrypt for
cryptographic operations on Windows is usually the best choice for several reasons.

On an availability perspective, most open source cryptographic libraries can be
ported to Windows. However, this is never easy. Open source developers often don't
care about Windows and the port is never free. When the port is completed in terms
of source code, there is usually no ready-to-use binaries for Windows developers
(with the notable exception of OpenSSL). Windows developers using these libraries
in their application need some non-trivial initial setup. At the deployment stage,
these libraries must be embedded with the application. BCrypt, on the other hand,
is always available by default on all Windows systems, build servers and deployment
targets.

On a performance perspective, BCrypt is either equivalent to OpenSSL or even better.
AES-XTS and AES-GCM, for instance, are better to much better than OpenSSL. See more
details and tests in this project: https://github.com/lelegard/aesbench

Note, however, that BCrypt is not open source. If you have stringent security and
verifiability requirements, you may prefer to port an open source cryptographic
library on Windows and pay the cost of porting and deployment.
