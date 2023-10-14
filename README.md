# hash dumper

Simple Windows NTLM hash dumper utility written in C language. It has support for Windows realtime dumping and Linux dumping from files.

## Responsibility

The author is not responsible for the actions of third parties committed while using the provided software. This software is regarded as a tool for legal penetration testing or conducting research. In case of misuse, the author does not bear any responsibility for the actions of third parties.

## Compilation

For compilation required *OpenSSL >= 3.0* library. Use cmake to generate a solution for Visual Studio or Make file. Cmake requires **OPENSSL_ROOT_DIR** and **OPENSSL_LIB** variables to be set.

### Resources
 - [Compiling OpenSSL for Windows](https://wiki.openssl.org/index.php/Compilation_and_Installation)
 - [Running CMake with OpenSSL](https://stackoverflow.com/a/45548831)
