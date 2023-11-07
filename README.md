# [NTLMv1/2 Hash Dumper](https://github.com/Retr0-code/hash-dumper)

Windows NTLM hash dump utility written in C language, that supports Windows and Linux.

**Hash dumper** has got 2 modes:
 - *Realtime mode* (only for windows);
 - *Extraction mode* (dumps from saved SAM and SYSTEM hives files);

[![GitHub issues](https://img.shields.io/github/issues/Retr0-code/hash-dumper?labelColor=44E26E&color=505050)](https://github.com/Retr0-code/hash-dumper/issues?q=is%3Aopen+is%3Aissue)
[![GitHub closed issues](https://img.shields.io/github/issues-closed/Retr0-code/hash-dumper?labelColor=40D668&color=505050)](https://github.com/Retr0-code/hash-dumper/issues?q=is%3Aissue+is%3Aclosed)
[![GitHub release (latest by SemVer including pre-releases)](https://img.shields.io/github/downloads-pre/Retr0-code/hash-dumper/latest/total?labelColor=32a852&color=505050)](https://github.com/Retr0-code/hash-dumper/releases/latest)
[![GitHub pull requests](https://img.shields.io/github/issues-pr/Retr0-code/hash-dumper?labelColor=288541&color=505050)](https://github.com/Retr0-code/hash-dumper/pulls)

[![GitHub License](https://img.shields.io/github/license/Retr0-code/hash-dumper?labelColor=6967A6&color=505050)](https://github.com/Retr0-code/hash-dumper/blob/main/LICENSE.txt)
[![GitHub commit activity (branch)](https://img.shields.io/github/commit-activity/t/Retr0-code/hash-dumper?labelColor=525182&color=505050)](https://github.com/Retr0-code/hash-dumper/commits/main)

![Linux support](https://img.shields.io/badge/Linux-Supported-505050?labelColor=8C0842)
![NTLMv1](https://img.shields.io/badge/NTLMv1-Supported-505050?labelColor=B00B53)
![NTLMv2](https://img.shields.io/badge/NTLMv2-Supported-505050?labelColor=DE0D68)


## Table of content

 - [Responsibility](README.md#Responsibility)
 - [Building the project](README.md#building-the-project)
 - [Manual](README.md#Manual)

## Responsibility

The author is not responsible for the actions of third parties committed while using the provided software. This software is regarded as a tool for legal penetration testing or conducting research. In case of misuse, the author does not bear any responsibility for the actions of third parties.

## Building the project

For building required *OpenSSL >= 3.0 or OpenSSL 1.1.1* library. Use cmake to generate a solution for Visual Studio or Make file. If CMake cannot find OpenSSL, than set **OPENSSL_ROOT_DIR** and **OPENSSL_LIB_DIR** variables.

**If OpenSSL >= 3.0 was chosen, than legacy provider have to be compiled for RC4 and DES**

 - [Compiling OpenSSL for Windows](https://wiki.openssl.org/index.php/Compilation_and_Installation)
 - [Running CMake with OpenSSL](https://stackoverflow.com/a/45548831)
 - [How to enable legacy provider?](https://github.com/openssl/openssl/issues/20112)

**Basic setup**

Cloning repository

```sh
$ git clone https://github.com/Retr0-code/hash-dumper
$ git submodule update --init
```

----

If You work alone

```sh
$ git branch dev_<username>
$ git checkout dev_<username>
$ git push -u origin dev_<username>
```

**OR**

If You work in a small team

```sh
$ git checkout dev_<team_tag>
$ git pull
```


**Building using cmake**

Use *BUILD_ARCH* parameter to specify architecture of output binary

*Architectures:*

 - amd64 (default);
 - i386;

Use *BUILD_TARGET* parameter to specify compiling configuration

*Configurations:*

 - RELEASE (default);
 - DEBUG;


## Manual

You can use this utility to dump NTLMv1/2 hashes from already compromised host by using `--realtime` flag

```
> ./hash_dumper.exe --realtime
[+] Hives successfully opened
[+] Successfully dumped bootkey: 2766FA60DBAB4DEE67237AC942E35271
[+] Successfully hashed the bootkey: 966408e98667069a4884956c5e397575

Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:9cf3445f9555a4c246fe2c3c2446b103:::
sandbox:1002:aad3b435b51404eeaad3b435b51404ee:67b6acadb87c12e9d84e6e73b6883601:::

[+] Successfully finished
```

Otherwise You can extract hashes from already saved hives using parameters `--sam <path_to_sam_hive>` and `--system <path_to_system_hive>`

```
> ./hash_dumper.exe --sam hives/sam --system hives/system
[+] Hives successfully opened
[+] Successfully dumped bootkey: 2766FA60DBAB4DEE67237AC942E35271
[+] Successfully hashed the bootkey: 966408e98667069a4884956c5e397575

Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:9cf3445f9555a4c246fe2c3c2446b103:::
sandbox:1002:aad3b435b51404eeaad3b435b51404ee:67b6acadb87c12e9d84e6e73b6883601:::

[+] Successfully finished
```

**If You supply all parameters only `--realtime` will work.**
