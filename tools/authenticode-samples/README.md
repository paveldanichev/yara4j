# Authenticode test samples

`yara4j-core/src/test/resources/authenticode` contains PE files with generated Authenticode
signatures and, for each one, the signature related part of `yara -D` produced by **native
libyara 4.5.8 built with OpenSSL 3.0.13**. `AuthenticodeTest` checks that yara4j produces
exactly the same output.

The samples cover digest algorithms (MD5, SHA-1, SHA-2), RSA, RSA-PSS and ECDSA keys,
PKCS#9 and RFC 3161 (PKCS#7 and CMS-only) countersignatures, nested signatures, malformed
or invalid signatures, program names (BMP, IA5, NUL, surrogates), certificate names
(multi-valued RDNs, escapes, BMP/T61 strings, unknown OIDs, truncation at 255 characters),
serial numbers (negative, 20 and 21 bytes), UTCTime/GeneralizedTime variants and chain
building corner cases (duplicate, expired and mismatching candidate issuers, case
insensitive name matching, certificates without extensions).

## Regenerating

The generator uses random keys, so regenerating changes the samples and the expected files
must be produced again with native YARA:

```bash
CP=bcprov-jdk18on-1.86.jar:bcpkix-jdk18on-1.86.jar:bcutil-jdk18on-1.86.jar
javac -cp $CP -d classes AuthenticodeSampleGenerator.java
java -cp classes:$CP AuthenticodeSampleGenerator path/to/yara/tests/data out
for f in out/*; do
  yara -w -D pe.yar "$f" | python3 sigextract.py > "$f.expected"   # pe.yar: import "pe" rule r { condition: false }
done
```

`yara` must be built with OpenSSL (`HAVE_LIBCRYPTO`) so that `pe.signatures` is available.
Chain building depends on the current time when several candidate issuers exist; the
certificates used here are valid until 2039 or later.
