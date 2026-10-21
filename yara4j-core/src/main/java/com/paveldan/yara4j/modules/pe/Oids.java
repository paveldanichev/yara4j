package com.paveldan.yara4j.modules.pe;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHA512tDigest;
import org.bouncycastle.crypto.digests.SM3Digest;

/**
 * The subset of OpenSSL's object database (obj_mac.h) needed to reproduce the names produced by
 * the authenticode-parser library used by libyara.
 */
final class Oids {
  private Oids() {}

  static final String SIGNED_DATA = "1.2.840.113549.1.7.2";
  static final String PKCS7_DATA = "1.2.840.113549.1.7.1";
  static final String MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
  static final String SIGNING_TIME = "1.2.840.113549.1.9.5";
  static final String COUNTERSIGNATURE = "1.2.840.113549.1.9.6";
  static final String TST_INFO = "1.2.840.113549.1.9.16.1.4";
  static final String SPC_INDIRECT_DATA = "1.3.6.1.4.1.311.2.1.4";
  static final String SPC_SP_OPUS_INFO = "1.3.6.1.4.1.311.2.1.12";
  static final String SPC_NESTED_SIGNATURE = "1.3.6.1.4.1.311.2.4.1";
  static final String SPC_MS_COUNTERSIGNATURE = "1.3.6.1.4.1.311.3.3.1";
  static final String SUBJECT_KEY_IDENTIFIER = "2.5.29.14";
  static final String AUTHORITY_KEY_IDENTIFIER = "2.5.29.35";
  static final String RSA_ENCRYPTION = "1.2.840.113549.1.1.1";
  static final String RSASSA_PSS = "1.2.840.113549.1.1.10";
  static final String EC_PUBLIC_KEY = "1.2.840.10045.2.1";
  static final String DSA = "1.2.840.10040.4.1";
  static final String ED25519 = "1.3.101.112";
  static final String ED448 = "1.3.101.113";

  /** Key types used to emulate OpenSSL's check_sig_alg_match. */
  enum KeyType {
    RSA,
    RSA_PSS,
    EC,
    DSA,
    ED25519,
    ED448,
    SM2,
    NONE
  }

  private static final Map<String, String[]> NAMES = new HashMap<>();
  private static final Map<String, KeyType> SIG_KEY_TYPE = new HashMap<>();

  /** A message digest algorithm known to OpenSSL's EVP_get_digestbyname. */
  static final class Md {
    final String oid;
    final int size;
    final String pkeyOid;
    private final Supplier<Digest> factory;

    Md(String oid, int size, String pkeyOid, Supplier<Digest> factory) {
      this.oid = oid;
      this.size = size;
      this.pkeyOid = pkeyOid;
      this.factory = factory;
    }

    Digest newDigest() {
      return factory.get();
    }

    byte[] digest(byte[] data, int off, int len) {
      Digest d = newDigest();
      d.update(data, off, len);
      byte[] out = new byte[d.getDigestSize()];
      d.doFinal(out, 0);
      return out;
    }

    byte[] digest(byte[] data) {
      return digest(data, 0, data.length);
    }
  }

  private static final Map<String, Md> MD_BY_OID = new HashMap<>();

  private static void name(String oid, String sn, String ln) {
    NAMES.put(oid, new String[] {sn, ln});
  }

  private static void sig(String oid, String sn, String ln, KeyType key) {
    name(oid, sn, ln);
    SIG_KEY_TYPE.put(oid, key);
  }

  private static void md(String oid, int size, String pkeyOid, Supplier<Digest> f) {
    Md m = new Md(oid, size, pkeyOid, f);
    MD_BY_OID.put(oid, m);
    if (pkeyOid != null) {
      MD_BY_OID.put(pkeyOid, m);
    }
  }

  static {
    // Distinguished name attributes.
    name("2.5.4.3", "CN", "commonName");
    name("2.5.4.4", "SN", "surname");
    name("2.5.4.5", "serialNumber", "serialNumber");
    name("2.5.4.6", "C", "countryName");
    name("2.5.4.7", "L", "localityName");
    name("2.5.4.8", "ST", "stateOrProvinceName");
    name("2.5.4.9", "street", "streetAddress");
    name("2.5.4.10", "O", "organizationName");
    name("2.5.4.11", "OU", "organizationalUnitName");
    name("2.5.4.12", "title", "title");
    name("2.5.4.13", "description", "description");
    name("2.5.4.14", "searchGuide", "searchGuide");
    name("2.5.4.15", "businessCategory", "businessCategory");
    name("2.5.4.16", "postalAddress", "postalAddress");
    name("2.5.4.17", "postalCode", "postalCode");
    name("2.5.4.18", "postOfficeBox", "postOfficeBox");
    name("2.5.4.19", "physicalDeliveryOfficeName", "physicalDeliveryOfficeName");
    name("2.5.4.20", "telephoneNumber", "telephoneNumber");
    name("2.5.4.41", "name", "name");
    name("2.5.4.42", "GN", "givenName");
    name("2.5.4.43", "initials", "initials");
    name("2.5.4.44", "generationQualifier", "generationQualifier");
    name("2.5.4.45", "x500UniqueIdentifier", "x500UniqueIdentifier");
    name("2.5.4.46", "dnQualifier", "dnQualifier");
    name("2.5.4.65", "pseudonym", "pseudonym");
    name("2.5.4.72", "role", "role");
    name("2.5.4.97", "organizationIdentifier", "organizationIdentifier");
    name("1.2.840.113549.1.9.1", "emailAddress", "emailAddress");
    name("1.2.840.113549.1.9.2", "unstructuredName", "unstructuredName");
    name("1.2.840.113549.1.9.8", "unstructuredAddress", "unstructuredAddress");
    name("0.9.2342.19200300.100.1.1", "UID", "userId");
    name("0.9.2342.19200300.100.1.25", "DC", "domainComponent");
    name("1.3.6.1.4.1.311.60.2.1.1", "jurisdictionL", "jurisdictionLocalityName");
    name("1.3.6.1.4.1.311.60.2.1.2", "jurisdictionST", "jurisdictionStateOrProvinceName");
    name("1.3.6.1.4.1.311.60.2.1.3", "jurisdictionC", "jurisdictionCountryName");

    // Public key algorithms.
    name(RSA_ENCRYPTION, "rsaEncryption", "rsaEncryption");
    name(EC_PUBLIC_KEY, "id-ecPublicKey", "id-ecPublicKey");
    name(DSA, "DSA", "dsaEncryption");
    name("1.3.14.3.2.12", "DSA-old", "dsaEncryption-old");

    // Signature algorithms.
    sig("1.2.840.113549.1.1.2", "RSA-MD2", "md2WithRSAEncryption", KeyType.RSA);
    sig("1.2.840.113549.1.1.3", "RSA-MD4", "md4WithRSAEncryption", KeyType.RSA);
    sig("1.2.840.113549.1.1.4", "RSA-MD5", "md5WithRSAEncryption", KeyType.RSA);
    sig("1.2.840.113549.1.1.5", "RSA-SHA1", "sha1WithRSAEncryption", KeyType.RSA);
    sig(RSASSA_PSS, "RSASSA-PSS", "rsassaPss", KeyType.RSA_PSS);
    sig("1.2.840.113549.1.1.11", "RSA-SHA256", "sha256WithRSAEncryption", KeyType.RSA);
    sig("1.2.840.113549.1.1.12", "RSA-SHA384", "sha384WithRSAEncryption", KeyType.RSA);
    sig("1.2.840.113549.1.1.13", "RSA-SHA512", "sha512WithRSAEncryption", KeyType.RSA);
    sig("1.2.840.113549.1.1.14", "RSA-SHA224", "sha224WithRSAEncryption", KeyType.RSA);
    sig("1.2.840.113549.1.1.15", "RSA-SHA512/224", "sha512-224WithRSAEncryption", KeyType.RSA);
    sig("1.2.840.113549.1.1.16", "RSA-SHA512/256", "sha512-256WithRSAEncryption", KeyType.RSA);
    sig("1.3.14.3.2.3", "RSA-NP-MD5", "md5WithRSA", KeyType.RSA);
    sig("1.3.14.3.2.13", "DSA-SHA", "dsaWithSHA", KeyType.DSA);
    sig("1.3.14.3.2.15", "RSA-SHA", "shaWithRSAEncryption", KeyType.RSA);
    sig("1.3.14.3.2.27", "DSA-SHA1-old", "dsaWithSHA1-old", KeyType.DSA);
    sig("1.3.14.3.2.29", "RSA-SHA1-2", "sha1WithRSA", KeyType.RSA);
    sig("1.2.840.10040.4.3", "DSA-SHA1", "dsaWithSHA1", KeyType.DSA);
    sig("2.16.840.1.101.3.4.3.1", "dsa_with_SHA224", "dsa_with_SHA224", KeyType.DSA);
    sig("2.16.840.1.101.3.4.3.2", "dsa_with_SHA256", "dsa_with_SHA256", KeyType.DSA);
    sig("2.16.840.1.101.3.4.3.3", "id-dsa-with-sha384", "dsa_with_SHA384", KeyType.DSA);
    sig("2.16.840.1.101.3.4.3.4", "id-dsa-with-sha512", "dsa_with_SHA512", KeyType.DSA);
    sig("2.16.840.1.101.3.4.3.9", "id-ecdsa-with-sha3-224", "ecdsa_with_SHA3-224", KeyType.EC);
    sig("2.16.840.1.101.3.4.3.10", "id-ecdsa-with-sha3-256", "ecdsa_with_SHA3-256", KeyType.EC);
    sig("2.16.840.1.101.3.4.3.11", "id-ecdsa-with-sha3-384", "ecdsa_with_SHA3-384", KeyType.EC);
    sig("2.16.840.1.101.3.4.3.12", "id-ecdsa-with-sha3-512", "ecdsa_with_SHA3-512", KeyType.EC);
    sig("2.16.840.1.101.3.4.3.13", "id-rsassa-pkcs1-v1_5-with-sha3-224", "RSA-SHA3-224",
        KeyType.RSA);
    sig("2.16.840.1.101.3.4.3.14", "id-rsassa-pkcs1-v1_5-with-sha3-256", "RSA-SHA3-256",
        KeyType.RSA);
    sig("2.16.840.1.101.3.4.3.15", "id-rsassa-pkcs1-v1_5-with-sha3-384", "RSA-SHA3-384",
        KeyType.RSA);
    sig("2.16.840.1.101.3.4.3.16", "id-rsassa-pkcs1-v1_5-with-sha3-512", "RSA-SHA3-512",
        KeyType.RSA);
    sig("1.2.840.10045.4.1", "ecdsa-with-SHA1", "ecdsa-with-SHA1", KeyType.EC);
    sig("1.2.840.10045.4.3.1", "ecdsa-with-SHA224", "ecdsa-with-SHA224", KeyType.EC);
    sig("1.2.840.10045.4.3.2", "ecdsa-with-SHA256", "ecdsa-with-SHA256", KeyType.EC);
    sig("1.2.840.10045.4.3.3", "ecdsa-with-SHA384", "ecdsa-with-SHA384", KeyType.EC);
    sig("1.2.840.10045.4.3.4", "ecdsa-with-SHA512", "ecdsa-with-SHA512", KeyType.EC);
    sig("1.3.36.3.3.1.2", "RSA-RIPEMD160", "ripemd160WithRSA", KeyType.RSA);
    sig("1.2.156.10197.1.504", "RSA-SM3", "sm3WithRSAEncryption", KeyType.RSA);
    sig("1.2.156.10197.1.501", "SM2-SM3", "SM2-with-SM3", KeyType.SM2);
    sig(ED25519, "ED25519", "ED25519", KeyType.ED25519);
    sig(ED448, "ED448", "ED448", KeyType.ED448);

    // Message digests.
    name("1.2.840.113549.2.2", "MD2", "md2");
    name("1.2.840.113549.2.4", "MD4", "md4");
    name("1.2.840.113549.2.5", "MD5", "md5");
    name("1.3.14.3.2.18", "SHA", "sha");
    name("1.3.14.3.2.26", "SHA1", "sha1");
    name("2.16.840.1.101.3.4.2.1", "SHA256", "sha256");
    name("2.16.840.1.101.3.4.2.2", "SHA384", "sha384");
    name("2.16.840.1.101.3.4.2.3", "SHA512", "sha512");
    name("2.16.840.1.101.3.4.2.4", "SHA224", "sha224");
    name("2.16.840.1.101.3.4.2.5", "SHA512-224", "sha512-224");
    name("2.16.840.1.101.3.4.2.6", "SHA512-256", "sha512-256");
    name("2.16.840.1.101.3.4.2.7", "SHA3-224", "sha3-224");
    name("2.16.840.1.101.3.4.2.8", "SHA3-256", "sha3-256");
    name("2.16.840.1.101.3.4.2.9", "SHA3-384", "sha3-384");
    name("2.16.840.1.101.3.4.2.10", "SHA3-512", "sha3-512");
    name("2.16.840.1.101.3.4.2.11", "SHAKE128", "shake128");
    name("2.16.840.1.101.3.4.2.12", "SHAKE256", "shake256");
    name("1.3.36.3.2.1", "RIPEMD160", "ripemd160");
    name("1.2.156.10197.1.401", "SM3", "sm3");

    md("1.2.840.113549.2.5", 16, "1.2.840.113549.1.1.4", MD5Digest::new);
    md("1.3.14.3.2.26", 20, "1.2.840.113549.1.1.5", SHA1Digest::new);
    // EVP_add_digest_alias(SN_sha1WithRSAEncryption, SN_sha1WithRSA)
    MD_BY_OID.put("1.3.14.3.2.29", MD_BY_OID.get("1.3.14.3.2.26"));
    md("2.16.840.1.101.3.4.2.4", 28, "1.2.840.113549.1.1.14", SHA224Digest::new);
    md("2.16.840.1.101.3.4.2.1", 32, "1.2.840.113549.1.1.11", SHA256Digest::new);
    md("2.16.840.1.101.3.4.2.2", 48, "1.2.840.113549.1.1.12", SHA384Digest::new);
    md("2.16.840.1.101.3.4.2.3", 64, "1.2.840.113549.1.1.13", SHA512Digest::new);
    md("2.16.840.1.101.3.4.2.5", 28, "1.2.840.113549.1.1.15", () -> new SHA512tDigest(224));
    md("2.16.840.1.101.3.4.2.6", 32, "1.2.840.113549.1.1.16", () -> new SHA512tDigest(256));
    md("2.16.840.1.101.3.4.2.7", 28, "2.16.840.1.101.3.4.3.13", () -> new SHA3Digest(224));
    md("2.16.840.1.101.3.4.2.8", 32, "2.16.840.1.101.3.4.3.14", () -> new SHA3Digest(256));
    md("2.16.840.1.101.3.4.2.9", 48, "2.16.840.1.101.3.4.3.15", () -> new SHA3Digest(384));
    md("2.16.840.1.101.3.4.2.10", 64, "2.16.840.1.101.3.4.3.16", () -> new SHA3Digest(512));
    md("1.3.36.3.2.1", 20, "1.3.36.3.3.1.2", RIPEMD160Digest::new);
    md("1.2.156.10197.1.401", 32, "1.2.156.10197.1.504", SM3Digest::new);

    // PKCS#7 / PKCS#9 / Authenticode.
    name(PKCS7_DATA, "pkcs7-data", "pkcs7-data");
    name(SIGNED_DATA, "pkcs7-signedData", "pkcs7-signedData");
    name("1.2.840.113549.1.9.3", "contentType", "contentType");
    name(MESSAGE_DIGEST, "messageDigest", "messageDigest");
    name(SIGNING_TIME, "signingTime", "signingTime");
    name(COUNTERSIGNATURE, "countersignature", "countersignature");
    name(TST_INFO, "id-smime-ct-TSTInfo", "id-smime-ct-TSTInfo");
    name(SPC_SP_OPUS_INFO, "spcSpOpusInfo", "SPC_SP_OPUS_INFO_OBJID");
    name(SPC_MS_COUNTERSIGNATURE, "spcMsCountersignature", "SPC_MICROSOFT_COUNTERSIGNATURE");
    name(SPC_NESTED_SIGNATURE, "spcNestedSignature", "SPC_NESTED_SIGNATUREs");
    name(SPC_INDIRECT_DATA, "spcIndirectData", "SPC_INDIRECT_DATA");
  }

  /** OBJ_nid2sn(OBJ_obj2nid(oid)), or null for objects unknown to OpenSSL. */
  static String shortName(String oid) {
    String[] n = NAMES.get(oid);
    return n == null ? null : n[0];
  }

  /** OBJ_nid2ln(OBJ_obj2nid(oid)): "undefined" for objects unknown to OpenSSL. */
  static String longName(String oid) {
    String[] n = NAMES.get(oid);
    return n == null ? "undefined" : n[1];
  }

  /** OBJ_obj2txt(OBJ_nid2obj(OBJ_obj2nid(oid)), 1): empty for unknown objects. */
  static String oidText(String oid) {
    return NAMES.containsKey(oid) ? oid : "";
  }

  /** The digest returned by EVP_get_digestbyname for the names of the given object. */
  static Md md(String oid) {
    return oid == null ? null : MD_BY_OID.get(oid);
  }

  /** The public key type expected by a signature algorithm (OBJ_find_sigid_algs). */
  static KeyType sigKeyType(String oid) {
    KeyType t = SIG_KEY_TYPE.get(oid);
    return t == null ? KeyType.NONE : t;
  }

  static KeyType keyType(String spkiOid) {
    if (spkiOid == null) {
      return KeyType.NONE;
    }
    switch (spkiOid) {
      case RSA_ENCRYPTION:
        return KeyType.RSA;
      case RSASSA_PSS:
        return KeyType.RSA_PSS;
      case EC_PUBLIC_KEY:
        return KeyType.EC;
      case DSA:
        return KeyType.DSA;
      case ED25519:
        return KeyType.ED25519;
      case ED448:
        return KeyType.ED448;
      default:
        return KeyType.NONE;
    }
  }
}
