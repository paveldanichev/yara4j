package com.paveldan.yara4j.modules.pe;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import com.paveldan.yara4j.modules.hash.HashModule;
import com.paveldan.yara4j.modules.pe.Asn1.Asn1Exception;
import com.paveldan.yara4j.modules.pe.PeModule.Pe;
import com.paveldan.yara4j.object.YStructure;
import com.paveldan.yara4j.util.CStrings;

/**
 * Parsing and verification of Authenticode signatures. Port of the authenticode-parser library
 * (Avast, MIT license) bundled with libyara, with OpenSSL replaced by a small ASN.1 reader and
 * BouncyCastle's lightweight crypto API. OpenSSL behaviours that affect the values visible to
 * rules (one-line names, chain building, algorithm names) are emulated.
 */
final class Authenticode {
  private Authenticode() {}

  static final int VFY_VALID = 0;
  static final int VFY_CANT_PARSE = 1;
  static final int VFY_NO_SIGNER_CERT = 2;
  static final int VFY_DIGEST_MISSING = 3;
  static final int VFY_INTERNAL_ERROR = 4;
  static final int VFY_NO_SIGNER_INFO = 5;
  static final int VFY_WRONG_PKCS7_TYPE = 6;
  static final int VFY_BAD_CONTENT = 7;
  static final int VFY_INVALID = 8;
  static final int VFY_WRONG_FILE_DIGEST = 9;
  static final int VFY_UNKNOWN_ALGORITHM = 10;

  static final int CS_VFY_VALID = 0;
  static final int CS_VFY_CANT_PARSE = 1;
  static final int CS_VFY_NO_SIGNER_CERT = 2;
  static final int CS_VFY_UNKNOWN_ALGORITHM = 3;
  static final int CS_VFY_INVALID = 4;
  static final int CS_VFY_CANT_DECRYPT_DIGEST = 5;
  static final int CS_VFY_DIGEST_MISSING = 6;
  static final int CS_VFY_DOESNT_MATCH_SIGNATURE = 7;
  static final int CS_VFY_INTERNAL_ERROR = 8;
  static final int CS_VFY_TIME_MISSING = 9;

  private static final int MAX_NESTED_COUNT = 16;

  /** timegm() of a zeroed struct tm, returned by ASN1_TIME_to_int64_t on parse errors. */
  static final long ZERO_TM = -2209161600L;

  // ---------------------------------------------------------------------------------------------
  // Result model (authenticode.h)

  static final class Countersignature {
    int verifyFlags;
    long signTime;
    String digestAlg;
    byte[] digest;
    List<Cert> chain;
    List<Cert> certs;
  }

  static final class Signer {
    byte[] digest;
    String digestAlg;
    String programName;
    List<Cert> chain;
  }

  static final class Signature {
    int verifyFlags;
    long version;
    String digestAlg;
    byte[] digest;
    byte[] fileDigest;
    Signer signer;
    List<Cert> certs;
    List<Countersignature> countersigs;
  }

  // ---------------------------------------------------------------------------------------------
  // PKCS#7 / CMS structures

  static final class Attribute {
    final Asn1 element;
    final String oid;
    final List<Asn1> values;

    Attribute(Asn1 element, String oid, List<Asn1> values) {
      this.element = element;
      this.oid = oid;
      this.values = values;
    }
  }

  static final class SignerInfo {
    Cert.Name issuer;
    BigInteger serial;
    byte[] subjectKeyId;
    String digestAlgOid;
    List<Attribute> authAttrs;
    byte[] encDigest;
    List<Attribute> unauthAttrs;
  }

  static final class SignedData {
    Asn1 version;
    List<String> mdAlgs = new ArrayList<>();
    String contentType;
    /** The inner content ([0] EXPLICIT value), or null when detached. */
    Asn1 content;
    List<Cert> certs;
    List<SignerInfo> signerInfos = new ArrayList<>();
  }

  static final class ContentInfo {
    String type;
    SignedData signed;
  }

  private static String algorithm(Asn1 alg) throws Asn1Exception {
    alg.expectSequence();
    if (alg.size() < 1 || alg.size() > 2) {
      throw new Asn1Exception("bad algorithm identifier");
    }
    return alg.get(0).oid();
  }

  private static List<Attribute> attributes(Asn1 set) throws Asn1Exception {
    List<Attribute> list = new ArrayList<>();
    for (Asn1 a : set.children()) {
      a.expectSequence();
      if (a.size() != 2) {
        throw new Asn1Exception("bad attribute");
      }
      String oid = a.get(0).oid();
      a.get(1).expectSet();
      list.add(new Attribute(a, oid, a.get(1).children()));
    }
    return list;
  }

  /** d2i_PKCS7_SIGNER_INFO (cms = false) or CMS SignerInfo (cms = true). */
  static SignerInfo parseSignerInfo(Asn1 s, boolean cms) throws Asn1Exception {
    s.expectSequence();
    List<Asn1> c = s.children();
    int i = 0;
    if (c.size() < 5) {
      throw new Asn1Exception("bad signer info");
    }
    SignerInfo si = new SignerInfo();
    c.get(i++).integer();
    Asn1 sid = c.get(i++);
    if (sid.isUniversal(Asn1.SEQUENCE)) {
      sid.expectSequence();
      if (sid.size() != 2) {
        throw new Asn1Exception("bad issuer and serial");
      }
      si.issuer = Cert.Name.parse(sid.get(0));
      si.serial = sid.get(1).integer();
    } else if (cms && sid.isContext(0) && !sid.constructed) {
      si.subjectKeyId = sid.contents();
    } else {
      throw new Asn1Exception("bad signer identifier");
    }
    si.digestAlgOid = algorithm(c.get(i++));
    if (i < c.size() && c.get(i).isContext(0)) {
      if (!c.get(i).constructed) {
        throw new Asn1Exception("bad attributes");
      }
      si.authAttrs = attributes(c.get(i++));
    }
    if (i + 2 > c.size()) {
      throw new Asn1Exception("bad signer info");
    }
    algorithm(c.get(i++));
    Asn1 enc = c.get(i++);
    enc.expectUniversal(Asn1.OCTET_STRING);
    si.encDigest = enc.contents();
    if (i < c.size() && c.get(i).isContext(1)) {
      if (!c.get(i).constructed) {
        throw new Asn1Exception("bad attributes");
      }
      si.unauthAttrs = attributes(c.get(i++));
    }
    if (i != c.size()) {
      throw new Asn1Exception("trailing signer info fields");
    }
    return si;
  }

  /** d2i_PKCS7 (cms = false) or d2i_CMS_ContentInfo (cms = true). */
  static ContentInfo parseContentInfo(Asn1 e, boolean cms) throws Asn1Exception {
    e.expectSequence();
    if (e.size() < 1 || e.size() > 2) {
      throw new Asn1Exception("bad content info");
    }
    ContentInfo ci = new ContentInfo();
    ci.type = e.get(0).oid();
    Asn1 content = null;
    if (e.size() == 2) {
      Asn1 x = e.get(1);
      if (!x.isContext(0) || !x.constructed || x.size() != 1) {
        throw new Asn1Exception("bad content");
      }
      content = x.get(0);
    }
    if (ci.type.equals(Oids.SIGNED_DATA)) {
      if (content == null) {
        if (cms) {
          throw new Asn1Exception("missing signed data");
        }
        return ci;
      }
      ci.signed = parseSignedData(content, cms);
    } else if (ci.type.equals(Oids.PKCS7_DATA) && content != null) {
      content.expectUniversal(Asn1.OCTET_STRING);
    }
    return ci;
  }

  static SignedData parseSignedData(Asn1 s, boolean cms) throws Asn1Exception {
    s.expectSequence();
    List<Asn1> c = s.children();
    if (c.size() < 4) {
      throw new Asn1Exception("bad signed data");
    }
    SignedData sd = new SignedData();
    int i = 0;
    sd.version = c.get(i++);
    sd.version.integer();
    Asn1 algs = c.get(i++);
    algs.expectSet();
    for (Asn1 a : algs.children()) {
      sd.mdAlgs.add(algorithm(a));
    }
    Asn1 inner = c.get(i++);
    if (cms) {
      inner.expectSequence();
      if (inner.size() < 1 || inner.size() > 2) {
        throw new Asn1Exception("bad encapsulated content");
      }
      sd.contentType = inner.get(0).oid();
      if (inner.size() == 2) {
        Asn1 x = inner.get(1);
        if (!x.isContext(0) || !x.constructed || x.size() != 1) {
          throw new Asn1Exception("bad encapsulated content");
        }
        x.get(0).expectUniversal(Asn1.OCTET_STRING);
        sd.content = x.get(0);
      }
    } else {
      // The inner content is itself a PKCS7 structure.
      parseContentInfo(inner, false);
      sd.contentType = inner.get(0).oid();
      if (inner.size() == 2) {
        sd.content = inner.get(1).get(0);
      }
    }
    if (i < c.size() && c.get(i).isContext(0)) {
      Asn1 certs = c.get(i++);
      if (!certs.constructed) {
        throw new Asn1Exception("bad certificates");
      }
      sd.certs = new ArrayList<>();
      for (Asn1 cert : certs.children()) {
        if (cert.isUniversal(Asn1.SEQUENCE)) {
          sd.certs.add(Cert.parse(cert));
        } else if (!cms || cert.tagClass != Asn1.CONTEXT) {
          throw new Asn1Exception("bad certificate choice");
        }
      }
    }
    if (i < c.size() && c.get(i).isContext(1)) {
      i++;
    }
    if (i != c.size() - 1) {
      throw new Asn1Exception("bad signed data");
    }
    Asn1 sis = c.get(i);
    sis.expectSet();
    for (Asn1 si : sis.children()) {
      sd.signerInfos.add(parseSignerInfo(si, cms));
    }
    return sd;
  }

  /** get_attribute(): first value of the first attribute with the given type, or null. */
  private static Asn1 attributeValue(List<Attribute> attrs, String oid) {
    if (attrs == null) {
      return null;
    }
    for (Attribute a : attrs) {
      if (a.oid.equals(oid)) {
        return a.values.isEmpty() ? null : a.values.get(0);
      }
    }
    return null;
  }

  private static Attribute attribute(List<Attribute> attrs, String oid) {
    if (attrs == null) {
      return null;
    }
    for (Attribute a : attrs) {
      if (a.oid.equals(oid)) {
        return a;
      }
    }
    return null;
  }

  // ---------------------------------------------------------------------------------------------
  // Time

  /** ASN1_TIME_to_int64_t: OpenSSL's ossl_asn1_time_to_tm followed by timegm. */
  static long asn1TimeToEpoch(Asn1 t) {
    if (t == null) {
      return ZERO_TM;
    }
    boolean utc;
    if (t.isUniversal(Asn1.UTC_TIME)) {
      utc = true;
    } else if (t.isUniversal(Asn1.GENERALIZED_TIME)) {
      utc = false;
    } else {
      return ZERO_TM;
    }
    Long r = parseTime(t.contents(), utc);
    return r == null ? ZERO_TM : r;
  }

  private static final int[] TMIN = {0, 0, 1, 1, 0, 0, 0, 0, 0};
  private static final int[] TMAX = {99, 99, 12, 31, 23, 59, 59, 12, 59};
  private static final int[] MDAYS = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

  private static boolean leap(int year) {
    return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
  }

  private static Long parseTime(byte[] a, boolean utc) {
    int end = utc ? 6 : 7;
    int btz = utc ? 5 : 6;
    int minL = utc ? 11 : 13;
    int l = a.length;
    int o = 0;
    int year = 0;
    int mon = 0;
    int mday = 0;
    int hour = 0;
    int min = 0;
    int sec = 0;
    if (l < minL) {
      return null;
    }
    for (int i = 0; i < end; i++) {
      if (i == btz && (a[o] == 'Z' || a[o] == '+' || a[o] == '-')) {
        break;
      }
      if (!digit(a[o])) {
        return null;
      }
      int n = a[o] - '0';
      if (++o == l) {
        return null;
      }
      if (!digit(a[o])) {
        return null;
      }
      n = n * 10 + a[o] - '0';
      if (++o == l) {
        return null;
      }
      int i2 = utc ? i + 1 : i;
      if (n < TMIN[i2] || n > TMAX[i2]) {
        return null;
      }
      switch (i2) {
        case 0:
          year = n * 100;
          break;
        case 1:
          if (utc) {
            year = n < 50 ? 2000 + n : 1900 + n;
          } else {
            year += n;
          }
          break;
        case 2:
          mon = n - 1;
          break;
        case 3:
          int md = mon == 1 ? MDAYS[1] + (leap(year) ? 1 : 0) : MDAYS[mon];
          if (n > md) {
            return null;
          }
          mday = n;
          break;
        case 4:
          hour = n;
          break;
        case 5:
          min = n;
          break;
        default:
          sec = n;
          break;
      }
    }
    if (!utc && a[o] == '.') {
      if (++o == l) {
        return null;
      }
      int s = o;
      while (o < l && digit(a[o])) {
        o++;
      }
      if (s == o || o == l) {
        return null;
      }
    }
    long offset = 0;
    if (a[o] == 'Z') {
      o++;
    } else if (a[o] == '+' || a[o] == '-') {
      int offsign = a[o] == '-' ? 1 : -1;
      o++;
      if (o + 4 != l) {
        return null;
      }
      for (int i = end; i < end + 2; i++) {
        if (!digit(a[o])) {
          return null;
        }
        int n = a[o] - '0';
        o++;
        if (!digit(a[o])) {
          return null;
        }
        n = n * 10 + a[o] - '0';
        int i2 = utc ? i + 1 : i;
        if (n < TMIN[i2] || n > TMAX[i2]) {
          return null;
        }
        offset += i == end ? n * 3600L : n * 60L;
        o++;
      }
      offset *= offsign;
    } else {
      return null;
    }
    if (o != l) {
      return null;
    }
    long days = daysFromCivil(year, mon + 1, mday);
    return days * 86400 + hour * 3600L + min * 60L + sec + offset;
  }

  private static boolean digit(byte b) {
    return b >= '0' && b <= '9';
  }

  private static long daysFromCivil(long y, int m, int d) {
    y -= m <= 2 ? 1 : 0;
    long era = (y >= 0 ? y : y - 399) / 400;
    long yoe = y - era * 400;
    long doy = (153L * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
  }

  // ---------------------------------------------------------------------------------------------
  // Certificates and chains

  /** X509_find_by_issuer_and_serial. */
  private static Cert findByIssuerAndSerial(List<Cert> certs, Cert.Name issuer, BigInteger serial) {
    if (certs == null) {
      return null;
    }
    for (Cert c : certs) {
      if (c.serial.equals(serial) && c.issuer.sameAs(issuer)) {
        return c;
      }
    }
    return null;
  }

  /** PKCS7_get0_signers(p7, certs, 0): null if any signer certificate is missing. */
  private static List<Cert> pkcs7Signers(SignedData sd) {
    if (sd.signerInfos.isEmpty()) {
      return null;
    }
    List<Cert> signers = new ArrayList<>();
    for (SignerInfo si : sd.signerInfos) {
      Cert signer = si.issuer == null ? null : findByIssuerAndSerial(sd.certs, si.issuer, si.serial);
      if (signer == null) {
        return null;
      }
      signers.add(signer);
    }
    return signers;
  }

  /** The emulation of get_signers for CMS countersignatures. */
  private static List<Cert> cmsSigners(SignedData sd) {
    List<Cert> result = new ArrayList<>();
    for (SignerInfo si : sd.signerInfos) {
      if (sd.certs == null) {
        continue;
      }
      for (Cert c : sd.certs) {
        boolean match;
        if (si.issuer != null) {
          match = c.issuer.sameAs(si.issuer) && c.serial.equals(si.serial);
        } else {
          match = c.skid != null && Arrays.equals(c.skid, si.subjectKeyId);
        }
        if (match) {
          result.add(c);
        }
      }
    }
    return result;
  }

  /** ossl_x509_check_cert_time against the current time. */
  private static boolean currentlyValid(Cert c) {
    long now = System.currentTimeMillis() / 1000;
    long nb = c.notBeforeTime();
    long na = c.notAfterTime();
    if (nb == ZERO_TM || na == ZERO_TM) {
      return false;
    }
    return nb <= now && now <= na;
  }

  /** find_issuer() from OpenSSL 3 x509_vfy.c. */
  private static Cert findIssuer(List<Cert> untrusted, List<Cert> chain, Cert x) {
    Cert rv = null;
    for (Cert issuer : untrusted) {
      if (!Cert.likelyIssued(issuer, x)) {
        continue;
      }
      boolean inChain = false;
      for (Cert c : chain) {
        if (c.sameCert(issuer)) {
          inChain = true;
          break;
        }
      }
      if (inChain) {
        continue;
      }
      if (currentlyValid(issuer)) {
        return issuer;
      }
      if (rv == null || issuer.notAfterTime() > rv.notAfterTime()) {
        rv = issuer;
      }
    }
    return rv;
  }

  /**
   * parse_signer_chain: the chain OpenSSL's X509_verify_cert builds from the untrusted
   * certificates when no trust anchors are available.
   */
  static List<Cert> signerChain(Cert signCert, List<Cert> certs) {
    if (signCert == null || certs == null) {
      return null;
    }
    List<Cert> chain = new ArrayList<>();
    chain.add(signCert);
    boolean selfSigned = signCert.selfSigned();
    while (!selfSigned && chain.size() <= 100) {
      Cert issuer = findIssuer(certs, chain, chain.get(chain.size() - 1));
      if (issuer == null) {
        break;
      }
      chain.add(issuer);
      selfSigned = issuer.selfSigned();
    }
    return chain;
  }

  // ---------------------------------------------------------------------------------------------
  // Signature verification

  /** RSA_public_decrypt with PKCS#1 type 1 padding, or null on failure. */
  private static byte[] rsaRecover(AsymmetricKeyParameter key, byte[] sig) {
    if (!(key instanceof RSAKeyParameters)) {
      return null;
    }
    try {
      PKCS1Encoding eng = new PKCS1Encoding(new RSAEngine());
      eng.init(false, key);
      return eng.processBlock(sig, 0, sig.length);
    } catch (Exception e) {
      return null;
    }
  }

  private static byte[] digestInfo(Oids.Md md, byte[] digest) {
    byte[] oid = encodeOid(md.oid);
    byte[] alg = Cert.tlv(0x30, Cert.concat(oid, new byte[] {0x05, 0x00}));
    return Cert.tlv(0x30, Cert.concat(alg, Cert.tlv(0x04, digest)));
  }

  private static byte[] encodeOid(String oid) {
    String[] parts = oid.split("\\.");
    ByteArrayOutputStream o = new ByteArrayOutputStream();
    BigInteger first =
        new BigInteger(parts[0]).multiply(BigInteger.valueOf(40)).add(new BigInteger(parts[1]));
    writeBase128(o, first);
    for (int i = 2; i < parts.length; i++) {
      writeBase128(o, new BigInteger(parts[i]));
    }
    return Cert.tlv(0x06, o.toByteArray());
  }

  private static void writeBase128(ByteArrayOutputStream o, BigInteger v) {
    int bits = Math.max(v.bitLength(), 1);
    int groups = (bits + 6) / 7;
    for (int g = groups - 1; g >= 0; g--) {
      int b = v.shiftRight(g * 7).intValue() & 0x7F;
      o.write(g == 0 ? b : b | 0x80);
    }
  }

  /** Parses a DER ECDSA/DSA signature, rejecting non canonical encodings like OpenSSL. */
  private static BigInteger[] dsaSignature(byte[] sig) {
    try {
      Asn1 s = Asn1.parse(sig);
      s.expectSequence();
      if (s.end != sig.length || s.size() != 2) {
        return null;
      }
      BigInteger r = s.get(0).integer();
      BigInteger v = s.get(1).integer();
      byte[] der =
          Cert.tlv(
              0x30,
              Cert.concat(Cert.tlv(0x02, r.toByteArray()), Cert.tlv(0x02, v.toByteArray())));
      if (!Arrays.equals(der, sig)) {
        return null;
      }
      return new BigInteger[] {r, v};
    } catch (Asn1Exception e) {
      return null;
    }
  }

  /** EVP_VerifyFinal with the given digest algorithm. */
  static boolean verifySignature(Oids.Md md, byte[] digest, byte[] sig, Cert signer) {
    AsymmetricKeyParameter key = signer.publicKey();
    if (key == null) {
      return false;
    }
    try {
      if (key instanceof RSAKeyParameters) {
        int k = (((RSAKeyParameters) key).getModulus().bitLength() + 7) / 8;
        if (sig.length != k) {
          return false;
        }
        byte[] dec = rsaRecover(key, sig);
        return dec != null && Arrays.equals(dec, digestInfo(md, digest));
      }
      if (key instanceof ECPublicKeyParameters) {
        BigInteger[] rs = dsaSignature(sig);
        if (rs == null) {
          return false;
        }
        ECDSASigner s = new ECDSASigner();
        s.init(false, key);
        return s.verifySignature(digest, rs[0], rs[1]);
      }
      if (key instanceof DSAPublicKeyParameters) {
        BigInteger[] rs = dsaSignature(sig);
        if (rs == null) {
          return false;
        }
        DSASigner s = new DSASigner();
        s.init(false, key);
        return s.verifySignature(digest, rs[0], rs[1]);
      }
    } catch (RuntimeException e) {
      return false;
    }
    return false;
  }

  /** The encoding of signed attributes used for signatures (PKCS7_ATTR_VERIFY). */
  private static byte[] encodeAttributes(List<Attribute> attrs) {
    ByteArrayOutputStream content = new ByteArrayOutputStream();
    for (Attribute a : attrs) {
      List<byte[]> values = new ArrayList<>();
      for (Asn1 v : a.values) {
        if (v.constructed && v.tagClass == Asn1.UNIVERSAL && v.tag != Asn1.SEQUENCE
            && v.tag != Asn1.SET) {
          values.add(Cert.tlv(v.tag, v.contents()));
        } else {
          values.add(v.encoded());
        }
      }
      values.sort(Cert::derCompare);
      ByteArrayOutputStream set = new ByteArrayOutputStream();
      for (byte[] v : values) {
        set.write(v, 0, v.length);
      }
      byte[] oid = a.element.get(0).encoded();
      byte[] e = Cert.tlv(0x30, Cert.concat(oid, Cert.tlv(0x31, set.toByteArray())));
      content.write(e, 0, e.length);
    }
    return Cert.tlv(0x31, content.toByteArray());
  }

  /**
   * The digest BIO selected for a signer: PKCS7_dataInit creates one per digestAlgorithms
   * entry (failing for unknown algorithms) and the first whose type or pkey type matches the
   * signer's digest algorithm is used.
   */
  private static Oids.Md selectMd(SignedData sd, String signerDigestOid) {
    List<Oids.Md> mds = new ArrayList<>();
    for (String alg : sd.mdAlgs) {
      Oids.Md md = Oids.md(alg);
      if (md == null) {
        return null;
      }
      mds.add(md);
    }
    for (Oids.Md md : mds) {
      if (md.oid.equals(signerDigestOid) || signerDigestOid.equals(md.pkeyOid)) {
        return md;
      }
    }
    return null;
  }

  /** PKCS7_signatureVerify over content already read through the digest BIOs. */
  private static boolean pkcs7SignatureVerify(
      SignedData sd, SignerInfo si, Cert signer, byte[] content) {
    Oids.Md md = selectMd(sd, si.digestAlgOid);
    if (md == null || content == null) {
      return false;
    }
    byte[] digest = md.digest(content);
    if (si.authAttrs != null && !si.authAttrs.isEmpty()) {
      Asn1 v = attributeValue(si.authAttrs, Oids.MESSAGE_DIGEST);
      byte[] messageDigest = v == null ? null : v.anyValue();
      if (messageDigest == null || !Arrays.equals(messageDigest, digest)) {
        return false;
      }
      digest = md.digest(encodeAttributes(si.authAttrs));
    }
    return verifySignature(md, digest, si.encDigest, signer);
  }

  /** authenticode_verify(). */
  private static boolean authenticodeVerify(SignedData sd, SignerInfo si, Cert signCert) {
    if (sd.content == null) {
      return false;
    }
    byte[] contentData = sd.content.anyValue();
    if (contentData == null) {
      return false;
    }
    BigInteger version;
    try {
      version = sd.version.integer();
    } catch (Asn1Exception e) {
      version = BigInteger.ZERO;
    }
    if (version.equals(BigInteger.ONE)) {
      contentData = skipHeader(contentData);
    }
    return pkcs7SignatureVerify(sd, si, signCert, contentData);
  }

  /** ASN1_get_object: returns the content following the identifier and length octets. */
  private static byte[] skipHeader(byte[] d) {
    int p = 0;
    if (d.length == 0) {
      return d;
    }
    int id = d[p++] & 0xFF;
    if ((id & 0x1F) == 0x1F) {
      while (p < d.length && (d[p] & 0x80) != 0) {
        p++;
      }
      p++;
    }
    if (p >= d.length) {
      return new byte[0];
    }
    int l = d[p++] & 0xFF;
    long len;
    if (l == 0x80) {
      len = 0;
    } else if ((l & 0x80) != 0) {
      int n = l & 0x7F;
      len = 0;
      for (int i = 0; i < n && p < d.length; i++) {
        len = (len << 8) | (d[p++] & 0xFF);
      }
    } else {
      len = l;
    }
    long avail = d.length - p;
    int n = (int) Math.max(0, Math.min(len, avail));
    return Arrays.copyOfRange(d, p, p + n);
  }

  // ---------------------------------------------------------------------------------------------
  // Countersignatures

  /** pkcs9_countersig_new(). */
  static Countersignature pkcs9Countersig(byte[] data, List<Cert> certs, byte[] encDigest) {
    Countersignature result = new Countersignature();
    SignerInfo si;
    try {
      Asn1 e = Asn1.parse(data, 0, data.length);
      si = parseSignerInfo(e, false);
    } catch (Asn1Exception e) {
      result.verifyFlags = CS_VFY_CANT_PARSE;
      return result;
    }
    result.digestAlg = Oids.longName(si.digestAlgOid);
    Asn1 signTime = attributeValue(si.authAttrs, Oids.SIGNING_TIME);
    if (signTime == null || signTime.anyValue() == null) {
      result.verifyFlags = CS_VFY_TIME_MISSING;
      return result;
    }
    result.signTime = asn1TimeToEpoch(signTime);
    Cert signCert = findByIssuerAndSerial(certs, si.issuer, si.serial);
    if (signCert == null) {
      result.verifyFlags = CS_VFY_NO_SIGNER_CERT;
      return result;
    }
    result.chain = signerChain(signCert, certs);
    Asn1 md = attributeValue(si.authAttrs, Oids.MESSAGE_DIGEST);
    byte[] digestData = md == null ? null : md.anyValue();
    if (digestData == null || digestData.length == 0) {
      result.verifyFlags = CS_VFY_DIGEST_MISSING;
      return result;
    }
    Oids.Md alg = Oids.md(si.digestAlgOid);
    if (alg == null) {
      result.verifyFlags = CS_VFY_UNKNOWN_ALGORITHM;
      return result;
    }
    result.digest = digestData;
    byte[] calc = alg.digest(encodeAttributes(si.authAttrs));
    byte[] dec = rsaRecover(signCert.publicKey(), si.encDigest);
    if (dec == null) {
      result.verifyFlags = CS_VFY_CANT_DECRYPT_DIGEST;
      return result;
    }
    boolean valid;
    if (alg.size == dec.length) {
      valid = Arrays.equals(calc, dec);
    } else {
      byte[] d = digestInfoDigest(dec);
      valid = d != null && Arrays.equals(d, calc);
    }
    if (!valid) {
      result.verifyFlags = CS_VFY_INVALID;
      return result;
    }
    calc = alg.digest(encDigest);
    if (digestData.length != alg.size || !Arrays.equals(calc, digestData)) {
      result.verifyFlags = CS_VFY_DOESNT_MATCH_SIGNATURE;
    }
    return result;
  }

  /** d2i_DigestInfo, returning the digest. */
  private static byte[] digestInfoDigest(byte[] data) {
    try {
      Asn1 di = Asn1.parse(data, 0, data.length);
      di.expectSequence();
      if (di.size() != 2) {
        return null;
      }
      algorithm(di.get(0));
      di.get(1).expectUniversal(Asn1.OCTET_STRING);
      return di.get(1).contents();
    } catch (Asn1Exception e) {
      return null;
    }
  }

  /** The TSTInfo fields used by the parser. */
  static final class TstInfo {
    long version;
    String imprintAlgOid;
    byte[] imprint;
    Asn1 genTime;
  }

  static TstInfo parseTstInfo(byte[] der) {
    try {
      Asn1 t = Asn1.parse(der, 0, der.length);
      t.expectSequence();
      List<Asn1> c = t.children();
      if (c.size() < 5) {
        return null;
      }
      TstInfo r = new TstInfo();
      BigInteger v = c.get(0).integer();
      r.version = v.bitLength() < 64 ? v.longValue() : -1;
      c.get(1).oid();
      Asn1 imprint = c.get(2);
      imprint.expectSequence();
      if (imprint.size() != 2) {
        return null;
      }
      r.imprintAlgOid = algorithm(imprint.get(0));
      imprint.get(1).expectUniversal(Asn1.OCTET_STRING);
      r.imprint = imprint.get(1).contents();
      c.get(3).integer();
      c.get(4).expectUniversal(Asn1.GENERALIZED_TIME);
      r.genTime = c.get(4);
      int i = 5;
      if (i < c.size() && c.get(i).isUniversal(Asn1.SEQUENCE)) {
        i++;
      }
      if (i < c.size() && c.get(i).isUniversal(Asn1.BOOLEAN)) {
        i++;
      }
      if (i < c.size() && c.get(i).isUniversal(Asn1.INTEGER)) {
        c.get(i).integer();
        i++;
      }
      if (i < c.size() && c.get(i).isContext(0)) {
        i++;
      }
      if (i < c.size() && c.get(i).isContext(1)) {
        i++;
      }
      return i == c.size() ? r : null;
    } catch (Asn1Exception e) {
      return null;
    }
  }

  /** ms_countersig_new(). */
  static Countersignature msCountersig(byte[] data, byte[] encDigest) {
    Countersignature result = new Countersignature();
    SignedData sd = null;
    boolean cms = false;
    Asn1 e;
    try {
      e = Asn1.parse(data, 0, data.length);
    } catch (Asn1Exception ex) {
      e = null;
    }
    if (e != null) {
      boolean pkcs7Parsed = false;
      try {
        ContentInfo ci = parseContentInfo(e, false);
        pkcs7Parsed = true;
        sd = ci.signed;
      } catch (Asn1Exception ex) {
        // Fall back to CMS below.
      }
      if (!pkcs7Parsed) {
        try {
          ContentInfo ci = parseContentInfo(e, true);
          sd = ci.signed;
          cms = true;
        } catch (Asn1Exception ex) {
          sd = null;
        }
      }
    }
    if (sd == null) {
      result.verifyFlags = CS_VFY_CANT_PARSE;
      return result;
    }
    // get_ts_tst_info
    TstInfo ts = null;
    if (Oids.TST_INFO.equals(sd.contentType) && sd.content != null
        && sd.content.isUniversal(Asn1.OCTET_STRING)) {
      ts = parseTstInfo(sd.content.contents());
    }
    if (ts == null) {
      result.verifyFlags = CS_VFY_CANT_PARSE;
      return result;
    }
    result.signTime = asn1TimeToEpoch(ts.genTime);
    List<Cert> sigs = cms ? cmsSigners(sd) : pkcs7Signers(sd);
    Cert signCert = sigs == null || sigs.isEmpty() ? null : sigs.get(0);
    if (signCert == null) {
      result.verifyFlags = CS_VFY_NO_SIGNER_CERT;
      return result;
    }
    if (sd.certs == null) {
      result.verifyFlags = VFY_INTERNAL_ERROR;
      return result;
    }
    result.certs = new ArrayList<>(sd.certs);
    result.chain = signerChain(signCert, sd.certs);
    result.digestAlg = Oids.longName(ts.imprintAlgOid);
    byte[] digest = ts.imprint;
    result.digest = digest.length == 0 ? null : digest;
    if (digest.length == 0) {
      result.verifyFlags = CS_VFY_DIGEST_MISSING;
      return result;
    }
    Oids.Md md = Oids.md(ts.imprintAlgOid);
    if (md == null) {
      result.verifyFlags = CS_VFY_UNKNOWN_ALGORITHM;
      return result;
    }
    byte[] calc = md.digest(encDigest);
    if (digest.length != md.size || !Arrays.equals(calc, digest)) {
      result.verifyFlags = CS_VFY_DOESNT_MATCH_SIGNATURE;
      return result;
    }
    // verify_digest: TS_RESP_verify_token with TS_VFY_VERSION | TS_VFY_IMPRINT.
    if (ts.version != 1) {
      result.verifyFlags = CS_VFY_INVALID;
      return result;
    }
    boolean valid;
    if (sd.signerInfos.isEmpty()) {
      valid = false;
    } else if (!cms) {
      valid = pkcs7SignatureVerify(sd, sd.signerInfos.get(0), signCert, sd.content.contents());
    } else {
      valid = cmsVerifyContent(sd, sd.signerInfos.get(0), sd.content.contents());
    }
    if (!valid) {
      result.verifyFlags = CS_VFY_INVALID;
    }
    return result;
  }

  /** CMS_SignerInfo_verify_content() without a signer public key. */
  private static boolean cmsVerifyContent(SignedData sd, SignerInfo si, byte[] content) {
    Oids.Md md = selectMd(sd, si.digestAlgOid);
    if (md == null || si.authAttrs == null) {
      return false;
    }
    Attribute a = attribute(si.authAttrs, Oids.MESSAGE_DIGEST);
    if (a == null || a.values.size() != 1 || !a.values.get(0).isUniversal(Asn1.OCTET_STRING)) {
      return false;
    }
    int count = 0;
    for (Attribute x : si.authAttrs) {
      if (x.oid.equals(Oids.MESSAGE_DIGEST)) {
        count++;
      }
    }
    if (count != 1) {
      return false;
    }
    return Arrays.equals(md.digest(content), a.values.get(0).contents());
  }

  // ---------------------------------------------------------------------------------------------
  // Authenticode

  /** parse_program_name(). */
  private static String programName(Asn1 spcAttr) {
    byte[] spcData = spcAttr.anyValue();
    if (spcData == null) {
      return null;
    }
    try {
      Asn1 info = Asn1.parse(spcData, 0, spcData.length);
      info.expectSequence();
      Asn1 program = null;
      int i = 0;
      List<Asn1> c = info.children();
      if (i < c.size() && c.get(i).isContext(0)) {
        program = c.get(i++);
      }
      if (i < c.size() && c.get(i).isContext(1)) {
        i++;
      }
      if (i != c.size()) {
        return null;
      }
      if (program == null) {
        return null;
      }
      if (!program.constructed || program.size() != 1) {
        return null;
      }
      Asn1 s = program.get(0);
      String name;
      byte[] raw = s.contents();
      if (s.isContext(0)) {
        if (raw.length % 2 != 0) {
          return null;
        }
        StringBuilder sb = new StringBuilder();
        for (int k = 0; k < raw.length; k += 2) {
          char ch = (char) (((raw[k] & 0xFF) << 8) | (raw[k + 1] & 0xFF));
          if (Character.isSurrogate(ch)) {
            return null;
          }
          sb.append(ch);
        }
        name = sb.toString();
      } else if (s.isContext(1)) {
        name = new String(raw, StandardCharsets.ISO_8859_1);
      } else {
        return null;
      }
      byte[] utf8 = name.getBytes(StandardCharsets.UTF_8);
      if (utf8.length >= spcData.length) {
        return null;
      }
      return new String(CStrings.cstr(utf8), StandardCharsets.ISO_8859_1);
    } catch (Asn1Exception e) {
      return null;
    }
  }

  /** authenticode_new(). */
  static List<Signature> authenticodeNew(byte[] data) {
    if (data == null || data.length == 0) {
      return null;
    }
    List<Signature> result = new ArrayList<>();
    Signature auth = new Signature();
    result.add(auth);
    ContentInfo p7;
    try {
      p7 = parseContentInfo(Asn1.parse(data, 0, data.length), false);
    } catch (Asn1Exception e) {
      auth.verifyFlags = VFY_CANT_PARSE;
      return result;
    }
    if (!Oids.SIGNED_DATA.equals(p7.type) || p7.signed == null) {
      auth.verifyFlags = VFY_WRONG_PKCS7_TYPE;
      return result;
    }
    SignedData sd = p7.signed;
    try {
      BigInteger v = sd.version.integer();
      if (v.signum() >= 0 && v.bitLength() <= 64) {
        auth.version = v.longValue();
      }
    } catch (Asn1Exception e) {
      // Unreachable, the version was validated while parsing.
    }
    if (sd.certs == null) {
      auth.verifyFlags = VFY_INTERNAL_ERROR;
      return result;
    }
    auth.certs = new ArrayList<>(sd.certs);

    // get_content(): SpcIndirectDataContent
    byte[] contentValue =
        Oids.SPC_INDIRECT_DATA.equals(sd.contentType) && sd.content != null
            ? sd.content.anyValue()
            : null;
    String digestOid;
    byte[] digest;
    try {
      if (contentValue == null) {
        throw new Asn1Exception("no content");
      }
      Asn1 idc = Asn1.parse(contentValue, 0, contentValue.length);
      idc.expectSequence();
      if (idc.size() != 2) {
        throw new Asn1Exception("bad SpcIndirectDataContent");
      }
      Asn1 typeAndValue = idc.get(0);
      typeAndValue.expectSequence();
      if (typeAndValue.size() < 1 || typeAndValue.size() > 2) {
        throw new Asn1Exception("bad SpcAttributeTypeAndOptionalValue");
      }
      typeAndValue.get(0).oid();
      Asn1 di = idc.get(1);
      di.expectSequence();
      if (di.size() != 2) {
        throw new Asn1Exception("bad DigestInfo");
      }
      digestOid = algorithm(di.get(0));
      di.get(1).expectUniversal(Asn1.OCTET_STRING);
      digest = di.get(1).contents();
    } catch (Asn1Exception e) {
      auth.verifyFlags = VFY_BAD_CONTENT;
      return result;
    }
    auth.digestAlg = Oids.longName(digestOid);
    auth.digest = digest.length == 0 ? null : digest;

    Signer signer = new Signer();
    auth.signer = signer;
    if (sd.signerInfos.isEmpty()) {
      auth.verifyFlags = VFY_NO_SIGNER_INFO;
      return result;
    }
    SignerInfo si = sd.signerInfos.get(0);
    auth.countersigs = new ArrayList<>();

    parseNested(si, result);
    parsePkcs9Countersigs(sd, si, auth);
    parseMsCountersigs(si, auth);

    List<Cert> signers = pkcs7Signers(sd);
    Cert signCert = signers == null || signers.isEmpty() ? null : signers.get(0);
    if (signCert == null) {
      auth.verifyFlags = VFY_NO_SIGNER_CERT;
      return result;
    }
    signer.chain = signerChain(signCert, sd.certs);

    Asn1 messageDigest = attributeValue(si.authAttrs, Oids.MESSAGE_DIGEST);
    byte[] md = messageDigest == null ? null : messageDigest.anyValue();
    if (md == null) {
      auth.verifyFlags = VFY_DIGEST_MISSING;
      return result;
    }
    signer.digestAlg = Oids.longName(si.digestAlgOid);
    signer.digest = md.length == 0 ? null : md;
    Asn1 spcInfo = attributeValue(si.authAttrs, Oids.SPC_SP_OPUS_INFO);
    if (spcInfo != null) {
      signer.programName = programName(spcInfo);
    }
    if (!authenticodeVerify(sd, si, signCert)) {
      auth.verifyFlags = VFY_INVALID;
    }
    return result;
  }

  private static List<Asn1> limitedValues(List<Attribute> attrs, String oid) {
    Attribute a = attribute(attrs, oid);
    if (a == null) {
      return new ArrayList<>();
    }
    return a.values.subList(0, Math.min(a.values.size(), MAX_NESTED_COUNT));
  }

  private static void parseNested(SignerInfo si, List<Signature> result) {
    for (Asn1 nested : limitedValues(si.unauthAttrs, Oids.SPC_NESTED_SIGNATURE)) {
      byte[] data = nested.anyValue();
      if (data == null) {
        break;
      }
      List<Signature> auth = authenticodeNew(data);
      if (auth != null) {
        result.addAll(auth);
      }
    }
  }

  private static void parsePkcs9Countersigs(SignedData sd, SignerInfo si, Signature auth) {
    for (Asn1 nested : limitedValues(si.unauthAttrs, Oids.COUNTERSIGNATURE)) {
      byte[] data = nested.anyValue();
      if (data == null) {
        break;
      }
      auth.countersigs.add(pkcs9Countersig(data, sd.certs, si.encDigest));
    }
  }

  private static void parseMsCountersigs(SignerInfo si, Signature auth) {
    for (Asn1 nested : limitedValues(si.unauthAttrs, Oids.SPC_MS_COUNTERSIGNATURE)) {
      byte[] data = nested.anyValue();
      if (data == null) {
        break;
      }
      Countersignature csig = msCountersig(data, si.encDigest);
      auth.countersigs.add(csig);
      if (csig.certs != null) {
        auth.certs.addAll(csig.certs);
      }
    }
  }

  /** authenticode_digest(): the PE file digest, or null if the file is too short. */
  static byte[] fileDigest(
      Oids.Md md, ByteBuffer data, long peHdrOffset, boolean is64, long certTableAddr) {
    final int bufferSize = 0xFFFF;
    byte[] buffer = new byte[bufferSize];
    long[] pos = {0};
    Digest d = md.newDigest();
    java.util.function.IntUnaryOperator read =
        n -> {
          long r = Math.min(n, certTableAddr - pos[0]);
          if (r <= 0) {
            return 0;
          }
          for (int i = 0; i < r; i++) {
            buffer[i] = data.get((int) (pos[0] + i));
          }
          pos[0] += r;
          return (int) r;
        };
    long checksumOffset = (peHdrOffset + 0x58) & 0xffffffffL;
    long fpos = 0;
    while (fpos < checksumOffset) {
      int len = (int) Math.min(checksumOffset - fpos, bufferSize);
      int rlen = read.applyAsInt(len);
      if (rlen <= 0) {
        return null;
      }
      d.update(buffer, 0, rlen);
      fpos = (fpos + rlen) & 0xffffffffL;
    }
    if (read.applyAsInt(4) <= 0) {
      return null;
    }
    int certTableOffset = 0x3c + (is64 ? 16 : 0);
    if (read.applyAsInt(certTableOffset) <= 0) {
      return null;
    }
    d.update(buffer, 0, certTableOffset);
    if (read.applyAsInt(8) <= 0) {
      return null;
    }
    fpos = (checksumOffset + 4 + certTableOffset + 8) & 0xffffffffL;
    while (fpos < certTableAddr) {
      int len = (int) Math.min(certTableAddr - fpos, bufferSize);
      int rlen = read.applyAsInt(len);
      if (rlen <= 0) {
        return null;
      }
      d.update(buffer, 0, rlen);
      fpos = (fpos + rlen) & 0xffffffffL;
    }
    byte[] out = new byte[d.getDigestSize()];
    d.doFinal(out, 0);
    return out;
  }

  private static long u32(ByteBuffer b, long off) {
    int i = (int) off;
    return (b.get(i) & 0xFFL)
        | (b.get(i + 1) & 0xFFL) << 8
        | (b.get(i + 2) & 0xFFL) << 16
        | (b.get(i + 3) & 0xFFL) << 24;
  }

  /** parse_authenticode(). */
  static List<Signature> parseAuthenticode(ByteBuffer data, long peLen) {
    if (peLen < 0x40) {
      return null;
    }
    if (data.get(0) != 0x4d || data.get(1) != 0x5a) {
      return null;
    }
    long peOffset = u32(data, 0x3c);
    long magicAddr = (peOffset + 0x18) & 0xffffffffL;
    if (peLen < magicAddr + 2) {
      return null;
    }
    int magic = (data.get((int) magicAddr) & 0xFF) | (data.get((int) magicAddr + 1) & 0xFF) << 8;
    boolean is64 = magic == 0x20b;
    long certTableAddrPtr = (peOffset + (is64 ? 16 : 0) + 0x98) & 0xffffffffL;
    if (peLen < certTableAddrPtr + 8) {
      return null;
    }
    long certAddr = u32(data, certTableAddrPtr);
    long certLen = u32(data, certTableAddrPtr + 4);
    if (certLen < 8 || peLen < certAddr + 8) {
      return null;
    }
    long dwLength = u32(data, certAddr);
    if (peLen < certAddr + dwLength) {
      return null;
    }
    int len = (int) ((dwLength - 8) & 0xffffffffL);
    if (len <= 0) {
      return null;
    }
    byte[] blob = new byte[len];
    for (int i = 0; i < len; i++) {
      blob[i] = data.get((int) (certAddr + 8 + i));
    }
    List<Signature> sigs = authenticodeNew(blob);
    if (sigs == null) {
      return null;
    }
    for (Signature sig : sigs) {
      Oids.Md md = sig.digestAlg == null ? null : Oids.md(oidForLongName(sig));
      if (md == null || sig.digest == null) {
        if (sig.verifyFlags == VFY_VALID) {
          sig.verifyFlags = VFY_UNKNOWN_ALGORITHM;
        }
        continue;
      }
      byte[] fd = fileDigest(md, data, peOffset, is64, certAddr);
      if (fd == null) {
        if (sig.verifyFlags == VFY_VALID) {
          sig.verifyFlags = VFY_INTERNAL_ERROR;
        }
        break;
      }
      sig.fileDigest = fd;
      if (sig.digest.length != md.size || !Arrays.equals(fd, sig.digest)) {
        sig.verifyFlags = VFY_WRONG_FILE_DIGEST;
      }
    }
    return sigs;
  }

  /** The digest algorithm OID of a signature, kept to resolve EVP_get_digestbyname(ln). */
  private static String oidForLongName(Signature sig) {
    return LONG_NAME_TO_MD_OID.get(sig.digestAlg);
  }

  private static final java.util.Map<String, String> LONG_NAME_TO_MD_OID =
      new java.util.HashMap<>();

  static {
    String[] mdOids = {
      "1.2.840.113549.2.5", "1.3.14.3.2.26", "2.16.840.1.101.3.4.2.4", "2.16.840.1.101.3.4.2.1",
      "2.16.840.1.101.3.4.2.2", "2.16.840.1.101.3.4.2.3", "2.16.840.1.101.3.4.2.5",
      "2.16.840.1.101.3.4.2.6", "2.16.840.1.101.3.4.2.7", "2.16.840.1.101.3.4.2.8",
      "2.16.840.1.101.3.4.2.9", "2.16.840.1.101.3.4.2.10", "1.3.36.3.2.1", "1.2.156.10197.1.401"
    };
    for (String oid : mdOids) {
      Oids.Md md = Oids.md(oid);
      LONG_NAME_TO_MD_OID.put(Oids.longName(oid), oid);
      if (md.pkeyOid != null) {
        LONG_NAME_TO_MD_OID.put(Oids.longName(md.pkeyOid), md.pkeyOid);
      }
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Output to the module object (pe.c: _process_authenticode / pe_parse_certificates)

  private static void writeCertificate(YStructure o, Cert cert, String fmt, Object... args) {
    o.setString(HashModule.hex(cert.sha1()), fmt + ".thumbprint", args);
    o.setString(cert.issuer.oneline(), fmt + ".issuer", args);
    o.setString(cert.subject.oneline(), fmt + ".subject", args);
    o.setInteger(cert.version + 1, fmt + ".version", args);
    o.setString(Oids.longName(cert.sigAlgOid), fmt + ".algorithm", args);
    o.setString(Oids.oidText(cert.sigAlgOid), fmt + ".algorithm_oid", args);
    o.setString(cert.serialString(), fmt + ".serial", args);
    o.setInteger(cert.notBeforeTime(), fmt + ".not_before", args);
    o.setInteger(cert.notAfterTime(), fmt + ".not_after", args);
  }

  private static String hex(byte[] b) {
    return b == null ? null : HashModule.hex(b);
  }

  static int processAuthenticode(YStructure o, List<Signature> sigs) {
    int sigCount = 0;
    if (sigs == null || sigs.isEmpty()) {
      return 0;
    }
    boolean signatureValid = false;
    for (Signature auth : sigs) {
      int f = auth.verifyFlags;
      if (f == VFY_CANT_PARSE
          || f == VFY_WRONG_PKCS7_TYPE
          || f == VFY_NO_SIGNER_INFO
          || f == VFY_NO_SIGNER_CERT
          || f == VFY_INTERNAL_ERROR) {
        continue;
      }
      boolean verified = f == VFY_VALID;
      signatureValid |= verified;
      o.setInteger(verified ? 1 : 0, "signatures[%i].verified", sigCount);
      o.setString(auth.digestAlg, "signatures[%i].digest_alg", sigCount);
      if (auth.digest != null) {
        o.setString(hex(auth.digest), "signatures[%i].digest", sigCount);
      }
      if (auth.fileDigest != null) {
        o.setString(hex(auth.fileDigest), "signatures[%i].file_digest", sigCount);
      }
      o.setInteger(
          auth.certs != null ? auth.certs.size() : 0,
          "signatures[%i].number_of_certificates",
          sigCount);
      if (auth.certs != null) {
        for (int k = 0; k < auth.certs.size(); k++) {
          writeCertificate(o, auth.certs.get(k), "signatures[%i].certificates[%i]", sigCount, k);
        }
      }
      Signer signer = auth.signer;
      if (signer != null) {
        if (signer.chain != null && !signer.chain.isEmpty()) {
          writeCertificate(o, signer.chain.get(0), "signatures[%i]", sigCount);
        }
        o.setString(signer.programName, "signatures[%i].signer_info.program_name", sigCount);
        o.setString(signer.digestAlg, "signatures[%i].signer_info.digest_alg", sigCount);
        if (signer.digest != null) {
          o.setString(hex(signer.digest), "signatures[%i].signer_info.digest", sigCount);
        }
        o.setInteger(
            signer.chain != null ? signer.chain.size() : 0,
            "signatures[%i].signer_info.length_of_chain",
            sigCount);
        if (signer.chain != null) {
          for (int k = 0; k < signer.chain.size(); k++) {
            writeCertificate(
                o, signer.chain.get(k), "signatures[%i].signer_info.chain[%i]", sigCount, k);
          }
        }
      }
      o.setInteger(
          auth.countersigs != null ? auth.countersigs.size() : 0,
          "signatures[%i].number_of_countersignatures",
          sigCount);
      if (auth.countersigs != null) {
        for (int j = 0; j < auth.countersigs.size(); j++) {
          Countersignature c = auth.countersigs.get(j);
          String p = "signatures[%i].countersignatures[%i]";
          o.setInteger(c.verifyFlags == CS_VFY_VALID ? 1 : 0, p + ".verified", sigCount, j);
          o.setString(c.digestAlg, p + ".digest_alg", sigCount, j);
          o.setInteger(c.signTime, p + ".sign_time", sigCount, j);
          if (c.digest != null) {
            o.setString(hex(c.digest), p + ".digest", sigCount, j);
          }
          o.setInteger(c.chain != null ? c.chain.size() : 0, p + ".length_of_chain", sigCount, j);
          if (c.chain != null) {
            for (int k = 0; k < c.chain.size(); k++) {
              writeCertificate(o, c.chain.get(k), p + ".chain[%i]", sigCount, j, k);
            }
          }
        }
      }
      sigCount++;
    }
    o.setInteger(signatureValid ? 1 : 0, "is_signed");
    return sigCount;
  }

  /** pe_parse_certificates(). */
  static void parseCertificates(Pe pe) {
    YStructure o = pe.object;
    o.setInteger(0, "number_of_signatures");
    o.setInteger(0, "is_signed");
    long directory = pe.directoryEntry(PeModule.IMAGE_DIRECTORY_ENTRY_SECURITY);
    if (directory < 0) {
      return;
    }
    long va = pe.u32(directory);
    long size = pe.u32(directory + 4);
    if (va == 0 || va > pe.size || size > pe.size || ((va + size) & 0xffffffffL) > pe.size) {
      return;
    }
    List<Signature> sigs;
    try {
      sigs = parseAuthenticode(pe.r.buffer(), pe.size);
    } catch (RuntimeException e) {
      sigs = null;
    }
    int counter = processAuthenticode(o, sigs);
    o.setInteger(counter, "number_of_signatures");
  }
}
