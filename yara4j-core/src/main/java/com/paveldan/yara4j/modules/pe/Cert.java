package com.paveldan.yara4j.modules.pe;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import com.paveldan.yara4j.modules.pe.Asn1.Asn1Exception;

/**
 * An X.509 certificate with the properties that OpenSSL exposes to authenticode-parser:
 * one-line names, serial, validity, signature algorithm and the data needed to build chains.
 */
final class Cert {

  /** An X509_NAME. */
  static final class Name {
    final List<String> oids = new ArrayList<>();
    final List<Asn1> oidElements = new ArrayList<>();
    final List<Asn1> values = new ArrayList<>();
    final List<Integer> sets = new ArrayList<>();
    private byte[] canon;

    static Name parse(Asn1 n) throws Asn1Exception {
      n.expectSequence();
      Name name = new Name();
      int setIndex = 0;
      for (Asn1 rdn : n.children()) {
        rdn.expectSet();
        for (Asn1 atv : rdn.children()) {
          atv.expectSequence();
          if (atv.size() != 2) {
            throw new Asn1Exception("bad attribute type and value");
          }
          name.oids.add(atv.get(0).oid());
          name.oidElements.add(atv.get(0));
          Asn1 v = atv.get(1);
          if (v.isUniversal(Asn1.NULL) || v.isUniversal(Asn1.BOOLEAN)
              || v.isUniversal(Asn1.OBJECT) || v.tagClass != Asn1.UNIVERSAL) {
            throw new Asn1Exception("bad name value");
          }
          name.values.add(v);
          name.sets.add(setIndex);
        }
        setIndex++;
      }
      return name;
    }

    /** X509_NAME_oneline into a 256 byte buffer, with OpenSSL 3 escaping removed. */
    String oneline() {
      final int len = 255;
      StringBuilder sb = new StringBuilder();
      int l = 0;
      int prevSet = -1;
      for (int i = 0; i < oids.size(); i++) {
        String s = Oids.shortName(oids.get(i));
        if (s == null) {
          s = oids.get(i);
        }
        Asn1 v = values.get(i);
        byte[] q = valueBytes(v);
        int num = q.length;
        boolean[] gs = {true, true, true, true};
        if (v.isUniversal(Asn1.GENERAL_STRING) && num % 4 == 0) {
          boolean[] nz = new boolean[4];
          for (int j = 0; j < num; j++) {
            if (q[j] != 0) {
              nz[j & 3] = true;
            }
          }
          if (!(nz[0] | nz[1] | nz[2])) {
            gs = new boolean[] {false, false, false, true};
          }
        }
        StringBuilder val = new StringBuilder();
        for (int j = 0; j < num; j++) {
          if (!gs[j & 3]) {
            continue;
          }
          int c = q[j] & 0xFF;
          if (c < ' ' || c > '~') {
            val.append("\\x").append(String.format("%02X", c));
          } else {
            if (c == '/' || c == '+') {
              val.append('\\');
            }
            val.append((char) c);
          }
        }
        l += 1 + s.length() + 1 + val.length();
        if (l > len) {
          break;
        }
        sb.append(prevSet == sets.get(i) ? '+' : '/').append(s).append('=').append(val);
        prevSet = sets.get(i);
      }
      // parse_oneline_string: "\/" -> "/"
      return sb.toString().replace("\\/", "/");
    }

    private static byte[] valueBytes(Asn1 v) {
      byte[] b = v.anyValue();
      return b == null ? new byte[0] : b;
    }

    /** OpenSSL's canonical encoding used by X509_NAME_cmp. */
    byte[] canonical() {
      if (canon != null) {
        return canon;
      }
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      int i = 0;
      while (i < oids.size()) {
        int set = sets.get(i);
        List<byte[]> entries = new ArrayList<>();
        while (i < oids.size() && sets.get(i) == set) {
          byte[] oid = oidElements.get(i).encoded();
          byte[] value = canonValue(values.get(i));
          entries.add(tlv(0x30, concat(oid, value)));
          i++;
        }
        entries.sort(Cert::derCompare);
        ByteArrayOutputStream setContent = new ByteArrayOutputStream();
        for (byte[] e : entries) {
          setContent.write(e, 0, e.length);
        }
        byte[] s = tlv(0x31, setContent.toByteArray());
        out.write(s, 0, s.length);
      }
      canon = out.toByteArray();
      return canon;
    }

    private static byte[] canonValue(Asn1 v) {
      if (v.tagClass != Asn1.UNIVERSAL) {
        return v.encoded();
      }
      String str;
      byte[] c = v.contents();
      switch (v.tag) {
        case Asn1.UTF8_STRING:
          str = new String(c, StandardCharsets.UTF_8);
          break;
        case Asn1.BMP_STRING:
          str = new String(c, StandardCharsets.UTF_16BE);
          break;
        case Asn1.UNIVERSAL_STRING:
          str = new String(c, java.nio.charset.Charset.forName("UTF-32BE"));
          break;
        case Asn1.PRINTABLE_STRING:
        case Asn1.T61_STRING:
        case Asn1.IA5_STRING:
        case Asn1.VISIBLE_STRING:
          str = new String(c, StandardCharsets.ISO_8859_1);
          break;
        default:
          return v.encoded();
      }
      byte[] u = str.getBytes(StandardCharsets.UTF_8);
      int from = 0;
      int to = u.length;
      while (from < to && isSpace(u[from])) {
        from++;
      }
      while (to > from && isSpace(u[to - 1])) {
        to--;
      }
      ByteArrayOutputStream o = new ByteArrayOutputStream();
      int p = from;
      while (p < to) {
        int ch = u[p] & 0xFF;
        if (ch >= 0x80) {
          o.write(ch);
          p++;
        } else if (isSpace(u[p])) {
          o.write(' ');
          while (p < to && isSpace(u[p])) {
            p++;
          }
        } else {
          o.write(ch >= 'A' && ch <= 'Z' ? ch + 32 : ch);
          p++;
        }
      }
      return tlv(0x0C, o.toByteArray());
    }

    private static boolean isSpace(byte b) {
      return b == ' ' || (b >= 9 && b <= 13);
    }

    /** X509_NAME_cmp(a, b) == 0. */
    boolean sameAs(Name other) {
      return Arrays.equals(canonical(), other.canonical());
    }
  }

  final byte[] encoded;
  final long version;
  final BigInteger serial;
  final Name issuer;
  final Name subject;
  final Asn1 notBefore;
  final Asn1 notAfter;
  final String sigAlgOid;
  final String tbsSigAlgOid;
  final String spkiAlgOid;
  final byte[] spki;
  // Extensions used for chain building.
  final byte[] skid;
  final byte[] akidKeyId;
  final Name akidIssuer;
  final BigInteger akidSerial;
  final boolean extensionsInvalid;
  private AsymmetricKeyParameter publicKey;
  private boolean publicKeyDecoded;
  private byte[] sha1;

  private Cert(
      byte[] encoded,
      long version,
      BigInteger serial,
      Name issuer,
      Name subject,
      Asn1 notBefore,
      Asn1 notAfter,
      String sigAlgOid,
      String tbsSigAlgOid,
      String spkiAlgOid,
      byte[] spki,
      byte[] skid,
      byte[] akidKeyId,
      Name akidIssuer,
      BigInteger akidSerial,
      boolean extensionsInvalid) {
    this.encoded = encoded;
    this.version = version;
    this.serial = serial;
    this.issuer = issuer;
    this.subject = subject;
    this.notBefore = notBefore;
    this.notAfter = notAfter;
    this.sigAlgOid = sigAlgOid;
    this.tbsSigAlgOid = tbsSigAlgOid;
    this.spkiAlgOid = spkiAlgOid;
    this.spki = spki;
    this.skid = skid;
    this.akidKeyId = akidKeyId;
    this.akidIssuer = akidIssuer;
    this.akidSerial = akidSerial;
    this.extensionsInvalid = extensionsInvalid;
  }

  private static String algorithmOid(Asn1 alg) throws Asn1Exception {
    alg.expectSequence();
    if (alg.size() < 1 || alg.size() > 2) {
      throw new Asn1Exception("bad algorithm identifier");
    }
    return alg.get(0).oid();
  }

  private static void expectTime(Asn1 t) throws Asn1Exception {
    if (!t.isUniversal(Asn1.UTC_TIME) && !t.isUniversal(Asn1.GENERALIZED_TIME)) {
      throw new Asn1Exception("bad time");
    }
  }

  /** d2i_X509. */
  static Cert parse(Asn1 c) throws Asn1Exception {
    c.expectSequence();
    if (c.size() != 3) {
      throw new Asn1Exception("bad certificate");
    }
    Asn1 tbs = c.get(0);
    tbs.expectSequence();
    String sigAlg = algorithmOid(c.get(1));
    c.get(2).expectUniversal(Asn1.BIT_STRING);
    List<Asn1> t = tbs.children();
    int i = 0;
    long version = 0;
    if (i < t.size() && t.get(i).isContext(0) && t.get(i).constructed) {
      Asn1 v = t.get(i);
      if (v.size() != 1) {
        throw new Asn1Exception("bad version");
      }
      version = v.get(0).integer().longValue();
      i++;
    }
    if (t.size() < i + 6) {
      throw new Asn1Exception("truncated tbs");
    }
    BigInteger serial = t.get(i++).integer();
    String tbsSigAlg = algorithmOid(t.get(i++));
    Name issuer = Name.parse(t.get(i++));
    Asn1 validity = t.get(i++);
    validity.expectSequence();
    if (validity.size() != 2) {
      throw new Asn1Exception("bad validity");
    }
    expectTime(validity.get(0));
    expectTime(validity.get(1));
    Name subject = Name.parse(t.get(i++));
    Asn1 spki = t.get(i++);
    spki.expectSequence();
    if (spki.size() != 2) {
      throw new Asn1Exception("bad spki");
    }
    String spkiAlg = algorithmOid(spki.get(0));
    spki.get(1).expectUniversal(Asn1.BIT_STRING);
    byte[] skid = null;
    byte[] akidKeyId = null;
    Name akidIssuer = null;
    BigInteger akidSerial = null;
    boolean invalid = false;
    for (; i < t.size(); i++) {
      Asn1 e = t.get(i);
      if (e.isContext(1) || e.isContext(2)) {
        continue;
      }
      if (!e.isContext(3) || !e.constructed || e.size() != 1) {
        throw new Asn1Exception("bad tbs element");
      }
      Asn1 exts = e.get(0);
      exts.expectSequence();
      boolean seenSkid = false;
      boolean seenAkid = false;
      for (Asn1 ext : exts.children()) {
        ext.expectSequence();
        if (ext.size() < 2 || ext.size() > 3) {
          throw new Asn1Exception("bad extension");
        }
        String oid = ext.get(0).oid();
        Asn1 value = ext.get(ext.size() - 1);
        value.expectUniversal(Asn1.OCTET_STRING);
        try {
          if (oid.equals(Oids.SUBJECT_KEY_IDENTIFIER)) {
            if (seenSkid) {
              invalid = true;
            }
            seenSkid = true;
            Asn1 s = Asn1.parse(value.contents());
            s.expectUniversal(Asn1.OCTET_STRING);
            skid = s.contents();
          } else if (oid.equals(Oids.AUTHORITY_KEY_IDENTIFIER)) {
            if (seenAkid) {
              invalid = true;
            }
            seenAkid = true;
            Asn1 a = Asn1.parse(value.contents());
            a.expectSequence();
            for (Asn1 f : a.children()) {
              if (f.isContext(0)) {
                akidKeyId = f.contents();
              } else if (f.isContext(1)) {
                for (Asn1 gn : f.children()) {
                  if (gn.isContext(4) && gn.constructed && gn.size() == 1 && akidIssuer == null) {
                    akidIssuer = Name.parse(gn.get(0));
                  }
                }
              } else if (f.isContext(2)) {
                byte[] raw = f.rawContents();
                if (raw.length == 0) {
                  throw new Asn1Exception("bad serial");
                }
                akidSerial = new BigInteger(raw);
              } else {
                throw new Asn1Exception("bad akid");
              }
            }
          }
        } catch (Asn1Exception ex) {
          invalid = true;
        }
      }
    }
    return new Cert(
        c.encoded(),
        version,
        serial,
        issuer,
        subject,
        validity.get(0),
        validity.get(1),
        sigAlg,
        tbsSigAlg,
        spkiAlg,
        spki.encoded(),
        skid,
        akidKeyId,
        akidIssuer,
        akidSerial,
        invalid);
  }

  byte[] sha1() {
    if (sha1 == null) {
      sha1 = Oids.md("1.3.14.3.2.26").digest(encoded);
    }
    return sha1;
  }

  /** X509_get0_pubkey: null if the key can't be decoded. */
  AsymmetricKeyParameter publicKey() {
    if (!publicKeyDecoded) {
      publicKeyDecoded = true;
      try {
        publicKey = decodePublicKey(SubjectPublicKeyInfo.getInstance(spki));
      } catch (Exception | LinkageError e) {
        publicKey = null;
      }
    }
    return publicKey;
  }

  /** The RSA and DSA key algorithms that PublicKeyFactory decodes. */
  private static final Set<String> RSA_KEY_OIDS =
      Set.of("1.2.840.113549.1.1.1", "1.2.840.113549.1.1.7", Oids.RSASSA_PSS, "2.5.8.1.1");

  private static final Set<String> DSA_KEY_OIDS = Set.of(Oids.DSA, "1.3.14.3.2.27");

  /**
   * A key that decodes, so that it can be used for building chains, but that OpenSSL refuses
   * to verify signatures with. Signature verification fails with it.
   */
  static final class UnverifiableKey extends AsymmetricKeyParameter {
    UnverifiableKey() {
      super(false);
    }
  }

  private static AsymmetricKeyParameter decodePublicKey(SubjectPublicKeyInfo info)
      throws java.io.IOException {
    String alg = info.getAlgorithm().getAlgorithm().getId();
    if (RSA_KEY_OIDS.contains(alg)) {
      // Like OpenSSL, the modulus isn't validated when decoding the key. PublicKeyFactory runs
      // primality tests on it, which take seconds with the large moduli a file can contain.
      // The limits OpenSSL applies when verifying are checked by Authenticode.rsaRecover.
      RSAPublicKey k = RSAPublicKey.getInstance(info.parsePublicKey());
      return new RSAKeyParameters(false, k.getModulus(), k.getPublicExponent(), true);
    }
    if (DSA_KEY_OIDS.contains(alg)) {
      // PublicKeyFactory checks y^q mod p == 1, which is slow when q and p are large; OpenSSL
      // can't verify with such keys anyway.
      ASN1Encodable params = info.getAlgorithm().getParameters();
      if (params instanceof ASN1Sequence) {
        DSAParameter p = DSAParameter.getInstance(params);
        if (!Authenticode.dsaVerifiable(p.getP(), p.getQ())) {
          return new UnverifiableKey();
        }
      }
    }
    return PublicKeyFactory.createKey(info);
  }

  /** integer_to_serial: "00:01:02..." or null. */
  String serialString() {
    byte[] content = serial.toByteArray();
    int bytes = content.length + 2;
    if (bytes < 2 || bytes > 22) {
      return null;
    }
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < content.length; i++) {
      if (i > 0) {
        sb.append(':');
      }
      sb.append(String.format("%02x", content[i] & 0xFF));
    }
    return sb.toString();
  }

  /** check_sig_alg_match(issuer key, subject). */
  private static boolean sigAlgMatch(Cert issuer, Cert subject) {
    if (issuer.publicKey() == null) {
      return false;
    }
    Oids.KeyType key = Oids.keyType(issuer.spkiAlgOid);
    Oids.KeyType sig = Oids.sigKeyType(subject.tbsSigAlgOid);
    if (sig == Oids.KeyType.NONE) {
      return false;
    }
    if (sig == key) {
      return true;
    }
    return key == Oids.KeyType.RSA && sig == Oids.KeyType.RSA_PSS;
  }

  /** X509_check_akid(issuer, subject->akid) == X509_V_OK. */
  private static boolean akidMatch(Cert issuer, Cert subject) {
    if (subject.akidKeyId != null
        && issuer.skid != null
        && !Arrays.equals(subject.akidKeyId, issuer.skid)) {
      return false;
    }
    if (subject.akidSerial != null && !subject.akidSerial.equals(issuer.serial)) {
      return false;
    }
    return subject.akidIssuer == null || subject.akidIssuer.sameAs(issuer.issuer);
  }

  /** ossl_x509_likely_issued(issuer, subject) == X509_V_OK. */
  static boolean likelyIssued(Cert issuer, Cert subject) {
    if (!issuer.subject.sameAs(subject.issuer)) {
      return false;
    }
    if (issuer.extensionsInvalid || subject.extensionsInvalid) {
      return false;
    }
    if (!akidMatch(issuer, subject)) {
      return false;
    }
    return sigAlgMatch(issuer, subject);
  }

  boolean selfSigned() {
    return likelyIssued(this, this);
  }

  boolean sameCert(Cert other) {
    return Arrays.equals(sha1(), other.sha1());
  }

  long notBeforeTime() {
    return Authenticode.asn1TimeToEpoch(notBefore);
  }

  long notAfterTime() {
    return Authenticode.asn1TimeToEpoch(notAfter);
  }

  // DER helpers

  static byte[] tlv(int tag, byte[] content) {
    ByteArrayOutputStream o = new ByteArrayOutputStream();
    o.write(tag);
    int n = content.length;
    if (n < 0x80) {
      o.write(n);
    } else if (n < 0x100) {
      o.write(0x81);
      o.write(n);
    } else if (n < 0x10000) {
      o.write(0x82);
      o.write(n >> 8);
      o.write(n);
    } else if (n < 0x1000000) {
      o.write(0x83);
      o.write(n >> 16);
      o.write(n >> 8);
      o.write(n);
    } else {
      o.write(0x84);
      o.write(n >>> 24);
      o.write(n >> 16);
      o.write(n >> 8);
      o.write(n);
    }
    o.write(content, 0, n);
    return o.toByteArray();
  }

  static byte[] concat(byte[] a, byte[] b) {
    byte[] r = Arrays.copyOf(a, a.length + b.length);
    System.arraycopy(b, 0, r, a.length, b.length);
    return r;
  }

  /** The ordering used for DER SET OF (OpenSSL's der_cmp). */
  static int derCompare(byte[] a, byte[] b) {
    int n = Math.min(a.length, b.length);
    for (int i = 0; i < n; i++) {
      int d = (a[i] & 0xFF) - (b[i] & 0xFF);
      if (d != 0) {
        return d;
      }
    }
    return a.length - b.length;
  }
}
