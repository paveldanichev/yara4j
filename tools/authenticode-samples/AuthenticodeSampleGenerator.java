import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Generates PE files with Authenticode signatures exercising unusual but plausible
 * structures, to compare yara4j with libyara+OpenSSL. Test tool, not part of the project.
 */
public class AuthenticodeSampleGenerator {
  static final SecureRandom RND = new SecureRandom(new byte[] {1, 2, 3});

  // OIDs
  static final String SHA1 = "1.3.14.3.2.26", SHA256 = "2.16.840.1.101.3.4.2.1",
      SHA384 = "2.16.840.1.101.3.4.2.2", SHA512 = "2.16.840.1.101.3.4.2.3",
      MD5 = "1.2.840.113549.2.5", SHA1RSA = "1.2.840.113549.1.1.5",
      RSA = "1.2.840.113549.1.1.1", ECPUB = "1.2.840.10045.2.1",
      ECDSA256 = "1.2.840.10045.4.3.2", SIGNED_DATA = "1.2.840.113549.1.7.2",
      DATA = "1.2.840.113549.1.7.1", SPC_INDIRECT = "1.3.6.1.4.1.311.2.1.4",
      SPC_PE_IMAGE = "1.3.6.1.4.1.311.2.1.15", SPC_OPUS = "1.3.6.1.4.1.311.2.1.12",
      NESTED = "1.3.6.1.4.1.311.2.4.1", MS_CS = "1.3.6.1.4.1.311.3.3.1",
      CONTENT_TYPE = "1.2.840.113549.1.9.3", MESSAGE_DIGEST = "1.2.840.113549.1.9.4",
      SIGNING_TIME = "1.2.840.113549.1.9.5", COUNTERSIG = "1.2.840.113549.1.9.6",
      TSTINFO = "1.2.840.113549.1.9.16.1.4";

  static ASN1ObjectIdentifier oid(String s) {
    return new ASN1ObjectIdentifier(s);
  }

  static String jcaDigest(String oid) {
    switch (oid) {
      case SHA1:
      case SHA1RSA:
        return "SHA-1";
      case SHA256:
        return "SHA-256";
      case SHA384:
        return "SHA-384";
      case SHA512:
        return "SHA-512";
      case MD5:
        return "MD5";
      default:
        throw new IllegalArgumentException(oid);
    }
  }

  static String jcaSig(String digestOid, PrivateKey k) {
    String d = jcaDigest(digestOid).replace("-", "");
    return d + (k.getAlgorithm().equals("EC") ? "withECDSA" : "withRSA");
  }

  static byte[] hash(String oid, byte[]... parts) throws Exception {
    MessageDigest md = MessageDigest.getInstance(jcaDigest(oid));
    for (byte[] p : parts) md.update(p);
    return md.digest();
  }

  static byte[] der(ASN1Encodable e) throws Exception {
    return e.toASN1Primitive().getEncoded(ASN1Encoding.DL);
  }

  static AlgorithmIdentifier alg(String o) {
    return new AlgorithmIdentifier(oid(o), DERNull.INSTANCE);
  }

  // -------------------------------------------------------------------------------------------
  // PKI

  static KeyPair rsa(int bits) throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
    g.initialize(bits, RND);
    return g.generateKeyPair();
  }

  static KeyPair ec() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
    g.initialize(new ECGenParameterSpec("secp256r1"), RND);
    return g.generateKeyPair();
  }

  static final class Cert {
    X509CertificateHolder holder;
    KeyPair keys;
    X500Name name;
  }

  static X500Name name(String... kv) {
    List<RDN> rdns = new ArrayList<>();
    for (int i = 0; i < kv.length; i += 2) {
      rdns.add(new RDN(oid(kv[i]), new DERUTF8String(kv[i + 1])));
    }
    return new X500Name(rdns.toArray(new RDN[0]));
  }

  static final String C = "2.5.4.6", O = "2.5.4.10", OU = "2.5.4.11", CN = "2.5.4.3",
      ST = "2.5.4.8", L = "2.5.4.7", EMAIL = "1.2.840.113549.1.9.1";

  static Time time(String s) {
    return s.length() == 13 || s.contains("+") && s.length() < 17
        ? new Time(new DERUTCTime(s))
        : new Time(new DERGeneralizedTime(s));
  }

  static Cert cert(
      X500Name subject, KeyPair keys, Cert issuer, String sigAlg, BigInteger serial,
      Time nb, Time na, boolean ca, boolean extensions) throws Exception {
    X500Name issuerName = issuer == null ? subject : issuer.name;
    PrivateKey signer = issuer == null ? keys.getPrivate() : issuer.keys.getPrivate();
    PublicKey issuerPub = issuer == null ? keys.getPublic() : issuer.keys.getPublic();
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded());
    X509v3CertificateBuilder b = new X509v3CertificateBuilder(issuerName, serial, nb, na, subject, spki);
    if (extensions) {
      JcaX509ExtensionUtils u = new JcaX509ExtensionUtils();
      b.addExtension(Extension.subjectKeyIdentifier, false, u.createSubjectKeyIdentifier(keys.getPublic()));
      b.addExtension(Extension.authorityKeyIdentifier, false, u.createAuthorityKeyIdentifier(issuerPub));
      if (ca) {
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
      }
    }
    Cert c = new Cert();
    c.holder = b.build(new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(signer));
    c.keys = keys;
    c.name = subject;
    return c;
  }

  static Cert cert(X500Name subject, KeyPair keys, Cert issuer, String sigAlg) throws Exception {
    return cert(subject, keys, issuer, sigAlg, new BigInteger(64, RND).add(BigInteger.ONE),
        time("100101000000Z"), time("20391231235959Z"), issuer == null || subject.toString().contains("CA"), true);
  }

  // -------------------------------------------------------------------------------------------
  // Authenticode

  static final class Sig {
    String idcDigest = SHA256;          // digest in SpcIndirectDataContent
    String signerDigest = null;         // SignerInfo digestAlgorithm (default idcDigest)
    String mdAlgs = null;               // SignedData digestAlgorithms (default signerDigest)
    List<Cert> certs = new ArrayList<>();
    Cert signer;
    boolean messageDigest = true;
    boolean authAttrs = true;
    ASN1Encodable programName = new DERBMPString("yara4j test");
    Cert pkcs9Tsa;                      // pkcs9 countersignature
    String pkcs9Digest = SHA1;
    ASN1Encodable pkcs9Time = new DERUTCTime("180605163551Z");
    Cert msTsa;                         // RFC 3161 countersignature
    String msDigest = SHA256;
    boolean msCmsOnly = false;          // use a SubjectKeyIdentifier signer id
    boolean msBadImprint = false;
    List<Sig> nested = new ArrayList<>();
    boolean badSignature = false;
    boolean badFileDigest = false;
    int version = 1;
    boolean signerCertMissing = false;
  }

  static byte[] fileDigest; // set per signature by sign()

  static ASN1Encodable attribute(String type, ASN1Encodable... values) {
    return new DLSequence(new ASN1Encodable[] {oid(type), new DLSet(values)});
  }

  static byte[] signBytes(PrivateKey k, String digestOid, byte[] data) throws Exception {
    Signature s = Signature.getInstance(jcaSig(digestOid, k));
    s.initSign(k);
    s.update(data);
    return s.sign();
  }

  /** The DER of [0] IMPLICIT SET OF attributes, and the bytes signed (SET tag). */
  static ASN1Set attrSet(List<ASN1Encodable> attrs) {
    // Keep the order: DLSet doesn't sort.
    return new DLSet(attrs.toArray(new ASN1Encodable[0]));
  }

  static byte[] signedAttrsBytes(ASN1Set set) throws Exception {
    return set.getEncoded(ASN1Encoding.DL);
  }

  static ASN1Encodable issuerAndSerial(Cert c) {
    return new DLSequence(new ASN1Encodable[] {
      c.holder.toASN1Structure().getIssuer(), new ASN1Integer(c.holder.getSerialNumber())});
  }

  static ASN1Encodable signerInfo(
      Cert signer, String digest, List<ASN1Encodable> auth, byte[] directContent,
      List<ASN1Encodable> unauth, boolean bad, boolean skid, int version) throws Exception {
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(new ASN1Integer(version));
    if (skid) {
      byte[] id = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signer.keys.getPublic()).getKeyIdentifier();
      v.add(new DLTaggedObject(false, 0, new DEROctetString(id)));
    } else {
      v.add(issuerAndSerial(signer));
    }
    v.add(alg(digest));
    byte[] toSign;
    if (auth != null) {
      ASN1Set set = attrSet(auth);
      v.add(new DLTaggedObject(false, 0, set));
      toSign = signedAttrsBytes(set);
    } else {
      toSign = directContent;
    }
    v.add(new AlgorithmIdentifier(oid(signer.keys.getPrivate().getAlgorithm().equals("EC") ? ECDSA256 : RSA),
        signer.keys.getPrivate().getAlgorithm().equals("EC") ? null : DERNull.INSTANCE));
    String sigDigest = digest.equals(SHA1RSA) ? SHA1 : digest;
    byte[] sig = signBytes(signer.keys.getPrivate(), sigDigest, toSign);
    if (bad) sig[sig.length / 2] ^= 1;
    v.add(new DEROctetString(sig));
    if (unauth != null && !unauth.isEmpty()) {
      v.add(new DLTaggedObject(false, 1, new DLSet(unauth.toArray(new ASN1Encodable[0]))));
    }
    return new DLSequence(v);
  }

  static byte[] encDigestOf(ASN1Encodable si) {
    ASN1Sequence s = (ASN1Sequence) si;
    for (int i = s.size() - 1; i >= 0; i--) {
      if (s.getObjectAt(i) instanceof ASN1OctetString) return ((ASN1OctetString) s.getObjectAt(i)).getOctets();
    }
    throw new IllegalStateException();
  }

  static ASN1Encodable pkcs9Countersig(Sig s, byte[] parentEncDigest) throws Exception {
    List<ASN1Encodable> auth = new ArrayList<>();
    auth.add(attribute(CONTENT_TYPE, oid(DATA)));
    if (s.pkcs9Time != null) auth.add(attribute(SIGNING_TIME, s.pkcs9Time));
    auth.add(attribute(MESSAGE_DIGEST, new DEROctetString(hash(s.pkcs9Digest, parentEncDigest))));
    return signerInfo(s.pkcs9Tsa, s.pkcs9Digest, auth, null, null, false, false, 1);
  }

  static ASN1Encodable msCountersig(Sig s, byte[] parentEncDigest) throws Exception {
    byte[] imprint = hash(s.msDigest, parentEncDigest);
    if (s.msBadImprint) imprint[0] ^= 1;
    ASN1Encodable tst = new DLSequence(new ASN1Encodable[] {
      new ASN1Integer(1), oid("1.2.3.4.1"),
      new DLSequence(new ASN1Encodable[] {alg(s.msDigest), new DEROctetString(imprint)}),
      new ASN1Integer(4242), new DERGeneralizedTime("20240115083000.123Z")});
    byte[] tstDer = der(tst);
    List<ASN1Encodable> auth = new ArrayList<>();
    auth.add(attribute(CONTENT_TYPE, oid(TSTINFO)));
    auth.add(attribute(MESSAGE_DIGEST, new DEROctetString(hash(SHA256, tstDer))));
    ASN1Encodable si = signerInfo(s.msTsa, SHA256, auth, null, null, false, s.msCmsOnly, s.msCmsOnly ? 3 : 1);
    ASN1EncodableVector certs = new ASN1EncodableVector();
    certs.add(s.msTsa.holder.toASN1Structure());
    ASN1Encodable sd = new DLSequence(new ASN1Encodable[] {
      new ASN1Integer(s.msCmsOnly ? 3 : 3), new DLSet(alg(SHA256)),
      new DLSequence(new ASN1Encodable[] {oid(TSTINFO), new DLTaggedObject(true, 0, new DEROctetString(tstDer))}),
      new DLTaggedObject(false, 0, new DLSet(certs)), new DLSet(si)});
    return new DLSequence(new ASN1Encodable[] {oid(SIGNED_DATA), new DLTaggedObject(true, 0, sd)});
  }

  static ASN1Encodable authenticode(Sig s, byte[] pe, long checksumOff, long certDirOff, long certAddr) throws Exception {
    String signerDigest = s.signerDigest != null ? s.signerDigest : s.idcDigest;
    String mdAlgs = s.mdAlgs != null ? s.mdAlgs : signerDigest;
    byte[] fd = peDigest(s.idcDigest, pe, checksumOff, certDirOff, certAddr);
    if (s.badFileDigest) fd[0] ^= 1;
    ASN1Encodable peImage = new DLSequence(new ASN1Encodable[] {
      new DERBitString(new byte[0]),
      new DLTaggedObject(true, 0, new DLTaggedObject(true, 2, new DLTaggedObject(false, 0, new DERBMPString("<<<Obsolete>>>"))))});
    ASN1Encodable idc = new DLSequence(new ASN1Encodable[] {
      new DLSequence(new ASN1Encodable[] {oid(SPC_PE_IMAGE), peImage}),
      new DLSequence(new ASN1Encodable[] {alg(s.idcDigest), new DEROctetString(fd)})});
    byte[] idcDer = der(idc);
    // version 1: the digest skips the SEQUENCE tag and length
    ASN1Primitive p = idc.toASN1Primitive();
    byte[] content = Arrays.copyOfRange(idcDer, idcDer.length - contentLength(idcDer), idcDer.length);
    String sigDigest = signerDigest.equals(SHA1RSA) ? SHA1 : signerDigest;
    List<ASN1Encodable> auth = null;
    if (s.authAttrs) {
      auth = new ArrayList<>();
      auth.add(attribute(CONTENT_TYPE, oid(SPC_INDIRECT)));
      if (s.programName != null) {
        auth.add(attribute(SPC_OPUS, new DLSequence(new DLTaggedObject(true, 0,
            new DLTaggedObject(false, s.programName instanceof DERIA5String ? 1 : 0, s.programName)))));
      }
      if (s.messageDigest) {
        auth.add(attribute(MESSAGE_DIGEST, new DEROctetString(hash(sigDigest, s.version == 1 ? content : idcDer))));
      }
    }
    // Build unauthenticated attributes after the signature is known.
    ASN1Encodable si0 = signerInfo(s.signer, signerDigest, auth, s.version == 1 ? content : idcDer, null, s.badSignature, false, 1);
    byte[] encDigest = encDigestOf(si0);
    List<ASN1Encodable> unauth = new ArrayList<>();
    if (s.pkcs9Tsa != null) unauth.add(attribute(COUNTERSIG, pkcs9Countersig(s, encDigest)));
    if (s.msTsa != null) unauth.add(attribute(MS_CS, msCountersig(s, encDigest)));
    if (!s.nested.isEmpty()) {
      ASN1EncodableVector nv = new ASN1EncodableVector();
      for (Sig n : s.nested) nv.add(authenticode(n, pe, checksumOff, certDirOff, certAddr));
      unauth.add(new DLSequence(new ASN1Encodable[] {oid(NESTED), new DLSet(nv)}));
    }
    ASN1Sequence si = (ASN1Sequence) si0;
    ASN1EncodableVector siv = new ASN1EncodableVector();
    for (int i = 0; i < si.size(); i++) siv.add(si.getObjectAt(i));
    if (!unauth.isEmpty()) siv.add(new DLTaggedObject(false, 1, new DLSet(unauth.toArray(new ASN1Encodable[0]))));
    ASN1EncodableVector certs = new ASN1EncodableVector();
    for (Cert c : s.certs) certs.add(c.holder.toASN1Structure());
    if (s.pkcs9Tsa != null) certs.add(s.pkcs9Tsa.holder.toASN1Structure());
    ASN1Encodable sd = new DLSequence(new ASN1Encodable[] {
      new ASN1Integer(s.version), new DLSet(alg(mdAlgs)),
      new DLSequence(new ASN1Encodable[] {oid(SPC_INDIRECT), new DLTaggedObject(true, 0, idc)}),
      new DLTaggedObject(false, 0, new DLSet(certs)), new DLSet(new DLSequence(siv))});
    return new DLSequence(new ASN1Encodable[] {oid(SIGNED_DATA), new DLTaggedObject(true, 0, sd)});
  }

  static int contentLength(byte[] der) {
    int l = der[1] & 0xFF;
    if (l < 0x80) return l;
    int n = l & 0x7F, len = 0;
    for (int i = 0; i < n; i++) len = (len << 8) | (der[2 + i] & 0xFF);
    return len;
  }

  static long u32(byte[] b, long o) {
    int i = (int) o;
    return (b[i] & 0xFFL) | (b[i + 1] & 0xFFL) << 8 | (b[i + 2] & 0xFFL) << 16 | (b[i + 3] & 0xFFL) << 24;
  }

  static void put32(byte[] b, long o, long v) {
    for (int k = 0; k < 4; k++) b[(int) o + k] = (byte) (v >> (8 * k));
  }

  static byte[] peDigest(String digest, byte[] pe, long cs, long certDir, long certAddr) throws Exception {
    MessageDigest md = MessageDigest.getInstance(jcaDigest(digest));
    md.update(pe, 0, (int) cs);
    md.update(pe, (int) cs + 4, (int) (certDir - cs - 4));
    md.update(pe, (int) certDir + 8, (int) (certAddr - certDir - 8));
    return md.digest();
  }

  static byte[] sign(byte[] base, Sig s) throws Exception {
    int len = (base.length + 7) & ~7;
    byte[] pe = Arrays.copyOf(base, len);
    long peOff = u32(pe, 0x3c);
    boolean is64 = (pe[(int) peOff + 24] & 0xFF) == 0x0b && pe[(int) peOff + 25] == 2;
    long cs = peOff + 0x58;
    long certDir = peOff + (is64 ? 16 : 0) + 0x98;
    byte[] blob = der(authenticode(s, pe, cs, certDir, len));
    int total = (8 + blob.length + 7) & ~7;
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    put32(pe, certDir, len);
    put32(pe, certDir + 4, total);
    out.write(pe);
    byte[] hdr = new byte[8];
    put32(hdr, 0, 8 + blob.length);
    hdr[4] = 0; hdr[5] = 2; hdr[6] = 2; hdr[7] = 0;
    out.write(hdr);
    out.write(blob);
    out.write(new byte[total - 8 - blob.length]);
    return out.toByteArray();
  }

  // -------------------------------------------------------------------------------------------

  public static void main(String[] a) throws Exception {
    java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    Path outDir = Paths.get(a[1]);
    Files.createDirectories(outDir);
    byte[] pe32 = Files.readAllBytes(Paths.get(a[0], "tiny"));
    byte[] pe64 = Files.readAllBytes(Paths.get(a[0], "mtxex.dll"));

    KeyPair rootK = rsa(2048), interK = rsa(2048), leafK = rsa(2048), tsaK = rsa(2048), ecK = ec(), ecInterK = ec();
    Cert root = cert(name(C, "US", O, "Test Root CA", CN, "Root CA"), rootK, null, "SHA256withRSA");
    Cert inter = cert(name(C, "US", O, "Test", CN, "Intermediate CA"), interK, root, "SHA256withRSA");
    Cert leaf = cert(name(C, "US", ST, "California", L, "Menlo Park", O, "Signer, Inc.", OU, "Ops", CN, "Signer Inc"), leafK, inter, "SHA256withRSA");
    Cert tsaRoot = cert(name(C, "ZA", O, "TSA Root CA", CN, "TSA CA"), rsa(2048), null, "SHA1withRSA");
    Cert tsa = cert(name(C, "US", O, "Time", CN, "Timestamp Signer"), tsaK, tsaRoot, "SHA1withRSA");

    List<Object[]> variants = new ArrayList<>();
    java.util.function.Supplier<Sig> basic = () -> {
      Sig s = new Sig();
      s.signer = leaf;
      s.certs.addAll(List.of(leaf, inter));
      return s;
    };
    Sig s;

    s = basic.get(); variants.add(new Object[] {"basic_sha256", pe32, s});
    s = basic.get(); s.idcDigest = SHA1; variants.add(new Object[] {"sha1", pe32, s});
    s = basic.get(); s.idcDigest = SHA384; variants.add(new Object[] {"sha384", pe64, s});
    s = basic.get(); s.idcDigest = SHA512; s.signerDigest = SHA256; variants.add(new Object[] {"sha512_signer_sha256", pe64, s});
    s = basic.get(); s.idcDigest = MD5; variants.add(new Object[] {"md5", pe32, s});
    s = basic.get(); s.signerDigest = SHA1RSA; s.idcDigest = SHA1; variants.add(new Object[] {"signer_digest_sha1withrsa", pe32, s});
    s = basic.get(); s.mdAlgs = SHA384; variants.add(new Object[] {"mdalgs_mismatch", pe32, s});
    s = basic.get(); s.badSignature = true; variants.add(new Object[] {"bad_signature", pe32, s});
    s = basic.get(); s.badFileDigest = true; variants.add(new Object[] {"bad_file_digest", pe32, s});
    s = basic.get(); s.messageDigest = false; variants.add(new Object[] {"no_message_digest", pe32, s});
    s = basic.get(); s.authAttrs = false; variants.add(new Object[] {"no_auth_attrs", pe32, s});
    s = basic.get(); s.version = 3; variants.add(new Object[] {"version3", pe32, s});
    s = basic.get(); s.programName = new DERIA5String("ascii program"); variants.add(new Object[] {"program_ia5", pe32, s});
    s = basic.get(); s.programName = new DERBMPString("café 中文"); variants.add(new Object[] {"program_unicode", pe32, s});
    s = basic.get(); s.programName = new DERBMPString("nul\u0000inside"); variants.add(new Object[] {"program_nul", pe32, s});
    s = basic.get(); s.programName = new DERBMPString("emoji 😀"); variants.add(new Object[] {"program_surrogates", pe32, s});
    s = basic.get(); s.programName = null; variants.add(new Object[] {"no_program", pe32, s});
    s = basic.get(); s.certs.clear(); s.certs.add(inter); variants.add(new Object[] {"signer_cert_missing", pe32, s});
    s = basic.get(); s.certs.clear(); s.certs.addAll(List.of(inter, leaf, root, leaf)); variants.add(new Object[] {"cert_order_dupes_root", pe32, s});

    s = basic.get(); s.pkcs9Tsa = tsa; variants.add(new Object[] {"pkcs9_countersig", pe32, s});
    s = basic.get(); s.pkcs9Tsa = tsa; s.pkcs9Digest = SHA256; s.pkcs9Time = new DERGeneralizedTime("20200229120000Z"); variants.add(new Object[] {"pkcs9_sha256_gentime", pe32, s});
    s = basic.get(); s.pkcs9Tsa = tsa; s.pkcs9Time = null; variants.add(new Object[] {"pkcs9_no_time", pe32, s});
    s = basic.get(); s.msTsa = tsa; variants.add(new Object[] {"ms_countersig", pe32, s});
    s = basic.get(); s.msTsa = tsa; s.msDigest = SHA1; variants.add(new Object[] {"ms_countersig_sha1", pe64, s});
    s = basic.get(); s.msTsa = tsa; s.msCmsOnly = true; variants.add(new Object[] {"ms_countersig_cms_skid", pe32, s});
    s = basic.get(); s.msTsa = tsa; s.msBadImprint = true; variants.add(new Object[] {"ms_countersig_bad_imprint", pe32, s});
    s = basic.get(); s.msTsa = tsa; s.pkcs9Tsa = tsa; variants.add(new Object[] {"both_countersigs", pe32, s});

    Sig n1 = basic.get(); n1.idcDigest = SHA1; n1.pkcs9Tsa = tsa;
    Sig n2 = basic.get(); n2.idcDigest = SHA512;
    Sig n3 = basic.get(); n3.badFileDigest = true;
    n2.nested.add(n3);
    s = basic.get(); s.nested.add(n1); s.nested.add(n2); variants.add(new Object[] {"nested", pe32, s});

    // EC keys and signature algorithms
    Cert ecInter = cert(name(C, "US", O, "Test", CN, "EC Intermediate CA"), ecInterK, root, "SHA256withRSA");
    Cert ecLeaf = cert(name(C, "US", O, "EC Signer", CN, "EC Signer"), ecK, ecInter, "SHA256withECDSA");
    s = new Sig(); s.signer = ecLeaf; s.certs.addAll(List.of(ecLeaf, ecInter)); variants.add(new Object[] {"ecdsa", pe32, s});
    Cert rsaUnderEc = cert(name(C, "US", O, "RSA under EC", CN, "Mixed"), rsa(2048), ecInter, "SHA384withECDSA");
    s = new Sig(); s.signer = rsaUnderEc; s.certs.addAll(List.of(rsaUnderEc, ecInter, root)); variants.add(new Object[] {"rsa_leaf_ec_issuer", pe32, s});
    Cert pss = cert(name(C, "US", CN, "PSS signed"), rsa(2048), inter, "SHA256withRSAandMGF1");
    s = new Sig(); s.signer = pss; s.certs.addAll(List.of(pss, inter)); variants.add(new Object[] {"pss_cert", pe32, s});
    Cert md5cert = cert(name(C, "US", CN, "MD5 signed"), rsa(1024), inter, "MD5withRSA");
    s = new Sig(); s.signer = md5cert; s.certs.addAll(List.of(md5cert, inter)); variants.add(new Object[] {"md5_cert", pe32, s});

    // Names
    X500Name multi = new X500Name(new RDN[] {
      new RDN(oid(C), new DERPrintableString("US")),
      new RDN(new AttributeTypeAndValue[] {
        new AttributeTypeAndValue(oid(O), new DERUTF8String("Multi")),
        new AttributeTypeAndValue(oid(OU), new DERUTF8String("Valued"))}),
      new RDN(oid(CN), new DERUTF8String("a/b+c=d,e\\f"))});
    Cert multiC = cert(multi, rsa(2048), inter, "SHA256withRSA");
    s = new Sig(); s.signer = multiC; s.certs.addAll(List.of(multiC, inter)); variants.add(new Object[] {"names_multivalued_escapes", pe32, s});
    X500Name weird = new X500Name(new RDN[] {
      new RDN(oid(C), new DERPrintableString("DE")),
      new RDN(oid(O), new DERBMPString("Büro GmbH")),
      new RDN(oid(L), new DERT61String("München")),
      new RDN(oid("1.2.3.4.5.6"), new DERUTF8String("custom attr")),
      new RDN(oid("1.3.6.1.4.1.311.60.2.1.3"), new DERPrintableString("DE")),
      new RDN(oid("2.5.4.15"), new DERUTF8String("Private Organization")),
      new RDN(oid("2.5.4.5"), new DERPrintableString("HRB 1234")),
      new RDN(oid(EMAIL), new DERIA5String("a@b.c")),
      new RDN(oid(CN), new DERUTF8String("日本語 tab\there"))});
    Cert weirdC = cert(weird, rsa(2048), inter, "SHA256withRSA");
    s = new Sig(); s.signer = weirdC; s.certs.addAll(List.of(weirdC, inter)); variants.add(new Object[] {"names_types", pe32, s});
    StringBuilder longCn = new StringBuilder();
    for (int i = 0; i < 30; i++) longCn.append("LongName").append(i);
    X500Name longName = name(C, "US", O, "Long Org Name That Takes Space", OU, "Unit/With/Slashes", CN, longCn.toString(), EMAIL, "after@long.name");
    Cert longC = cert(longName, rsa(2048), inter, "SHA256withRSA");
    s = new Sig(); s.signer = longC; s.certs.addAll(List.of(longC, inter)); variants.add(new Object[] {"names_long", pe32, s});
    X500Name midLong = name(C, "US", O, "x".repeat(200), CN, "short cn after 200 chars");
    Cert midC = cert(midLong, rsa(2048), inter, "SHA256withRSA");
    s = new Sig(); s.signer = midC; s.certs.addAll(List.of(midC, inter)); variants.add(new Object[] {"names_truncation_boundary", pe32, s});

    // Serials and times
    Cert negSerial = cert(name(CN, "Negative serial"), rsa(2048), inter, "SHA256withRSA", BigInteger.valueOf(-123456789L),
        time("100101000000Z"), time("20391231235959Z"), false, true);
    s = new Sig(); s.signer = negSerial; s.certs.addAll(List.of(negSerial, inter)); variants.add(new Object[] {"serial_negative", pe32, s});
    Cert bigSerial = cert(name(CN, "Big serial"), rsa(2048), inter, "SHA256withRSA", new BigInteger(1, new byte[] {(byte) 0x80, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}),
        time("100101000000Z"), time("20391231235959Z"), false, true);
    s = new Sig(); s.signer = bigSerial; s.certs.addAll(List.of(bigSerial, inter)); variants.add(new Object[] {"serial_21_bytes", pe32, s});
    Cert serial20 = cert(name(CN, "20 byte serial"), rsa(2048), inter, "SHA256withRSA", new BigInteger(1, new byte[] {0x7f, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}),
        time("100101000000Z"), time("20391231235959Z"), false, true);
    s = new Sig(); s.signer = serial20; s.certs.addAll(List.of(serial20, inter)); variants.add(new Object[] {"serial_20_bytes", pe32, s});
    Cert times = cert(name(CN, "Odd times"), rsa(2048), inter, "SHA256withRSA", BigInteger.TEN,
        new Time(new DERUTCTime("4912312359Z")), new Time(new DERGeneralizedTime("20501231235959.999Z")), false, true);
    s = new Sig(); s.signer = times; s.certs.addAll(List.of(times, inter)); variants.add(new Object[] {"times_odd", pe32, s});
    Cert offs = cert(name(CN, "Offset times"), rsa(2048), inter, "SHA256withRSA", BigInteger.TWO,
        new Time(new ASN1UTCTime("150101000000+0130")), new Time(new ASN1GeneralizedTime("20300101000000-0800")), false, true);
    s = new Sig(); s.signer = offs; s.certs.addAll(List.of(offs, inter)); variants.add(new Object[] {"times_offsets", pe32, s});

    // Chain building: two candidate issuers with the same name and key, one expired.
    Cert interExpired = cert(inter.name, interK, root, "SHA256withRSA", BigInteger.valueOf(777),
        time("100101000000Z"), time("120101000000Z"), true, true);
    s = basic.get(); s.certs.clear(); s.certs.addAll(List.of(leaf, interExpired, inter)); variants.add(new Object[] {"chain_expired_candidate_first", pe32, s});
    Cert interLater = cert(inter.name, interK, root, "SHA256withRSA", BigInteger.valueOf(778),
        time("100101000000Z"), time("20450101000000Z"), true, true);
    s = basic.get(); s.certs.clear(); s.certs.addAll(List.of(leaf, inter, interLater)); variants.add(new Object[] {"chain_two_valid_candidates", pe32, s});
    // Issuer name matches but the key doesn't (AKID mismatch), followed by the right one.
    Cert fakeInter = cert(inter.name, rsa(2048), root, "SHA256withRSA");
    s = basic.get(); s.certs.clear(); s.certs.addAll(List.of(leaf, fakeInter, inter, root)); variants.add(new Object[] {"chain_akid_mismatch", pe32, s});
    // No extensions at all (no AKID/SKID), chain by name only.
    Cert rootNoExt = cert(name(CN, "NoExt Root"), rsa(2048), null, "SHA256withRSA", BigInteger.ONE, time("100101000000Z"), time("20391231235959Z"), true, false);
    Cert leafNoExt = cert(name(CN, "NoExt Leaf"), rsa(2048), rootNoExt, "SHA256withRSA", BigInteger.TWO, time("100101000000Z"), time("20391231235959Z"), false, false);
    s = new Sig(); s.signer = leafNoExt; s.certs.addAll(List.of(leafNoExt, rootNoExt)); variants.add(new Object[] {"chain_no_extensions", pe32, s});
    // Self signed signer
    Cert self = cert(name(CN, "Self Signed"), rsa(2048), null, "SHA256withRSA");
    s = new Sig(); s.signer = self; s.certs.add(self); variants.add(new Object[] {"self_signed", pe32, s});
    // Name differing only by case/whitespace in issuer (X509_NAME_cmp canonicalization)
    X500Name interCanon = new X500Name(new RDN[] {
      new RDN(oid(C), new DERPrintableString("us")),
      new RDN(oid(O), new DERPrintableString("  TEST ")),
      new RDN(oid(CN), new DERPrintableString("intermediate   ca"))});
    Cert canonIssued = cert(name(CN, "Canon"), rsa(2048), null, "SHA256withRSA");
    {
      // leaf whose issuer name is a case/space variant of inter's subject, signed by inter
      X509v3CertificateBuilder b = new X509v3CertificateBuilder(interCanon, BigInteger.valueOf(99),
          time("100101000000Z"), time("20391231235959Z"), name(CN, "Canon leaf"),
          SubjectPublicKeyInfo.getInstance(canonIssued.keys.getPublic().getEncoded()));
      canonIssued.holder = b.build(new JcaContentSignerBuilder("SHA256withRSA").build(interK.getPrivate()));
      canonIssued.name = name(CN, "Canon leaf");
    }
    s = new Sig(); s.signer = canonIssued; s.certs.addAll(List.of(canonIssued, inter)); variants.add(new Object[] {"chain_name_canonical", pe32, s});

    for (Object[] v : variants) {
      Files.write(outDir.resolve("sig_" + v[0]), sign((byte[]) v[1], (Sig) v[2]));
    }
    System.out.println(variants.size() + " samples");
  }
}
