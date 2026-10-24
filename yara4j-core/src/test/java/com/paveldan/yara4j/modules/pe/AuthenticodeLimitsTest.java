package com.paveldan.yara4j.modules.pe;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeout;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.Random;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.junit.jupiter.api.Test;
import com.paveldan.yara4j.CraftedFiles;
import com.paveldan.yara4j.ErrorCode;
import com.paveldan.yara4j.internal.YaraError;
import com.paveldan.yara4j.module.MemoryBlock;
import com.paveldan.yara4j.module.ScanContext;
import com.paveldan.yara4j.object.YStructure;
import com.paveldan.yara4j.util.BinaryReader;

/** Limits that keep Authenticode parsing and verification cheap on crafted files. */
class AuthenticodeLimitsTest {

  private static final AlgorithmIdentifier SHA256_RSA =
      new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE);

  @Test
  void fileDigestComputedOnce() {
    byte[] pe = CraftedFiles.peWithNestedSignatures(5, 0x200);
    List<Authenticode.Signature> sigs =
        Authenticode.parseAuthenticode(ByteBuffer.wrap(pe), pe.length, null);
    assertEquals(6, sigs.size());
    for (Authenticode.Signature s : sigs) {
      assertNotNull(s.fileDigest);
      assertSame(sigs.get(0).fileDigest, s.fileDigest);
    }
  }

  @Test
  void timeoutIsNotSwallowed() {
    byte[] data = CraftedFiles.peWithNestedSignatures(5, 0x200);
    ScanContext context =
        new ScanContext() {
          @Override
          public long fileSize() {
            return data.length;
          }

          @Override
          public List<MemoryBlock> blocks() {
            return List.of();
          }

          @Override
          public void consoleLog(String message) {}

          @Override
          public YStructure moduleObject(String name) {
            return null;
          }

          @Override
          public void checkTimeout() {
            throw new YaraError(ErrorCode.SCAN_TIMEOUT);
          }
        };
    BinaryReader r = new BinaryReader(ByteBuffer.wrap(data), context);
    PeModule.Pe pe = new PeModule.Pe(r, PeModule.getHeader(r), new YStructure("pe"));
    YaraError e = assertThrows(YaraError.class, () -> Authenticode.parseCertificates(pe));
    assertEquals(ErrorCode.SCAN_TIMEOUT, e.toException().getErrorCode());
  }

  /** A self-issued certificate with the given key, whose own signature is garbage. */
  private static Cert certificate(SubjectPublicKeyInfo key) throws Exception {
    V3TBSCertificateGenerator g = new V3TBSCertificateGenerator();
    g.setSerialNumber(new ASN1Integer(1));
    g.setSignature(SHA256_RSA);
    X500Name name = new X500Name("CN=test");
    g.setIssuer(name);
    g.setSubject(name);
    g.setStartDate(new Time(new Date(0)));
    g.setEndDate(new Time(new Date(4102444800000L)));
    g.setSubjectPublicKeyInfo(key);
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(g.generateTBSCertificate());
    v.add(SHA256_RSA);
    v.add(new DERBitString(new byte[256]));
    byte[] der = new DERSequence(v).getEncoded(ASN1Encoding.DER);
    return Cert.parse(Asn1.parse(der));
  }

  private static Cert rsaCertificate(BigInteger n, BigInteger e) throws Exception {
    return certificate(
        new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
            new RSAPublicKey(n, e)));
  }

  private static BigInteger odd(int bits, Random r) {
    return new BigInteger(bits, r).setBit(bits - 1).setBit(0);
  }

  @Test
  void rsaKeysAreDecodedWithoutValidation() throws Exception {
    // BouncyCastle rejects this modulus (it has small factors) after primality tests that take
    // seconds on large moduli. OpenSSL decodes it.
    BigInteger n = odd(16384, new Random(1)).multiply(BigInteger.valueOf(3));
    Cert c = rsaCertificate(n, BigInteger.valueOf(65537));
    RSAKeyParameters key = assertInstanceOf(RSAKeyParameters.class, c.publicKey());
    assertEquals(n, key.getModulus());
  }

  @Test
  void opensslRsaLimits() {
    Random r = new Random(2);
    BigInteger e64 = odd(64, r);
    BigInteger e65 = odd(65, r);
    assertTrue(Authenticode.rsaVerifiable(odd(3072, r), odd(3000, r)));
    assertTrue(Authenticode.rsaVerifiable(odd(16384, r), e64));
    assertFalse(Authenticode.rsaVerifiable(odd(3073, r), e65));
    assertFalse(Authenticode.rsaVerifiable(odd(16385, r), BigInteger.valueOf(3)));
    BigInteger n = odd(2048, r);
    assertFalse(Authenticode.rsaVerifiable(n, n));
  }

  @Test
  void largeRsaExponentIsNotVerified() throws Exception {
    // A modulus without small factors, which BouncyCastle accepted after seconds of primality
    // tests, with an exponent that made each verification take seconds too.
    Random r = new Random(3);
    BigInteger n = BigInteger.ONE;
    for (int i = 0; i < 16; i++) {
      n = n.multiply(BigInteger.probablePrime(1024, r));
    }
    Cert c = rsaCertificate(n, odd(n.bitLength() - 1, r));
    Oids.Md sha256 = Oids.md(NISTObjectIdentifiers.id_sha256.getId());
    byte[] sig = new byte[(n.bitLength() + 7) / 8];
    sig[1] = 1;
    assertTimeout(
        Duration.ofSeconds(1),
        () -> assertFalse(Authenticode.verifySignature(sha256, new byte[32], sig, c)));
  }

  @Test
  void rsaSignaturesStillVerify() throws Exception {
    RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
    gen.init(
        new RSAKeyGenerationParameters(BigInteger.valueOf(65537), new SecureRandom(), 2048, 80));
    AsymmetricCipherKeyPair pair = gen.generateKeyPair();
    RSAKeyParameters pub = (RSAKeyParameters) pair.getPublic();
    byte[] digest = new byte[32];
    new Random(4).nextBytes(digest);
    byte[] digestInfo =
        new DigestInfo(
                new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE), digest)
            .getEncoded(ASN1Encoding.DER);
    PKCS1Encoding signer = new PKCS1Encoding(new RSAEngine());
    signer.init(true, pair.getPrivate());
    byte[] sig = signer.processBlock(digestInfo, 0, digestInfo.length);
    Cert c = rsaCertificate(pub.getModulus(), pub.getExponent());
    Oids.Md sha256 = Oids.md(NISTObjectIdentifiers.id_sha256.getId());
    assertTrue(Authenticode.verifySignature(sha256, digest, sig, c));
    digest[0] ^= 1;
    assertFalse(Authenticode.verifySignature(sha256, digest, sig, c));
  }

  @Test
  void opensslDsaLimits() throws Exception {
    Random r = new Random(5);
    assertTrue(Authenticode.dsaVerifiable(odd(3072, r), odd(256, r)));
    assertFalse(Authenticode.dsaVerifiable(odd(3072, r), odd(512, r)));
    assertFalse(Authenticode.dsaVerifiable(odd(10001, r), odd(256, r)));
    // BouncyCastle's check of y on this key used to take seconds.
    BigInteger p = odd(16384, r);
    BigInteger q = odd(16000, r);
    SubjectPublicKeyInfo key =
        new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(
                X9ObjectIdentifiers.id_dsa, new DSAParameter(p, q, BigInteger.valueOf(3))),
            new ASN1Integer(odd(16000, r)));
    Cert c = certificate(key);
    assertInstanceOf(Cert.UnverifiableKey.class, c.publicKey());
    Oids.Md sha256 = Oids.md(NISTObjectIdentifiers.id_sha256.getId());
    assertFalse(Authenticode.verifySignature(sha256, new byte[32], new byte[8], c));
  }
}
