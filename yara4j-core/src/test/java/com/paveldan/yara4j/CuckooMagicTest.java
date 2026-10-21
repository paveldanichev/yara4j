package com.paveldan.yara4j;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/** Tests for the cuckoo module and for the magic module without a MagicProvider. */
class CuckooMagicTest {

  private static final String REPORT =
      "{\"network\": {"
          + "\"domains\": [{\"ip\": \"1.2.3.4\", \"domain\": \"evil.example.com\"}],"
          + "\"http\": [{\"uri\": \"http://evil.example.com/a.php\", \"method\": \"POST\","
          + "  \"user-agent\": \"Mozilla/4.0 (yara)\"}],"
          + "\"hosts\": [\"10.0.0.1\", 5],"
          + "\"tcp\": [{\"dst\": \"10.0.0.1\", \"dport\": 443}],"
          + "\"udp\": [{\"dst\": \"8.8.8.8\", \"dport\": 53.0}]},"
          + "\"behavior\": {\"summary\": {"
          + "\"keys\": [\"HKEY_LOCAL_MACHINE\\\\Software\\\\Evil\"],"
          + "\"files\": [\"C:\\\\evil.exe\"],"
          + "\"mutexes\": [\"Global\\\\EvilMutex\\u0000hidden\"]}}}";

  private static int count(String condition, String report) throws Exception {
    Rules rules = YaraCompiler.compile("import \"cuckoo\" rule t { condition: " + condition + " }");
    Scanner s = rules.newScanner();
    if (report != null) {
      s.setModuleData("cuckoo", report.getBytes(StandardCharsets.UTF_8));
    }
    return s.scan(new byte[0]).size();
  }

  @Test
  void network() throws Exception {
    assertEquals(1, count("cuckoo.network.dns_lookup(/evil\\.example/)", REPORT));
    assertEquals(0, count("cuckoo.network.dns_lookup(/good/)", REPORT));
    assertEquals(1, count("cuckoo.network.http_post(/a\\.php/)", REPORT));
    assertEquals(0, count("cuckoo.network.http_get(/a\\.php/)", REPORT));
    assertEquals(1, count("cuckoo.network.http_request(/a\\.php/)", REPORT));
    assertEquals(1, count("cuckoo.network.http_user_agent(/yara/)", REPORT));
    assertEquals(1, count("cuckoo.network.host(/10\\.0\\.0\\.1/)", REPORT));
    assertEquals(1, count("cuckoo.network.tcp(/10\\.0/, 443)", REPORT));
    assertEquals(0, count("cuckoo.network.tcp(/10\\.0/, 80)", REPORT));
    // dport is a real number, json_unpack "i" fails.
    assertEquals(0, count("cuckoo.network.udp(/8\\.8/, 53)", REPORT));
  }

  @Test
  void behavior() throws Exception {
    assertEquals(1, count("cuckoo.registry.key_access(/Software\\\\Evil/)", REPORT));
    assertEquals(1, count("cuckoo.filesystem.file_access(/evil\\.exe$/)", REPORT));
    assertEquals(1, count("cuckoo.sync.mutex(/EvilMutex$/)", REPORT));
    assertEquals(0, count("cuckoo.sync.mutex(/hidden/)", REPORT));
  }

  @Test
  void missingOrInvalidReport() throws Exception {
    assertEquals(0, count("cuckoo.network.host(/./)", null));
    assertEquals(1, count("not cuckoo.network.host(/./)", null));
    YaraException e =
        assertThrows(YaraException.class, () -> count("cuckoo.network.host(/./)", "{\"a\": 01}"));
    assertEquals(ErrorCode.INVALID_MODULE_DATA, e.getErrorCode());
    assertThrows(YaraException.class, () -> count("true", "\"just a string\""));
    assertThrows(YaraException.class, () -> count("true", "{} trailing"));
  }

  @Test
  void magicWithoutProviderIsUndefined() throws Exception {
    Rules rules =
        YaraCompiler.compile(
            "import \"magic\" rule t { condition: not defined magic.type() and "
                + "not defined magic.mime_type() }");
    assertEquals(1, rules.newScanner().scan("%PDF-1.4".getBytes(StandardCharsets.US_ASCII)).size());
  }
}
