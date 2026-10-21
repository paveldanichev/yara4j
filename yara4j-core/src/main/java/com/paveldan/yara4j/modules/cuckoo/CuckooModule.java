package com.paveldan.yara4j.modules.cuckoo;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import com.paveldan.yara4j.ErrorCode;
import com.paveldan.yara4j.internal.YaraError;
import com.paveldan.yara4j.module.FunctionCall;
import com.paveldan.yara4j.module.ModuleDeclarations;
import com.paveldan.yara4j.module.Regexp;
import com.paveldan.yara4j.module.ScanContext;
import com.paveldan.yara4j.module.YaraModule;
import com.paveldan.yara4j.object.YObject;
import com.paveldan.yara4j.object.YStructure;
import com.paveldan.yara4j.util.CStrings;

/**
 * The "cuckoo" module. Port of libyara/modules/cuckoo/cuckoo.c. The Cuckoo sandbox JSON report
 * is passed as module data (see {@code Scanner.setModuleData} and {@code
 * ScanCallback.importModule}).
 */
public final class CuckooModule implements YaraModule {

  private static final int METHOD_GET = 0x01;
  private static final int METHOD_POST = 0x02;

  @Override
  public String name() {
    return "cuckoo";
  }

  // jansson helpers

  private static Object get(Object json, String key) {
    if (json instanceof Map) {
      return ((Map<?, ?>) json).get(key);
    }
    return null;
  }

  @SuppressWarnings("unchecked")
  private static List<Object> array(Object json) {
    return json instanceof List ? (List<Object>) json : Collections.emptyList();
  }

  /** json_unpack "s": the string value of a member, or null if missing or not a string. */
  private static byte[] stringMember(Object obj, String key) {
    Object v = get(obj, key);
    return v instanceof byte[] ? (byte[]) v : null;
  }

  /** yr_re_match(context, re, value) > 0 for a C string, false for non-strings. */
  private static boolean matches(FunctionCall c, Regexp re, Object value) {
    if (!(value instanceof byte[])) {
      return false;
    }
    return re.match(c.context(), CStrings.cstr((byte[]) value)) > 0;
  }

  private static boolean equalsIgnoreCase(byte[] s, String other) {
    byte[] cs = CStrings.cstr(s);
    if (cs.length != other.length()) {
      return false;
    }
    for (int i = 0; i < cs.length; i++) {
      int a = cs[i] & 0xFF;
      if (a >= 'A' && a <= 'Z') {
        a += 32;
      }
      if (a != other.charAt(i)) {
        return false;
      }
    }
    return true;
  }

  private static Object dnsLookup(FunctionCall c) {
    Object network = c.parent().getData();
    String fieldName = "domain";
    Object dnsInfo = get(network, "domains");
    if (dnsInfo == null) {
      dnsInfo = get(network, "dns");
      fieldName = "hostname";
    }
    for (Object value : array(dnsInfo)) {
      byte[] ip = stringMember(value, "ip");
      byte[] hostname = stringMember(value, fieldName);
      if (ip != null && hostname != null && matches(c, c.regexpArgument(1), hostname)) {
        return 1L;
      }
    }
    return 0L;
  }

  private static long httpRequest(FunctionCall c, int methods) {
    Object network = c.parent().getData();
    for (Object value : array(get(network, "http"))) {
      byte[] uri = stringMember(value, "uri");
      byte[] method = stringMember(value, "method");
      if (uri != null && method != null) {
        if (((methods & METHOD_GET) != 0 && equalsIgnoreCase(method, "get")
                || (methods & METHOD_POST) != 0 && equalsIgnoreCase(method, "post"))
            && matches(c, c.regexpArgument(1), uri)) {
          return 1;
        }
      }
    }
    return 0;
  }

  private static Object host(FunctionCall c) {
    Object network = c.parent().getData();
    for (Object value : array(get(network, "hosts"))) {
      if (matches(c, c.regexpArgument(1), value)) {
        return 1L;
      }
    }
    return 0L;
  }

  private static Object connection(FunctionCall c, String protocol) {
    Object network = c.parent().getData();
    for (Object value : array(get(network, protocol))) {
      Object dport = get(value, "dport");
      byte[] dst = stringMember(value, "dst");
      if (dport instanceof Long && dst != null) {
        if (matches(c, c.regexpArgument(1), dst)) {
          // json_unpack "i" stores the value in an int.
          if ((long) (int) (long) (Long) dport == c.integerArgument(2)) {
            return 1L;
          }
        }
      }
    }
    return 0L;
  }

  private static Object userAgent(FunctionCall c) {
    Object network = c.parent().getData();
    for (Object value : array(get(network, "http"))) {
      byte[] ua = stringMember(value, "user-agent");
      if (ua != null && matches(c, c.regexpArgument(1), ua)) {
        return 1L;
      }
    }
    return 0L;
  }

  /** registry.key_access, filesystem.file_access and sync.mutex. */
  private static Object listMatch(FunctionCall c) {
    for (Object value : array(c.parent().getData())) {
      if (matches(c, c.regexpArgument(1), value)) {
        return 1L;
      }
    }
    return 0L;
  }

  @Override
  public void declare(ModuleDeclarations d) {
    d.beginStruct("network")
        .declareFunction("dns_lookup", "r", "i", CuckooModule::dnsLookup)
        .declareFunction("http_get", "r", "i", c -> httpRequest(c, METHOD_GET))
        .declareFunction("http_post", "r", "i", c -> httpRequest(c, METHOD_POST))
        .declareFunction("http_request", "r", "i", c -> httpRequest(c, METHOD_GET | METHOD_POST))
        .declareFunction("http_user_agent", "r", "i", CuckooModule::userAgent)
        .declareFunction("host", "r", "i", CuckooModule::host)
        .declareFunction("tcp", "ri", "i", c -> connection(c, "tcp"))
        .declareFunction("udp", "ri", "i", c -> connection(c, "udp"))
        .endStruct("network")
        .beginStruct("registry")
        .declareFunction("key_access", "r", "i", CuckooModule::listMatch)
        .endStruct("registry")
        .beginStruct("filesystem")
        .declareFunction("file_access", "r", "i", CuckooModule::listMatch)
        .endStruct("filesystem")
        .beginStruct("sync")
        .declareFunction("mutex", "r", "i", CuckooModule::listMatch)
        .endStruct("sync");
  }

  @Override
  public void load(ScanContext context, YStructure module, byte[] moduleData) {
    if (moduleData == null) {
      return;
    }
    Object json;
    try {
      json = Json.parse(moduleData);
    } catch (Json.JsonException e) {
      throw new YaraError(ErrorCode.INVALID_MODULE_DATA);
    }
    module.setData(json);
    YObject network = module.lookup("network");
    YObject registry = module.lookup("registry");
    YObject filesystem = module.lookup("filesystem");
    YObject sync = module.lookup("sync");
    network.setData(get(json, "network"));
    Object summary = get(get(json, "behavior"), "summary");
    registry.setData(get(summary, "keys"));
    filesystem.setData(get(summary, "files"));
    sync.setData(get(summary, "mutexes"));
  }

  @Override
  public void unload(YStructure module) {
    module.setData(null);
    for (String s : new String[] {"network", "registry", "filesystem", "sync"}) {
      YObject o = module.lookup(s);
      if (o != null) {
        o.setData(null);
      }
    }
  }
}
