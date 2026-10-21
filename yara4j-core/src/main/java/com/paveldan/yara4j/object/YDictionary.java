package com.paveldan.yara4j.object;

import java.util.ArrayList;
import java.util.List;

/** Dictionary object, maps string keys to copies of a prototype item. */
public final class YDictionary extends YObject {
  YObject prototype;
  private final List<String> keys = new ArrayList<>();
  private final List<YObject> values = new ArrayList<>();

  public YDictionary(String identifier) {
    super(identifier);
  }

  @Override
  public Type type() {
    return Type.DICTIONARY;
  }

  public YObject prototype() {
    return prototype;
  }

  public void setPrototype(YObject prototype) {
    this.prototype = prototype;
    prototype.parent = this;
  }

  public int size() {
    return keys.size();
  }

  public String keyAt(int i) {
    return keys.get(i);
  }

  public YObject valueAt(int i) {
    return values.get(i);
  }

  /** Returns the item for the given key or null. Keys are compared as C strings. */
  public YObject get(String key) {
    return get(key, false);
  }

  YObject get(String key, boolean create) {
    key = cstr(key);
    YObject result = null;
    // libyara doesn't stop at the first match, so with duplicated keys the last one wins.
    for (int i = 0; i < keys.size(); i++) {
      if (keys.get(i).equals(key)) {
        result = values.get(i);
      }
    }
    if (result == null && create) {
      result = prototype.copy();
      put(key, result);
    }
    return result;
  }

  public void put(String key, YObject item) {
    item.parent = this;
    keys.add(cstr(key));
    values.add(item);
  }

  private static String cstr(String s) {
    int z = s.indexOf('\0');
    return z >= 0 ? s.substring(0, z) : s;
  }

  @Override
  public YObject copy() {
    YDictionary c = new YDictionary(identifier);
    c.setPrototype(prototype.copy());
    return c;
  }

  @Override
  void printValue(StringBuilder sb, String indentSpaces, int indent) {
    for (int i = 0; i < keys.size(); i++) {
      sb.append('\n').append(indentSpaces).append('\t').append(keys.get(i));
      values.get(i).printData(sb, indent + 1, false);
    }
  }
}
