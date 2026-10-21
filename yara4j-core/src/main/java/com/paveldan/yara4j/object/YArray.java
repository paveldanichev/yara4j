package com.paveldan.yara4j.object;

import java.util.ArrayList;
import java.util.List;

/** Array object. All items are copies of a prototype item. */
public final class YArray extends YObject {
  YObject prototype;
  private final List<YObject> items = new ArrayList<>();

  public YArray(String identifier) {
    super(identifier);
  }

  @Override
  public Type type() {
    return Type.ARRAY;
  }

  public YObject prototype() {
    return prototype;
  }

  public void setPrototype(YObject prototype) {
    this.prototype = prototype;
    prototype.parent = this;
  }

  /** Number of items, which is the highest index set plus one. */
  public int length() {
    return items.size();
  }

  /** Returns the item at the given index or null. */
  public YObject get(int index) {
    return get(index, false);
  }

  YObject get(int index, boolean create) {
    if (index < 0) {
      return null;
    }
    YObject result = index < items.size() ? items.get(index) : null;
    if (result == null && create) {
      result = prototype.copy();
      set(index, result);
    }
    return result;
  }

  public void set(int index, YObject item) {
    while (items.size() <= index) {
      items.add(null);
    }
    item.parent = this;
    items.set(index, item);
  }

  @Override
  public YObject copy() {
    YArray c = new YArray(identifier);
    c.setPrototype(prototype.copy());
    return c;
  }

  @Override
  void printValue(StringBuilder sb, String indentSpaces, int indent) {
    for (int i = 0; i < items.size(); i++) {
      YObject o = items.get(i);
      if (o != null) {
        sb.append('\n').append(indentSpaces).append("\t[").append(i).append(']');
        o.printData(sb, indent + 1, false);
      }
    }
  }
}
