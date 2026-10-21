package com.paveldan.yara4j.object;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Structure object, a named collection of member objects. */
public final class YStructure extends YObject {
  private final List<YObject> members = new ArrayList<>();
  private final Map<String, YObject> byName = new HashMap<>();

  public YStructure(String identifier) {
    super(identifier);
  }

  @Override
  public Type type() {
    return Type.STRUCTURE;
  }

  /** Returns the member with the given name, or null. */
  public YObject field(String name) {
    return byName.get(name);
  }

  /** Members in declaration order. */
  public List<YObject> members() {
    return Collections.unmodifiableList(members);
  }

  /**
   * Adds a member to the structure.
   *
   * @return false if a member with the same identifier already exists.
   */
  public boolean addMember(YObject member) {
    if (byName.containsKey(member.identifier)) {
      return false;
    }
    member.parent = this;
    members.add(member);
    byName.put(member.identifier, member);
    return true;
  }

  @Override
  public YObject copy() {
    // yr_object_copy walks the member list and prepends each copied member, so the copy has its
    // members in reverse order. This is visible in the output of --print-module-data.
    YStructure c = new YStructure(identifier);
    for (int i = members.size() - 1; i >= 0; i--) {
      c.addMember(members.get(i).copy());
    }
    return c;
  }

  @Override
  void printValue(StringBuilder sb, String indentSpaces, int indent) {
    // libyara keeps members in a linked list where new members are prepended, so they are
    // printed in reverse declaration order.
    for (int i = members.size() - 1; i >= 0; i--) {
      YObject m = members.get(i);
      if (m.type() != Type.FUNCTION) {
        sb.append('\n');
        m.printData(sb, indent + 1, true);
      }
    }
  }
}
