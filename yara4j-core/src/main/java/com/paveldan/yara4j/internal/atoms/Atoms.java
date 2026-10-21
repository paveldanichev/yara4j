package com.paveldan.yara4j.internal.atoms;

import com.paveldan.yara4j.internal.compiler.StringFlags;
import com.paveldan.yara4j.internal.re.ReAst;
import com.paveldan.yara4j.internal.re.ReNode;

/**
 * Atom extraction from strings, regexps and hex strings. Port of libyara's atoms.c.
 *
 * <p>Atoms are short substrings (up to 4 bytes) that must appear in the scanned data for a
 * string to match. They are added to an Aho-Corasick automaton, and only when an atom is found
 * the full string is verified.
 */
public final class Atoms {
  public static final int MAX_ATOM_LENGTH = 4;
  public static final int MAX_ATOM_QUALITY = 255;
  public static final int MIN_ATOM_QUALITY = 0;
  public static final int QUALITY_WARNING_THRESHOLD = MAX_ATOM_QUALITY - 22 * MAX_ATOM_LENGTH + 38;

  private Atoms() {}

  /** An atom with its mask. */
  public static final class Atom {
    public int length;
    public final int[] bytes = new int[MAX_ATOM_LENGTH];
    public final int[] mask = new int[MAX_ATOM_LENGTH];

    void copyFrom(Atom o) {
      length = o.length;
      System.arraycopy(o.bytes, 0, bytes, 0, MAX_ATOM_LENGTH);
      System.arraycopy(o.mask, 0, mask, 0, MAX_ATOM_LENGTH);
    }

    public byte[] toBytes() {
      byte[] b = new byte[length];
      for (int i = 0; i < length; i++) {
        b[i] = (byte) bytes[i];
      }
      return b;
    }
  }

  /** Item in a linked list of atoms (YR_ATOM_LIST_ITEM). */
  public static final class AtomListItem {
    public final Atom atom = new Atom();
    public int backtrack;
    public int forwardCodeRef = -1;
    public int backwardCodeRef = -1;
    public AtomListItem next;

    AtomListItem cloneItem() {
      AtomListItem c = new AtomListItem();
      c.atom.copyFrom(atom);
      c.backtrack = backtrack;
      c.forwardCodeRef = forwardCodeRef;
      c.backwardCodeRef = backwardCodeRef;
      c.next = next;
      return c;
    }
  }

  /** Computes the quality of an atom. */
  public interface QualityFunction {
    int quality(Atom atom);
  }

  /** The default heuristic quality function (yr_atoms_heuristic_quality). */
  public static final QualityFunction HEURISTIC = Atoms::heuristicQuality;

  /** Result of an atom extraction. */
  public static final class Extraction {
    public AtomListItem atoms;
    public int minQuality;
  }

  public static int heuristicQuality(Atom atom) {
    boolean[] seen = new boolean[256];
    int quality = 0;
    int uniqueBytes = 0;
    for (int i = 0; i < atom.length; i++) {
      switch (atom.mask[i]) {
        case 0x00:
          quality -= 10;
          break;
        case 0x0F:
        case 0xF0:
          quality += 4;
          break;
        case 0xFF:
          switch (atom.bytes[i]) {
            case 0x00:
            case 0x20:
            case 0xCC:
            case 0xFF:
              quality += 12;
              break;
            default:
              int l = lower(atom.bytes[i]);
              if (l >= 'a' && l <= 'z') {
                quality += 18;
              } else {
                quality += 20;
              }
          }
          if (!seen[atom.bytes[i]]) {
            seen[atom.bytes[i]] = true;
            uniqueBytes++;
          }
          break;
        default:
          break;
      }
    }
    if (uniqueBytes == 1 && (seen[0x00] || seen[0x20] || seen[0x90] || seen[0xCC] || seen[0xFF])) {
      quality -= 10 * atom.length;
    } else {
      quality += 2 * uniqueBytes;
    }
    return MAX_ATOM_QUALITY - 22 * MAX_ATOM_LENGTH + quality;
  }

  private static int lower(int c) {
    return (c >= 'A' && c <= 'Z') ? c + 32 : c;
  }

  /** Quality function based on a quality table (yr_atoms_table_quality). */
  public static QualityFunction tableQuality(final byte[] table) {
    final int entries = table.length / (MAX_ATOM_LENGTH + 1);
    return atom -> {
      int begin = 0;
      int end = entries;
      while (end > begin) {
        int middle = begin + (end - begin) / 2;
        int c = cmp(table, middle, atom);
        if (c < 0) {
          begin = middle + 1;
        } else if (c > 0) {
          end = middle;
        } else {
          int i = middle + 1;
          int quality = table[middle * 5 + 4] & 0xFF;
          int minQuality = quality;
          while (i < end && cmp(table, i, atom) == 0) {
            minQuality = Math.min(minQuality, table[i * 5 + 4] & 0xFF);
            i++;
          }
          i = middle - 1;
          while (i >= begin && cmp(table, i, atom) == 0) {
            minQuality = Math.min(minQuality, table[i * 5 + 4] & 0xFF);
            i--;
          }
          return minQuality >> (MAX_ATOM_LENGTH - atom.length);
        }
      }
      return MAX_ATOM_QUALITY;
    };
  }

  private static int cmp(byte[] table, int entry, Atom a2) {
    int result = 0;
    int i = 0;
    while (result == 0 && i < a2.length) {
      result = ((table[entry * 5 + i] & 0xFF) & a2.mask[i]) - a2.bytes[i];
      i++;
    }
    return result;
  }

  private static AtomListItem concat(AtomListItem list1, AtomListItem list2) {
    if (list1 == null) {
      return list2;
    }
    AtomListItem item = list1;
    while (item.next != null) {
      item = item.next;
    }
    item.next = list2;
    return list1;
  }

  /**
   * Trims leading and trailing unknown bytes (mask 0x00) from an atom. Returns the number of
   * bytes trimmed from the beginning.
   */
  static int trim(Atom atom) {
    int mask00 = 0;
    int maskFF = 0;
    int trimLeft = 0;
    while (trimLeft < atom.length && atom.mask[trimLeft] == 0) {
      trimLeft++;
    }
    while (atom.length > trimLeft && atom.mask[atom.length - 1] == 0) {
      atom.length--;
    }
    atom.length -= trimLeft;
    if (atom.length == 0) {
      return 0;
    }
    for (int i = 0; i < atom.length; i++) {
      if (atom.mask[trimLeft + i] == 0xFF) {
        maskFF++;
      } else if (atom.mask[trimLeft + i] == 0x00) {
        mask00++;
      }
    }
    if (mask00 >= maskFF) {
      atom.length = 1;
    }
    if (trimLeft == 0) {
      return 0;
    }
    for (int i = 0; i < MAX_ATOM_LENGTH - trimLeft; i++) {
      atom.bytes[i] = atom.bytes[trimLeft + i];
      atom.mask[i] = atom.mask[trimLeft + i];
    }
    return trimLeft;
  }

  // ---------------------------------------------------------------------------------------------
  // Atom trees

  private static final int TREE_LEAF = 1;
  private static final int TREE_AND = 2;
  private static final int TREE_OR = 3;

  private static final class TreeNode {
    final int type;
    final Atom atom = new Atom();
    final ReNode[] reNodes = new ReNode[MAX_ATOM_LENGTH];
    TreeNode nextSibling;
    TreeNode childrenHead;
    TreeNode childrenTail;

    TreeNode(int type) {
      this.type = type;
    }

    void append(TreeNode node) {
      if (childrenHead == null) {
        childrenHead = node;
      }
      if (childrenTail != null) {
        childrenTail.nextSibling = node;
      }
      childrenTail = node;
    }
  }

  private static final class ChooseResult {
    AtomListItem atoms;
    int quality;
  }

  private static ChooseResult choose(QualityFunction q, TreeNode node) {
    ChooseResult r = new ChooseResult();
    r.quality = MIN_ATOM_QUALITY;
    switch (node.type) {
      case TREE_LEAF:
        {
          AtomListItem item = new AtomListItem();
          item.atom.copyFrom(node.atom);
          int shift = trim(item.atom);
          if (item.atom.length > 0) {
            item.forwardCodeRef = node.reNodes[shift].forwardCodeRef;
            item.backwardCodeRef = node.reNodes[shift].backwardCodeRef;
            item.backtrack = 0;
            item.next = null;
            r.atoms = item;
            r.quality = q.quality(item.atom);
          }
          break;
        }
      case TREE_OR:
        {
          int maxQuality = MIN_ATOM_QUALITY;
          TreeNode child = node.childrenHead;
          while (child != null) {
            ChooseResult c = choose(q, child);
            if (c.quality > maxQuality) {
              maxQuality = c.quality;
              r.atoms = c.atoms;
            }
            if (maxQuality == MAX_ATOM_QUALITY) {
              break;
            }
            child = child.nextSibling;
          }
          r.quality = maxQuality;
          break;
        }
      case TREE_AND:
        {
          int minQuality = MAX_ATOM_QUALITY;
          TreeNode child = node.childrenHead;
          while (child != null) {
            ChooseResult c = choose(q, child);
            if (c.quality < minQuality) {
              minQuality = c.quality;
            }
            if (c.atoms != null) {
              AtomListItem tail = c.atoms;
              while (tail.next != null) {
                tail = tail.next;
              }
              tail.next = r.atoms;
              r.atoms = c.atoms;
            }
            child = child.nextSibling;
          }
          r.quality = minQuality;
          break;
        }
      default:
        break;
    }
    return r;
  }

  private static AtomListItem caseInsensitive(AtomListItem atoms) {
    AtomListItem result = null;
    AtomListItem atom = atoms;
    while (atom != null) {
      int[][] combinations = caseCombinations(atom.atom.bytes, atom.atom.length);
      for (int[] comb : combinations) {
        AtomListItem na = new AtomListItem();
        for (int i = 0; i < comb.length; i++) {
          na.atom.bytes[i] = comb[i];
          na.atom.mask[i] = 0xFF;
        }
        na.atom.length = comb.length;
        na.forwardCodeRef = atom.forwardCodeRef;
        na.backwardCodeRef = atom.backwardCodeRef;
        na.backtrack = atom.backtrack;
        na.next = result;
        result = na;
      }
      atom = atom.next;
    }
    return result;
  }

  /**
   * Port of _yr_atoms_case_combinations: returns the case combinations in the same order libyara
   * writes them into its output buffer.
   */
  private static int[][] caseCombinations(int[] atom, int length) {
    java.util.List<int[]> out = new java.util.ArrayList<>();
    caseCombinations(atom.clone(), length, 0, out);
    return out.toArray(new int[0][]);
  }

  private static void caseCombinations(
      int[] atom, int length, int offset, java.util.List<int[]> out) {
    if (offset + 1 < length) {
      caseCombinations(atom, length, offset + 1, out);
    }
    int c = atom[offset];
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
      int[] newAtom = java.util.Arrays.copyOf(atom, length);
      if (c >= 'a' && c <= 'z') {
        newAtom[offset] -= 32;
      } else {
        newAtom[offset] += 32;
      }
      out.add(newAtom);
      if (offset + 1 < length) {
        caseCombinations(newAtom, length, offset + 1, out);
      }
    }
  }

  private static AtomListItem xor(AtomListItem atoms, int min, int max) {
    AtomListItem result = null;
    AtomListItem atom = atoms;
    while (atom != null) {
      for (int j = min; j <= max; j++) {
        AtomListItem na = new AtomListItem();
        for (int i = 0; i < atom.atom.length; i++) {
          na.atom.bytes[i] = (atom.atom.bytes[i] ^ j) & 0xFF;
          na.atom.mask[i] = 0xFF;
        }
        na.atom.length = Math.min(atom.atom.length, MAX_ATOM_LENGTH);
        na.forwardCodeRef = atom.forwardCodeRef;
        na.backwardCodeRef = atom.backwardCodeRef;
        na.backtrack = atom.backtrack;
        na.next = result;
        result = na;
      }
      atom = atom.next;
    }
    return result;
  }

  private static AtomListItem wide(AtomListItem atoms) {
    AtomListItem result = null;
    AtomListItem atom = atoms;
    while (atom != null) {
      AtomListItem na = new AtomListItem();
      for (int i = 0; i < MAX_ATOM_LENGTH; i++) {
        na.atom.bytes[i] = 0;
        na.atom.mask[i] = 0xFF;
      }
      for (int i = 0; i < atom.atom.length; i++) {
        if (i * 2 < MAX_ATOM_LENGTH) {
          na.atom.bytes[i * 2] = atom.atom.bytes[i];
        } else {
          break;
        }
      }
      na.atom.length = Math.min(atom.atom.length * 2, MAX_ATOM_LENGTH);
      na.forwardCodeRef = atom.forwardCodeRef;
      na.backwardCodeRef = atom.backwardCodeRef;
      na.backtrack = atom.backtrack * 2;
      na.next = result;
      result = na;
      atom = atom.next;
    }
    return result;
  }

  private static final class StackItem {
    final ReNode reNode;
    final TreeNode newAppendingNode;

    StackItem(ReNode reNode, TreeNode newAppendingNode) {
      this.reNode = reNode;
      this.newAppendingNode = newAppendingNode;
    }
  }

  private static void makeAtom(Atom atom, int n, ReNode[] nodes) {
    atom.length = n;
    for (int i = 0; i < n; i++) {
      atom.bytes[i] = nodes[i].value & 0xFF;
      atom.mask[i] = nodes[i].mask & 0xFF;
    }
  }

  private static void extractFromRe(QualityFunction q, ReAst reAst, TreeNode appendingNode) {
    java.util.ArrayDeque<StackItem> stack = new java.util.ArrayDeque<>();
    Atom atom = new Atom();
    Atom bestAtom = new Atom();
    int bestQuality = -1;
    int n = 0;
    ReNode[] recentReNodes = new ReNode[MAX_ATOM_LENGTH];
    ReNode[] bestAtomReNodes = new ReNode[MAX_ATOM_LENGTH];
    TreeNode currentAppendingNode = null;

    stack.push(new StackItem(null, appendingNode));
    stack.push(new StackItem(reAst.root, appendingNode));

    while (!stack.isEmpty()) {
      StackItem si = stack.pop();
      if (si.newAppendingNode != null) {
        if (n > 0) {
          makeAtom(atom, n, recentReNodes);
          int shift = trim(atom);
          int quality = q.quality(atom);
          TreeNode leaf = new TreeNode(TREE_LEAF);
          if (quality > bestQuality) {
            leaf.atom.copyFrom(atom);
            for (int i = 0; i < MAX_ATOM_LENGTH - shift; i++) {
              leaf.reNodes[i] = recentReNodes[i + shift];
            }
          } else {
            leaf.atom.copyFrom(bestAtom);
            System.arraycopy(bestAtomReNodes, 0, leaf.reNodes, 0, MAX_ATOM_LENGTH);
          }
          currentAppendingNode.append(leaf);
          n = 0;
        }
        currentAppendingNode = si.newAppendingNode;
        bestQuality = -1;
      }
      if (si.reNode == null) {
        continue;
      }
      ReNode re = si.reNode;
      switch (re.type) {
        case ReNode.LITERAL:
        case ReNode.MASKED_LITERAL:
        case ReNode.ANY:
          if (n < MAX_ATOM_LENGTH) {
            recentReNodes[n] = re;
            bestAtomReNodes[n] = re;
            bestAtom.bytes[n] = re.value & 0xFF;
            bestAtom.mask[n] = re.mask & 0xFF;
            bestAtom.length = ++n;
          } else if (bestQuality < MAX_ATOM_QUALITY) {
            makeAtom(atom, n, recentReNodes);
            int shift = trim(atom);
            int quality = q.quality(atom);
            if (quality > bestQuality) {
              for (int i = 0; i < atom.length; i++) {
                bestAtom.bytes[i] = atom.bytes[i];
                bestAtom.mask[i] = atom.mask[i];
                bestAtomReNodes[i] = recentReNodes[i + shift];
              }
              bestAtom.length = atom.length;
              bestQuality = quality;
            }
            for (int i = 1; i < MAX_ATOM_LENGTH; i++) {
              recentReNodes[i - 1] = recentReNodes[i];
            }
            recentReNodes[MAX_ATOM_LENGTH - 1] = re;
          }
          break;
        case ReNode.CONCAT:
          {
            ReNode child = re.childrenTail;
            while (child != null) {
              stack.push(new StackItem(child, null));
              child = child.prevSibling;
            }
            break;
          }
        case ReNode.ALT:
          {
            TreeNode andNode = new TreeNode(TREE_AND);
            TreeNode leftNode = new TreeNode(TREE_OR);
            TreeNode rightNode = new TreeNode(TREE_OR);
            andNode.childrenHead = leftNode;
            andNode.childrenTail = rightNode;
            leftNode.nextSibling = rightNode;
            currentAppendingNode.append(andNode);
            stack.push(new StackItem(null, currentAppendingNode));
            stack.push(new StackItem(re.childrenTail, rightNode));
            stack.push(new StackItem(re.childrenHead, leftNode));
            break;
          }
        case ReNode.PLUS:
          stack.push(new StackItem(null, currentAppendingNode));
          stack.push(new StackItem(re.childrenHead, null));
          break;
        case ReNode.RANGE:
          {
            stack.push(new StackItem(null, currentAppendingNode));
            int count = Math.min(re.start(), MAX_ATOM_LENGTH);
            for (int i = 0; i < count; i++) {
              stack.push(new StackItem(re.childrenHead, null));
            }
            break;
          }
        case ReNode.RANGE_ANY:
        case ReNode.STAR:
        case ReNode.CLASS:
        case ReNode.WORD_CHAR:
        case ReNode.NON_WORD_CHAR:
        case ReNode.SPACE:
        case ReNode.NON_SPACE:
        case ReNode.DIGIT:
        case ReNode.NON_DIGIT:
        case ReNode.EMPTY:
        case ReNode.ANCHOR_START:
        case ReNode.ANCHOR_END:
        case ReNode.WORD_BOUNDARY:
        case ReNode.NON_WORD_BOUNDARY:
        case ReNode.NOT_LITERAL:
        case ReNode.MASKED_NOT_LITERAL:
          stack.push(new StackItem(null, currentAppendingNode));
          break;
        default:
          throw new IllegalStateException("unexpected node type " + re.type);
      }
    }
  }

  private static void expandWildcards(AtomListItem atoms) {
    AtomListItem atom = atoms;
    while (atom != null) {
      boolean expanded = false;
      for (int i = 0; i < atom.atom.length; i++) {
        int s;
        int e;
        int incr = 1;
        switch (atom.atom.mask[i]) {
          case 0x00:
            expanded = true;
            s = 0x00;
            e = 0xFF;
            break;
          case 0x0F:
            expanded = true;
            s = atom.atom.bytes[i];
            e = atom.atom.bytes[i] | 0xF0;
            incr = 0x10;
            break;
          case 0xF0:
            expanded = true;
            s = atom.atom.bytes[i];
            e = atom.atom.bytes[i] | 0x0F;
            break;
          default:
            s = 0;
            e = 0;
        }
        if (s != e) {
          atom.atom.bytes[i] = s & 0xFF;
          atom.atom.mask[i] = 0xFF;
        }
        AtomListItem prevAtom = atom;
        AtomListItem nextAtom = atom.next;
        for (int a = s + incr; a <= e; a += incr) {
          AtomListItem na = atom.cloneItem();
          na.atom.bytes[i] = a & 0xFF;
          na.atom.mask[i] = 0xFF;
          na.next = nextAtom;
          prevAtom.next = na;
          prevAtom = na;
        }
      }
      if (!expanded) {
        atom = atom.next;
      }
    }
  }

  /** Extracts atoms from a regexp or hex string AST (yr_atoms_extract_from_re). */
  public static Extraction extractFromRe(QualityFunction q, ReAst reAst, int modifierFlags) {
    TreeNode root = new TreeNode(TREE_OR);
    extractFromRe(q, reAst, root);
    ChooseResult c = choose(q, root);
    Extraction r = new Extraction();
    r.atoms = c.atoms;
    r.minQuality = c.quality;
    expandWildcards(r.atoms);
    if ((modifierFlags & StringFlags.WIDE) != 0
        && (modifierFlags & (StringFlags.BASE64 | StringFlags.BASE64_WIDE)) == 0) {
      AtomListItem wideAtoms = wide(r.atoms);
      if ((modifierFlags & StringFlags.ASCII) != 0) {
        r.atoms = concat(r.atoms, wideAtoms);
      } else {
        r.atoms = wideAtoms;
      }
    }
    if ((modifierFlags & StringFlags.NO_CASE) != 0) {
      r.atoms = concat(r.atoms, caseInsensitive(r.atoms));
    }
    return r;
  }

  /** Extracts atoms from a literal string (yr_atoms_extract_from_string). */
  public static Extraction extractFromString(
      QualityFunction q, byte[] string, int modifierFlags, int xorMin, int xorMax) {
    AtomListItem item = new AtomListItem();
    item.backtrack = 0;
    item.atom.length = Math.min(string.length, MAX_ATOM_LENGTH);
    for (int i = 0; i < item.atom.length; i++) {
      item.atom.bytes[i] = string[i] & 0xFF;
      item.atom.mask[i] = 0xFF;
    }
    int maxQuality = q.quality(item.atom);
    Atom atom = new Atom();
    atom.length = MAX_ATOM_LENGTH;
    for (int i = 0; i < MAX_ATOM_LENGTH; i++) {
      atom.mask[i] = 0xFF;
    }
    for (int i = MAX_ATOM_LENGTH; i < string.length && maxQuality < MAX_ATOM_QUALITY; i++) {
      atom.length = MAX_ATOM_LENGTH;
      for (int j = 0; j < MAX_ATOM_LENGTH; j++) {
        atom.bytes[j] = string[i - MAX_ATOM_LENGTH + 1 + j] & 0xFF;
      }
      int quality = q.quality(atom);
      if (quality > maxQuality) {
        item.atom.copyFrom(atom);
        item.backtrack = i - MAX_ATOM_LENGTH + 1;
        maxQuality = quality;
      }
    }
    Extraction r = new Extraction();
    r.atoms = item;
    r.minQuality = maxQuality;
    if ((modifierFlags & StringFlags.WIDE) != 0) {
      AtomListItem wideAtoms = wide(r.atoms);
      if ((modifierFlags & StringFlags.ASCII) != 0) {
        r.atoms = concat(r.atoms, wideAtoms);
      } else {
        r.atoms = wideAtoms;
      }
    }
    if ((modifierFlags & StringFlags.NO_CASE) != 0) {
      r.atoms = concat(r.atoms, caseInsensitive(r.atoms));
    }
    if ((modifierFlags & StringFlags.XOR) != 0) {
      r.atoms = xor(r.atoms, xorMin, xorMax);
    }
    for (AtomListItem it = r.atoms; it != null; it = it.next) {
      int quality = q.quality(it.atom);
      if (quality < r.minQuality) {
        r.minQuality = quality;
      }
    }
    return r;
  }
}
