package com.paveldan.yara4j.internal.exec;

import java.nio.ByteBuffer;
import com.paveldan.yara4j.ErrorCode;
import com.paveldan.yara4j.internal.ArrayBacked;
import com.paveldan.yara4j.internal.YaraError;
import com.paveldan.yara4j.internal.ac.AcMatch;
import com.paveldan.yara4j.internal.ac.AhoCorasick;
import com.paveldan.yara4j.internal.compiler.StringFlags;
import com.paveldan.yara4j.internal.re.Re;
import com.paveldan.yara4j.internal.re.ReExec;
import com.paveldan.yara4j.internal.rules.CompiledString;
import com.paveldan.yara4j.module.MemoryBlock;

/**
 * Searches for strings in memory blocks using the Aho-Corasick automaton and verifies the
 * candidate matches. Port of libyara's scan.c and _yr_scanner_scan_mem_block.
 */
public final class ScanEngine {

  /** Events raised during the scan that require a decision from the user. */
  public interface Events {
    /** Too many matches for a string, return true to continue (ignoring further matches). */
    boolean tooManyMatches(CompiledString string);

    /** The scan is being slowed down by a string, return true to continue. */
    boolean tooSlowScanning(CompiledString string);
  }

  private final ExecContext ctx;
  private final byte[] reCode;
  private final int[] transitions;
  private final AcMatch[] matchTable;
  private final Events events;

  /** String whose verification caused the last error. */
  public CompiledString lastErrorString;

  public ScanEngine(ExecContext ctx, Events events) {
    this.ctx = ctx;
    this.reCode = ctx.rules.reCode;
    this.transitions = ctx.rules.ac.transitions;
    this.matchTable = ctx.rules.ac.matches;
    this.events = events;
  }

  /** Scans a memory block (_yr_scanner_scan_mem_block). */
  public void scanBlock(MemoryBlock block) {
    ByteBuffer data = block.data();
    int size = block.size();
    long base = block.base();
    // Reading the backing array directly is noticeably faster than ByteBuffer.get().
    byte[] array = block instanceof ArrayBacked ? ((ArrayBacked) block).array() : null;
    int arrayOffset = array != null ? ((ArrayBacked) block).arrayOffset() : 0;
    int[] t = transitions;
    AcMatch[] mt = matchTable;
    int i = 0;
    int state = AhoCorasick.ROOT_STATE;
    CompiledString reportString = null;
    boolean slow = false;
    while (i < size) {
      if ((i & 4095) == 0 && ctx.deadline != 0) {
        ctx.checkTimeout();
      }
      AcMatch match = mt[state];
      if (match != null) {
        // libyara checks scanner->matches->count, which is the number of matches of the
        // first string in the rule set.
        if (firstStringMatches() >= ExecContext.SLOW_STRING_MATCHES) {
          reportString = match.string;
          slow = true;
        }
        while (match != null) {
          if (match.backtrack <= i) {
            verifyMatch(match, data, size, base, i - match.backtrack);
          }
          match = match.next();
        }
      }
      int index = ((array != null ? array[arrayOffset + i] : data.get(i)) & 0xFF) + 1;
      i++;
      int transition = t[state + index];
      while ((transition & 0x1FF) != index) {
        if (state != AhoCorasick.ROOT_STATE) {
          state = t[state] >>> AhoCorasick.SLOT_OFFSET_BITS;
          transition = t[state + index];
        } else {
          transition = 0;
          break;
        }
      }
      state = transition >>> AhoCorasick.SLOT_OFFSET_BITS;
    }
    AcMatch match = mt[state];
    while (match != null) {
      if (match.backtrack <= i) {
        verifyMatch(match, data, size, base, i - match.backtrack);
      }
      match = match.next();
    }
    if (slow
        && reportString != null
        && firstStringMatches() >= ExecContext.SLOW_STRING_MATCHES
        && firstStringMatches() < ExecContext.MAX_STRING_MATCHES) {
      if (!events.tooSlowScanning(reportString)) {
        throw new YaraError(ErrorCode.TOO_SLOW_SCANNING);
      }
    }
  }

  private int firstStringMatches() {
    return ctx.matches.length > 0 ? ctx.matches[0].count : 0;
  }

  // ---------------------------------------------------------------------------------------------
  // Comparison functions. They return the number of matching bytes, or 0.

  private int xorKey;

  private int xorCompare(ByteBuffer data, int at, int dataSize, byte[] s) {
    if (dataSize < s.length) {
      return 0;
    }
    int k = (data.get(at) ^ s[0]) & 0xFF;
    int i = 0;
    while (i < s.length && data.get(at + i) == (byte) (s[i] ^ k)) {
      i++;
    }
    int result = i == s.length ? i : 0;
    if (result > 0) {
      xorKey = k;
    }
    return result;
  }

  private int xorWcompare(ByteBuffer data, int at, int dataSize, byte[] s) {
    if (dataSize < s.length * 2) {
      return 0;
    }
    int k = (data.get(at) ^ s[0]) & 0xFF;
    int i = 0;
    int p = at;
    while (i < s.length
        && data.get(p) == (byte) (s[i] ^ k)
        && ((data.get(p + 1) & 0xFF) ^ k) == 0) {
      p += 2;
      i++;
    }
    int result = i == s.length ? i * 2 : 0;
    if (result > 0) {
      xorKey = k;
    }
    return result;
  }

  private static int compare(ByteBuffer data, int at, int dataSize, byte[] s) {
    if (dataSize < s.length) {
      return 0;
    }
    int i = 0;
    while (i < s.length && data.get(at + i) == s[i]) {
      i++;
    }
    return i == s.length ? i : 0;
  }

  private static int icompare(ByteBuffer data, int at, int dataSize, byte[] s) {
    if (dataSize < s.length) {
      return 0;
    }
    int i = 0;
    while (i < s.length && Re.lower(data.get(at + i)) == Re.lower(s[i])) {
      i++;
    }
    return i == s.length ? i : 0;
  }

  private static int wcompare(ByteBuffer data, int at, int dataSize, byte[] s) {
    if (dataSize < s.length * 2) {
      return 0;
    }
    int i = 0;
    int p = at;
    while (i < s.length && data.get(p) == s[i] && data.get(p + 1) == 0) {
      p += 2;
      i++;
    }
    return i == s.length ? i * 2 : 0;
  }

  private static int wicompare(ByteBuffer data, int at, int dataSize, byte[] s) {
    if (dataSize < s.length * 2) {
      return 0;
    }
    int i = 0;
    int p = at;
    while (i < s.length && Re.lower(data.get(p)) == Re.lower(s[i]) && data.get(p + 1) == 0) {
      p += 2;
      i++;
    }
    return i == s.length ? i * 2 : 0;
  }

  // ---------------------------------------------------------------------------------------------
  // Match lists

  private static void updateMatchChainLength(
      ExecContext ctx, CompiledString string, Match matchToUpdate, int chainLength) {
    if (matchToUpdate.chainLength == chainLength) {
      return;
    }
    matchToUpdate.chainLength = chainLength;
    if (string.chainedTo == null) {
      return;
    }
    for (Match m = ctx.unconfirmedMatches[string.chainedTo.idx].head; m != null; m = m.next) {
      long endingOffset = m.offset + m.matchLength;
      if (endingOffset + string.chainGapMax >= matchToUpdate.offset
          && endingOffset + string.chainGapMin <= matchToUpdate.offset) {
        updateMatchChainLength(ctx, string.chainedTo, m, chainLength + 1);
      }
    }
  }

  /** Returns false if the list is full (ERROR_TOO_MANY_MATCHES). */
  private boolean addMatchToList(Match match, MatchList list, boolean replaceIfExists) {
    Match insertionPoint = list.tail;
    if (list.count == ExecContext.MAX_STRING_MATCHES) {
      return false;
    }
    while (insertionPoint != null) {
      if (match.base + match.offset == insertionPoint.base + insertionPoint.offset) {
        if (replaceIfExists) {
          insertionPoint.matchLength = match.matchLength;
          insertionPoint.data = match.data;
        }
        return true;
      }
      if (match.base + match.offset > insertionPoint.base + insertionPoint.offset) {
        break;
      }
      insertionPoint = insertionPoint.prev;
    }
    match.prev = insertionPoint;
    if (insertionPoint != null) {
      match.next = insertionPoint.next;
      insertionPoint.next = match;
    } else {
      match.next = list.head;
      list.head = match;
    }
    list.count++;
    list.changed();
    if (match.next != null) {
      match.next.prev = match;
    } else {
      list.tail = match;
    }
    return true;
  }

  private static void removeMatchFromList(Match match, MatchList list) {
    if (match.prev != null) {
      match.prev.next = match.next;
    }
    if (match.next != null) {
      match.next.prev = match.prev;
    }
    if (list.head == match) {
      list.head = match.next;
    }
    if (list.tail == match) {
      list.tail = match.prev;
    }
    list.count--;
    list.changed();
    match.next = null;
    match.prev = null;
  }

  private byte[] copyData(ByteBuffer data, int from, int length) {
    int n = Math.min(length, ctx.maxMatchData);
    if (n <= 0) {
      return null;
    }
    byte[] b = new byte[n];
    for (int i = 0; i < n; i++) {
      b[i] = data.get(from + i);
    }
    return b;
  }

  private static final class TooManyMatches extends RuntimeException {
    private static final long serialVersionUID = 1L;

    TooManyMatches() {
      super(null, null, false, false);
    }
  }

  private void verifyChainedStringMatch(
      CompiledString matchingString,
      ByteBuffer data,
      int matchDataIdx,
      long matchBase,
      long matchOffset,
      int matchLength,
      int xorKey) {
    boolean addMatch = false;
    if (matchingString.chainedTo == null) {
      addMatch = true;
    } else {
      Match match = ctx.unconfirmedMatches[matchingString.idx].head;
      long lowestOffset = match != null ? match.offset : matchOffset;
      match = ctx.unconfirmedMatches[matchingString.chainedTo.idx].head;
      while (match != null) {
        Match nextMatch = match.next;
        long endingOffset = match.offset + match.matchLength;
        if (endingOffset + matchingString.chainGapMax < lowestOffset) {
          removeMatchFromList(match, ctx.unconfirmedMatches[matchingString.chainedTo.idx]);
        } else if (endingOffset + matchingString.chainGapMax >= matchOffset
            && endingOffset + matchingString.chainGapMin <= matchOffset) {
          addMatch = true;
          break;
        }
        match = nextMatch;
      }
    }
    if (!addMatch) {
      return;
    }
    if (matchingString.is(StringFlags.CHAIN_TAIL)) {
      for (Match m = ctx.unconfirmedMatches[matchingString.chainedTo.idx].head;
          m != null;
          m = m.next) {
        long endingOffset = m.offset + m.matchLength;
        if (endingOffset + matchingString.chainGapMax >= matchOffset
            && endingOffset + matchingString.chainGapMin <= matchOffset) {
          updateMatchChainLength(ctx, matchingString.chainedTo, m, 1);
        }
      }
      int fullChainLength = 0;
      CompiledString string = matchingString;
      while (string.chainedTo != null) {
        fullChainLength++;
        string = string.chainedTo;
      }
      Match match = ctx.unconfirmedMatches[string.idx].head;
      while (match != null) {
        Match nextMatch = match.next;
        if (match.chainLength == fullChainLength) {
          removeMatchFromList(match, ctx.unconfirmedMatches[string.idx]);
          match.matchLength = (int) (matchOffset - match.offset + matchLength);
          // The data for the whole match is copied from the start of the first fragment.
          int start = (int) (matchDataIdx - matchOffset + match.offset);
          int n = Math.min(match.matchLength, ctx.maxMatchData);
          byte[] d = new byte[Math.max(n, 0)];
          for (int k = 0; k < n; k++) {
            d[k] = data.get(start + k);
          }
          match.data = d;
          ctx.requiredEval[string.ruleIdx] = true;
          if (!addMatchToList(match, ctx.matches[string.idx], false)) {
            throw new TooManyMatches();
          }
        }
        match = nextMatch;
      }
    } else {
      Match newMatch = new Match();
      newMatch.base = matchBase;
      newMatch.offset = matchOffset;
      newMatch.matchLength = matchLength;
      newMatch.chainLength = 0;
      newMatch.isPrivate = matchingString.isPrivate();
      newMatch.xorKey = xorKey;
      newMatch.data = copyData(data, matchDataIdx, matchLength);
      if (!addMatchToList(newMatch, ctx.unconfirmedMatches[matchingString.idx], false)) {
        throw new TooManyMatches();
      }
    }
  }

  // State shared with the regexp match callback (CALLBACK_ARGS in libyara).
  private CompiledString cbString;
  private ByteBuffer cbData;
  private int cbDataSize;
  private long cbDataBase;
  private int cbForwardMatches;
  private boolean cbFullWord;
  private int cbXorKey;

  private final ReExec.MatchCallback matchCallback = this::matchCallback;

  private static boolean isAlnum(ByteBuffer data, int at) {
    return Re.isAlnum(data.get(at) & 0xFF);
  }

  private void matchCallback(int matchData, int matchLength, int flags) {
    CompiledString string = cbString;
    int matchOffset = matchData;
    matchLength += cbForwardMatches;
    if (cbFullWord) {
      if ((flags & Re.FLAGS_WIDE) != 0) {
        if (matchOffset >= 2
            && cbData.get(matchData - 1) == 0
            && isAlnum(cbData, matchData - 2)) {
          return;
        }
        if (matchOffset + matchLength + 1 < cbDataSize
            && cbData.get(matchData + matchLength + 1) == 0
            && isAlnum(cbData, matchData + matchLength)) {
          return;
        }
      } else {
        if (matchOffset >= 1 && isAlnum(cbData, matchData - 1)) {
          return;
        }
        if (matchOffset + matchLength < cbDataSize && isAlnum(cbData, matchData + matchLength)) {
          return;
        }
      }
    }
    if (string.is(StringFlags.CHAIN_PART)) {
      verifyChainedStringMatch(
          string, cbData, matchData, cbDataBase, matchOffset, matchLength, cbXorKey);
    } else {
      Match newMatch = new Match();
      newMatch.data = copyData(cbData, matchData, matchLength);
      newMatch.base = cbDataBase;
      newMatch.offset = matchOffset;
      newMatch.matchLength = matchLength;
      newMatch.isPrivate = string.isPrivate();
      newMatch.xorKey = cbXorKey;
      ctx.requiredEval[string.ruleIdx] = true;
      if (!addMatchToList(
          newMatch, ctx.matches[string.idx], string.is(StringFlags.GREEDY_REGEXP))) {
        throw new TooManyMatches();
      }
    }
  }

  private void verifyReMatch(
      AcMatch acMatch, ByteBuffer data, int dataSize, long dataBase, int offset) {
    CompiledString string = acMatch.string;
    int flags = 0;
    if (string.is(StringFlags.GREEDY_REGEXP)) {
      flags |= Re.FLAGS_GREEDY;
    }
    if (string.is(StringFlags.NO_CASE)) {
      flags |= Re.FLAGS_NO_CASE;
    }
    if (string.is(StringFlags.DOT_ALL)) {
      flags |= Re.FLAGS_DOT_ALL;
    }
    boolean fast = string.is(StringFlags.FAST_REGEXP);
    ReExec exec = ctx.reExec;
    cbString = string;
    cbData = data;
    cbDataSize = dataSize;
    cbDataBase = dataBase;
    cbForwardMatches = -1;
    cbFullWord = string.is(StringFlags.FULL_WORD);
    cbXorKey = 0;

    if (string.is(StringFlags.ASCII)
        || string.is(StringFlags.BASE64)
        || string.is(StringFlags.BASE64_WIDE)) {
      cbForwardMatches =
          fast
              ? exec.fastExec(
                  reCode, acMatch.forwardCode, data, offset, dataSize - offset, offset, flags, null)
              : exec.exec(
                  reCode,
                  acMatch.forwardCode,
                  data,
                  offset,
                  dataSize - offset,
                  offset,
                  flags,
                  null);
      if (cbForwardMatches != -1 && acMatch.backwardCode != -1) {
        int bflags = flags | Re.FLAGS_BACKWARDS | Re.FLAGS_EXHAUSTIVE;
        if (fast) {
          exec.fastExec(
              reCode,
              acMatch.backwardCode,
              data,
              offset,
              dataSize - offset,
              offset,
              bflags,
              matchCallback);
        } else {
          exec.exec(
              reCode,
              acMatch.backwardCode,
              data,
              offset,
              dataSize - offset,
              offset,
              bflags,
              matchCallback);
        }
      } else if (cbForwardMatches >= 0) {
        matchCallback(offset, 0, flags);
      }
    }
    if (string.is(StringFlags.WIDE)) {
      int wflags = flags | Re.FLAGS_WIDE;
      cbForwardMatches =
          fast
              ? exec.fastExec(
                  reCode,
                  acMatch.forwardCode,
                  data,
                  offset,
                  dataSize - offset,
                  offset,
                  wflags,
                  null)
              : exec.exec(
                  reCode,
                  acMatch.forwardCode,
                  data,
                  offset,
                  dataSize - offset,
                  offset,
                  wflags,
                  null);
      if (cbForwardMatches != -1 && acMatch.backwardCode != -1) {
        int bflags = wflags | Re.FLAGS_BACKWARDS | Re.FLAGS_EXHAUSTIVE;
        if (fast) {
          exec.fastExec(
              reCode,
              acMatch.backwardCode,
              data,
              offset,
              dataSize - offset,
              offset,
              bflags,
              matchCallback);
        } else {
          exec.exec(
              reCode,
              acMatch.backwardCode,
              data,
              offset,
              dataSize - offset,
              offset,
              bflags,
              matchCallback);
        }
      } else if (cbForwardMatches >= 0) {
        matchCallback(offset, 0, flags);
      }
    }
  }

  private void verifyLiteralMatch(
      AcMatch acMatch, ByteBuffer data, int dataSize, long dataBase, int offset) {
    CompiledString string = acMatch.string;
    byte[] s = string.string;
    int flags = 0;
    int forwardMatches = 0;
    xorKey = 0;
    int avail = dataSize - offset;
    if (string.is(StringFlags.FITS_IN_ATOM)) {
      forwardMatches = acMatch.backtrack;
      if (string.is(StringFlags.XOR)) {
        if (string.is(StringFlags.WIDE)) {
          xorWcompare(data, offset, avail, s);
        }
        if (string.is(StringFlags.ASCII)) {
          xorCompare(data, offset, avail, s);
        }
      }
    } else if (string.is(StringFlags.NO_CASE)) {
      if (string.is(StringFlags.ASCII)) {
        forwardMatches = icompare(data, offset, avail, s);
      }
      if (string.is(StringFlags.WIDE) && forwardMatches == 0) {
        forwardMatches = wicompare(data, offset, avail, s);
      }
    } else {
      if (string.is(StringFlags.ASCII)) {
        forwardMatches = compare(data, offset, avail, s);
      }
      if (string.is(StringFlags.WIDE) && forwardMatches == 0) {
        forwardMatches = wcompare(data, offset, avail, s);
      }
      if (string.is(StringFlags.XOR) && forwardMatches == 0) {
        if (string.is(StringFlags.WIDE)) {
          forwardMatches = xorWcompare(data, offset, avail, s);
        }
        if (forwardMatches == 0) {
          forwardMatches = xorCompare(data, offset, avail, s);
        }
      }
    }
    if (forwardMatches == 0) {
      return;
    }
    if (forwardMatches == s.length * 2) {
      flags |= Re.FLAGS_WIDE;
    }
    if (string.is(StringFlags.NO_CASE)) {
      flags |= Re.FLAGS_NO_CASE;
    }
    cbString = string;
    cbData = data;
    cbDataSize = dataSize;
    cbDataBase = dataBase;
    cbForwardMatches = forwardMatches;
    cbFullWord = string.is(StringFlags.FULL_WORD);
    cbXorKey = xorKey;
    matchCallback(offset, 0, flags);
  }

  /** Verifies a match found by the automaton (yr_scan_verify_match). */
  private void verifyMatch(AcMatch acMatch, ByteBuffer data, int dataSize, long dataBase, int offset) {
    CompiledString string = acMatch.string;
    if (dataSize - offset <= 0) {
      return;
    }
    if (ctx.stringsTempDisabled[string.idx]) {
      return;
    }
    if (ctx.fastMode
        && string.is(StringFlags.SINGLE_MATCH)
        && ctx.matches[string.idx].head != null) {
      return;
    }
    if (string.is(StringFlags.FIXED_OFFSET) && string.fixedOffset != dataBase + offset) {
      return;
    }
    try {
      if (string.is(StringFlags.LITERAL)) {
        verifyLiteralMatch(acMatch, data, dataSize, dataBase, offset);
      } else {
        verifyReMatch(acMatch, data, dataSize, dataBase, offset);
      }
    } catch (TooManyMatches e) {
      if (events.tooManyMatches(string)) {
        ctx.stringsTempDisabled[string.idx] = true;
      } else {
        lastErrorString = string;
        throw new YaraError(ErrorCode.TOO_MANY_MATCHES);
      }
    } catch (YaraError e) {
      lastErrorString = string;
      throw e;
    }
  }
}
