package com.paveldan.yara4j.internal.re;

import java.nio.ByteBuffer;
import java.util.Arrays;
import com.paveldan.yara4j.ErrorCode;
import com.paveldan.yara4j.internal.YaraError;

/**
 * Regular expression matching engine based on Thompson's algorithm. Port of yr_re_exec and
 * yr_re_fast_exec from libyara's re.c. An instance holds the fiber pools and must not be used by
 * more than one thread at a time.
 */
public final class ReExec {

  /** Receives matches found when executing with FLAGS_EXHAUSTIVE. */
  public interface MatchCallback {
    /**
     * @param matchStart absolute index of the first matching byte within the data buffer.
     * @param matchLength number of matching bytes.
     * @param flags flags used for the match.
     */
    void onMatch(int matchStart, int matchLength, int flags);
  }

  private static final class Fiber {
    int ip;
    int sp;
    int rc;
    Fiber prev;
    Fiber next;
    char[] stack = new char[4];

    void push(int v) {
      if (sp + 1 >= stack.length) {
        stack = Arrays.copyOf(stack, Math.min(stack.length * 2, Re.MAX_STACK));
      }
      stack[++sp] = (char) v;
    }
  }

  private static final class FiberList {
    Fiber head;
    Fiber tail;
  }

  // Fiber pool.
  private int fiberCount;
  private final FiberList pool = new FiberList();

  // Fast exec position pool.
  private static final class Position {
    int input;
    int round;
    Position prev;
    Position next;
  }

  private Position positionPool;

  private Fiber fiberCreate() {
    Fiber fiber;
    if (pool.head != null) {
      fiber = pool.head;
      pool.head = fiber.next;
      if (pool.tail == fiber) {
        pool.tail = null;
      }
    } else {
      if (fiberCount == Re.MAX_FIBERS) {
        throw new YaraError(ErrorCode.TOO_MANY_RE_FIBERS);
      }
      fiber = new Fiber();
      fiberCount++;
    }
    fiber.ip = -1;
    fiber.sp = -1;
    fiber.rc = -1;
    fiber.next = null;
    fiber.prev = null;
    return fiber;
  }

  private static void fiberAppend(FiberList list, Fiber fiber) {
    fiber.prev = list.tail;
    if (list.tail != null) {
      list.tail.next = fiber;
    }
    list.tail = fiber;
    if (list.head == null) {
      list.head = fiber;
    }
  }

  private static boolean fiberExists(FiberList list, Fiber target, Fiber last) {
    if (last == null) {
      return false;
    }
    Fiber fiber = list.head;
    while (fiber != last.next) {
      if (fiber.ip == target.ip && fiber.sp == target.sp && fiber.rc == target.rc) {
        boolean equal = true;
        for (int i = 0; i <= fiber.sp; i++) {
          if (fiber.stack[i] != target.stack[i]) {
            equal = false;
            break;
          }
        }
        if (equal) {
          return true;
        }
      }
      fiber = fiber.next;
    }
    return false;
  }

  private Fiber fiberSplit(FiberList list, Fiber fiber) {
    Fiber nf = fiberCreate();
    nf.sp = fiber.sp;
    nf.ip = fiber.ip;
    nf.rc = fiber.rc;
    if (nf.stack.length < fiber.stack.length) {
      nf.stack = new char[fiber.stack.length];
    }
    System.arraycopy(fiber.stack, 0, nf.stack, 0, fiber.sp + 1);
    nf.next = fiber.next;
    nf.prev = fiber;
    if (fiber.next != null) {
      fiber.next.prev = nf;
    }
    fiber.next = nf;
    if (list.tail == fiber) {
      list.tail = nf;
    }
    return nf;
  }

  private Fiber fiberKill(FiberList list, Fiber fiber) {
    Fiber nextFiber = fiber.next;
    if (fiber.prev != null) {
      fiber.prev.next = nextFiber;
    }
    if (nextFiber != null) {
      nextFiber.prev = fiber.prev;
    }
    if (pool.tail != null) {
      pool.tail.next = fiber;
    }
    if (list.tail == fiber) {
      list.tail = fiber.prev;
    }
    if (list.head == fiber) {
      list.head = nextFiber;
    }
    fiber.next = null;
    fiber.prev = pool.tail;
    pool.tail = fiber;
    if (pool.head == null) {
      pool.head = fiber;
    }
    return nextFiber;
  }

  private void fiberKillTail(FiberList list, Fiber fiber) {
    Fiber prevFiber = fiber.prev;
    if (prevFiber != null) {
      prevFiber.next = null;
    }
    fiber.prev = pool.tail;
    if (pool.tail != null) {
      pool.tail.next = fiber;
    }
    pool.tail = list.tail;
    list.tail = prevFiber;
    if (list.head == fiber) {
      list.head = null;
    }
    if (pool.head == null) {
      pool.head = fiber;
    }
  }

  private void fiberKillAll(FiberList list) {
    if (list.head != null) {
      fiberKillTail(list, list.head);
    }
  }

  private static int u16(byte[] code, int at) {
    return (code[at] & 0xFF) | (code[at + 1] & 0xFF) << 8;
  }

  private static int i16(byte[] code, int at) {
    return (short) u16(code, at);
  }

  private static int i32(byte[] code, int at) {
    return (code[at] & 0xFF)
        | (code[at + 1] & 0xFF) << 8
        | (code[at + 2] & 0xFF) << 16
        | (code[at + 3] & 0xFF) << 24;
  }

  // Arrays used by fiberSync for tracking executed splits, one per recursion level.
  private int[][] splitsCache = new int[4][];
  private int syncDepth;

  private void fiberSync(FiberList list, Fiber fiberToSync, byte[] code) {
    if (syncDepth == splitsCache.length) {
      splitsCache = Arrays.copyOf(splitsCache, syncDepth * 2);
    }
    int[] splitsExecuted = splitsCache[syncDepth];
    if (splitsExecuted == null) {
      splitsExecuted = splitsCache[syncDepth] = new int[Re.MAX_SPLIT_ID];
    }
    syncDepth++;
    try {
      fiberSync(list, fiberToSync, code, splitsExecuted);
    } finally {
      syncDepth--;
    }
  }

  private void fiberSync(FiberList list, Fiber fiberToSync, byte[] code, int[] splitsExecuted) {
    int splitsExecutedCount = 0;
    Fiber fiber = fiberToSync;
    Fiber last = fiberToSync.next;
    while (fiber != last) {
      int opcode = code[fiber.ip] & 0xFF;
      switch (opcode) {
        case Re.OP_SPLIT_A:
        case Re.OP_SPLIT_B:
          {
            int splitId = code[fiber.ip + 1] & 0xFF;
            boolean alreadyExecuted = false;
            for (int i = 0; i < splitsExecutedCount; i++) {
              if (splitId == splitsExecuted[i]) {
                alreadyExecuted = true;
                break;
              }
            }
            if (alreadyExecuted) {
              fiber = fiberKill(list, fiber);
            } else {
              Fiber branchA = fiber;
              Fiber branchB = fiberSplit(list, branchA);
              if (opcode == Re.OP_SPLIT_B) {
                Fiber t = branchA;
                branchA = branchB;
                branchB = t;
              }
              branchA.ip += 4;
              branchB.ip += i16(code, branchB.ip + 2);
              if (splitsExecutedCount >= Re.MAX_SPLIT_ID) {
                throw new YaraError(ErrorCode.INTERNAL_FATAL_ERROR);
              }
              splitsExecuted[splitsExecutedCount++] = splitId;
            }
            break;
          }
        case Re.OP_REPEAT_START_GREEDY:
        case Re.OP_REPEAT_START_UNGREEDY:
          {
            int min = u16(code, fiber.ip + 1);
            int offset = i32(code, fiber.ip + 5);
            Fiber branchA = fiber;
            if (min == 0) {
              Fiber branchB = fiberSplit(list, branchA);
              if (opcode == Re.OP_REPEAT_START_UNGREEDY) {
                Fiber t = branchA;
                branchA = branchB;
                branchB = t;
              }
              branchB.ip += offset;
            }
            if (branchA.sp >= Re.MAX_STACK - 1) {
              throw new YaraError(ErrorCode.INTERNAL_FATAL_ERROR);
            }
            branchA.push(0);
            branchA.ip += 1 + Re.REPEAT_ARGS_SIZE;
            break;
          }
        case Re.OP_REPEAT_END_GREEDY:
        case Re.OP_REPEAT_END_UNGREEDY:
          {
            int min = u16(code, fiber.ip + 1);
            int max = u16(code, fiber.ip + 3);
            int offset = i32(code, fiber.ip + 5);
            if (fiber.sp < 0) {
              throw new YaraError(ErrorCode.INTERNAL_FATAL_ERROR);
            }
            fiber.stack[fiber.sp]++;
            if (fiber.stack[fiber.sp] < min) {
              fiber.ip += offset;
              break;
            }
            Fiber branchA = fiber;
            if (fiber.stack[fiber.sp] < max) {
              Fiber branchB = fiberSplit(list, branchA);
              if (opcode == Re.OP_REPEAT_END_GREEDY) {
                Fiber t = branchA;
                branchA = branchB;
                branchB = t;
              }
              branchB.ip += offset;
            }
            branchA.sp--;
            branchA.ip += 1 + Re.REPEAT_ARGS_SIZE;
            break;
          }
        case Re.OP_REPEAT_ANY_GREEDY:
        case Re.OP_REPEAT_ANY_UNGREEDY:
          {
            int min = u16(code, fiber.ip + 1);
            int max = u16(code, fiber.ip + 3);
            if (fiber.rc == -1) {
              fiber.rc = 0;
            }
            if (fiber.rc < min) {
              fiber.rc++;
              fiber = fiber.next;
            } else if (fiber.rc < max) {
              Fiber next = fiber.next;
              Fiber branchA = fiber;
              Fiber branchB = fiberSplit(list, branchA);
              if (opcode == Re.OP_REPEAT_ANY_UNGREEDY) {
                Fiber t = branchA;
                branchA = branchB;
                branchB = t;
              }
              branchA.rc++;
              branchB.ip += 1 + Re.REPEAT_ANY_ARGS_SIZE;
              branchB.rc = -1;
              fiberSync(list, branchB, code);
              fiber = next;
            } else {
              fiber.ip += 1 + Re.REPEAT_ANY_ARGS_SIZE;
              fiber.rc = -1;
            }
            break;
          }
        case Re.OP_JUMP:
          fiber.ip += i16(code, fiber.ip + 1);
          break;
        default:
          fiber = fiber.next;
      }
    }
  }

  private static boolean isWordChar(ByteBuffer data, int input, int characterSize) {
    int c = data.get(input) & 0xFF;
    boolean result = Re.isAlnum(c) || c == '_';
    if (characterSize == 2) {
      result = result && data.get(input + 1) == 0;
    }
    return result;
  }

  private static boolean isCharInClass(byte[] code, int classAt, int chr, boolean noCase) {
    boolean result = (code[classAt + 1 + (chr >> 3)] & (1 << (chr & 7))) != 0;
    if (noCase) {
      int alt = Re.altercase(chr);
      result |= (code[classAt + 1 + (alt >> 3)] & (1 << (alt & 7))) != 0;
    }
    if (code[classAt] != 0) {
      result = !result;
    }
    return result;
  }

  private static final int ACTION_NONE = 0;
  private static final int ACTION_CONTINUE = 1;
  private static final int ACTION_KILL = 2;
  private static final int ACTION_KILL_TAIL = 3;

  /**
   * Executes a regular expression. Port of yr_re_exec.
   *
   * @param code the code buffer.
   * @param codeStart offset of the regexp's code.
   * @param data input data.
   * @param inputData index in data where matching starts.
   * @param inputForwardsSize number of bytes accessible from inputData going forwards.
   * @param inputBackwardsSize number of bytes accessible from inputData going backwards.
   * @param flags RE flags.
   * @param callback receives matches when FLAGS_EXHAUSTIVE is used, may be null.
   * @return number of matching bytes, or -1 if no match.
   */
  public int exec(
      byte[] code,
      int codeStart,
      ByteBuffer data,
      int inputData,
      int inputForwardsSize,
      int inputBackwardsSize,
      int flags,
      MatchCallback callback) {
    int matches = -1;
    int characterSize = (flags & Re.FLAGS_WIDE) != 0 ? 2 : 1;
    int input = inputData;
    int inputIncr = characterSize;
    int maxBytesMatched;
    if ((flags & Re.FLAGS_BACKWARDS) != 0) {
      maxBytesMatched = Math.min(inputBackwardsSize, Re.SCAN_LIMIT);
      input -= characterSize;
      inputIncr = -inputIncr;
    } else {
      maxBytesMatched = Math.min(inputForwardsSize, Re.SCAN_LIMIT);
    }
    maxBytesMatched = maxBytesMatched - maxBytesMatched % characterSize;
    int bytesMatched = 0;
    boolean noCase = (flags & Re.FLAGS_NO_CASE) != 0;
    boolean dotAll = (flags & Re.FLAGS_DOT_ALL) != 0;

    FiberList fibers = new FiberList();
    Fiber fiber = fiberCreate();
    fiber.ip = codeStart;
    fibers.head = fiber;
    fibers.tail = fiber;
    try {
      fiberSync(fibers, fiber, code);
      while (fibers.head != null) {
        fiber = fibers.head;
        while (fiber != null) {
          Fiber nextFiber = fiber.next;
          if (fiberExists(fibers, fiber, fiber.prev)) {
            fiberKill(fibers, fiber);
          }
          fiber = nextFiber;
        }
        fiber = fibers.head;
        while (fiber != null) {
          int ip = fiber.ip;
          int action = ACTION_NONE;
          int op = code[ip] & 0xFF;
          boolean match;
          // prolog check shared by all the instructions that consume input
          boolean consumes =
              op != Re.OP_WORD_BOUNDARY
                  && op != Re.OP_NON_WORD_BOUNDARY
                  && op != Re.OP_MATCH_AT_START
                  && op != Re.OP_MATCH_AT_END
                  && op != Re.OP_MATCH;
          if (consumes
              && ((bytesMatched >= maxBytesMatched)
                  || (characterSize == 2 && data.get(input + 1) != 0))) {
            action = ACTION_KILL;
          } else {
            switch (op) {
              case Re.OP_ANY:
                match = dotAll || data.get(input) != 0x0A;
                action = match ? ACTION_NONE : ACTION_KILL;
                fiber.ip += 1;
                break;
              case Re.OP_REPEAT_ANY_GREEDY:
              case Re.OP_REPEAT_ANY_UNGREEDY:
                match = dotAll || data.get(input) != 0x0A;
                action = match ? ACTION_NONE : ACTION_KILL;
                break;
              case Re.OP_LITERAL:
                if (noCase) {
                  match = Re.lower(data.get(input)) == Re.lower(code[ip + 1]);
                } else {
                  match = data.get(input) == code[ip + 1];
                }
                action = match ? ACTION_NONE : ACTION_KILL;
                fiber.ip += 2;
                break;
              case Re.OP_NOT_LITERAL:
                match = data.get(input) != code[ip + 1];
                action = match ? ACTION_NONE : ACTION_KILL;
                fiber.ip += 2;
                break;
              case Re.OP_MASKED_LITERAL:
                {
                  int args = u16(code, ip + 1);
                  int mask = args >> 8;
                  int value = args & 0xFF;
                  match = (data.get(input) & mask) == value;
                  action = match ? ACTION_NONE : ACTION_KILL;
                  fiber.ip += 3;
                  break;
                }
              case Re.OP_MASKED_NOT_LITERAL:
                {
                  int args = u16(code, ip + 1);
                  int mask = args >> 8;
                  int value = args & 0xFF;
                  match = (data.get(input) & mask) != value;
                  action = match ? ACTION_NONE : ACTION_KILL;
                  fiber.ip += 3;
                  break;
                }
              case Re.OP_CLASS:
                match = isCharInClass(code, ip + 1, data.get(input) & 0xFF, noCase);
                action = match ? ACTION_NONE : ACTION_KILL;
                fiber.ip += Re.CLASS_SIZE + 1;
                break;
              case Re.OP_WORD_CHAR:
                match = isWordChar(data, input, characterSize);
                action = match ? ACTION_NONE : ACTION_KILL;
                fiber.ip += 1;
                break;
              case Re.OP_NON_WORD_CHAR:
                match = !isWordChar(data, input, characterSize);
                action = match ? ACTION_NONE : ACTION_KILL;
                fiber.ip += 1;
                break;
              case Re.OP_SPACE:
              case Re.OP_NON_SPACE:
                {
                  int c = data.get(input) & 0xFF;
                  match = c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == 0x0B || c == '\f';
                  if (op == Re.OP_NON_SPACE) {
                    match = !match;
                  }
                  action = match ? ACTION_NONE : ACTION_KILL;
                  fiber.ip += 1;
                  break;
                }
              case Re.OP_DIGIT:
                {
                  int c = data.get(input) & 0xFF;
                  match = c >= '0' && c <= '9';
                  action = match ? ACTION_NONE : ACTION_KILL;
                  fiber.ip += 1;
                  break;
                }
              case Re.OP_NON_DIGIT:
                {
                  int c = data.get(input) & 0xFF;
                  match = !(c >= '0' && c <= '9');
                  action = match ? ACTION_NONE : ACTION_KILL;
                  fiber.ip += 1;
                  break;
                }
              case Re.OP_WORD_BOUNDARY:
              case Re.OP_NON_WORD_BOUNDARY:
                {
                  boolean prevIsWordChar;
                  boolean inputIsWordChar;
                  int prev = input - inputIncr;
                  if (prev + characterSize <= inputData + inputForwardsSize
                      && prev >= inputData - inputBackwardsSize) {
                    prevIsWordChar = isWordChar(data, prev, characterSize);
                  } else {
                    prevIsWordChar = false;
                  }
                  if (input + characterSize <= inputData + inputForwardsSize
                      && input >= inputData - inputBackwardsSize) {
                    inputIsWordChar = isWordChar(data, input, characterSize);
                  } else {
                    inputIsWordChar = false;
                  }
                  match = prevIsWordChar != inputIsWordChar;
                  if (op == Re.OP_NON_WORD_BOUNDARY) {
                    match = !match;
                  }
                  action = match ? ACTION_CONTINUE : ACTION_KILL;
                  fiber.ip += 1;
                  break;
                }
              case Re.OP_MATCH_AT_START:
                {
                  boolean kill;
                  if ((flags & Re.FLAGS_BACKWARDS) != 0) {
                    kill = inputBackwardsSize > bytesMatched;
                  } else {
                    kill = inputBackwardsSize > 0 || bytesMatched != 0;
                  }
                  action = kill ? ACTION_KILL : ACTION_CONTINUE;
                  fiber.ip += 1;
                  break;
                }
              case Re.OP_MATCH_AT_END:
                {
                  boolean kill =
                      (flags & Re.FLAGS_BACKWARDS) != 0 || inputForwardsSize > bytesMatched;
                  action = kill ? ACTION_KILL : ACTION_CONTINUE;
                  fiber.ip += 1;
                  break;
                }
              case Re.OP_MATCH:
                matches = bytesMatched;
                if ((flags & Re.FLAGS_EXHAUSTIVE) != 0) {
                  if (callback != null) {
                    if ((flags & Re.FLAGS_BACKWARDS) != 0) {
                      callback.onMatch(input + characterSize, bytesMatched, flags);
                    } else {
                      callback.onMatch(inputData, bytesMatched, flags);
                    }
                  }
                  action = ACTION_KILL;
                } else {
                  action = ACTION_KILL_TAIL;
                }
                break;
              default:
                throw new YaraError(ErrorCode.INTERNAL_FATAL_ERROR, "invalid regexp opcode");
            }
          }
          switch (action) {
            case ACTION_KILL:
              fiber = fiberKill(fibers, fiber);
              break;
            case ACTION_KILL_TAIL:
              fiberKillTail(fibers, fiber);
              fiber = null;
              break;
            case ACTION_CONTINUE:
              fiberSync(fibers, fiber, code);
              break;
            default:
              {
                Fiber nextFiber = fiber.next;
                fiberSync(fibers, fiber, code);
                fiber = nextFiber;
              }
          }
        }
        input += inputIncr;
        bytesMatched += characterSize;
        if ((flags & Re.FLAGS_SCAN) != 0 && bytesMatched < maxBytesMatched) {
          fiber = fiberCreate();
          fiber.ip = codeStart;
          fiberAppend(fibers, fiber);
          fiberSync(fibers, fiber, code);
        }
      }
    } catch (RuntimeException e) {
      fiberKillAll(fibers);
      throw e;
    }
    return matches;
  }

  // ---------------------------------------------------------------------------------------------
  // Fast exec

  private Position positionCreate() {
    Position p;
    if (positionPool != null) {
      p = positionPool;
      positionPool = p.next;
    } else {
      p = new Position();
    }
    p.input = 0;
    p.round = 0;
    p.next = null;
    p.prev = null;
    return p;
  }

  private void destroyPositionList(Position first, Position last) {
    last.next = positionPool;
    if (positionPool != null) {
      positionPool.prev = last;
    }
    positionPool = first;
  }

  /**
   * Faster algorithm for regexps derived from hex strings without alternatives. Port of
   * yr_re_fast_exec, same arguments and return value as {@link #exec}.
   */
  public int fastExec(
      byte[] code,
      int codeStart,
      ByteBuffer data,
      int inputData,
      int inputForwardsSize,
      int inputBackwardsSize,
      int flags,
      MatchCallback callback) {
    boolean backwards = (flags & Re.FLAGS_BACKWARDS) != 0;
    int inputIncr = backwards ? -1 : 1;
    int maxBytesMatched =
        backwards
            ? Math.min(inputBackwardsSize, Re.SCAN_LIMIT)
            : Math.min(inputForwardsSize, Re.SCAN_LIMIT);
    int ip = codeStart;
    Position first = positionCreate();
    first.round = 0;
    first.input = inputData;
    if (backwards) {
      first.input--;
    }
    Position last = first;
    int round = 0;
    while (first != null) {
      Position current = first;
      while (current != null) {
        Position next = current.next;
        if (current.round != round) {
          current = next;
          continue;
        }
        int bytesMatched = backwards ? inputData - current.input - 1 : current.input - inputData;
        boolean match = false;
        int op = code[ip] & 0xFF;
        switch (op) {
          case Re.OP_ANY:
            if (bytesMatched >= maxBytesMatched) {
              break;
            }
            match = true;
            current.input += inputIncr;
            break;
          case Re.OP_LITERAL:
            if (bytesMatched >= maxBytesMatched) {
              break;
            }
            if (data.get(current.input) == code[ip + 1]) {
              match = true;
              current.input += inputIncr;
            }
            break;
          case Re.OP_NOT_LITERAL:
            if (bytesMatched >= maxBytesMatched) {
              break;
            }
            if (data.get(current.input) != code[ip + 1]) {
              match = true;
              current.input += inputIncr;
            }
            break;
          case Re.OP_MASKED_LITERAL:
            {
              if (bytesMatched >= maxBytesMatched) {
                break;
              }
              int args = u16(code, ip + 1);
              int mask = args >> 8;
              int value = args & 0xFF;
              if ((data.get(current.input) & mask) == value) {
                match = true;
                current.input += inputIncr;
              }
              break;
            }
          case Re.OP_MASKED_NOT_LITERAL:
            {
              if (bytesMatched >= maxBytesMatched) {
                break;
              }
              int args = u16(code, ip + 1);
              int mask = args >> 8;
              int value = args & 0xFF;
              if ((data.get(current.input) & mask) != value) {
                match = true;
                current.input += inputIncr;
              }
              break;
            }
          case Re.OP_REPEAT_ANY_UNGREEDY:
            {
              int min = u16(code, ip + 1);
              int max = u16(code, ip + 3);
              if (bytesMatched + min >= maxBytesMatched) {
                break;
              }
              match = true;
              int nextOpcode = ip + 1 + Re.REPEAT_ANY_ARGS_SIZE;
              Position insertionPoint = current;
              for (int j = min + 1; j <= max; j++) {
                if (bytesMatched + j >= maxBytesMatched) {
                  break;
                }
                int nextInput = current.input + j * inputIncr;
                while (insertionPoint.next != null && insertionPoint.next.input <= nextInput) {
                  insertionPoint = insertionPoint.next;
                }
                if (insertionPoint.round == round + 1 && insertionPoint.input == nextInput) {
                  continue;
                }
                if ((code[nextOpcode] & 0xFF) == Re.OP_LITERAL
                    && code[nextOpcode + 1] != data.get(nextInput)) {
                  continue;
                }
                Position newInput = positionCreate();
                newInput.input = nextInput;
                newInput.round = round + 1;
                newInput.prev = insertionPoint;
                newInput.next = insertionPoint.next;
                insertionPoint.next = newInput;
                if (newInput.next != null) {
                  newInput.next.prev = newInput;
                }
                if (insertionPoint == last) {
                  last = newInput;
                }
              }
              current.input += inputIncr * min;
              break;
            }
          case Re.OP_MATCH:
            if ((flags & Re.FLAGS_EXHAUSTIVE) != 0) {
              try {
                callback.onMatch(
                    backwards
                        ? Math.max(current.input + 1, inputData - inputBackwardsSize)
                        : inputData,
                    Math.min(bytesMatched, maxBytesMatched),
                    flags);
              } catch (RuntimeException e) {
                destroyPositionList(first, last);
                throw e;
              }
            } else {
              destroyPositionList(first, last);
              return bytesMatched;
            }
            break;
          default:
            throw new YaraError(ErrorCode.INTERNAL_FATAL_ERROR, "non-supported opcode " + op);
        }
        if (match) {
          current.round = round + 1;
        } else {
          if (current == first) {
            first = current.next;
          }
          if (current == last) {
            last = current.prev;
          }
          if (current.prev != null) {
            current.prev.next = current.next;
          }
          if (current.next != null) {
            current.next.prev = current.prev;
          }
          current.prev = null;
          current.next = positionPool;
          if (current.next != null) {
            current.next.prev = current;
          }
          positionPool = current;
        }
        current = next;
      }
      switch (code[ip] & 0xFF) {
        case Re.OP_ANY:
          ip += 1;
          break;
        case Re.OP_LITERAL:
        case Re.OP_NOT_LITERAL:
          ip += 2;
          break;
        case Re.OP_MASKED_LITERAL:
        case Re.OP_MASKED_NOT_LITERAL:
          ip += 3;
          break;
        case Re.OP_REPEAT_ANY_UNGREEDY:
          ip += 1 + Re.REPEAT_ANY_ARGS_SIZE;
          break;
        case Re.OP_MATCH:
          break;
        default:
          throw new YaraError(ErrorCode.INTERNAL_FATAL_ERROR);
      }
      round++;
    }
    return -1;
  }
}
