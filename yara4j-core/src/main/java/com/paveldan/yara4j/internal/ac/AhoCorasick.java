package com.paveldan.yara4j.internal.ac;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.BitSet;
import com.paveldan.yara4j.internal.atoms.Atoms;
import com.paveldan.yara4j.internal.rules.CompiledString;

/**
 * Aho-Corasick automaton builder. Port of libyara's ahocorasick.c. The compiled automaton is a
 * single transition table where the transitions of different states are interleaved, exactly
 * like in libyara.
 */
public final class AhoCorasick {
  public static final int SLOT_OFFSET_BITS = 9;
  public static final int ROOT_STATE = 0;

  private static final class State {
    int input;
    int depth;
    AcMatch matches;
    State failure;
    State firstChild;
    State siblings;
    int slot;
  }

  private final State root = new State();

  /** Compiled automaton. */
  public static final class Tables {
    /** Transition table. */
    public final int[] transitions;
    /** Head of the match list for each slot, or null. */
    public final AcMatch[] matches;

    Tables(int[] transitions, AcMatch[] matches) {
      this.transitions = transitions;
      this.matches = matches;
    }
  }

  private static State nextState(State state, int input) {
    State s = state.firstChild;
    while (s != null) {
      if (s.input == input) {
        return s;
      }
      s = s.siblings;
    }
    return null;
  }

  private static State createState(State state, int input) {
    State ns = new State();
    ns.input = input;
    ns.depth = state.depth + 1;
    ns.siblings = state.firstChild;
    state.firstChild = ns;
    return ns;
  }

  /** Adds the atoms of a string to the automaton (yr_ac_add_string). */
  public void addString(CompiledString string, Atoms.AtomListItem atom) {
    while (atom != null) {
      State state = root;
      for (int i = 0; i < atom.atom.length; i++) {
        State next = nextState(state, atom.atom.bytes[i]);
        if (next == null) {
          next = createState(state, atom.atom.bytes[i]);
        }
        state = next;
      }
      AcMatch m =
          new AcMatch(
              string, state.depth + atom.backtrack, atom.forwardCodeRef, atom.backwardCodeRef);
      m.next = state.matches;
      state.matches = m;
      atom = atom.next;
    }
  }

  private void createFailureLinks() {
    ArrayDeque<State> queue = new ArrayDeque<>();
    root.failure = root;
    for (State s = root.firstChild; s != null; s = s.siblings) {
      queue.add(s);
      s.failure = root;
    }
    while (!queue.isEmpty()) {
      State current = queue.poll();
      AcMatch match = current.matches;
      if (match != null) {
        while (match.next != null) {
          match = match.next;
        }
        if (match.backtrack > 0) {
          match.next = root.matches;
        }
      } else {
        current.matches = root.matches;
      }
      for (State t = current.firstChild; t != null; t = t.siblings) {
        queue.add(t);
        State failure = current.failure;
        while (true) {
          State temp = nextState(failure, t.input);
          if (temp != null) {
            t.failure = temp;
            if (t.matches == null) {
              t.matches = temp.matches;
            } else {
              match = t.matches;
              while (match.next != null) {
                match = match.next;
              }
              match.next = temp.matches;
            }
            break;
          } else {
            if (failure == root) {
              t.failure = root;
              break;
            } else {
              failure = failure.failure;
            }
          }
        }
      }
    }
  }

  private static boolean transitionsSubset(State s1, State s2) {
    boolean[] set = new boolean[256];
    for (State s = s1.firstChild; s != null; s = s.siblings) {
      set[s.input] = true;
    }
    for (State s = s2.firstChild; s != null; s = s.siblings) {
      if (!set[s.input]) {
        return false;
      }
    }
    return true;
  }

  private void optimizeFailureLinks() {
    ArrayDeque<State> queue = new ArrayDeque<>();
    for (State s = root.firstChild; s != null; s = s.siblings) {
      queue.add(s);
    }
    while (!queue.isEmpty()) {
      State current = queue.poll();
      if (current.failure != root) {
        if (transitionsSubset(current, current.failure)) {
          current.failure = current.failure.failure;
        }
      }
      for (State s = current.firstChild; s != null; s = s.siblings) {
        queue.add(s);
      }
    }
  }

  /** Compiles the automaton (yr_ac_compile). */
  public Tables compile() {
    createFailureLinks();
    optimizeFailureLinks();

    int size = 512;
    int[] t = new int[size];
    AcMatch[] m = new AcMatch[size];
    BitSet used = new BitSet(size);

    t[0] = 0;
    m[0] = root.matches;
    used.set(0);
    int unusedCandidate = 1;

    ArrayDeque<State> queue = new ArrayDeque<>();
    for (State c = root.firstChild; c != null; c = c.siblings) {
      // t_table_slot holds the position of the transition pointing to the state until the state
      // gets its own slot.
      c.slot = c.input + 1;
      t[c.input + 1] = c.input + 1;
      used.set(c.input + 1);
      queue.add(c);
    }
    while (!queue.isEmpty()) {
      State state = queue.poll();
      // Find a slot where the state's transitions don't collide with others.
      int slot = used.nextClearBit(unusedCandidate);
      unusedCandidate = slot;
      while (true) {
        boolean ok = true;
        for (State c = state.firstChild; c != null; c = c.siblings) {
          if (used.get(slot + c.input + 1)) {
            ok = false;
            break;
          }
        }
        if (ok) {
          break;
        }
        slot = used.nextClearBit(slot + 1);
      }
      if (slot + 257 > size) {
        int newSize = Math.max(size * 2, slot + 257);
        t = Arrays.copyOf(t, newSize);
        m = Arrays.copyOf(m, newSize);
        size = newSize;
      }
      t[state.slot] |= slot << SLOT_OFFSET_BITS;
      t[slot] = state.failure.slot << SLOT_OFFSET_BITS;
      m[slot] = state.matches;
      state.slot = slot;
      used.set(slot);
      for (State c = state.firstChild; c != null; c = c.siblings) {
        c.slot = slot + c.input + 1;
        t[c.slot] = c.input + 1;
        used.set(c.slot);
        queue.add(c);
      }
    }
    // Make sure that the table can be indexed with any state + 256.
    int maxSlot = used.length();
    if (maxSlot + 257 > size) {
      t = Arrays.copyOf(t, maxSlot + 257);
      m = Arrays.copyOf(m, maxSlot + 257);
    }
    return new Tables(t, m);
  }
}
