package com.paveldan.yara4j.module;

import com.paveldan.yara4j.YaraException;

/**
 * Implementation of a module function. Equivalent to libyara's define_function.
 *
 * <p>The returned value must match the function's declared return type: a {@link Number} for
 * "i" (integer) functions, a {@link Number} for "f" (float) functions and a {@code byte[]} or
 * {@link String} for "s" (string) functions. Returning null means that the result is undefined.
 */
@FunctionalInterface
public interface ModuleFunction {
  Object call(FunctionCall call) throws YaraException;
}
