import * as s from "superstruct"

/**
 * Validated using SuperStruct buts when an error is thrown, we add the scope
 * to the error message.
 */
export function validateWithScope<T, S>(
  value: unknown,
  struct: s.Struct<T, S>,
  scope: string
): T {
  const [err, v] = s.validate(value, struct)
  if (err) {
    err.message = `Error validating ${scope}. ${err.message}`
    throw err
  }
  return v
}
