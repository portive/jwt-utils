// import JWT from "jsonwebtoken"
import { JsonValue } from "type-fest"
import * as s from "superstruct"
import JWT from "jsonwebtoken"
import { AES, enc } from "crypto-js"

export function base64ToJson(s: string): JsonValue {
  return JSON.parse(Buffer.from(s, "base64").toString())
}

/**
 * Validated using SuperStruct buts when an error is thrown, we add the scope
 * to the error message.
 */
function validateWithScope<T, S>(
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

/**
 * Parses a segment like the header or payload part of a JWT token.
 * Validates the returns JsonValue against the given `struct`.
 * When throwing validation errors, adds the `scope` to the Error.
 */
function parseSegment<T>(
  part: string | undefined,
  struct: s.Struct<T>,
  scope: string
): T {
  if (typeof part !== "string")
    throw new Error(`Expected part to be string but is ${part}`)
  const unvalidatedJson = base64ToJson(part)
  const json = validateWithScope(unvalidatedJson, struct, scope)
  return json
}

function splitIntoSegments(s: string): [string, string, string] {
  const segments = s.split(".")
  if (segments.length !== 3) throw new Error(`Expected 3 segments in jwt token`)
  return segments as [string, string, string]
}

export function parseHeader<T>(
  jwt: string,
  struct: s.Struct<T>,
  scope: string
): T {
  const segments = splitIntoSegments(jwt)
  return parseSegment(segments[0], struct, scope)
}

export function parsePayload<T>(
  jwt: string,
  struct: s.Struct<T>,
  scope: string
): T {
  const segments = splitIntoSegments(jwt)
  return parseSegment(segments[1], struct, scope)
}

export function verifyJWT<T>(
  jwt: string,
  secretKey: string,
  struct: s.Struct<T>
): T {
  const rawPayload = JWT.verify(jwt, secretKey, {
    algorithms: ["HS256"],
    // complete: true,
    clockTolerance: 60, // seconds
  })
  const payload = validateWithScope(rawPayload, struct, "JWT token")
  return payload
}

// /**
//  * Takes a key stored in the `env` and the `secretKey` that we want to store
//  * in the database then returns the `storedKey` to put into the database.
//  */
// export function storeSecretKey({
//   envKey,
//   secretKey,
// }: {
//   envKey: string
//   secretKey: string
// }): string {
//   return AES.encrypt(secretKey, envKey)
// }

// /**
//  * Takes a key stored in the `env` and the `storedKey` in the database then
//  * returns the encrypted `secretKey` that we use to encrypt things like the
//  * JWT token.
//  */
// export function restoreSecretKey({
//   envKey,
//   storedKey,
// }: {
//   envKey: string
//   storedKey: string
// }) {
//   return AES.decrypt(storedKey, envKey).toString(enc.Utf8)
// }
