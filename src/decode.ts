import * as s from "superstruct"
import JWT from "jsonwebtoken"
import { validateWithScope } from "./validate-with-scope"

/**
 * Takes a JWT token and parses the header using the Struct.
 *
 * IMPORTANT: It does not verify the JWT token. It only extracts data.
 */
export function parseHeader<T>(
  jwt: string,
  struct: s.Struct<T>,
  scope: string
): T {
  const json = JWT.decode(jwt, { complete: true })
  if (json == null) throw new Error(`Expected JWT.decode to return a value`)
  return validateWithScope(json.header, struct, scope)
}

/**
 * Takes a JWT token and verifies the payload/body with the `secretKey` and
 * returns the payload/body or throws an error if the token is invalid.
 */
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
