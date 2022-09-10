import * as s from "superstruct"
import { JsonObject } from "type-fest"
import JWT from "jsonwebtoken"
import { validateWithScope } from "./validate-with-scope"

/**
 * We provide this `signJWT` method instead of using `JWT.sign` directly to
 * help us verify that the delivered JWT is in the expected shape.
 *
 * We can use the same `headerStruct` and `payloadStruct` in the sender and
 * receiver.
 *
 * This prevents schema errors before they are delivered through the Internet
 * and allows code on the client to fail fast without ever making a connection
 * to the Internet.
 */
export function signJWT<
  P extends JsonObject,
  H extends JsonObject & { alg: "HS256"; typ: "JWT" }
>(
  payload: P,
  payloadStruct: s.Struct<P & { iat: number; exp: number }>, // iat is always added
  headerStruct: s.Struct<H & { alg: "HS256"; typ: "JWT" }>,
  secretKey: string,
  options?: JWT.SignOptions // expiresIn is an important option here
) {
  const signOptions = Object.assign({ algorithm: "HS256" }, options)
  const jwt = JWT.sign(payload, secretKey, signOptions)
  const complete = JWT.decode(jwt, { complete: true })
  if (complete == null)
    throw new Error(`Expected JWT.decode to return a non-null value`)
  validateWithScope(complete.header, headerStruct, "JWT Header")
  validateWithScope(complete.payload, payloadStruct, "JWT Payload")
  return jwt
}
