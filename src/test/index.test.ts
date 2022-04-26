import JWT from "jsonwebtoken"
import { base64ToJson, parseHeader, verifyJWT } from ".."
import * as s from "superstruct"

const KEY_ID = "KEY_ID"
const SECRET_KEY = "SECRET_HMAC_KEY"

describe("JWT utils", () => {
  const jwt = JWT.sign({ a: "alpha" }, SECRET_KEY, { keyid: KEY_ID })

  describe("base64ToJson", () => {
    it("should convert base64ToJson", async () => {
      const header = base64ToJson(jwt.split(".")[0])
      const payload = base64ToJson(jwt.split(".")[1])

      expect(header).toEqual({ alg: "HS256", typ: "JWT", kid: KEY_ID })
      expect(payload).toEqual({ a: "alpha", iat: expect.any(Number) })
    })
  })

  describe("extractHeader", () => {
    it("should extract header", async () => {
      const Struct = s.object({
        alg: s.literal("HS256"),
        typ: s.literal("JWT"),
        kid: s.literal(KEY_ID),
      })
      const header = parseHeader(jwt, Struct, "JWT header")
      expect(header).toEqual({ alg: "HS256", typ: "JWT", kid: KEY_ID })
    })

    it("should fail extract header with scope wrong key name", async () => {
      const Struct = s.object({
        alg: s.literal("HS256"),
        typ: s.literal("JWT"),
        INVALID: s.literal(KEY_ID),
      })
      expect(() => parseHeader(jwt, Struct, "JWT header")).toThrow(
        "Error validating JWT header. At path: INVALID"
      )
    })
  })

  describe("JWT", () => {
    it("should verify JWT token", async () => {
      const Struct = s.object({
        a: s.string(),
        iat: s.number(),
        exp: s.optional(s.number()),
      })
      const auth = verifyJWT(jwt, SECRET_KEY, Struct)
      expect(auth).toEqual({ a: "alpha", iat: expect.any(Number) })
    })
  })
})
