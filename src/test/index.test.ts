import JWT from "jsonwebtoken"
import { signJWT, base64ToJson, jsonToBase64, parseHeader, verifyJWT } from ".."
import * as s from "superstruct"

const KEY_ID = "KEY_ID"
const SECRET_KEY = "SECRET_HMAC_KEY"

describe("jwt-utils", () => {
  describe("base64", () => {
    it("should encode/decode base64", async () => {
      const json = { name: "John", age: 23 }
      const base64 = jsonToBase64(json)
      const parsedJson = base64ToJson(base64)
      expect(parsedJson).toEqual({ name: "John", age: 23 })
    })
  })
  describe("sign", () => {
    const HeaderStruct = s.object({
      alg: s.literal("HS256"),
      typ: s.literal("JWT"),
      kid: s.string(),
    })
    const PayloadStruct = s.object({
      name: s.string(),
      iat: s.number(),
      exp: s.number(),
    })

    it("should sign and validate against struct", async () => {
      const jwt = signJWT(
        { name: "John" },
        PayloadStruct,
        HeaderStruct,
        SECRET_KEY,
        { keyid: KEY_ID, expiresIn: 60 * 60 }
      )
      const complete = JWT.verify(jwt, SECRET_KEY, { complete: true })
      expect(complete.header).toEqual({ alg: "HS256", typ: "JWT", kid: KEY_ID })
      expect(complete.payload).toEqual({
        name: "John",
        iat: expect.any(Number),
        exp: expect.any(Number),
      })
      const payload = complete.payload as { iat: number; exp: number }
      expect(payload.exp).toEqual(payload.iat + 60 * 60)
    })

    it("should fail validating payload", async () => {
      expect(() =>
        signJWT(
          { name: 123 },
          // @ts-ignore
          PayloadStruct,
          HeaderStruct,
          SECRET_KEY,
          { keyid: KEY_ID, expiresIn: 60 * 60 }
        )
      ).toThrow("Error validating JWT Payload.")
    })
  })
  describe("decode jwt utils", () => {
    /**
     * Create a JWT manually using 'jsonwebtoken'
     */
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
})
