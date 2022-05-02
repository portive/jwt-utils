import { JsonValue } from "type-fest"

/**
 * Base 64 encoding resource
 * https://stackoverflow.com/questions/38134200/base64-encode-a-javascript-object
 */

export function base64ToJson(s: string): JsonValue {
  return JSON.parse(Buffer.from(s, "base64").toString())
}

export function jsonToBase64(json: JsonValue): string {
  return Buffer.from(JSON.stringify(json)).toString("base64")
}
