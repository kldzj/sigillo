// Type checks for the arguments of server actions and API handlers.
//
// These arguments come from the client. React's server-action reply decoding
// and JSON both accept plain objects where a string belongs, and drizzle's
// relational `where` reads an object value as filter operators (`{ gt: '…' }`
// becomes `column > '…'`). So a field that should be an id but arrives as an
// object could look a row up by something other than its exact value. Every
// action checks the shapes of its arguments here before any of them reaches a
// query; anything unexpected throws a plain "Invalid input".

const MAX_STRING = 4096
// A secret value, or a pasted key set: larger, but still bounded
const MAX_LONG = 512 * 1024
const MAX_LIST = 1000

// The ids this app makes are ULIDs (Crockford base32). The set is kept a
// little wider so any id-shaped value passes and only objects, empty strings
// and junk are refused.
const ID = /^[A-Za-z0-9_-]{1,64}$/

function invalid(): never {
  throw new Error('Invalid input')
}

// A required id: a non-empty string in the id charset
export function asId(value: unknown): string {
  if (typeof value !== 'string' || !ID.test(value)) invalid()
  return value
}

// A required, non-empty string within a length bound
export function asString(value: unknown, max = MAX_STRING): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > max) invalid()
  return value
}

// A string that may be empty: a secret value, a typed confirmation, or a name
// or slug whose own validator (requireValidName, getEnvSlugError, …) runs next
export function asText(value: unknown, max = MAX_LONG): string {
  if (typeof value !== 'string' || value.length > max) invalid()
  return value
}

export function asBool(value: unknown): boolean {
  if (typeof value !== 'boolean') invalid()
  return value
}

// A string or number that must be one of a fixed set (an enum, or an allowed
// number of days)
export function asOneOf<const T extends string | number>(value: unknown, allowed: readonly T[]): T {
  if ((typeof value !== 'string' && typeof value !== 'number') || !allowed.includes(value as T)) invalid()
  return value as T
}

// An array whose every item passes `each`
export function asList<T>(value: unknown, each: (item: unknown) => T, max = MAX_LIST): T[] {
  if (!Array.isArray(value) || value.length > max) invalid()
  return value.map(each)
}

// A plain object (not an array, not null)
export function asObject(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) invalid()
  return value as Record<string, unknown>
}

// A record whose keys and values are all strings (a trust rule's claims)
export function asStringRecord(value: unknown, maxEntries = 200): Record<string, string> {
  const object = asObject(value)
  const entries = Object.entries(object)
  if (entries.length > maxEntries) invalid()
  for (const [, item] of entries) if (typeof item !== 'string' || item.length > MAX_STRING) invalid()
  return object as Record<string, string>
}

// undefined passes through; anything present is checked
export function optional<T>(value: unknown, check: (v: unknown) => T): T | undefined {
  return value === undefined ? undefined : check(value)
}

// null passes through; anything else is checked
export function nullable<T>(value: unknown, check: (v: unknown) => T): T | null {
  return value === null ? null : check(value)
}
