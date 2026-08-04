type RecordValue = Record<string, unknown>

function recordValue(value: unknown): RecordValue | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as RecordValue)
    : undefined
}

function responseEventValues(responseBody?: string): unknown[] {
  if (!responseBody) return []
  const parsed = parseJson(responseBody)
  if (recordValue(parsed)?.output) return [parsed]
  return responseBody.split(/\r?\n/).flatMap((line) => {
    if (!line.startsWith("data: ")) return []
    try {
      return [JSON.parse(line.slice("data: ".length)) as unknown]
    } catch {
      return []
    }
  })
}

function parseJson(value: string): unknown | undefined {
  try {
    return JSON.parse(value) as unknown
  } catch {
    return undefined
  }
}

function responseOutputParts(value: unknown): string[] {
  const event = recordValue(value)
  const response = recordValue(event?.response) ?? event
  const output = Array.isArray(response?.output) ? response.output : []
  return output.flatMap((item) => {
    const content = recordValue(item)?.content
    if (!Array.isArray(content)) return []
    return content.flatMap((part) => {
      const text = recordValue(part)?.text
      return typeof text === "string" && text ? [text] : []
    })
  })
}

export function responseOutputText(responseBody?: string): string | undefined {
  const parts = responseEventValues(responseBody).flatMap(responseOutputParts)
  return parts.length > 0 ? parts.join("\n\n") : undefined
}
