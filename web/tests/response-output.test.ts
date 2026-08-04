import assert from "node:assert/strict"
import test from "node:test"

import { responseOutputText } from "../src/lib/response-output.ts"

test("joins output text from completed response events", () => {
  const events = [
    'data: {"type":"response.created","response":{"output":[]}}',
    'data: {"type":"response.completed","response":{"output":[{"type":"message","content":[{"type":"output_text","text":"First reply"}]},{"type":"message","content":[{"type":"output_text","text":"Second reply"}]}]}}',
  ].join("\n\n")

  assert.equal(responseOutputText(events), "First reply\n\nSecond reply")
})

test("reads output from a non-stream response body", () => {
  const response = JSON.stringify({
    output: [
      {
        type: "message",
        content: [{ type: "output_text", text: "Final reply" }],
      },
    ],
  })

  assert.equal(responseOutputText(response), "Final reply")
})
