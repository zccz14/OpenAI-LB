import assert from "node:assert/strict"
import test from "node:test"

import { responseOutputText } from "../src/lib/response-output.ts"

test("uses finalized output text events without duplicating their deltas", () => {
  const events = [
    'data: {"type":"response.created","response":{"output":[]}}',
    'data: {"type":"response.output_text.delta","output_index":1,"content_index":0,"delta":"Second reply"}',
    'data: {"type":"response.output_text.done","output_index":1,"content_index":0,"text":"Second reply"}',
    'data: {"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"First"}',
    'data: {"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":" reply"}',
    'data: {"type":"response.output_text.done","output_index":0,"content_index":0,"text":"First reply"}',
    'data: {"type":"response.completed","response":{"output":[{"type":"message","content":[{"type":"output_text","text":"Incorrect fallback"}]}]}}',
  ].join("\n\n")

  assert.equal(responseOutputText(events), "First reply\n\nSecond reply")
})

test("joins output text deltas when a stream ends before final text events", () => {
  const events = [
    'data: {"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"Hello"}',
    'data: {"type":"response.function_call_arguments.delta","output_index":1,"delta":"{\\"ignored\\":true}"}',
    'data: {"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":" world"}',
  ].join("\r\n\r\n")

  assert.equal(responseOutputText(events), "Hello world")
})

test("falls back to the completed response output", () => {
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
