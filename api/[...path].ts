import type { IncomingMessage, ServerResponse } from "node:http";
import { handleRequest } from "../src/server.ts";

export const config = { api: { bodyParser: false } };

export default async function handler(request: IncomingMessage, response: ServerResponse): Promise<void> {
  await handleRequest(request, response);
}