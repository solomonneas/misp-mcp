import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { MispClient } from "../client.js";

export function registerSightingTools(server: McpServer, client: MispClient): void {
  server.tool(
    "misp_add_sighting",
    "Report a sighting of an IOC (confirms it was observed in the wild, marks as false positive, or sets expiration)",
    {
      attributeId: z.string().optional().describe("Attribute ID to sight (use this or value)"),
      value: z.string().optional().describe("Attribute value to sight (use this or attributeId)"),
      type: z.union([z.literal(0), z.literal(1), z.literal(2)])
        .describe("0=Sighting (seen in the wild), 1=False positive, 2=Expiration"),
      source: z.string().optional().describe("Source of the sighting (e.g., organization name, sensor ID)"),
      timestamp: z.string().optional().describe("Timestamp of the sighting (Unix timestamp)"),
    },
    async (params) => {
      try {
        if (!params.attributeId && !params.value) {
          return {
            content: [
              { type: "text", text: "Either attributeId or value must be provided." },
            ],
            isError: true,
          };
        }

        const sighting = await client.addSighting({
          attributeId: params.attributeId,
          value: params.value,
          type: params.type,
          source: params.source,
          timestamp: params.timestamp,
        });

        const typeLabels = ["Sighting", "False positive", "Expiration"];

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  id: sighting.id,
                  type: typeLabels[params.type],
                  attribute_id: sighting.attribute_id,
                  event_id: sighting.event_id,
                  source: sighting.source,
                  date_sighting: sighting.date_sighting,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (err) {
        return {
          content: [
            { type: "text", text: `Error adding sighting: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    }
  );
}
