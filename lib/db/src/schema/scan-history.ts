import { pgTable, serial, text, timestamp, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const scanHistoryTable = pgTable("scan_history", {
  id: serial("id").primaryKey(),
  domain: text("domain").notNull(),
  scannedAt: timestamp("scanned_at", { withTimezone: true }).notNull().defaultNow(),
  result: jsonb("result").notNull(),
});

export const insertScanHistorySchema = createInsertSchema(scanHistoryTable).omit({ id: true, scannedAt: true });
export type InsertScanHistory = z.infer<typeof insertScanHistorySchema>;
export type ScanHistory = typeof scanHistoryTable.$inferSelect;
