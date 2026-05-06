import { Router } from "express";
import { desc, eq } from "drizzle-orm";

const router = Router();

async function get_history_db() {
  if (!process.env["DATABASE_URL"]) return null;

  try {
    const { db, scanHistoryTable } = await import("@workspace/db");
    return { db, scanHistoryTable };
  } catch {
    return null;
  }
}

// GET /api/history — list all scan history entries, newest first
router.get("/history", async (req, res) => {
  try {
    const historyDb = await get_history_db();
    if (!historyDb) {
      res.json([]);
      return;
    }

    const { db, scanHistoryTable } = historyDb;
    const rows = await db
      .select()
      .from(scanHistoryTable)
      .orderBy(desc(scanHistoryTable.scannedAt))
      .limit(50);

    const entries = rows.map((row) => ({
      id: row.id,
      domain: row.domain,
      scannedAt: row.scannedAt.toISOString(),
      result: row.result,
    }));

    res.json(entries);
  } catch (err) {
    req.log.error({ err }, "Failed to list scan history");
    res.status(500).json({ error: "Failed to fetch scan history" });
  }
});

// POST /api/history — save a scan result to history
router.post("/history", async (req, res) => {
  const body = req.body as { domain?: string };
  if (!body || !body.domain) {
    res.status(400).json({ error: "Invalid scan result" });
    return;
  }

  try {
    const historyDb = await get_history_db();
    if (!historyDb) {
      res.status(201).json({
        id: 0,
        domain: body.domain,
        scannedAt: new Date().toISOString(),
        result: body,
      });
      return;
    }

    const { db, scanHistoryTable } = historyDb;
    const [row] = await db
      .insert(scanHistoryTable)
      .values({
        domain: body.domain,
        result: body,
      })
      .returning();

    res.status(201).json({
      id: row.id,
      domain: row.domain,
      scannedAt: row.scannedAt.toISOString(),
      result: row.result,
    });
  } catch (err) {
    req.log.error({ err }, "Failed to save scan result");
    res.status(500).json({ error: "Failed to save scan result" });
  }
});

// GET /api/history/:id — get one scan history entry
router.get("/history/:id", async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) {
    res.status(400).json({ error: "Invalid id" });
    return;
  }

  try {
    const historyDb = await get_history_db();
    if (!historyDb) {
      res.status(404).json({ error: "Not found" });
      return;
    }

    const { db, scanHistoryTable } = historyDb;
    const [row] = await db
      .select()
      .from(scanHistoryTable)
      .where(eq(scanHistoryTable.id, id))
      .limit(1);

    if (!row) {
      res.status(404).json({ error: "Not found" });
      return;
    }

    res.json({
      id: row.id,
      domain: row.domain,
      scannedAt: row.scannedAt.toISOString(),
      result: row.result,
    });
  } catch (err) {
    req.log.error({ err }, "Failed to get scan history entry");
    res.status(500).json({ error: "Failed to get entry" });
  }
});

// DELETE /api/history/:id — delete a scan history entry
router.delete("/history/:id", async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) {
    res.status(400).json({ error: "Invalid id" });
    return;
  }

  try {
    const historyDb = await get_history_db();
    if (!historyDb) {
      res.status(204).send();
      return;
    }

    const { db, scanHistoryTable } = historyDb;
    const deleted = await db
      .delete(scanHistoryTable)
      .where(eq(scanHistoryTable.id, id))
      .returning();

    if (deleted.length === 0) {
      res.status(404).json({ error: "Not found" });
      return;
    }

    res.status(204).send();
  } catch (err) {
    req.log.error({ err }, "Failed to delete scan history entry");
    res.status(500).json({ error: "Failed to delete entry" });
  }
});

export default router;
