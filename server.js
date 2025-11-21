const express = require("express");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const LOG = path.join(process.cwd(), "traffic.log");

// CORS middleware - allow requests from Netlify
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
  next();
});

app.use(express.static("public"));

// Health check endpoint
app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

// Local stats endpoint
app.get("/api/stats", async (_req, res) => {
  try {
    if (!fs.existsSync(LOG)) {
      return res.json({ ipCounts: {}, portCounts: {}, lastSeen: {} });
    }

    const text = await fs.promises.readFile(LOG, "utf8");
    const ipCounts = Object.create(null);
    const portCounts = Object.create(null);
    const lastSeen = Object.create(null);

    // Parse lines: "2025-11-21T12:34:56Z SRC=1.2.3.4 DSTPORT=22"
    for (const line of text.split("\n")) {
      if (!line) continue;
      const ts = (line.match(/\d{4}-\d{2}-\d{2}T[^ ]+/) || [null])[0];
      const ip = (line.match(/SRC=([0-9.]+)/) || [null, null])[1];
      const port = (line.match(/DSTPORT=(\d{1,5})/) || [null, null])[1];
      
      if (ip) {
        ipCounts[ip] = (ipCounts[ip] || 0) + 1;
        if (ts) lastSeen[ip] = ts;
      }
      if (port) portCounts[port] = (portCounts[port] || 0) + 1;
    }

    res.json({ ipCounts, portCounts, lastSeen });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`SIEM UI listening on http://localhost:${PORT}`);
});
