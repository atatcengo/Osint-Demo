import { Router } from "express";
import dns from "dns/promises";
import { RunOsintScanBody, GenerateOsintReportBody } from "@workspace/api-zod";

const router = Router();

// Validate domain: allow only domain names like example.com or sub.example.com
// Reject URLs with protocol, paths, or suspicious characters
function validate_domain(domain: string): boolean {
  if (!domain || typeof domain !== "string") return false;
  // Reject if it contains protocol, path, or suspicious chars
  if (/https?:\/\//i.test(domain)) return false;
  if (domain.includes("/") || domain.includes("?") || domain.includes("#")) return false;
  // Must match valid domain pattern (supports multi-level like biga.bel.tr)
  const domainRegex =
    /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return domainRegex.test(domain);
}

// Query crt.sh for subdomains via certificate transparency logs
async function get_crtsh_subdomains(
  domain: string
): Promise<{ name: string }[]> {
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
  const resp = await fetch(url, {
    headers: { "User-Agent": "OSINT-Demo/1.0 (educational)" },
    signal: AbortSignal.timeout(15000),
  });
  if (!resp.ok) {
    throw new Error(`crt.sh returned ${resp.status}`);
  }
  const data = (await resp.json()) as Array<{ name_value: string }>;
  const seen = new Set<string>();
  const subdomains: { name: string }[] = [];
  for (const entry of data) {
    // name_value can contain multiple lines with wildcards
    const names = entry.name_value
      .split(/\n/)
      .map((n: string) => n.trim().replace(/^\*\./, ""))
      .filter((n: string) => n && n !== domain);
    for (const name of names) {
      if (!seen.has(name)) {
        seen.add(name);
        subdomains.push({ name });
      }
    }
  }
  return subdomains;
}

// Resolve DNS records using Node.js dns/promises
async function get_dns_records(domain: string): Promise<{
  A: string[];
  MX: string[];
  TXT: string[];
  NS: string[];
}> {
  const results = { A: [] as string[], MX: [] as string[], TXT: [] as string[], NS: [] as string[] };

  // Resolve A records
  try {
    const aRecords = await dns.resolve4(domain);
    results.A = aRecords;
  } catch {
    // No A records or resolution failed — leave empty
  }

  // Resolve MX records
  try {
    const mxRecords = await dns.resolveMx(domain);
    results.MX = mxRecords.map((r) => `${r.priority} ${r.exchange}`);
  } catch {
    // No MX records
  }

  // Resolve TXT records
  try {
    const txtRecords = await dns.resolveTxt(domain);
    results.TXT = txtRecords.map((r) => r.join(""));
  } catch {
    // No TXT records
  }

  // Resolve NS records
  try {
    const nsRecords = await dns.resolveNs(domain);
    results.NS = nsRecords;
  } catch {
    // No NS records
  }

  return results;
}

// Query Shodan for info about an IP address
async function get_shodan_host(
  ip: string,
  apiKey: string
): Promise<{
  ip: string;
  ports: number[];
  hostnames: string[];
  org: string;
  isp: string;
  country: string;
  tags: string[];
  vulns: string[];
}> {
  const url = `https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`;
  const resp = await fetch(url, {
    signal: AbortSignal.timeout(10000),
  });
  if (resp.status === 404) {
    return {
      ip,
      ports: [],
      hostnames: [],
      org: "Unknown",
      isp: "Unknown",
      country: "Unknown",
      tags: [],
      vulns: [],
    };
  }
  if (!resp.ok) {
    throw new Error(`Shodan API error: ${resp.status}`);
  }
  const data = (await resp.json()) as {
    ports?: number[];
    hostnames?: string[];
    org?: string;
    isp?: string;
    country_name?: string;
    tags?: string[];
    vulns?: Record<string, unknown>;
  };
  return {
    ip,
    ports: data.ports ?? [],
    hostnames: data.hostnames ?? [],
    org: data.org ?? "Unknown",
    isp: data.isp ?? "Unknown",
    country: data.country_name ?? "Unknown",
    tags: data.tags ?? [],
    vulns: data.vulns ? Object.keys(data.vulns) : [],
  };
}

// Query Shodan for all resolved IPs
async function get_shodan_info(
  ips: string[],
  apiKey: string
): Promise<
  {
    ip: string;
    ports: number[];
    hostnames: string[];
    org: string;
    isp: string;
    country: string;
    tags: string[];
    vulns: string[];
  }[]
> {
  const results = [];
  for (const ip of ips) {
    try {
      const info = await get_shodan_host(ip, apiKey);
      results.push(info);
    } catch {
      // Skip failed IPs
    }
  }
  return results;
}

// Query VirusTotal domain report
async function get_virustotal_info(
  domain: string,
  apiKey: string
): Promise<{
  harmless: number;
  suspicious: number;
  malicious: number;
  undetected: number;
  reputation: number;
  categories?: Record<string, string>;
}> {
  const url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`;
  const resp = await fetch(url, {
    headers: {
      "x-apikey": apiKey,
      "User-Agent": "OSINT-Demo/1.0 (educational)",
    },
    signal: AbortSignal.timeout(15000),
  });
  if (!resp.ok) {
    throw new Error(`VirusTotal API error: ${resp.status}`);
  }
  const data = (await resp.json()) as {
    data?: {
      attributes?: {
        last_analysis_stats?: {
          harmless?: number;
          suspicious?: number;
          malicious?: number;
          undetected?: number;
        };
        reputation?: number;
        categories?: Record<string, string>;
      };
    };
  };
  const attrs = data?.data?.attributes;
  const stats = attrs?.last_analysis_stats ?? {};
  return {
    harmless: stats.harmless ?? 0,
    suspicious: stats.suspicious ?? 0,
    malicious: stats.malicious ?? 0,
    undetected: stats.undetected ?? 0,
    reputation: attrs?.reputation ?? 0,
    categories: attrs?.categories,
  };
}

// Generate a Markdown report from scan results
function generate_markdown_report(result: {
  domain: string;
  timestamp: string;
  subdomains: { name: string }[];
  dns: { A: string[]; MX: string[]; TXT: string[]; NS: string[] };
  shodan: {
    ip: string;
    ports: number[];
    hostnames: string[];
    org: string;
    isp: string;
    country: string;
    tags: string[];
    vulns: string[];
  }[] | null;
  shodanConfigured: boolean;
  virusTotal: {
    harmless: number;
    suspicious: number;
    malicious: number;
    undetected: number;
    reputation: number;
  } | null;
  virusTotalConfigured: boolean;
  errors?: Record<string, string>;
}): string {
  const lines: string[] = [];
  lines.push(`# Passive OSINT Report`);
  lines.push(`\n**Target Domain:** \`${result.domain}\``);
  lines.push(`**Date/Time:** ${result.timestamp}`);
  lines.push(
    `\n> **Ethical Note:** This report was generated using passive OSINT sources only. No active scanning or exploitation was performed.`
  );

  lines.push(`\n## Subdomains (via crt.sh)`);
  if (result.subdomains.length === 0) {
    lines.push(`No subdomains found.`);
  } else {
    lines.push(`Found **${result.subdomains.length}** unique subdomains.\n`);
    lines.push(`| Subdomain |`);
    lines.push(`|-----------|`);
    for (const sub of result.subdomains) {
      lines.push(`| \`${sub.name}\` |`);
    }
  }

  lines.push(`\n## DNS Records`);

  lines.push(`\n### A Records`);
  if (result.dns.A.length === 0) {
    lines.push(`No A records found.`);
  } else {
    lines.push(`| IP Address |`);
    lines.push(`|------------|`);
    for (const r of result.dns.A) lines.push(`| \`${r}\` |`);
  }

  lines.push(`\n### MX Records`);
  if (result.dns.MX.length === 0) {
    lines.push(`No MX records found.`);
  } else {
    lines.push(`| MX Record |`);
    lines.push(`|-----------|`);
    for (const r of result.dns.MX) lines.push(`| \`${r}\` |`);
  }

  lines.push(`\n### TXT Records`);
  if (result.dns.TXT.length === 0) {
    lines.push(`No TXT records found.`);
  } else {
    lines.push(`| TXT Record |`);
    lines.push(`|------------|`);
    for (const r of result.dns.TXT) lines.push(`| \`${r}\` |`);
  }

  lines.push(`\n### NS Records`);
  if (result.dns.NS.length === 0) {
    lines.push(`No NS records found.`);
  } else {
    lines.push(`| NS Record |`);
    lines.push(`|-----------|`);
    for (const r of result.dns.NS) lines.push(`| \`${r}\` |`);
  }

  lines.push(`\n## Shodan Intelligence`);
  if (!result.shodanConfigured) {
    lines.push(`Shodan API key not configured.`);
  } else if (!result.shodan || result.shodan.length === 0) {
    lines.push(`No Shodan data found for this domain's IPs.`);
  } else {
    for (const host of result.shodan) {
      lines.push(`\n### IP: \`${host.ip}\``);
      lines.push(`- **Organization:** ${host.org}`);
      lines.push(`- **ISP:** ${host.isp}`);
      lines.push(`- **Country:** ${host.country}`);
      lines.push(`- **Open Ports:** ${host.ports.join(", ") || "None"}`);
      if (host.hostnames.length > 0) {
        lines.push(`- **Hostnames:** ${host.hostnames.join(", ")}`);
      }
      if (host.tags.length > 0) {
        lines.push(`- **Tags:** ${host.tags.join(", ")}`);
      }
      if (host.vulns.length > 0) {
        lines.push(
          `- **CVEs (reported by Shodan, not confirmed vulnerabilities):** ${host.vulns.join(", ")}`
        );
      }
    }
  }

  lines.push(`\n## VirusTotal Reputation`);
  if (!result.virusTotalConfigured) {
    lines.push(`VirusTotal API key not configured.`);
  } else if (!result.virusTotal) {
    lines.push(`No VirusTotal data found.`);
  } else {
    const vt = result.virusTotal;
    lines.push(`| Category | Count |`);
    lines.push(`|----------|-------|`);
    lines.push(`| Harmless | ${vt.harmless} |`);
    lines.push(`| Suspicious | ${vt.suspicious} |`);
    lines.push(`| Malicious | ${vt.malicious} |`);
    lines.push(`| Undetected | ${vt.undetected} |`);
    lines.push(`| Reputation Score | ${vt.reputation} |`);
  }

  lines.push(`\n---`);
  lines.push(
    `*This report was generated using passive OSINT sources only. No active scanning, brute forcing, or exploitation was performed. For educational use only.*`
  );

  return lines.join("\n");
}

// GET /api/osint/config — returns which API keys are configured
router.get("/osint/config", (req, res) => {
  res.json({
    shodanConfigured: !!process.env["SHODAN_API_KEY"],
    virusTotalConfigured: !!process.env["VIRUSTOTAL_API_KEY"],
  });
});

// POST /api/osint/scan — run a full passive OSINT scan
router.post("/osint/scan", async (req, res) => {
  const parseResult = RunOsintScanBody.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ error: "Invalid request body" });
    return;
  }

  const { domain } = parseResult.data;

  if (!validate_domain(domain)) {
    res.status(400).json({
      error:
        "Invalid domain format. Please enter a plain domain like example.com or sub.example.com (no http://, paths, or special characters).",
    });
    return;
  }

  const timestamp = new Date().toISOString();
  const errors: Record<string, string> = {};

  // Run subdomains and DNS in parallel
  const [subdomainsResult, dnsResult] = await Promise.allSettled([
    get_crtsh_subdomains(domain),
    get_dns_records(domain),
  ]);

  const subdomains =
    subdomainsResult.status === "fulfilled"
      ? subdomainsResult.value
      : (errors["subdomains"] = subdomainsResult.reason?.message ?? "Failed", []);

  const dns =
    dnsResult.status === "fulfilled"
      ? dnsResult.value
      : (errors["dns"] = dnsResult.reason?.message ?? "Failed",
        { A: [], MX: [], TXT: [], NS: [] });

  const resolvedIPs = dns.A;

  // Shodan integration
  const shodanKey = process.env["SHODAN_API_KEY"];
  const shodanConfigured = !!shodanKey;
  let shodan: typeof subdomains extends never ? never : (typeof subdomains extends { name: string }[] ? {
    ip: string;
    ports: number[];
    hostnames: string[];
    org: string;
    isp: string;
    country: string;
    tags: string[];
    vulns: string[];
  }[] | null : never) = null;

  if (shodanConfigured && resolvedIPs.length > 0 && shodanKey) {
    try {
      shodan = await get_shodan_info(resolvedIPs, shodanKey);
    } catch (err) {
      errors["shodan"] =
        err instanceof Error ? err.message : "Shodan query failed";
    }
  }

  // VirusTotal integration
  const vtKey = process.env["VIRUSTOTAL_API_KEY"];
  const virusTotalConfigured = !!vtKey;
  let virusTotal: {
    harmless: number;
    suspicious: number;
    malicious: number;
    undetected: number;
    reputation: number;
    categories?: Record<string, string>;
  } | null = null;

  if (virusTotalConfigured && vtKey) {
    try {
      virusTotal = await get_virustotal_info(domain, vtKey);
    } catch (err) {
      errors["virusTotal"] =
        err instanceof Error ? err.message : "VirusTotal query failed";
    }
  }

  res.json({
    domain,
    timestamp,
    subdomains,
    dns,
    shodan,
    shodanConfigured,
    virusTotal,
    virusTotalConfigured,
    errors,
  });
});

// POST /api/osint/report — generate a Markdown report from scan results
router.post("/osint/report", (req, res) => {
  const parseResult = GenerateOsintReportBody.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ error: "Invalid request body" });
    return;
  }

  const scanResult = parseResult.data as Parameters<typeof generate_markdown_report>[0];
  const content = generate_markdown_report(scanResult);
  const filename = `osint-report-${scanResult.domain}-${new Date().toISOString().slice(0, 10)}.md`;

  res.json({ content, filename });
});

export default router;
