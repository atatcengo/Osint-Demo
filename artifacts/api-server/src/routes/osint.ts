import { Router } from "express";
import dns from "dns/promises";
import net from "node:net";
import { RunOsintScanBody, GenerateOsintReportBody } from "@workspace/api-zod";

const router = Router();

type DnsRecords = {
  A: string[];
  MX: string[];
  TXT: string[];
  NS: string[];
};

type DnsSecurityInfo = {
  spf: string[];
  dmarc?: string;
  dmarcPolicy?: string;
  caa: string[];
  dnssec: boolean;
  dnssecRecords: string[];
  mtaSts?: string;
  tlsRpt?: string;
};

type ShodanHostInfo = {
  ip: string;
  ports: number[];
  hostnames: string[];
  org: string;
  isp: string;
  country: string;
  tags: string[];
  vulns: string[];
};

type WhoisInfo = {
  server?: string;
  registrar?: string;
  creationDate?: string;
  expirationDate?: string;
  updatedDate?: string;
  statuses: string[];
  nameServers: string[];
  rawText: string;
};

type UrlscanResult = {
  url: string;
  pageDomain?: string;
  ip?: string;
  country?: string;
  server?: string;
  scannedAt?: string;
  resultUrl?: string;
  screenshotUrl?: string;
};

type UrlscanInfo = {
  total: number;
  results: UrlscanResult[];
};

type AbuseIpInfo = {
  ip: string;
  abuseConfidenceScore: number;
  totalReports: number;
  countryCode?: string;
  isp?: string;
  domain?: string;
  lastReportedAt?: string;
};

type VirusTotalInfo = {
  harmless: number;
  suspicious: number;
  malicious: number;
  undetected: number;
  reputation: number;
  categories?: Record<string, string>;
};

type CisaKevMatch = {
  cveID: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  dateAdded?: string;
  dueDate?: string;
  knownRansomwareCampaignUse?: string;
};

type CisaKevInfo = {
  catalogVersion?: string;
  dateReleased?: string;
  matched: CisaKevMatch[];
};

type RiskFinding = {
  severity: "info" | "low" | "medium" | "high" | "critical";
  label: string;
  detail: string;
};

type RiskSummaryInfo = {
  score: number;
  level: "low" | "medium" | "high" | "critical";
  findings: RiskFinding[];
};

type ScanResultForReport = {
  domain: string;
  timestamp: string;
  subdomains: { name: string }[];
  dns: DnsRecords;
  dnsSecurity?: DnsSecurityInfo | null;
  whois?: WhoisInfo | null;
  urlscan?: UrlscanInfo | null;
  urlscanConfigured?: boolean;
  abuseIpDb?: AbuseIpInfo[] | null;
  abuseIpDbConfigured?: boolean;
  shodan?: ShodanHostInfo[] | null;
  shodanConfigured: boolean;
  cisaKev?: CisaKevInfo | null;
  virusTotal?: VirusTotalInfo | null;
  virusTotalConfigured: boolean;
  riskSummary?: RiskSummaryInfo;
  errors?: Record<string, string>;
};

// Validate domain: allow only domain names like example.com or sub.example.com
// Reject URLs with protocol, paths, or suspicious characters
function validate_domain(domain: string): boolean {
  if (!domain || typeof domain !== "string") return false;
  // Reject if it contains protocol, path, or suspicious chars
  if (/https?:\/\//i.test(domain)) return false;
  if (domain.includes("/") || domain.includes("?") || domain.includes("#"))
    return false;
  // Must match valid domain pattern (supports multi-level like biga.bel.tr)
  const domainRegex =
    /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return domainRegex.test(domain);
}

function normalize_subdomain_name(
  name: string,
  domain: string,
): string | undefined {
  const normalized = name
    .trim()
    .toLowerCase()
    .replace(/^\*\./, "")
    .replace(/\.$/, "");

  if (!normalized.endsWith(`.${domain}`) || normalized === domain) {
    return undefined;
  }

  if (
    !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/.test(
      normalized,
    )
  ) {
    return undefined;
  }

  return normalized;
}

function merge_subdomains(
  ...sources: Array<Array<{ name: string }>>
): { name: string }[] {
  const seen = new Set<string>();
  const subdomains: { name: string }[] = [];

  for (const source of sources) {
    for (const subdomain of source) {
      if (seen.has(subdomain.name)) continue;
      seen.add(subdomain.name);
      subdomains.push(subdomain);
    }
  }

  return subdomains.sort((a, b) => a.name.localeCompare(b.name));
}

// Query crt.sh for subdomains via certificate transparency logs
async function get_crtsh_subdomains(
  domain: string,
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
      .map((n: string) => normalize_subdomain_name(n, domain))
      .filter((n): n is string => Boolean(n));
    for (const name of names) {
      if (!seen.has(name)) {
        seen.add(name);
        subdomains.push({ name });
      }
    }
  }
  return subdomains;
}

async function get_commoncrawl_subdomains(
  domain: string,
): Promise<{ name: string }[]> {
  const indexResp = await fetch("https://index.commoncrawl.org/collinfo.json", {
    headers: { "User-Agent": "OSINT-Demo/1.0 (educational)" },
    signal: AbortSignal.timeout(8000),
  });

  if (!indexResp.ok) {
    throw new Error(`Common Crawl index list returned ${indexResp.status}`);
  }

  const indexes = (await indexResp.json()) as Array<{
    id?: string;
    "cdx-api"?: string;
  }>;
  const indexUrls = indexes
    .slice(0, 3)
    .map((index) => index["cdx-api"])
    .filter((url): url is string => Boolean(url));

  if (indexUrls.length === 0) {
    throw new Error("Common Crawl index list did not include a CDX API URL");
  }

  const seen = new Set<string>();
  const subdomains: { name: string }[] = [];

  const results = await Promise.allSettled(
    indexUrls.map(async (indexUrl) => {
      const queryUrl = new URL(indexUrl);
      queryUrl.search = new URLSearchParams({
        url: `*.${domain}/*`,
        output: "json",
        fl: "url",
        filter: "status:200",
        limit: "1000",
      }).toString();

      const resp = await fetch(queryUrl, {
        headers: { "User-Agent": "OSINT-Demo/1.0 (educational)" },
        signal: AbortSignal.timeout(15000),
      });

      if (!resp.ok) {
        throw new Error(`Common Crawl CDX returned ${resp.status}`);
      }

      return resp.text();
    }),
  );

  for (const result of results) {
    if (result.status !== "fulfilled") continue;

    for (const line of result.value.split(/\n/)) {
      if (!line.trim()) continue;
      try {
        const item = JSON.parse(line) as { url?: string };
        if (!item.url) continue;
        const hostname = new URL(item.url).hostname;
        const name = normalize_subdomain_name(hostname, domain);
        if (!name || seen.has(name)) continue;
        seen.add(name);
        subdomains.push({ name });
      } catch {
        // Skip malformed CDX lines and invalid URLs.
      }
    }
  }

  if (subdomains.length === 0 && results.every((r) => r.status === "rejected")) {
    throw new Error("Common Crawl CDX queries failed");
  }

  return subdomains;
}

async function get_passive_subdomains(
  domain: string,
): Promise<{ name: string }[]> {
  const [crtshResult, commonCrawlResult] = await Promise.allSettled([
    get_crtsh_subdomains(domain),
    get_commoncrawl_subdomains(domain),
  ]);

  const fulfilled = [crtshResult, commonCrawlResult].filter(
    (result): result is PromiseFulfilledResult<{ name: string }[]> =>
      result.status === "fulfilled",
  );

  if (fulfilled.length > 0) {
    return merge_subdomains(...fulfilled.map((result) => result.value));
  }

  throw new Error(
    [crtshResult, commonCrawlResult]
      .map((result) =>
        result.status === "rejected"
          ? result.reason?.message ?? "subdomain source failed"
          : undefined,
      )
      .filter(Boolean)
      .join("; "),
  );
}

// Resolve DNS records using Node.js dns/promises
async function get_dns_records(domain: string): Promise<{
  A: string[];
  MX: string[];
  TXT: string[];
  NS: string[];
}> {
  const results = {
    A: [] as string[],
    MX: [] as string[],
    TXT: [] as string[],
    NS: [] as string[],
  };

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

async function resolve_txt_records(name: string): Promise<string[]> {
  try {
    const records = await dns.resolveTxt(name);
    return records.map((parts) => parts.join(""));
  } catch {
    return [];
  }
}

async function resolve_caa_records(domain: string): Promise<string[]> {
  try {
    const records = (await dns.resolveCaa(domain)) as unknown as Array<
      Record<string, unknown>
    >;
    return records.flatMap((record) =>
      Object.entries(record)
        .filter(([key, value]) => key !== "critical" && typeof value === "string")
        .map(([key, value]) => `${key}=${value}`),
    );
  } catch {
    return [];
  }
}

async function resolve_ds_records(domain: string): Promise<string[]> {
  const params = new URLSearchParams({ name: domain, type: "DS" });
  try {
    const resp = await fetch(`https://cloudflare-dns.com/dns-query?${params}`, {
      headers: {
        Accept: "application/dns-json",
        "User-Agent": "OSINT-Demo/1.0 (educational)",
      },
      signal: AbortSignal.timeout(5000),
    });

    if (!resp.ok) return [];

    const data = (await resp.json()) as {
      Answer?: Array<{ data?: string }>;
    };

    return (
      data.Answer?.map((answer) => answer.data).filter(
        (value): value is string => Boolean(value),
      ) ?? []
    );
  } catch {
    return [];
  }
}

function find_txt_record(records: string[], prefix: string): string | undefined {
  return records.find((record) =>
    record.toLowerCase().startsWith(prefix.toLowerCase()),
  );
}

function get_dmarc_policy(record: string | undefined): string | undefined {
  return record?.match(/(?:^|;)\s*p=([^;]+)/i)?.[1]?.trim().toLowerCase();
}

async function get_dns_security_info(domain: string): Promise<DnsSecurityInfo> {
  const [txtRecords, dmarcRecords, caa, dnssecRecords, mtaStsRecords, tlsRptRecords] =
    await Promise.all([
      resolve_txt_records(domain),
      resolve_txt_records(`_dmarc.${domain}`),
      resolve_caa_records(domain),
      resolve_ds_records(domain),
      resolve_txt_records(`_mta-sts.${domain}`),
      resolve_txt_records(`_smtp._tls.${domain}`),
    ]);

  const dmarc = find_txt_record(dmarcRecords, "v=DMARC1");

  return {
    spf: txtRecords.filter((record) => /^v=spf1\b/i.test(record)),
    dmarc,
    dmarcPolicy: get_dmarc_policy(dmarc),
    caa,
    dnssec: dnssecRecords.length > 0,
    dnssecRecords,
    mtaSts: find_txt_record(mtaStsRecords, "v=STSv1"),
    tlsRpt: find_txt_record(tlsRptRecords, "v=TLSRPTv1"),
  };
}

function query_whois_server(server: string, query: string): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    const socket = net.createConnection(43, server);

    socket.setTimeout(8000);
    socket.setEncoding("utf8");

    socket.on("connect", () => {
      socket.write(`${query}\r\n`);
    });

    socket.on("data", (chunk) => {
      data += chunk;
      if (data.length > 50000) socket.end();
    });

    socket.on("end", () => resolve(data));
    socket.on("timeout", () => {
      socket.destroy(new Error(`WHOIS query to ${server} timed out`));
    });
    socket.on("error", reject);
  });
}

function get_whois_field(
  rawText: string,
  patterns: RegExp[],
): string | undefined {
  for (const pattern of patterns) {
    const flags = pattern.flags.includes("g")
      ? pattern.flags
      : `${pattern.flags}g`;
    const match = new RegExp(pattern.source, flags).exec(rawText);
    if (match?.[1]) return match[1].trim();
  }
  return undefined;
}

function get_whois_fields(rawText: string, patterns: RegExp[]): string[] {
  const values = new Set<string>();
  for (const pattern of patterns) {
    for (const match of rawText.matchAll(pattern)) {
      if (match[1]) values.add(match[1].trim());
    }
  }
  return [...values];
}

function parse_whois_info(rawText: string, server?: string): WhoisInfo {
  return {
    server,
    registrar: get_whois_field(rawText, [
      /^Registrar:\s*(.+)$/gim,
      /^Sponsoring Registrar:\s*(.+)$/gim,
      /^Registrar Name:\s*(.+)$/gim,
      /^Organization Name\s*:\s*(.+)$/gim,
    ]),
    creationDate: get_whois_field(rawText, [
      /^Creation Date:\s*(.+)$/gim,
      /^Created On:\s*(.+)$/gim,
      /^Registered On:\s*(.+)$/gim,
      /^Domain Registration Date:\s*(.+)$/gim,
      /^Created on\.+:\s*(.+)$/gim,
    ]),
    expirationDate: get_whois_field(rawText, [
      /^Registry Expiry Date:\s*(.+)$/gim,
      /^Expiration Date:\s*(.+)$/gim,
      /^Expiry Date:\s*(.+)$/gim,
      /^Expires On:\s*(.+)$/gim,
      /^Expires on\.+:\s*(.+)$/gim,
    ]),
    updatedDate: get_whois_field(rawText, [
      /^Updated Date:\s*(.+)$/gim,
      /^Last Updated On:\s*(.+)$/gim,
      /^Last Modified:\s*(.+)$/gim,
      /^Last Update Time:\s*(.+)$/gim,
    ]),
    statuses: get_whois_fields(rawText, [
      /^Domain Status:\s*(.+)$/gim,
      /^Frozen Status:\s*(.+)$/gim,
      /^Transfer Status:\s*(.+)$/gim,
      /^Status:\s*(.+)$/gim,
    ]),
    nameServers: get_whois_fields(rawText, [
      /^Name Server:\s*(.+)$/gim,
      /^Nameserver:\s*(.+)$/gim,
      /^nserver:\s*(.+)$/gim,
      /^\s*([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\s+(?:\d{1,3}\.){3}\d{1,3}\s*$/gim,
    ]).map((value) => value.split(/\s+/)[0]),
    rawText: rawText.slice(0, 8000),
  };
}

async function get_whois_info(domain: string): Promise<WhoisInfo> {
  const ianaRaw = await query_whois_server("whois.iana.org", domain);
  const referServer = get_whois_field(ianaRaw, [
    /^refer:\s*(.+)$/gim,
    /^whois:\s*(.+)$/gim,
  ]);

  if (!referServer) {
    return parse_whois_info(ianaRaw, "whois.iana.org");
  }

  try {
    const registryRaw = await query_whois_server(referServer, domain);
    return parse_whois_info(registryRaw, referServer);
  } catch {
    return parse_whois_info(ianaRaw, "whois.iana.org");
  }
}

async function get_urlscan_info(
  domain: string,
  apiKey?: string,
): Promise<UrlscanInfo> {
  const params = new URLSearchParams({
    q: `page.domain:${domain}`,
    size: "5",
  });
  const headers: Record<string, string> = {
    "User-Agent": "OSINT-Demo/1.0 (educational)",
  };
  if (apiKey) headers["API-Key"] = apiKey;

  const resp = await fetch(`https://urlscan.io/api/v1/search/?${params}`, {
    headers,
    signal: AbortSignal.timeout(12000),
  });

  if (!resp.ok) {
    throw new Error(`urlscan.io returned ${resp.status}`);
  }

  const data = (await resp.json()) as {
    total?: number | { value?: number };
    results?: Array<{
      page?: {
        url?: string;
        domain?: string;
        ip?: string;
        country?: string;
        server?: string;
      };
      task?: { time?: string; url?: string };
      result?: string;
      screenshot?: string;
    }>;
  };
  const total =
    typeof data.total === "number" ? data.total : (data.total?.value ?? 0);

  return {
    total,
    results:
      data.results
        ?.map((item) => ({
          url: item.page?.url ?? item.task?.url ?? "",
          pageDomain: item.page?.domain,
          ip: item.page?.ip,
          country: item.page?.country,
          server: item.page?.server,
          scannedAt: item.task?.time,
          resultUrl: item.result,
          screenshotUrl: item.screenshot,
        }))
        .filter((item) => item.url) ?? [],
  };
}

// Query Shodan for info about an IP address
async function get_shodan_host(
  ip: string,
  apiKey: string,
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
  apiKey: string,
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
  apiKey: string,
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

async function get_abuseipdb_info(
  ips: string[],
  apiKey: string,
): Promise<AbuseIpInfo[]> {
  const uniqueIps = [...new Set(ips)].slice(0, 5);
  const results: AbuseIpInfo[] = [];

  for (const ip of uniqueIps) {
    const params = new URLSearchParams({
      ipAddress: ip,
      maxAgeInDays: "90",
    });
    const resp = await fetch(
      `https://api.abuseipdb.com/api/v2/check?${params}`,
      {
        headers: {
          Accept: "application/json",
          Key: apiKey,
          "User-Agent": "OSINT-Demo/1.0 (educational)",
        },
        signal: AbortSignal.timeout(10000),
      },
    );

    if (!resp.ok) {
      throw new Error(`AbuseIPDB API error: ${resp.status}`);
    }

    const payload = (await resp.json()) as {
      data?: {
        ipAddress?: string;
        abuseConfidenceScore?: number;
        totalReports?: number;
        countryCode?: string;
        isp?: string;
        domain?: string;
        lastReportedAt?: string;
      };
    };
    const data = payload.data;
    if (!data?.ipAddress) continue;

    results.push({
      ip: data.ipAddress,
      abuseConfidenceScore: data.abuseConfidenceScore ?? 0,
      totalReports: data.totalReports ?? 0,
      countryCode: data.countryCode,
      isp: data.isp,
      domain: data.domain,
      lastReportedAt: data.lastReportedAt,
    });
  }

  return results;
}

async function get_cisa_kev_matches(cveIds: string[]): Promise<CisaKevInfo> {
  const normalizedCves = new Set(cveIds.map((cve) => cve.toUpperCase()));
  if (normalizedCves.size === 0) return { matched: [] };

  const resp = await fetch(
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    {
      headers: { "User-Agent": "OSINT-Demo/1.0 (educational)" },
      signal: AbortSignal.timeout(10000),
    },
  );

  if (!resp.ok) {
    throw new Error(`CISA KEV catalog returned ${resp.status}`);
  }

  const data = (await resp.json()) as {
    catalogVersion?: string;
    dateReleased?: string;
    vulnerabilities?: CisaKevMatch[];
  };

  return {
    catalogVersion: data.catalogVersion,
    dateReleased: data.dateReleased,
    matched:
      data.vulnerabilities?.filter((entry) =>
        normalizedCves.has(entry.cveID.toUpperCase()),
      ) ?? [],
  };
}

function get_risk_level(score: number): RiskSummaryInfo["level"] {
  if (score >= 80) return "critical";
  if (score >= 55) return "high";
  if (score >= 25) return "medium";
  return "low";
}

function compute_risk_summary(input: {
  dnsSecurity?: DnsSecurityInfo | null;
  abuseIpDb?: AbuseIpInfo[] | null;
  shodan?: ShodanHostInfo[] | null;
  cisaKev?: CisaKevInfo | null;
  virusTotal?: VirusTotalInfo | null;
}): RiskSummaryInfo {
  let score = 0;
  const findings: RiskFinding[] = [];

  const addFinding = (
    severity: RiskFinding["severity"],
    label: string,
    detail: string,
    points: number,
  ) => {
    findings.push({ severity, label, detail });
    score += points;
  };

  if ((input.virusTotal?.malicious ?? 0) > 0) {
    addFinding(
      "critical",
      "VirusTotal malicious detections",
      `${input.virusTotal?.malicious ?? 0} engine(s) marked the domain malicious.`,
      35,
    );
  } else if ((input.virusTotal?.suspicious ?? 0) > 0) {
    addFinding(
      "medium",
      "VirusTotal suspicious detections",
      `${input.virusTotal?.suspicious ?? 0} engine(s) marked the domain suspicious.`,
      15,
    );
  }

  const maxAbuseScore = Math.max(
    0,
    ...(input.abuseIpDb ?? []).map((entry) => entry.abuseConfidenceScore),
  );
  if (maxAbuseScore >= 50) {
    addFinding(
      "high",
      "AbuseIPDB reports",
      `Highest resolved-IP abuse confidence score is ${maxAbuseScore}.`,
      25,
    );
  } else if (maxAbuseScore >= 25) {
    addFinding(
      "medium",
      "AbuseIPDB reports",
      `Highest resolved-IP abuse confidence score is ${maxAbuseScore}.`,
      12,
    );
  }

  if ((input.cisaKev?.matched.length ?? 0) > 0) {
    addFinding(
      "critical",
      "Known exploited CVEs",
      `${input.cisaKev?.matched.length ?? 0} Shodan-reported CVE(s) are in the CISA KEV catalog.`,
      35,
    );
  }

  const shodanVulnCount = (input.shodan ?? []).flatMap(
    (host) => host.vulns,
  ).length;
  if (shodanVulnCount > 0) {
    addFinding(
      "high",
      "Shodan CVE signals",
      `${shodanVulnCount} CVE signal(s) were reported by Shodan.`,
      20,
    );
  }

  const exposedPorts = new Set(
    (input.shodan ?? []).flatMap((host) => host.ports),
  );
  const sensitivePorts = [21, 22, 23, 445, 3389, 5900].filter((port) =>
    exposedPorts.has(port),
  );
  if (sensitivePorts.length > 0) {
    addFinding(
      "medium",
      "Sensitive exposed services",
      `Shodan reported sensitive port(s): ${sensitivePorts.join(", ")}.`,
      12,
    );
  }

  if (input.dnsSecurity) {
    if (input.dnsSecurity.spf.length === 0) {
      addFinding("medium", "Missing SPF", "No SPF TXT record was found.", 10);
    }
    if (!input.dnsSecurity.dmarc) {
      addFinding(
        "medium",
        "Missing DMARC",
        "No DMARC TXT record was found.",
        12,
      );
    } else if (input.dnsSecurity.dmarcPolicy === "none") {
      addFinding(
        "low",
        "DMARC monitoring mode",
        "DMARC policy is p=none.",
        6,
      );
    }
    if (input.dnsSecurity.caa.length === 0) {
      addFinding("low", "Missing CAA", "No CAA record was found.", 4);
    }
    if (!input.dnsSecurity.dnssec) {
      addFinding("low", "Missing DNSSEC DS", "No DS record was found.", 4);
    }
  }

  if (findings.length === 0) {
    findings.push({
      severity: "info",
      label: "No elevated passive signals",
      detail: "No high-signal passive risk indicators were found.",
    });
  }

  const cappedScore = Math.min(score, 100);

  return {
    score: cappedScore,
    level: get_risk_level(cappedScore),
    findings,
  };
}

// Generate a Markdown report from scan results
function generate_markdown_report(result: ScanResultForReport): string {
  const lines: string[] = [];
  lines.push(`# Passive OSINT Report`);
  lines.push(`\n**Target Domain:** \`${result.domain}\``);
  lines.push(`**Date/Time:** ${result.timestamp}`);
  lines.push(
    `\n> **Ethical Note:** This report was generated using passive OSINT sources only. No active scanning or exploitation was performed.`,
  );

  if (result.riskSummary) {
    lines.push(`\n## Risk Summary`);
    lines.push(`- **Score:** ${result.riskSummary.score}/100`);
    lines.push(`- **Level:** ${result.riskSummary.level.toUpperCase()}`);
    if (result.riskSummary.findings.length > 0) {
      lines.push(`\n| Severity | Finding | Detail |`);
      lines.push(`|----------|---------|--------|`);
      for (const finding of result.riskSummary.findings) {
        lines.push(
          `| ${finding.severity} | ${finding.label} | ${finding.detail} |`,
        );
      }
    }
  }

  lines.push(`\n## Subdomains (passive sources)`);
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

  lines.push(`\n## DNS Security Posture`);
  if (!result.dnsSecurity) {
    lines.push(`No DNS security data available.`);
  } else {
    const security = result.dnsSecurity;
    lines.push(`| Control | Status | Details |`);
    lines.push(`|---------|--------|---------|`);
    lines.push(
      `| SPF | ${security.spf.length > 0 ? "Present" : "Missing"} | ${security.spf.join("<br>") || "-"} |`,
    );
    lines.push(
      `| DMARC | ${security.dmarc ? "Present" : "Missing"} | ${security.dmarcPolicy ? `Policy: ${security.dmarcPolicy}` : "-"} |`,
    );
    lines.push(
      `| CAA | ${security.caa.length > 0 ? "Present" : "Missing"} | ${security.caa.join("<br>") || "-"} |`,
    );
    lines.push(
      `| DNSSEC DS | ${security.dnssec ? "Present" : "Missing"} | ${security.dnssecRecords.length} record(s) |`,
    );
    lines.push(
      `| MTA-STS | ${security.mtaSts ? "Present" : "Missing"} | ${security.mtaSts ?? "-"} |`,
    );
    lines.push(
      `| TLS-RPT | ${security.tlsRpt ? "Present" : "Missing"} | ${security.tlsRpt ?? "-"} |`,
    );
  }

  lines.push(`\n## WHOIS Registration`);
  if (!result.whois) {
    lines.push(`No WHOIS data available.`);
  } else {
    if (result.whois.server) lines.push(`- **Server:** ${result.whois.server}`);
    if (result.whois.registrar)
      lines.push(`- **Registrar:** ${result.whois.registrar}`);
    if (result.whois.creationDate)
      lines.push(`- **Created:** ${result.whois.creationDate}`);
    if (result.whois.expirationDate)
      lines.push(`- **Expires:** ${result.whois.expirationDate}`);
    if (result.whois.updatedDate)
      lines.push(`- **Updated:** ${result.whois.updatedDate}`);
    if (result.whois.nameServers.length > 0) {
      lines.push(`- **Nameservers:** ${result.whois.nameServers.join(", ")}`);
    }
    if (result.whois.statuses.length > 0) {
      lines.push(`- **Statuses:** ${result.whois.statuses.join(", ")}`);
    }
  }

  lines.push(`\n## urlscan.io Search`);
  if (!result.urlscan || result.urlscan.results.length === 0) {
    lines.push(`No urlscan.io search results returned.`);
  } else {
    lines.push(
      `Found ${result.urlscan.total} matching urlscan.io results. Showing latest ${result.urlscan.results.length}.`,
    );
    for (const item of result.urlscan.results) {
      lines.push(`- ${item.url}${item.ip ? ` (${item.ip})` : ""}`);
    }
  }

  lines.push(`\n## AbuseIPDB`);
  if (!result.abuseIpDbConfigured) {
    lines.push(`AbuseIPDB API key not configured.`);
  } else if (!result.abuseIpDb || result.abuseIpDb.length === 0) {
    lines.push(`No AbuseIPDB data returned for resolved IPs.`);
  } else {
    lines.push(`| IP | Abuse confidence | Reports |`);
    lines.push(`|----|------------------|---------|`);
    for (const ip of result.abuseIpDb) {
      lines.push(
        `| ${ip.ip} | ${ip.abuseConfidenceScore} | ${ip.totalReports} |`,
      );
    }
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
          `- **CVEs (reported by Shodan, not confirmed vulnerabilities):** ${host.vulns.join(", ")}`,
        );
      }
    }
  }

  lines.push(`\n## CISA Known Exploited Vulnerabilities`);
  if (!result.cisaKev) {
    lines.push(`CISA KEV matching was not available.`);
  } else if (result.cisaKev.matched.length === 0) {
    lines.push(`No Shodan-reported CVEs matched the CISA KEV catalog.`);
  } else {
    lines.push(
      `Matched **${result.cisaKev.matched.length}** CVE(s) in CISA KEV catalog version ${result.cisaKev.catalogVersion ?? "unknown"}.`,
    );
    lines.push(`| CVE | Vendor/Product | Date Added | Due Date | Ransomware |`);
    lines.push(`|-----|----------------|------------|----------|------------|`);
    for (const item of result.cisaKev.matched) {
      lines.push(
        `| ${item.cveID} | ${[item.vendorProject, item.product].filter(Boolean).join(" / ") || "-"} | ${item.dateAdded ?? "-"} | ${item.dueDate ?? "-"} | ${item.knownRansomwareCampaignUse ?? "-"} |`,
      );
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
    `*This report was generated using passive OSINT sources only. No active scanning, brute forcing, or exploitation was performed. For educational use only.*`,
  );

  return lines.join("\n");
}

// GET /api/osint/config — returns which API keys are configured
router.get("/osint/config", (req, res) => {
  res.json({
    shodanConfigured: !!process.env["SHODAN_API_KEY"],
    virusTotalConfigured: !!process.env["VIRUSTOTAL_API_KEY"],
    urlscanConfigured: !!process.env["URLSCAN_API_KEY"],
    abuseIpDbConfigured: !!process.env["ABUSEIPDB_API_KEY"],
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

  // Run free passive sources in parallel.
  const [
    subdomainsResult,
    dnsResult,
    dnsSecurityResult,
    whoisResult,
    urlscanResult,
  ] = await Promise.allSettled([
    get_passive_subdomains(domain),
    get_dns_records(domain),
    get_dns_security_info(domain),
    get_whois_info(domain),
    get_urlscan_info(domain, process.env["URLSCAN_API_KEY"]),
  ]);

  const subdomains =
    subdomainsResult.status === "fulfilled"
      ? subdomainsResult.value
      : ((errors["subdomains"] = subdomainsResult.reason?.message ?? "Failed"),
        []);

  const dns =
    dnsResult.status === "fulfilled"
      ? dnsResult.value
      : ((errors["dns"] = dnsResult.reason?.message ?? "Failed"),
        { A: [], MX: [], TXT: [], NS: [] });

  const resolvedIPs = dns.A;

  const dnsSecurity =
    dnsSecurityResult.status === "fulfilled"
      ? dnsSecurityResult.value
      : ((errors["dnsSecurity"] =
          dnsSecurityResult.reason?.message ?? "Failed"),
        null);

  const whois =
    whoisResult.status === "fulfilled"
      ? whoisResult.value
      : ((errors["whois"] = whoisResult.reason?.message ?? "Failed"), null);

  const urlscanConfigured = !!process.env["URLSCAN_API_KEY"];
  const urlscan =
    urlscanResult.status === "fulfilled"
      ? urlscanResult.value
      : ((errors["urlscan"] = urlscanResult.reason?.message ?? "Failed"), null);

  const abuseIpDbKey = process.env["ABUSEIPDB_API_KEY"];
  const abuseIpDbConfigured = !!abuseIpDbKey;
  let abuseIpDb: AbuseIpInfo[] | null = null;

  if (abuseIpDbConfigured && abuseIpDbKey && resolvedIPs.length > 0) {
    try {
      abuseIpDb = await get_abuseipdb_info(resolvedIPs, abuseIpDbKey);
    } catch (err) {
      errors["abuseIpDb"] =
        err instanceof Error ? err.message : "AbuseIPDB query failed";
    }
  }

  // Shodan integration
  const shodanKey = process.env["SHODAN_API_KEY"];
  const shodanConfigured = !!shodanKey;
  let shodan: typeof subdomains extends never
    ? never
    : typeof subdomains extends { name: string }[]
      ?
          | {
              ip: string;
              ports: number[];
              hostnames: string[];
              org: string;
              isp: string;
              country: string;
              tags: string[];
              vulns: string[];
            }[]
          | null
      : never = null;

  if (shodanConfigured && resolvedIPs.length > 0 && shodanKey) {
    try {
      shodan = await get_shodan_info(resolvedIPs, shodanKey);
    } catch (err) {
      errors["shodan"] =
        err instanceof Error ? err.message : "Shodan query failed";
    }
  }

  const reportedCves = [
    ...new Set(
      (shodan ?? [])
        .flatMap((host) => host.vulns)
        .filter((cve) => /^CVE-\d{4}-\d{4,}$/i.test(cve)),
    ),
  ];
  let cisaKev: CisaKevInfo | null = { matched: [] };

  if (reportedCves.length > 0) {
    try {
      cisaKev = await get_cisa_kev_matches(reportedCves);
    } catch (err) {
      errors["cisaKev"] =
        err instanceof Error ? err.message : "CISA KEV query failed";
      cisaKev = null;
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

  const riskSummary = compute_risk_summary({
    dnsSecurity,
    abuseIpDb,
    shodan,
    cisaKev,
    virusTotal,
  });

  res.json({
    domain,
    timestamp,
    subdomains,
    dns,
    dnsSecurity,
    whois,
    urlscan,
    urlscanConfigured,
    abuseIpDb,
    abuseIpDbConfigured,
    shodan,
    shodanConfigured,
    cisaKev,
    virusTotal,
    virusTotalConfigured,
    riskSummary,
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

  const scanResult = parseResult.data as Parameters<
    typeof generate_markdown_report
  >[0];
  const content = generate_markdown_report(scanResult);
  const filename = `osint-report-${scanResult.domain}-${new Date().toISOString().slice(0, 10)}.md`;

  res.json({ content, filename });
});

export default router;
