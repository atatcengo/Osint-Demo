import { Router } from "express";
import dns from "dns/promises";
import { RunOsintScanBody, GenerateOsintReportBody } from "@workspace/api-zod";

const router = Router();

type DnsRecords = {
  A: string[];
  MX: string[];
  TXT: string[];
  NS: string[];
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

type RdapInfo = {
  registrar?: string;
  registrationDate?: string;
  expirationDate?: string;
  updatedDate?: string;
  status: string[];
  nameservers: string[];
  abuseContacts: string[];
};

type WaybackCapture = {
  url: string;
  timestamp: string;
  statusCode?: string;
  mimeType?: string;
};

type WaybackInfo = {
  captures: WaybackCapture[];
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

type SecurityTrailsInfo = {
  subdomains: string[];
};

type CensysHostInfo = {
  ip: string;
  services: string[];
  location?: string;
  autonomousSystem?: string;
};

type CensysInfo = {
  total: number;
  hosts: CensysHostInfo[];
};

type VirusTotalInfo = {
  harmless: number;
  suspicious: number;
  malicious: number;
  undetected: number;
  reputation: number;
  categories?: Record<string, string>;
};

type ScanResultForReport = {
  domain: string;
  timestamp: string;
  subdomains: { name: string }[];
  dns: DnsRecords;
  rdap?: RdapInfo | null;
  wayback?: WaybackInfo | null;
  urlscan?: UrlscanInfo | null;
  urlscanConfigured?: boolean;
  abuseIpDb?: AbuseIpInfo[] | null;
  abuseIpDbConfigured?: boolean;
  securityTrails?: SecurityTrailsInfo | null;
  securityTrailsConfigured?: boolean;
  censys?: CensysInfo | null;
  censysConfigured?: boolean;
  shodan?: ShodanHostInfo[] | null;
  shodanConfigured: boolean;
  virusTotal?: VirusTotalInfo | null;
  virusTotalConfigured: boolean;
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

function get_vcard_values(vcardArray: unknown, key: string): string[] {
  if (!Array.isArray(vcardArray) || !Array.isArray(vcardArray[1])) return [];

  return vcardArray[1]
    .filter((entry: unknown): entry is unknown[] => Array.isArray(entry))
    .filter((entry) => entry[0] === key && typeof entry[3] === "string")
    .map((entry) => String(entry[3]));
}

function get_rdap_event_date(
  events: Array<{ eventAction?: string; eventDate?: string }> | undefined,
  actions: string[],
): string | undefined {
  return events?.find(
    (event) =>
      event.eventAction && actions.includes(event.eventAction.toLowerCase()),
  )?.eventDate;
}

async function get_rdap_info(domain: string): Promise<RdapInfo> {
  const resp = await fetch(
    `https://rdap.org/domain/${encodeURIComponent(domain)}`,
    {
      headers: { "User-Agent": "OSINT-Demo/1.0 (educational)" },
      signal: AbortSignal.timeout(10000),
    },
  );

  if (resp.status === 404) {
    return { status: [], nameservers: [], abuseContacts: [] };
  }

  if (!resp.ok) {
    throw new Error(`RDAP returned ${resp.status}`);
  }

  const data = (await resp.json()) as {
    status?: string[];
    events?: Array<{ eventAction?: string; eventDate?: string }>;
    nameservers?: Array<{ ldhName?: string; unicodeName?: string }>;
    entities?: Array<{
      roles?: string[];
      vcardArray?: unknown;
      entities?: Array<{ roles?: string[]; vcardArray?: unknown }>;
    }>;
  };

  const registrarEntity = data.entities?.find((entity) =>
    entity.roles?.includes("registrar"),
  );
  const registrar = get_vcard_values(registrarEntity?.vcardArray, "fn")[0];

  const abuseContacts = new Set<string>();
  for (const entity of data.entities ?? []) {
    const nested = [entity, ...(entity.entities ?? [])];
    for (const candidate of nested) {
      if (!candidate.roles?.includes("abuse")) continue;
      for (const email of get_vcard_values(candidate.vcardArray, "email")) {
        abuseContacts.add(email);
      }
    }
  }

  return {
    registrar,
    registrationDate: get_rdap_event_date(data.events, ["registration"]),
    expirationDate: get_rdap_event_date(data.events, ["expiration"]),
    updatedDate: get_rdap_event_date(data.events, [
      "last changed",
      "last update of rdap database",
    ]),
    status: data.status ?? [],
    nameservers:
      data.nameservers
        ?.map((ns) => ns.ldhName ?? ns.unicodeName)
        .filter((name): name is string => Boolean(name)) ?? [],
    abuseContacts: [...abuseContacts],
  };
}

function format_wayback_timestamp(timestamp: string): string {
  if (!/^\d{14}$/.test(timestamp)) return timestamp;
  return `${timestamp.slice(0, 4)}-${timestamp.slice(4, 6)}-${timestamp.slice(6, 8)}T${timestamp.slice(8, 10)}:${timestamp.slice(10, 12)}:${timestamp.slice(12, 14)}Z`;
}

async function get_wayback_info(domain: string): Promise<WaybackInfo> {
  const params = new URLSearchParams({
    url: `${domain}/*`,
    output: "json",
    fl: "timestamp,original,statuscode,mimetype",
    filter: "statuscode:200",
    collapse: "urlkey",
    limit: "10",
  });
  try {
    const resp = await fetch(`https://web.archive.org/cdx?${params}`, {
      headers: { "User-Agent": "OSINT-Demo/1.0 (educational)" },
      signal: AbortSignal.timeout(8000),
    });

    if (!resp.ok) {
      throw new Error(`Wayback CDX returned ${resp.status}`);
    }

    const rows = (await resp.json()) as unknown[][];
    const captures = rows.slice(1).flatMap((row): WaybackCapture[] => {
      const [timestamp, url, statusCode, mimeType] = row;
      if (typeof timestamp !== "string" || typeof url !== "string") return [];

      return [
        {
          url,
          timestamp: format_wayback_timestamp(timestamp),
          statusCode: typeof statusCode === "string" ? statusCode : undefined,
          mimeType: typeof mimeType === "string" ? mimeType : undefined,
        },
      ];
    });

    return { captures };
  } catch {
    const availableParams = new URLSearchParams({ url: domain });
    const resp = await fetch(
      `https://archive.org/wayback/available?${availableParams}`,
      {
        headers: { "User-Agent": "OSINT-Demo/1.0 (educational)" },
        signal: AbortSignal.timeout(8000),
      },
    );

    if (!resp.ok) {
      throw new Error(`Wayback availability returned ${resp.status}`);
    }

    const data = (await resp.json()) as {
      archived_snapshots?: {
        closest?: {
          available?: boolean;
          url?: string;
          timestamp?: string;
          status?: string;
        };
      };
    };
    const closest = data.archived_snapshots?.closest;
    if (!closest?.available || !closest.url || !closest.timestamp) {
      return { captures: [] };
    }

    return {
      captures: [
        {
          url: closest.url,
          timestamp: format_wayback_timestamp(closest.timestamp),
          statusCode: closest.status,
        },
      ],
    };
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

async function get_securitytrails_info(
  domain: string,
  apiKey: string,
): Promise<SecurityTrailsInfo> {
  const resp = await fetch(
    `https://api.securitytrails.com/v1/domain/${encodeURIComponent(domain)}/subdomains?children_only=false`,
    {
      headers: {
        APIKEY: apiKey,
        "User-Agent": "OSINT-Demo/1.0 (educational)",
      },
      signal: AbortSignal.timeout(12000),
    },
  );

  if (!resp.ok) {
    throw new Error(`SecurityTrails API error: ${resp.status}`);
  }

  const data = (await resp.json()) as { subdomains?: string[] };
  return {
    subdomains:
      data.subdomains?.map((sub) => `${sub}.${domain}`).slice(0, 100) ?? [],
  };
}

async function get_censys_info(
  domain: string,
  apiId: string,
  apiSecret: string,
): Promise<CensysInfo> {
  const params = new URLSearchParams({
    q: domain,
    per_page: "5",
    virtual_hosts: "EXCLUDE",
  });
  const credentials = Buffer.from(`${apiId}:${apiSecret}`).toString("base64");
  const resp = await fetch(
    `https://search.censys.io/api/v2/hosts/search?${params}`,
    {
      headers: {
        Authorization: `Basic ${credentials}`,
        Accept: "application/json",
        "User-Agent": "OSINT-Demo/1.0 (educational)",
      },
      signal: AbortSignal.timeout(12000),
    },
  );

  if (!resp.ok) {
    throw new Error(`Censys API error: ${resp.status}`);
  }

  const data = (await resp.json()) as {
    result?: {
      total?: number;
      hits?: Array<{
        ip?: string;
        location?: { country?: string; city?: string };
        autonomous_system?: { name?: string; asn?: number };
        services?: Array<{
          port?: number;
          service_name?: string;
          transport_protocol?: string;
        }>;
      }>;
    };
  };

  return {
    total: data.result?.total ?? 0,
    hosts:
      data.result?.hits?.flatMap((hit): CensysHostInfo[] => {
        if (!hit.ip) return [];
        return [
          {
            ip: hit.ip,
            services:
              hit.services?.map((service) =>
                [service.service_name, service.port, service.transport_protocol]
                  .filter(Boolean)
                  .join("/"),
              ) ?? [],
            location:
              [hit.location?.city, hit.location?.country]
                .filter(Boolean)
                .join(", ") || undefined,
            autonomousSystem: hit.autonomous_system
              ? `${hit.autonomous_system.name ?? "AS"} ${hit.autonomous_system.asn ?? ""}`.trim()
              : undefined,
          },
        ];
      }) ?? [],
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

  lines.push(`\n## RDAP Registration`);
  if (!result.rdap) {
    lines.push(`No RDAP data available.`);
  } else {
    if (result.rdap.registrar)
      lines.push(`- **Registrar:** ${result.rdap.registrar}`);
    if (result.rdap.registrationDate)
      lines.push(`- **Registered:** ${result.rdap.registrationDate}`);
    if (result.rdap.expirationDate)
      lines.push(`- **Expires:** ${result.rdap.expirationDate}`);
    if (result.rdap.updatedDate)
      lines.push(`- **Updated:** ${result.rdap.updatedDate}`);
    if (result.rdap.nameservers.length > 0) {
      lines.push(`- **Nameservers:** ${result.rdap.nameservers.join(", ")}`);
    }
    if (result.rdap.abuseContacts.length > 0) {
      lines.push(
        `- **Abuse contacts:** ${result.rdap.abuseContacts.join(", ")}`,
      );
    }
  }

  lines.push(`\n## Wayback Machine`);
  if (!result.wayback || result.wayback.captures.length === 0) {
    lines.push(`No recent archived captures returned.`);
  } else {
    lines.push(`| Timestamp | URL |`);
    lines.push(`|-----------|-----|`);
    for (const capture of result.wayback.captures) {
      lines.push(`| ${capture.timestamp} | ${capture.url} |`);
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

  lines.push(`\n## SecurityTrails`);
  if (!result.securityTrailsConfigured) {
    lines.push(`SecurityTrails API key not configured.`);
  } else if (
    !result.securityTrails ||
    result.securityTrails.subdomains.length === 0
  ) {
    lines.push(`No SecurityTrails subdomains returned.`);
  } else {
    lines.push(
      `Returned ${result.securityTrails.subdomains.length} subdomains.`,
    );
  }

  lines.push(`\n## Censys`);
  if (!result.censysConfigured) {
    lines.push(`Censys API credentials not configured.`);
  } else if (!result.censys || result.censys.hosts.length === 0) {
    lines.push(`No Censys hosts returned.`);
  } else {
    lines.push(
      `Found ${result.censys.total} matching Censys hosts. Showing ${result.censys.hosts.length}.`,
    );
    for (const host of result.censys.hosts) {
      lines.push(
        `- ${host.ip}: ${host.services.join(", ") || "No services listed"}`,
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
    securityTrailsConfigured: !!process.env["SECURITYTRAILS_API_KEY"],
    censysConfigured: !!(
      process.env["CENSYS_API_ID"] && process.env["CENSYS_API_SECRET"]
    ),
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
    rdapResult,
    waybackResult,
    urlscanResult,
  ] = await Promise.allSettled([
    get_crtsh_subdomains(domain),
    get_dns_records(domain),
    get_rdap_info(domain),
    get_wayback_info(domain),
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

  const rdap =
    rdapResult.status === "fulfilled"
      ? rdapResult.value
      : ((errors["rdap"] = rdapResult.reason?.message ?? "Failed"), null);

  const wayback =
    waybackResult.status === "fulfilled"
      ? waybackResult.value
      : ((errors["wayback"] = waybackResult.reason?.message ?? "Failed"), null);

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

  const securityTrailsKey = process.env["SECURITYTRAILS_API_KEY"];
  const securityTrailsConfigured = !!securityTrailsKey;
  let securityTrails: SecurityTrailsInfo | null = null;

  if (securityTrailsConfigured && securityTrailsKey) {
    try {
      securityTrails = await get_securitytrails_info(domain, securityTrailsKey);
    } catch (err) {
      errors["securityTrails"] =
        err instanceof Error ? err.message : "SecurityTrails query failed";
    }
  }

  const censysApiId = process.env["CENSYS_API_ID"];
  const censysApiSecret = process.env["CENSYS_API_SECRET"];
  const censysConfigured = !!(censysApiId && censysApiSecret);
  let censys: CensysInfo | null = null;

  if (censysConfigured && censysApiId && censysApiSecret) {
    try {
      censys = await get_censys_info(domain, censysApiId, censysApiSecret);
    } catch (err) {
      errors["censys"] =
        err instanceof Error ? err.message : "Censys query failed";
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
    rdap,
    wayback,
    urlscan,
    urlscanConfigured,
    abuseIpDb,
    abuseIpDbConfigured,
    securityTrails,
    securityTrailsConfigured,
    censys,
    censysConfigured,
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

  const scanResult = parseResult.data as Parameters<
    typeof generate_markdown_report
  >[0];
  const content = generate_markdown_report(scanResult);
  const filename = `osint-report-${scanResult.domain}-${new Date().toISOString().slice(0, 10)}.md`;

  res.json({ content, filename });
});

export default router;
