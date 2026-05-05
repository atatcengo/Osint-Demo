import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import {
  Search,
  Download,
  ShieldAlert,
  Activity,
  AlertCircle,
  CheckCircle2,
  XCircle,
  Database,
  Server,
  Globe,
  Key,
  History,
  Trash2,
  Fingerprint,
  Archive,
  ExternalLink,
  Radar,
  Network,
} from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import {
  useRunOsintScan,
  useGenerateOsintReport,
  useGetOsintConfig,
  getGetOsintConfigQueryKey,
  useListScanHistory,
  getListScanHistoryQueryKey,
  useSaveScanResult,
  useDeleteScanHistoryEntry,
} from "@workspace/api-client-react";
import type { ScanResult } from "@workspace/api-client-react";

import { Button } from "@/components/ui/button";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Separator } from "@/components/ui/separator";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";

const formSchema = z.object({
  domain: z
    .string()
    .regex(
      /^(?!:\/\/)(?!https?:\/\/)([a-zA-Z0-9-_]+\.)+[a-zA-Z]{2,}$/,
      "Must be a valid domain name (e.g. example.com). No http:// or paths.",
    ),
});

export default function Home() {
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const queryClient = useQueryClient();

  const { data: config } = useGetOsintConfig({
    query: {
      enabled: true,
      queryKey: getGetOsintConfigQueryKey(),
    },
  });

  const { data: history } = useListScanHistory({
    query: {
      queryKey: getListScanHistoryQueryKey(),
    },
  });

  const saveScan = useSaveScanResult({
    mutation: {
      onSuccess: () => {
        queryClient.invalidateQueries({
          queryKey: getListScanHistoryQueryKey(),
        });
      },
    },
  });

  const deleteHistoryEntry = useDeleteScanHistoryEntry({
    mutation: {
      onSuccess: () => {
        queryClient.invalidateQueries({
          queryKey: getListScanHistoryQueryKey(),
        });
      },
    },
  });

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      domain: "",
    },
  });

  const runScan = useRunOsintScan();
  const generateReport = useGenerateOsintReport();

  async function onSubmit(values: z.infer<typeof formSchema>) {
    setScanResult(null);
    try {
      const result = await runScan.mutateAsync({
        data: { domain: values.domain },
      });
      setScanResult(result);
      await saveScan.mutateAsync({ data: result });
    } catch (error) {
      console.error(error);
    }
  }

  const loadHistoryResult = (result: ScanResult) => {
    setScanResult(result);
    form.setValue("domain", result.domain);
  };

  const handleDownload = async () => {
    if (!scanResult) return;
    try {
      const report = await generateReport.mutateAsync({ data: scanResult });
      const blob = new Blob([report.content], { type: "text/markdown" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = report.filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error("Failed to generate report", error);
    }
  };

  return (
    <div className="min-h-screen bg-background text-foreground font-mono p-4 md:p-8">
      <div className="max-w-6xl mx-auto space-y-8">
        {/* Header */}
        <header className="space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <h1 className="text-3xl font-bold text-primary flex items-center gap-2 tracking-tight">
                <Activity className="w-8 h-8" />
                PASSIVE_OSINT_DEMO
              </h1>
              <p className="text-muted-foreground mt-1 font-sans">
                Educational Reconnaissance Dashboard
              </p>
            </div>

            <div className="flex items-center gap-4 text-xs">
              <Sheet>
                <SheetTrigger asChild>
                  <Button
                    variant="outline"
                    className="border-primary/30 hover:bg-primary/10 h-auto py-1.5 px-3 text-xs"
                  >
                    <History className="w-3.5 h-3.5 mr-2" />
                    History
                  </Button>
                </SheetTrigger>
                <SheetContent className="bg-background border-l-border/50 font-mono w-full sm:max-w-md overflow-y-auto">
                  <SheetHeader className="mb-6">
                    <SheetTitle className="text-primary flex items-center gap-2 tracking-tight">
                      <History className="w-5 h-5" />
                      SCAN_HISTORY
                    </SheetTitle>
                  </SheetHeader>

                  <div className="space-y-4">
                    {!history || history.length === 0 ? (
                      <div className="text-sm text-muted-foreground text-center py-8">
                        No previous scans found.
                      </div>
                    ) : (
                      history?.map((entry) => (
                        <div
                          key={entry.id}
                          className="group flex flex-col gap-2 p-3 border border-border/50 rounded-lg bg-card/50 hover:bg-secondary/30 transition-colors"
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-primary truncate max-w-[200px]">
                              {entry.domain}
                            </span>
                            <span className="text-xs text-muted-foreground">
                              {new Date(entry.scannedAt).toLocaleString(
                                undefined,
                                {
                                  month: "short",
                                  day: "numeric",
                                  hour: "2-digit",
                                  minute: "2-digit",
                                },
                              )}
                            </span>
                          </div>
                          <div className="flex gap-2 mt-1">
                            <Button
                              variant="secondary"
                              size="sm"
                              className="flex-1 h-8 text-xs font-bold"
                              onClick={() => loadHistoryResult(entry.result)}
                            >
                              LOAD_RESULT
                            </Button>
                            <Button
                              variant="destructive"
                              size="sm"
                              className="h-8 w-8 p-0"
                              onClick={() =>
                                deleteHistoryEntry.mutate({ id: entry.id })
                              }
                              disabled={deleteHistoryEntry.isPending}
                            >
                              <Trash2 className="w-4 h-4" />
                            </Button>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </SheetContent>
              </Sheet>

              <div className="flex items-center gap-2 bg-secondary/50 px-3 py-1.5 rounded border border-border hidden md:flex">
                <Database className="w-3.5 h-3.5 text-muted-foreground" />
                <span className="text-muted-foreground">Shodan:</span>
                {config?.shodanConfigured ? (
                  <span className="text-emerald-400 flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" /> Active
                  </span>
                ) : (
                  <span className="text-muted-foreground flex items-center gap-1">
                    <XCircle className="w-3 h-3" /> Missing Key
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2 bg-secondary/50 px-3 py-1.5 rounded border border-border hidden md:flex">
                <ShieldAlert className="w-3.5 h-3.5 text-muted-foreground" />
                <span className="text-muted-foreground">VirusTotal:</span>
                {config?.virusTotalConfigured ? (
                  <span className="text-emerald-400 flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" /> Active
                  </span>
                ) : (
                  <span className="text-muted-foreground flex items-center gap-1">
                    <XCircle className="w-3 h-3" /> Missing Key
                  </span>
                )}
              </div>
            </div>
          </div>

          <Alert className="bg-primary/5 border-primary/20 text-primary-foreground">
            <AlertCircle className="h-4 w-4 text-primary" />
            <AlertTitle className="text-primary font-bold">
              ETHICAL DISCLAIMER
            </AlertTitle>
            <AlertDescription className="text-primary/80 font-sans">
              This tool uses passive/public sources only. No active scanning,
              probing, or exploitation is performed against the target
              infrastructure.
            </AlertDescription>
          </Alert>
        </header>

        {/* Input Form */}
        <Card className="border-primary/20 bg-card/50 backdrop-blur">
          <CardContent className="pt-6">
            <Form {...form}>
              <form
                onSubmit={form.handleSubmit(onSubmit)}
                className="flex flex-col md:flex-row gap-4 items-start md:items-start"
              >
                <FormField
                  control={form.control}
                  name="domain"
                  render={({ field }) => (
                    <FormItem className="flex-1 w-full">
                      <FormControl>
                        <div className="relative">
                          <Globe className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                          <Input
                            placeholder="target-domain.com"
                            className="pl-9 font-mono bg-background border-primary/30 focus-visible:ring-primary h-10 text-base"
                            {...field}
                            disabled={runScan.isPending}
                          />
                        </div>
                      </FormControl>
                      <FormMessage className="font-sans" />
                    </FormItem>
                  )}
                />
                <Button
                  type="submit"
                  disabled={runScan.isPending}
                  className="w-full md:w-auto h-10 bg-primary text-primary-foreground hover:bg-primary/90 font-bold tracking-wider"
                >
                  {runScan.isPending ? (
                    <>
                      <Activity className="w-4 h-4 mr-2 animate-pulse" />
                      INITIATING_SCAN...
                    </>
                  ) : (
                    <>
                      <Search className="w-4 h-4 mr-2" />
                      RUN_OSINT_CHECK
                    </>
                  )}
                </Button>
              </form>
            </Form>
          </CardContent>
        </Card>

        {/* Loading State */}
        {runScan.isPending && (
          <div className="py-12 flex flex-col items-center justify-center space-y-4 animate-in fade-in zoom-in duration-500">
            <div className="w-16 h-16 border-4 border-primary/20 border-t-primary rounded-full animate-spin"></div>
            <div className="text-primary font-bold animate-pulse tracking-widest">
              QUERYING PUBLIC INTELLIGENCE SOURCES...
            </div>
            <p className="text-muted-foreground text-sm font-sans">
              This may take 5-10 seconds depending on API response times.
            </p>
          </div>
        )}

        {/* Results */}
        {scanResult && !runScan.isPending && (
          <div className="space-y-6 animate-in slide-in-from-bottom-4 duration-700">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-bold text-foreground">
                  Scan Results: {scanResult.domain}
                </h2>
                <p className="text-sm text-muted-foreground">
                  Generated at {new Date(scanResult.timestamp).toLocaleString()}
                </p>
              </div>
              <Button
                variant="outline"
                onClick={handleDownload}
                disabled={generateReport.isPending}
                className="border-primary/30 hover:bg-primary/10"
              >
                <Download className="w-4 h-4 mr-2" />
                {generateReport.isPending ? "GENERATING..." : "DOWNLOAD_REPORT"}
              </Button>
            </div>

            {/* Errors Section */}
            {scanResult.errors && Object.keys(scanResult.errors).length > 0 && (
              <Alert
                variant="destructive"
                className="bg-destructive/10 border-destructive/50 text-destructive-foreground"
              >
                <AlertCircle className="h-4 w-4" />
                <AlertTitle>Partial Scan Failures</AlertTitle>
                <AlertDescription className="font-sans">
                  <ul className="list-disc pl-4 mt-2 space-y-1 text-sm">
                    {Object.entries(scanResult.errors).map(
                      ([source, error]) => (
                        <li key={source}>
                          <strong>{source}:</strong> {error}
                        </li>
                      ),
                    )}
                  </ul>
                </AlertDescription>
              </Alert>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* DNS Records */}
              <Card className="border-primary/20">
                <CardHeader className="pb-3 border-b border-border/50 bg-secondary/20">
                  <CardTitle className="flex items-center gap-2 text-lg">
                    <Server className="w-5 h-5 text-primary" />
                    DNS Records
                  </CardTitle>
                </CardHeader>
                <CardContent className="pt-4 space-y-4">
                  {Object.entries(scanResult.dns).map(([type, records]) => (
                    <div key={type}>
                      <h4 className="text-sm font-bold text-primary mb-2 border-b border-primary/20 inline-block pr-4">
                        {type} RECORDS
                      </h4>
                      {records.length > 0 ? (
                        <ul className="space-y-1">
                          {records.map((record: string, i: number) => (
                            <li
                              key={i}
                              className="text-sm text-muted-foreground break-all"
                            >
                              {record}
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className="text-sm text-muted-foreground/50 italic">
                          No records found
                        </p>
                      )}
                    </div>
                  ))}
                </CardContent>
              </Card>

              {/* VirusTotal */}
              <Card className="border-primary/20">
                <CardHeader className="pb-3 border-b border-border/50 bg-secondary/20">
                  <CardTitle className="flex items-center gap-2 text-lg">
                    <ShieldAlert className="w-5 h-5 text-primary" />
                    VirusTotal Reputation
                  </CardTitle>
                </CardHeader>
                <CardContent className="pt-4">
                  {!scanResult.virusTotalConfigured ? (
                    <div className="h-full flex flex-col items-center justify-center py-8 text-muted-foreground">
                      <Key className="w-8 h-8 mb-2 opacity-50" />
                      <p>API Key Not Configured</p>
                    </div>
                  ) : scanResult.virusTotal ? (
                    <div className="space-y-4">
                      <div className="flex items-end gap-2">
                        <span className="text-4xl font-bold leading-none">
                          {scanResult.virusTotal.reputation}
                        </span>
                        <span className="text-sm text-muted-foreground mb-1">
                          Reputation Score
                        </span>
                      </div>

                      <div className="grid grid-cols-2 gap-4">
                        <div className="bg-emerald-500/10 border border-emerald-500/20 p-3 rounded">
                          <div className="text-emerald-500 text-sm font-bold">
                            HARMLESS
                          </div>
                          <div className="text-2xl font-mono">
                            {scanResult.virusTotal.harmless}
                          </div>
                        </div>
                        <div className="bg-destructive/10 border border-destructive/20 p-3 rounded">
                          <div className="text-destructive text-sm font-bold">
                            MALICIOUS
                          </div>
                          <div className="text-2xl font-mono">
                            {scanResult.virusTotal.malicious}
                          </div>
                        </div>
                        <div className="bg-amber-500/10 border border-amber-500/20 p-3 rounded">
                          <div className="text-amber-500 text-sm font-bold">
                            SUSPICIOUS
                          </div>
                          <div className="text-2xl font-mono">
                            {scanResult.virusTotal.suspicious}
                          </div>
                        </div>
                        <div className="bg-secondary p-3 rounded">
                          <div className="text-muted-foreground text-sm font-bold">
                            UNDETECTED
                          </div>
                          <div className="text-2xl font-mono">
                            {scanResult.virusTotal.undetected}
                          </div>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground">
                      No data available.
                    </p>
                  )}
                </CardContent>
              </Card>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* RDAP */}
              <Card className="border-primary/20">
                <CardHeader className="pb-3 border-b border-border/50 bg-secondary/20">
                  <CardTitle className="flex items-center gap-2 text-lg">
                    <Fingerprint className="w-5 h-5 text-primary" />
                    RDAP Registration
                  </CardTitle>
                </CardHeader>
                <CardContent className="pt-4">
                  {scanResult.rdap ? (
                    <div className="space-y-3 text-sm">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                          <div className="text-xs font-bold text-muted-foreground uppercase">
                            Registrar
                          </div>
                          <div className="text-foreground break-words">
                            {scanResult.rdap.registrar || "Unknown"}
                          </div>
                        </div>
                        <div>
                          <div className="text-xs font-bold text-muted-foreground uppercase">
                            Registered
                          </div>
                          <div className="text-foreground">
                            {scanResult.rdap.registrationDate
                              ? new Date(
                                  scanResult.rdap.registrationDate,
                                ).toLocaleDateString()
                              : "Unknown"}
                          </div>
                        </div>
                        <div>
                          <div className="text-xs font-bold text-muted-foreground uppercase">
                            Expires
                          </div>
                          <div className="text-foreground">
                            {scanResult.rdap.expirationDate
                              ? new Date(
                                  scanResult.rdap.expirationDate,
                                ).toLocaleDateString()
                              : "Unknown"}
                          </div>
                        </div>
                        <div>
                          <div className="text-xs font-bold text-muted-foreground uppercase">
                            Updated
                          </div>
                          <div className="text-foreground">
                            {scanResult.rdap.updatedDate
                              ? new Date(
                                  scanResult.rdap.updatedDate,
                                ).toLocaleDateString()
                              : "Unknown"}
                          </div>
                        </div>
                      </div>
                      {scanResult.rdap.nameservers.length > 0 && (
                        <div>
                          <div className="text-xs font-bold text-muted-foreground uppercase mb-1">
                            Nameservers
                          </div>
                          <div className="flex flex-wrap gap-2">
                            {scanResult.rdap.nameservers.map((name) => (
                              <Badge
                                key={name}
                                variant="outline"
                                className="border-primary/30 text-muted-foreground"
                              >
                                {name}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}
                      {scanResult.rdap.abuseContacts.length > 0 && (
                        <div>
                          <div className="text-xs font-bold text-muted-foreground uppercase mb-1">
                            Abuse Contacts
                          </div>
                          <div className="space-y-1">
                            {scanResult.rdap.abuseContacts.map((email) => (
                              <div
                                key={email}
                                className="text-muted-foreground break-all"
                              >
                                {email}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground py-4 text-center">
                      No RDAP data returned.
                    </p>
                  )}
                </CardContent>
              </Card>

              {/* Wayback */}
              <Card className="border-primary/20">
                <CardHeader className="pb-3 border-b border-border/50 bg-secondary/20">
                  <CardTitle className="flex items-center gap-2 text-lg">
                    <Archive className="w-5 h-5 text-primary" />
                    Wayback Machine
                    <Badge
                      variant="secondary"
                      className="ml-2 bg-primary/10 text-primary"
                    >
                      {scanResult.wayback?.captures.length ?? 0} URLs
                    </Badge>
                  </CardTitle>
                </CardHeader>
                <CardContent className="pt-4">
                  {scanResult.wayback &&
                  scanResult.wayback.captures.length > 0 ? (
                    <div className="max-h-64 overflow-y-auto space-y-3">
                      {scanResult.wayback.captures.map((capture) => (
                        <div
                          key={`${capture.timestamp}-${capture.url}`}
                          className="border border-border/50 rounded p-3 bg-secondary/10"
                        >
                          <div className="text-xs text-muted-foreground mb-1">
                            {new Date(capture.timestamp).toLocaleString()}{" "}
                            {capture.mimeType ? `- ${capture.mimeType}` : ""}
                          </div>
                          <div className="text-sm text-foreground break-all">
                            {capture.url}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground py-4 text-center">
                      No archived captures returned.
                    </p>
                  )}
                </CardContent>
              </Card>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* urlscan */}
              <Card className="border-primary/20">
                <CardHeader className="pb-3 border-b border-border/50 bg-secondary/20">
                  <CardTitle className="flex items-center gap-2 text-lg">
                    <Radar className="w-5 h-5 text-primary" />
                    urlscan.io Search
                    <Badge
                      variant="secondary"
                      className="ml-2 bg-primary/10 text-primary"
                    >
                      {scanResult.urlscan?.total ?? 0} matches
                    </Badge>
                  </CardTitle>
                </CardHeader>
                <CardContent className="pt-4">
                  {scanResult.urlscan &&
                  scanResult.urlscan.results.length > 0 ? (
                    <div className="space-y-3">
                      {scanResult.urlscan.results.map((item) => (
                        <div
                          key={item.resultUrl ?? item.url}
                          className="border border-border/50 rounded p-3 bg-secondary/10"
                        >
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <div className="text-sm text-foreground break-all">
                                {item.url}
                              </div>
                              <div className="text-xs text-muted-foreground mt-1">
                                {[item.ip, item.country, item.server]
                                  .filter(Boolean)
                                  .join(" - ") || "No page metadata"}
                              </div>
                            </div>
                            {item.resultUrl && (
                              <a
                                href={item.resultUrl}
                                target="_blank"
                                rel="noreferrer"
                                className="text-primary hover:text-primary/80"
                              >
                                <ExternalLink className="w-4 h-4" />
                              </a>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground py-4 text-center">
                      No urlscan.io results returned.
                    </p>
                  )}
                </CardContent>
              </Card>

              {/* AbuseIPDB */}
              <Card className="border-primary/20">
                <CardHeader className="pb-3 border-b border-border/50 bg-secondary/20">
                  <CardTitle className="flex items-center gap-2 text-lg">
                    <ShieldAlert className="w-5 h-5 text-primary" />
                    AbuseIPDB Reputation
                  </CardTitle>
                </CardHeader>
                <CardContent className="pt-4">
                  {!scanResult.abuseIpDbConfigured ? (
                    <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                      <Key className="w-8 h-8 mb-2 opacity-50" />
                      <p>API Key Not Configured</p>
                    </div>
                  ) : scanResult.abuseIpDb &&
                    scanResult.abuseIpDb.length > 0 ? (
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>IP</TableHead>
                          <TableHead>Score</TableHead>
                          <TableHead>Reports</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {scanResult.abuseIpDb.map((item) => (
                          <TableRow key={item.ip}>
                            <TableCell className="font-mono">
                              {item.ip}
                            </TableCell>
                            <TableCell>{item.abuseConfidenceScore}</TableCell>
                            <TableCell>{item.totalReports}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  ) : (
                    <p className="text-sm text-muted-foreground py-4 text-center">
                      No AbuseIPDB data returned.
                    </p>
                  )}
                </CardContent>
              </Card>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* SecurityTrails */}
              <Card className="border-primary/20">
                <CardHeader className="pb-3 border-b border-border/50 bg-secondary/20">
                  <CardTitle className="flex items-center gap-2 text-lg">
                    <Network className="w-5 h-5 text-primary" />
                    SecurityTrails Subdomains
                    <Badge
                      variant="secondary"
                      className="ml-2 bg-primary/10 text-primary"
                    >
                      {scanResult.securityTrails?.subdomains.length ?? 0} found
                    </Badge>
                  </CardTitle>
                </CardHeader>
                <CardContent className="pt-4">
                  {!scanResult.securityTrailsConfigured ? (
                    <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                      <Key className="w-8 h-8 mb-2 opacity-50" />
                      <p>API Key Not Configured</p>
                    </div>
                  ) : scanResult.securityTrails &&
                    scanResult.securityTrails.subdomains.length > 0 ? (
                    <div className="max-h-64 overflow-y-auto space-y-1">
                      {scanResult.securityTrails.subdomains
                        .slice(0, 50)
                        .map((subdomain) => (
                          <div
                            key={subdomain}
                            className="text-sm text-muted-foreground break-all"
                          >
                            {subdomain}
                          </div>
                        ))}
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground py-4 text-center">
                      No SecurityTrails data returned.
                    </p>
                  )}
                </CardContent>
              </Card>

              {/* Censys */}
              <Card className="border-primary/20">
                <CardHeader className="pb-3 border-b border-border/50 bg-secondary/20">
                  <CardTitle className="flex items-center gap-2 text-lg">
                    <Database className="w-5 h-5 text-primary" />
                    Censys Hosts
                    <Badge
                      variant="secondary"
                      className="ml-2 bg-primary/10 text-primary"
                    >
                      {scanResult.censys?.total ?? 0} matches
                    </Badge>
                  </CardTitle>
                </CardHeader>
                <CardContent className="pt-4">
                  {!scanResult.censysConfigured ? (
                    <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                      <Key className="w-8 h-8 mb-2 opacity-50" />
                      <p>API Credentials Not Configured</p>
                    </div>
                  ) : scanResult.censys &&
                    scanResult.censys.hosts.length > 0 ? (
                    <div className="space-y-4">
                      {scanResult.censys.hosts.map((host) => (
                        <div
                          key={host.ip}
                          className="border border-border/50 rounded p-3 bg-secondary/10"
                        >
                          <div className="font-bold text-primary">
                            {host.ip}
                          </div>
                          <div className="text-xs text-muted-foreground mt-1">
                            {[host.location, host.autonomousSystem]
                              .filter(Boolean)
                              .join(" - ") || "No host metadata"}
                          </div>
                          {host.services.length > 0 && (
                            <div className="flex flex-wrap gap-2 mt-3">
                              {host.services.map((service) => (
                                <Badge
                                  key={`${host.ip}-${service}`}
                                  variant="outline"
                                  className="border-primary/30 text-muted-foreground"
                                >
                                  {service}
                                </Badge>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground py-4 text-center">
                      No Censys hosts returned.
                    </p>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* Subdomains */}
            <Card className="border-primary/20">
              <CardHeader className="pb-3 border-b border-border/50 bg-secondary/20">
                <CardTitle className="flex items-center gap-2 text-lg">
                  <Database className="w-5 h-5 text-primary" />
                  Subdomains (crt.sh)
                  <Badge
                    variant="secondary"
                    className="ml-2 bg-primary/10 text-primary"
                  >
                    {scanResult.subdomains.length} found
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="pt-4 p-0">
                {scanResult.subdomains.length > 0 ? (
                  <div className="max-h-64 overflow-y-auto">
                    <Table>
                      <TableHeader className="sticky top-0 bg-background/95 backdrop-blur z-10">
                        <TableRow className="border-border/50 hover:bg-transparent">
                          <TableHead className="text-primary">
                            Subdomain Name
                          </TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {scanResult.subdomains.map((sub, i) => (
                          <TableRow
                            key={i}
                            className="border-border/30 hover:bg-secondary/30"
                          >
                            <TableCell className="font-mono text-muted-foreground">
                              {sub.name}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                ) : (
                  <div className="p-6 text-center text-muted-foreground">
                    No subdomains found.
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Shodan */}
            <Card className="border-primary/20">
              <CardHeader className="pb-3 border-b border-border/50 bg-secondary/20">
                <CardTitle className="flex items-center gap-2 text-lg">
                  <Activity className="w-5 h-5 text-primary" />
                  Shodan Host Data
                </CardTitle>
              </CardHeader>
              <CardContent className="pt-4">
                {!scanResult.shodanConfigured ? (
                  <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                    <Key className="w-8 h-8 mb-2 opacity-50" />
                    <p>API Key Not Configured</p>
                  </div>
                ) : scanResult.shodan && scanResult.shodan.length > 0 ? (
                  <div className="space-y-6">
                    {scanResult.shodan.map((host, i) => (
                      <div
                        key={i}
                        className="border border-border/50 rounded-lg p-4 bg-secondary/10"
                      >
                        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 mb-4">
                          <div className="text-lg font-bold text-primary">
                            {host.ip}
                          </div>
                          <div className="flex flex-wrap gap-2">
                            {host.country && (
                              <Badge
                                variant="outline"
                                className="border-primary/30 text-muted-foreground"
                              >
                                {host.country}
                              </Badge>
                            )}
                            {host.isp && (
                              <Badge
                                variant="outline"
                                className="border-primary/30 text-muted-foreground"
                              >
                                {host.isp}
                              </Badge>
                            )}
                            {host.org && (
                              <Badge
                                variant="outline"
                                className="border-primary/30 text-muted-foreground"
                              >
                                {host.org}
                              </Badge>
                            )}
                          </div>
                        </div>

                        <div className="space-y-4">
                          {host.hostnames.length > 0 && (
                            <div>
                              <span className="text-xs font-bold text-muted-foreground uppercase tracking-wider">
                                Hostnames
                              </span>
                              <div className="mt-1 flex flex-wrap gap-2">
                                {host.hostnames.map((hn) => (
                                  <span
                                    key={hn}
                                    className="text-sm text-foreground bg-secondary/50 px-2 py-1 rounded"
                                  >
                                    {hn}
                                  </span>
                                ))}
                              </div>
                            </div>
                          )}

                          <div>
                            <span className="text-xs font-bold text-muted-foreground uppercase tracking-wider">
                              Open Ports
                            </span>
                            <div className="mt-1 flex flex-wrap gap-2">
                              {host.ports.map((port) => (
                                <span
                                  key={port}
                                  className="text-sm text-primary bg-primary/10 border border-primary/20 px-2 py-1 rounded"
                                >
                                  {port}
                                </span>
                              ))}
                            </div>
                          </div>

                          {host.vulns && host.vulns.length > 0 && (
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="text-xs font-bold text-destructive uppercase tracking-wider">
                                  Reported by Shodan (not confirmed
                                  vulnerabilities)
                                </span>
                              </div>
                              <div className="mt-2 flex flex-wrap gap-2">
                                {host.vulns.map((vuln) => (
                                  <Badge
                                    key={vuln}
                                    variant="destructive"
                                    className="bg-destructive/20 text-destructive border border-destructive/30"
                                  >
                                    {vuln}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground py-4 text-center">
                    No Shodan data found for resolving IPs.
                  </p>
                )}
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
}
