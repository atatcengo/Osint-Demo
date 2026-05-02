import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { Search, Download, ShieldAlert, Activity, AlertCircle, CheckCircle2, XCircle, Database, Server, Globe, Key } from "lucide-react";
import { useRunOsintScan, useGenerateOsintReport, useGetOsintConfig, getGetOsintConfigQueryKey } from "@workspace/api-client-react";
import type { ScanResult } from "@workspace/api-client-react/src/generated/api.schemas";

import { Button } from "@/components/ui/button";
import { Form, FormControl, FormField, FormItem, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Separator } from "@/components/ui/separator";

const formSchema = z.object({
  domain: z.string().regex(/^(?!:\/\/)(?!https?:\/\/)([a-zA-Z0-9-_]+\.)+[a-zA-Z]{2,}$/, "Must be a valid domain name (e.g. example.com). No http:// or paths."),
});

export default function Home() {
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);

  const { data: config } = useGetOsintConfig({
    query: {
      enabled: true,
      queryKey: getGetOsintConfigQueryKey(),
    }
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
      const result = await runScan.mutateAsync({ data: { domain: values.domain } });
      setScanResult(result);
    } catch (error) {
      console.error(error);
    }
  }

  const handleDownload = async () => {
    if (!scanResult) return;
    try {
      const report = await generateReport.mutateAsync({ data: scanResult });
      const blob = new Blob([report.content], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
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
              <p className="text-muted-foreground mt-1 font-sans">Educational Reconnaissance Dashboard</p>
            </div>
            
            <div className="flex items-center gap-4 text-xs">
              <div className="flex items-center gap-2 bg-secondary/50 px-3 py-1.5 rounded border border-border">
                <Database className="w-3.5 h-3.5 text-muted-foreground" />
                <span className="text-muted-foreground">Shodan:</span>
                {config?.shodanConfigured ? (
                  <span className="text-emerald-400 flex items-center gap-1"><CheckCircle2 className="w-3 h-3"/> Active</span>
                ) : (
                  <span className="text-muted-foreground flex items-center gap-1"><XCircle className="w-3 h-3"/> Missing Key</span>
                )}
              </div>
              <div className="flex items-center gap-2 bg-secondary/50 px-3 py-1.5 rounded border border-border">
                <ShieldAlert className="w-3.5 h-3.5 text-muted-foreground" />
                <span className="text-muted-foreground">VirusTotal:</span>
                {config?.virusTotalConfigured ? (
                  <span className="text-emerald-400 flex items-center gap-1"><CheckCircle2 className="w-3 h-3"/> Active</span>
                ) : (
                  <span className="text-muted-foreground flex items-center gap-1"><XCircle className="w-3 h-3"/> Missing Key</span>
                )}
              </div>
            </div>
          </div>

          <Alert className="bg-primary/5 border-primary/20 text-primary-foreground">
            <AlertCircle className="h-4 w-4 text-primary" />
            <AlertTitle className="text-primary font-bold">ETHICAL DISCLAIMER</AlertTitle>
            <AlertDescription className="text-primary/80 font-sans">
              This tool uses passive/public sources only. No active scanning, probing, or exploitation is performed against the target infrastructure.
            </AlertDescription>
          </Alert>
        </header>

        {/* Input Form */}
        <Card className="border-primary/20 bg-card/50 backdrop-blur">
          <CardContent className="pt-6">
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="flex flex-col md:flex-row gap-4 items-start md:items-start">
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
            <div className="text-primary font-bold animate-pulse tracking-widest">QUERYING PUBLIC INTELLIGENCE SOURCES...</div>
            <p className="text-muted-foreground text-sm font-sans">This may take 5-10 seconds depending on API response times.</p>
          </div>
        )}

        {/* Results */}
        {scanResult && !runScan.isPending && (
          <div className="space-y-6 animate-in slide-in-from-bottom-4 duration-700">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-bold text-foreground">Scan Results: {scanResult.domain}</h2>
                <p className="text-sm text-muted-foreground">Generated at {new Date(scanResult.timestamp).toLocaleString()}</p>
              </div>
              <Button variant="outline" onClick={handleDownload} disabled={generateReport.isPending} className="border-primary/30 hover:bg-primary/10">
                <Download className="w-4 h-4 mr-2" />
                {generateReport.isPending ? "GENERATING..." : "DOWNLOAD_REPORT"}
              </Button>
            </div>

            {/* Errors Section */}
            {scanResult.errors && Object.keys(scanResult.errors).length > 0 && (
              <Alert variant="destructive" className="bg-destructive/10 border-destructive/50 text-destructive-foreground">
                <AlertCircle className="h-4 w-4" />
                <AlertTitle>Partial Scan Failures</AlertTitle>
                <AlertDescription className="font-sans">
                  <ul className="list-disc pl-4 mt-2 space-y-1 text-sm">
                    {Object.entries(scanResult.errors).map(([source, error]) => (
                      <li key={source}><strong>{source}:</strong> {error}</li>
                    ))}
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
                      <h4 className="text-sm font-bold text-primary mb-2 border-b border-primary/20 inline-block pr-4">{type} RECORDS</h4>
                      {records.length > 0 ? (
                        <ul className="space-y-1">
                          {records.map((record, i) => (
                            <li key={i} className="text-sm text-muted-foreground break-all">{record}</li>
                          ))}
                        </ul>
                      ) : (
                        <p className="text-sm text-muted-foreground/50 italic">No records found</p>
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
                        <span className="text-4xl font-bold leading-none">{scanResult.virusTotal.reputation}</span>
                        <span className="text-sm text-muted-foreground mb-1">Reputation Score</span>
                      </div>
                      
                      <div className="grid grid-cols-2 gap-4">
                        <div className="bg-emerald-500/10 border border-emerald-500/20 p-3 rounded">
                          <div className="text-emerald-500 text-sm font-bold">HARMLESS</div>
                          <div className="text-2xl font-mono">{scanResult.virusTotal.harmless}</div>
                        </div>
                        <div className="bg-destructive/10 border border-destructive/20 p-3 rounded">
                          <div className="text-destructive text-sm font-bold">MALICIOUS</div>
                          <div className="text-2xl font-mono">{scanResult.virusTotal.malicious}</div>
                        </div>
                        <div className="bg-amber-500/10 border border-amber-500/20 p-3 rounded">
                          <div className="text-amber-500 text-sm font-bold">SUSPICIOUS</div>
                          <div className="text-2xl font-mono">{scanResult.virusTotal.suspicious}</div>
                        </div>
                        <div className="bg-secondary p-3 rounded">
                          <div className="text-muted-foreground text-sm font-bold">UNDETECTED</div>
                          <div className="text-2xl font-mono">{scanResult.virusTotal.undetected}</div>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground">No data available.</p>
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
                  <Badge variant="secondary" className="ml-2 bg-primary/10 text-primary">{scanResult.subdomains.length} found</Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="pt-4 p-0">
                {scanResult.subdomains.length > 0 ? (
                  <div className="max-h-64 overflow-y-auto">
                    <Table>
                      <TableHeader className="sticky top-0 bg-background/95 backdrop-blur z-10">
                        <TableRow className="border-border/50 hover:bg-transparent">
                          <TableHead className="text-primary">Subdomain Name</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {scanResult.subdomains.map((sub, i) => (
                          <TableRow key={i} className="border-border/30 hover:bg-secondary/30">
                            <TableCell className="font-mono text-muted-foreground">{sub.name}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                ) : (
                  <div className="p-6 text-center text-muted-foreground">No subdomains found.</div>
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
                      <div key={i} className="border border-border/50 rounded-lg p-4 bg-secondary/10">
                        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 mb-4">
                          <div className="text-lg font-bold text-primary">{host.ip}</div>
                          <div className="flex flex-wrap gap-2">
                            {host.country && <Badge variant="outline" className="border-primary/30 text-muted-foreground">{host.country}</Badge>}
                            {host.isp && <Badge variant="outline" className="border-primary/30 text-muted-foreground">{host.isp}</Badge>}
                            {host.org && <Badge variant="outline" className="border-primary/30 text-muted-foreground">{host.org}</Badge>}
                          </div>
                        </div>

                        <div className="space-y-4">
                          {host.hostnames.length > 0 && (
                            <div>
                              <span className="text-xs font-bold text-muted-foreground uppercase tracking-wider">Hostnames</span>
                              <div className="mt-1 flex flex-wrap gap-2">
                                {host.hostnames.map(hn => <span key={hn} className="text-sm text-foreground bg-secondary/50 px-2 py-1 rounded">{hn}</span>)}
                              </div>
                            </div>
                          )}
                          
                          <div>
                            <span className="text-xs font-bold text-muted-foreground uppercase tracking-wider">Open Ports</span>
                            <div className="mt-1 flex flex-wrap gap-2">
                              {host.ports.map(port => <span key={port} className="text-sm text-primary bg-primary/10 border border-primary/20 px-2 py-1 rounded">{port}</span>)}
                            </div>
                          </div>

                          {host.vulns && host.vulns.length > 0 && (
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="text-xs font-bold text-destructive uppercase tracking-wider">Reported by Shodan (not confirmed vulnerabilities)</span>
                              </div>
                              <div className="mt-2 flex flex-wrap gap-2">
                                {host.vulns.map(vuln => <Badge key={vuln} variant="destructive" className="bg-destructive/20 text-destructive border border-destructive/30">{vuln}</Badge>)}
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground py-4 text-center">No Shodan data found for resolving IPs.</p>
                )}
              </CardContent>
            </Card>

          </div>
        )}
      </div>
    </div>
  );
}
