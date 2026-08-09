import { resolveMx, resolveNs } from "node:dns/promises";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

export type DnsResolver = {
  resolveNs(zone: string): Promise<string[]>;
  resolveMx(zone: string): Promise<Array<{ exchange: string; priority: number }>>;
};

export type DnsDiscoveryFailure = {
  zone: string;
  recordType: "NS" | "MX";
  error: string;
};

export type DnsDiscoveryResult = {
  hosts: string[];
  nameservers: string[];
  mailExchanges: string[];
  failures: DnsDiscoveryFailure[];
};

const systemResolver: DnsResolver = { resolveNs, resolveMx };

function hostname(value: string): string {
  const normalised = value.trim().toLowerCase().replace(/\.+$/, "");
  if (!normalised) throw new Error(`DNS returned an empty hostname from ${JSON.stringify(value)}`);
  return normalised;
}

export async function discoverDnsRecords(
  inputZones: string[],
  resolver: DnsResolver = systemResolver,
): Promise<DnsDiscoveryResult> {
  const zones = [...new Set(inputZones.map(hostname))].sort();
  if (zones.length === 0) throw new Error("DNS discovery requires at least one zone");
  const nameservers = new Set<string>();
  const mailExchanges = new Set<string>();
  const failures: DnsDiscoveryFailure[] = [];

  await Promise.all(
    zones.flatMap((zone) => [
      resolver
        .resolveNs(zone)
        .then((records) => records.forEach((record) => nameservers.add(hostname(record))))
        .catch((error: unknown) =>
          failures.push({ zone, recordType: "NS", error: (error as Error).message }),
        ),
      resolver
        .resolveMx(zone)
        .then((records) => {
          for (const record of records) {
            if (record.exchange.trim() === ".") continue;
            mailExchanges.add(hostname(record.exchange));
          }
        })
        .catch((error: unknown) =>
          failures.push({ zone, recordType: "MX", error: (error as Error).message }),
        ),
    ]),
  );

  const sortedNameservers = [...nameservers].sort();
  const sortedMailExchanges = [...mailExchanges].sort();
  return {
    hosts: [...new Set([...sortedNameservers, ...sortedMailExchanges])].sort(),
    nameservers: sortedNameservers,
    mailExchanges: sortedMailExchanges,
    failures: failures.sort(
      (left, right) =>
        left.zone.localeCompare(right.zone) || left.recordType.localeCompare(right.recordType),
    ),
  };
}

function zonesPath(args: string[]): string {
  const index = args.indexOf("--zones");
  const path = index === -1 ? undefined : args[index + 1];
  if (!path) throw new Error("usage: dns-discovery.ts --zones <file>");
  return resolve(process.cwd(), path);
}

async function main(): Promise<void> {
  const zones = readFileSync(zonesPath(process.argv.slice(2)), "utf8")
    .split("\n")
    .filter((zone) => zone.trim().length > 0);
  const result = await discoverDnsRecords(zones);
  if (result.failures.length === zones.length * 2) {
    throw new Error(`all ${result.failures.length} NS/MX queries failed`);
  }
  process.stdout.write(result.hosts.map((host) => `${host}\n`).join(""));
  process.stderr.write(
    `[+] dns: ${result.nameservers.length} NS and ${result.mailExchanges.length} MX target(s)\n`,
  );
  for (const failure of result.failures) {
    process.stderr.write(
      `[!] dns: ${failure.recordType} ${failure.zone}: ${failure.error}\n`,
    );
  }
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  void main().catch((error: unknown) => {
    process.stderr.write(`[!] DNS discovery failed: ${(error as Error).message}\n`);
    process.exitCode = 1;
  });
}
