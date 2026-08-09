import { spawn } from "node:child_process";
import {
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

type JsonObject = Record<string, unknown>;

export type DiscoveryCommand = {
  command: string;
  args: string[];
};

const NUCLEI_DIR = resolve(import.meta.dirname, "..", "..");
const HOST_RE = /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/;

function object(value: unknown): JsonObject | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}

function string(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function integer(value: unknown): number | undefined {
  const number = typeof value === "number" ? value : Number(value);
  return Number.isInteger(number) ? number : undefined;
}

function uniqueSorted<T>(values: T[], compare: (a: T, b: T) => number): T[] {
  return [...new Set(values)].sort(compare);
}

export function discoveryCommands(hostList: string): {
  naabu: DiscoveryCommand;
  httpx: DiscoveryCommand;
} {
  return {
    naabu: {
      command: "naabu",
      args: [
        "-config",
        "config/discovery.naabu.yaml",
        "-silent",
        "-json",
        "-no-color",
        "-disable-update-check",
        "-no-stdin",
        "-l",
        hostList,
      ],
    },
    httpx: {
      command: "httpx",
      args: [
        "-config",
        "config/discovery.httpx.yaml",
        "-silent",
        "-json",
        "-no-color",
        "-disable-update-check",
      ],
    },
  };
}

function resultHost(record: JsonObject): string | undefined {
  const host = string(record.host) ?? string(record.hostname);
  if (host) return host.toLowerCase();
  const url = string(record.url);
  if (url) return new URL(url).hostname.toLowerCase();
  const input = string(record.input)?.replace(/^https?:\/\//, "");
  return input?.replace(/:\d+$/, "").replace(/\/.*$/, "").toLowerCase();
}

function statusRank(record: JsonObject): number {
  if (record.failed === true) return 6;
  const status = integer(record.status_code);
  if (status === undefined) return 5;
  if (status >= 200 && status < 400) return 0;
  if (status === 401 || status === 403) return 1;
  if (status >= 400 && status < 500 && status !== 404 && status !== 410) return 2;
  if (status >= 500) return 3;
  if (status === 404 || status === 410) return 4;
  return 5;
}

function primaryRecord(records: JsonObject[]): JsonObject | undefined {
  return [...records].sort((left, right) => {
    const rank = statusRank(left) - statusRank(right);
    if (rank !== 0) return rank;
    const defaultPort = (record: JsonObject) =>
      [80, 443].includes(integer(record.port) ?? 0) ? 0 : 1;
    const portRank = defaultPort(left) - defaultPort(right);
    if (portRank !== 0) return portRank;
    const schemeRank = Number(string(left.scheme) !== "https") - Number(string(right.scheme) !== "https");
    if (schemeRank !== 0) return schemeRank;
    return (string(left.url) ?? "").localeCompare(string(right.url) ?? "");
  })[0];
}

function recordPath(record: JsonObject): string | undefined {
  const path = string(record.path);
  if (path) return path.startsWith("/") ? path : `/${path}`;
  const url = string(record.url);
  return url ? new URL(url).pathname || "/" : undefined;
}

function knownPath(record: JsonObject): string | undefined {
  const status = integer(record.status_code);
  if (
    record.failed === true ||
    status === undefined ||
    status === 404 ||
    status === 410
  ) {
    return undefined;
  }
  return recordPath(record);
}

const AUTH_SCHEMES: Array<[string, string]> = [
  ["basic", "Basic"],
  ["bearer", "Bearer"],
  ["digest", "Digest"],
  ["negotiate", "Negotiate"],
  ["ntlm", "NTLM"],
];

function headerValues(record: JsonObject, name: string): string[] {
  const headers = object(record.header);
  if (!headers) return [];
  const target = name.toLowerCase().replaceAll(/[-_]/g, "");
  const value = Object.entries(headers).find(
    ([key]) => key.toLowerCase().replaceAll(/[-_]/g, "") === target,
  )?.[1];
  if (typeof value === "string") return [value];
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

function loginMethods(record: JsonObject): string[] {
  const methods: string[] = [];
  const challenges = headerValues(record, "www-authenticate").join(",");
  for (const [scheme, label] of AUTH_SCHEMES) {
    if (new RegExp(`(?:^|[\\s,])${scheme}(?:[\\s,]|$)`, "i").test(challenges)) {
      methods.push(label);
    }
  }
  const path = recordPath(record)?.toLowerCase();
  const status = integer(record.status_code);
  if (path && knownPath(record)) {
    if (path === "/login" || path === "/signin") methods.push("Web login");
    if (path.includes("oauth2")) methods.push("OAuth 2.0");
    if (path.includes("openid-configuration") && status === 200) methods.push("OpenID Connect");
    if (path.includes("saml")) methods.push("SAML");
  }
  const location = string(record.location)?.toLowerCase();
  if (location?.includes("oauth")) methods.push("OAuth 2.0");
  if (location?.match(/openid|oidc/)) methods.push("OpenID Connect");
  if (location?.includes("saml")) methods.push("SAML");
  if (location?.match(/\/(?:login|signin)(?:[/?#]|$)/)) methods.push("Web login");
  return methods;
}

function inventoryProjection(record: JsonObject | undefined): JsonObject {
  if (!record) return {};
  const {
    header: _header,
    raw_header: _rawHeader,
    request: _request,
    response: _response,
    ...projection
  } = record;
  return projection;
}

export function buildDiscoveryObservations(options: {
  hosts: string[];
  naabu: unknown[];
  httpx: unknown[];
  paths: unknown[];
}): JsonObject[] {
  const naabu = options.naabu.flatMap((value) => (object(value) ? [object(value)!] : []));
  const httpx = options.httpx.flatMap((value) => (object(value) ? [object(value)!] : []));
  const paths = options.paths.flatMap((value) => (object(value) ? [object(value)!] : []));
  return uniqueSorted(
    options.hosts.map((host) => host.toLowerCase()),
    (left, right) => left.localeCompare(right),
  ).map((host) => {
    const baseRecords = httpx.filter((record) => resultHost(record) === host && record.failed !== true);
    const pathRecords = paths.filter((record) => resultHost(record) === host && record.failed !== true);
    const primary = primaryRecord(baseRecords);
    const ports = uniqueSorted(
      [
        ...naabu.filter((record) => resultHost(record) === host).map((record) => integer(record.port)),
        ...baseRecords.map((record) => integer(record.port)),
      ].filter((port): port is number => port !== undefined && port >= 1 && port <= 65535),
      (left, right) => left - right,
    );
    if (!primary && ports.length === 0) {
      return {
        input: host,
        failed: true,
        error: "no open ports or HTTP endpoints responded",
      };
    }
    const records = [...baseRecords, ...pathRecords];
    const pathsFound = uniqueSorted(
      records.map(knownPath).filter((path): path is string => path !== undefined),
      (left, right) => left.localeCompare(right),
    );
    const methods = uniqueSorted(records.flatMap(loginMethods), (left, right) => left.localeCompare(right));
    return {
      ...inventoryProjection(primary),
      input: host,
      ...(ports.length > 0 ? { open_ports: ports } : {}),
      ...(pathsFound.length > 0 ? { known_paths: pathsFound } : {}),
      ...(methods.length > 0 ? { login_methods: methods } : {}),
    };
  });
}

function parseJsonLine(line: string, label: string): JsonObject {
  let value: unknown;
  try {
    value = JSON.parse(line) as unknown;
  } catch (error) {
    throw new Error(`${label} produced invalid JSON: ${(error as Error).message}`);
  }
  const record = object(value);
  if (!record) throw new Error(`${label} produced a non-object JSON value`);
  return record;
}

function runJsonCommand(
  invocation: DiscoveryCommand,
  label: string,
  summarize: (record: JsonObject) => string,
): Promise<JsonObject[]> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(invocation.command, invocation.args, {
      cwd: NUCLEI_DIR,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        PATH: `${process.env.HOME}/go/bin:${process.env.HOME}/.local/bin:${process.env.PATH}`,
      },
    });
    const records: JsonObject[] = [];
    let stdout = "";
    let stderr = "";
    let failure: Error | null = null;
    const consume = (line: string) => {
      if (!line.trim()) return;
      try {
        const record = parseJsonLine(line, label);
        records.push(record);
        process.stderr.write(`${summarize(record)}\n`);
      } catch (error) {
        failure = error as Error;
        child.kill("SIGKILL");
      }
    };
    child.stdout?.on("data", (buffer: Buffer) => {
      stdout += buffer.toString();
      const lines = stdout.split("\n");
      stdout = lines.pop() ?? "";
      lines.forEach(consume);
    });
    child.stderr?.on("data", (buffer: Buffer) => {
      const chunk = buffer.toString();
      stderr = `${stderr}${chunk}`.slice(-4000);
      process.stderr.write(chunk);
    });
    child.on("close", (code) => {
      if (stdout.trim()) consume(stdout);
      if (failure) return reject(failure);
      if (code !== 0) {
        return reject(
          new Error(`${label} exited with code ${code}${stderr ? `\n${stderr}` : ""}`),
        );
      }
      resolvePromise(records);
    });
    child.on("error", (error) => reject(new Error(`failed to spawn ${label}: ${error.message}`)));
  });
}

function endpointInputs(hosts: string[], records: JsonObject[]): string[] {
  const endpoints = [...hosts];
  for (const record of records) {
    const host = resultHost(record);
    const port = integer(record.port);
    if (host && port && hosts.includes(host)) endpoints.push(`${host}:${port}`);
  }
  return uniqueSorted(endpoints, (left, right) => left.localeCompare(right));
}

function liveOrigins(records: JsonObject[]): string[] {
  return uniqueSorted(
    records.flatMap((record) => {
      if (record.failed === true) return [];
      const url = string(record.url);
      return url ? [new URL(url).origin] : [];
    }),
    (left, right) => left.localeCompare(right),
  );
}

function readHosts(hostList: string): string[] {
  const hosts = uniqueSorted(
    readFileSync(resolve(NUCLEI_DIR, hostList), "utf8")
      .split("\n")
      .map((host) => host.trim().toLowerCase())
      .filter(Boolean),
    (left, right) => left.localeCompare(right),
  );
  if (hosts.length === 0) throw new Error(`discovery host list is empty: ${hostList}`);
  const invalid = hosts.filter((host) => !HOST_RE.test(host) || host.includes(".."));
  if (invalid.length > 0) throw new Error(`invalid discovery host(s): ${invalid.join(", ")}`);
  return hosts;
}

export async function runDiscoveryProfile(hostList: string): Promise<JsonObject[]> {
  const hosts = readHosts(hostList);
  const commands = discoveryCommands(hostList);
  const runDir = resolve(NUCLEI_DIR, ".gen", `discovery-${process.pid}`);
  const endpointsPath = resolve(runDir, "endpoints.txt");
  const originsPath = resolve(runDir, "origins.txt");
  mkdirSync(runDir, { recursive: true });
  try {
    process.stderr.write(`[*] naabu scanning top ports on ${hosts.length} host(s)\n`);
    const naabu = await runJsonCommand(commands.naabu, "naabu", (record) =>
      `[naabu] ${resultHost(record) ?? string(record.ip) ?? "unknown"}:${integer(record.port) ?? "none"}`,
    );
    const endpoints = endpointInputs(hosts, naabu);
    writeFileSync(endpointsPath, `${endpoints.join("\n")}\n`, "utf8");
    process.stderr.write(`[*] httpx probing ${endpoints.length} host/port endpoint(s)\n`);
    const httpx = await runJsonCommand(
      { ...commands.httpx, args: [...commands.httpx.args, "-l", endpointsPath] },
      "httpx",
      (record) => `[httpx] ${string(record.url) ?? resultHost(record) ?? "unknown"} ${integer(record.status_code) ?? "failed"} ${string(record.time) ?? ""}`.trim(),
    );
    const origins = liveOrigins(httpx);
    let paths: JsonObject[] = [];
    if (origins.length > 0) {
      writeFileSync(originsPath, `${origins.join("\n")}\n`, "utf8");
      process.stderr.write(`[*] httpx probing known paths on ${origins.length} live origin(s)\n`);
      paths = await runJsonCommand(
        {
          ...commands.httpx,
          args: [
            ...commands.httpx.args,
            "-path",
            "config/discovery-paths.txt",
            "-filter-code",
            "404,410",
            "-filter-error-page",
            "-l",
            originsPath,
          ],
        },
        "httpx path discovery",
        (record) => `[httpx:path] ${string(record.url) ?? "unknown"} ${integer(record.status_code) ?? "failed"} ${string(record.time) ?? ""}`.trim(),
      );
    }
    return buildDiscoveryObservations({ hosts, naabu, httpx, paths });
  } finally {
    rmSync(runDir, { recursive: true, force: true });
  }
}

function hostListArgument(args: string[]): string {
  const index = args.indexOf("--hosts");
  const value = index >= 0 ? args[index + 1] : undefined;
  if (!value) throw new Error("usage: discovery-profile.ts --hosts <path>");
  return value;
}

async function main(): Promise<void> {
  const observations = await runDiscoveryProfile(hostListArgument(process.argv.slice(2)));
  for (const observation of observations) process.stdout.write(`${JSON.stringify(observation)}\n`);
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`[!] discovery profile failed: ${(error as Error).message}\n`);
    process.exitCode = 1;
  });
}
