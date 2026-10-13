// Rewrites what the upstream MCP server tells the agent (tool list, server info)
// and maps the agent's tool calls back to what the upstream expects.

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type JsonObject = { [key: string]: Json };

/** Placeholder replaced by the upstream's original text in description/instructions overrides. */
export const ORIGINAL = '{{original}}';

export interface ParamOverride {
  /** Name the agent sees. Calls are mapped back to the upstream name. */
  name?: string;
  /** New description; null removes it. `{{original}}` inserts the upstream text. */
  description?: string | null;
  /** Force the parameter required (true) or optional (false). */
  required?: boolean;
  /** Remove the parameter from the schema; any value the agent sends is dropped. */
  hidden?: boolean;
  /** Hide the parameter and always send this value upstream. */
  value?: Json;
  /** Make the parameter optional and send this value upstream when the agent omits it. */
  default?: Json;
  /** JSON Merge Patch (RFC 7396) applied to the parameter's schema: type, enum, items, minimum, … */
  schema?: JsonObject;
}

export interface ToolOverride {
  /** Remove the tool from the list and refuse calls to it. */
  hidden?: boolean;
  name?: string;
  title?: string | null;
  description?: string | null;
  /** Merge patch on annotations (readOnlyHint, destructiveHint, idempotentHint, openWorldHint, title). */
  annotations?: JsonObject | null;
  /** Per-parameter changes, keyed by the upstream parameter name. */
  params?: Record<string, ParamOverride>;
  /** Merge patch on the whole inputSchema, applied after `params`. */
  inputSchema?: JsonObject;
  /** Merge patch on outputSchema; null removes it. */
  outputSchema?: JsonObject | null;
  /** Merge patch on the entire tool definition, applied last. Reaches any field. */
  patch?: JsonObject;
}

export interface ProxyConfig {
  server?: {
    /** Replaces the initialize result's instructions. `{{original}}` inserts the upstream text; null removes. */
    instructions?: string | null;
    /** Merge patch on serverInfo (name, title, version, …). */
    serverInfo?: JsonObject;
  };
  tools?: {
    /** Only expose tools that have an entry in `overrides` (and aren't hidden). */
    hideUnlisted?: boolean;
    /** Keyed by the upstream tool name. */
    overrides?: Record<string, ToolOverride>;
  };
}

export class ConfigError extends Error {}

/** RFC 7396 JSON Merge Patch. */
export function mergePatch(target: Json | undefined, patch: Json): Json {
  if (!isObject(patch)) return structuredClone(patch);
  const result: JsonObject = isObject(target) ? { ...target } : {};
  for (const [key, value] of Object.entries(patch)) {
    if (value === null) delete result[key];
    else result[key] = mergePatch(result[key], value);
  }
  return result;
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function substitute(template: string | null, original: unknown): string | null {
  if (template === null) return null;
  return template.split(ORIGINAL).join(typeof original === 'string' ? original : '');
}

function setOrDelete(target: JsonObject, key: string, value: Json | null | undefined) {
  if (value === undefined) return;
  if (value === null) delete target[key];
  else target[key] = value;
}

/** Throws ConfigError when renames collide or fields have the wrong shape. */
export function validateConfig(config: ProxyConfig): void {
  const overrides = config.tools?.overrides ?? {};
  const exposed = new Map<string, string>();
  for (const [original, tool] of Object.entries(overrides)) {
    if (!isObject(tool)) throw new ConfigError(`tools.overrides.${original} must be an object`);
    if (tool.hidden) continue;
    const name = tool.name ?? original;
    if (typeof name !== 'string' || !name) throw new ConfigError(`tools.overrides.${original}.name must be a non-empty string`);
    if (exposed.has(name)) throw new ConfigError(`Tools "${exposed.get(name)}" and "${original}" are both exposed as "${name}"`);
    exposed.set(name, original);
    const params = new Map<string, string>();
    for (const [param, change] of Object.entries(tool.params ?? {})) {
      if (!isObject(change)) throw new ConfigError(`tools.overrides.${original}.params.${param} must be an object`);
      const paramChange = change as ParamOverride;
      if (paramChange.hidden || paramChange.value !== undefined) continue;
      const paramName = paramChange.name ?? param;
      if (typeof paramName !== 'string' || !paramName) throw new ConfigError(`tools.overrides.${original}.params.${param}.name must be a non-empty string`);
      if (params.has(paramName)) throw new ConfigError(`${original}: parameters "${params.get(paramName)}" and "${param}" both exposed as "${paramName}"`);
      params.set(paramName, param);
    }
  }
}

export interface CallMapping {
  /** Upstream tool name to call. */
  name: string;
  arguments: JsonObject;
}

export class Rewriter {
  readonly config: ProxyConfig;
  private readonly overrides: Record<string, ToolOverride>;
  /** Exposed name → upstream name, for renamed tools. */
  private readonly renamed = new Map<string, string>();

  constructor(config: ProxyConfig) {
    validateConfig(config);
    this.config = config;
    this.overrides = config.tools?.overrides ?? {};
    for (const [original, tool] of Object.entries(this.overrides)) {
      if (!tool.hidden && tool.name && tool.name !== original) this.renamed.set(tool.name, original);
    }
  }

  private isExposed(original: string): boolean {
    const tool = this.overrides[original];
    if (tool?.hidden) return false;
    if (this.config.tools?.hideUnlisted && !tool) return false;
    return true;
  }

  /** Rewrites a tools/list result's tools array. Renamed tools win name collisions with unlisted ones. */
  rewriteTools(tools: unknown[]): Json[] {
    const out: Json[] = [];
    for (const tool of tools) {
      const name = isObject(tool) ? tool.name : undefined;
      if (!isObject(tool) || typeof name !== 'string') {
        out.push(tool as Json);
        continue;
      }
      if (!this.isExposed(name)) continue;
      if (!this.overrides[name] && this.renamed.has(name)) continue; // shadowed by a rename
      out.push(this.rewriteTool(tool));
    }
    return out;
  }

  rewriteTool(tool: JsonObject): JsonObject {
    const change = this.overrides[tool.name as string];
    if (!change) return tool;
    let result: JsonObject = structuredClone(tool);
    if (change.name !== undefined) result.name = change.name;
    setOrDelete(result, 'title', change.title);
    if (change.description !== undefined) setOrDelete(result, 'description', substitute(change.description, tool.description));
    if (change.annotations !== undefined) setOrDelete(result, 'annotations', change.annotations === null ? null : mergePatch(result.annotations, change.annotations));
    if (change.params || change.inputSchema) {
      let schema = isObject(result.inputSchema) ? result.inputSchema : { type: 'object' };
      if (change.params) schema = rewriteSchema(schema, change.params);
      if (change.inputSchema) schema = mergePatch(schema, change.inputSchema) as JsonObject;
      result.inputSchema = schema;
    }
    if (change.outputSchema !== undefined) setOrDelete(result, 'outputSchema', change.outputSchema === null ? null : mergePatch(result.outputSchema, change.outputSchema));
    if (change.patch) result = mergePatch(result, change.patch) as JsonObject;
    return result;
  }

  /** Maps an agent's tools/call params to the upstream call, or returns null for a tool the agent may not call. */
  mapCall(name: string, args: unknown): CallMapping | null {
    let original = name;
    if (this.renamed.has(name)) original = this.renamed.get(name)!;
    else if (this.overrides[name]?.name && this.overrides[name].name !== name) return null; // old name of a renamed tool
    if (!this.isExposed(original)) return null;
    const input: JsonObject = isObject(args) ? args : {};
    const params = this.overrides[original]?.params;
    return { name: original, arguments: params ? mapArguments(input, params) : input };
  }

  /** Rewrites an initialize result. */
  rewriteInitialize(result: JsonObject): JsonObject {
    const server = this.config.server;
    if (!server) return result;
    const out = { ...result };
    if (server.instructions !== undefined) setOrDelete(out, 'instructions', substitute(server.instructions, result.instructions));
    if (server.serverInfo) out.serverInfo = mergePatch(result.serverInfo, server.serverInfo);
    return out;
  }
}

function rewriteSchema(schema: JsonObject, params: Record<string, ParamOverride>): JsonObject {
  const properties = isObject(schema.properties) ? schema.properties : {};
  let required = new Set(Array.isArray(schema.required) ? schema.required.filter((r): r is string => typeof r === 'string') : []);
  const nextProperties: JsonObject = {};
  const nextRequired = new Set<string>();

  for (const [original, propSchema] of Object.entries(properties)) {
    const change = params[original];
    if (!change) {
      nextProperties[original] = propSchema;
      if (required.has(original)) nextRequired.add(original);
      continue;
    }
    if (change.hidden || change.value !== undefined) continue;
    const name = change.name ?? original;
    let prop: Json = propSchema;
    if (change.default !== undefined) prop = mergePatch(prop, { default: change.default });
    if (change.description !== undefined) {
      const current = isObject(propSchema) ? propSchema.description : undefined;
      prop = mergePatch(prop, { description: substitute(change.description, current) });
    }
    if (change.schema) prop = mergePatch(prop, change.schema);
    nextProperties[name] = prop;
    const isRequired = change.required ?? (change.default === undefined && required.has(original));
    if (isRequired) nextRequired.add(name);
  }
  // A required override on a parameter the upstream schema doesn't declare still applies.
  for (const [original, change] of Object.entries(params)) {
    if (!(original in properties) && !change.hidden && change.value === undefined && change.schema) {
      const name = change.name ?? original;
      nextProperties[name] = change.schema;
      if (change.required) nextRequired.add(name);
    }
  }

  const out: JsonObject = { ...schema, properties: nextProperties };
  if (nextRequired.size) out.required = [...nextRequired];
  else delete out.required;
  return out;
}

function mapArguments(args: JsonObject, params: Record<string, ParamOverride>): JsonObject {
  const toOriginal = new Map<string, string>();
  const withheld = new Set<string>(); // upstream names the agent may not set directly
  for (const [original, change] of Object.entries(params)) {
    if (change.hidden || change.value !== undefined) withheld.add(original);
    else if (change.name && change.name !== original) {
      toOriginal.set(change.name, original);
      withheld.add(original);
    }
  }
  const out: JsonObject = {};
  for (const [key, value] of Object.entries(args)) {
    if (toOriginal.has(key)) out[toOriginal.get(key)!] = value;
    else if (!withheld.has(key)) out[key] = value;
  }
  for (const [original, change] of Object.entries(params)) {
    if (change.value !== undefined) out[original] = change.value;
    else if (change.default !== undefined && out[original] === undefined) out[original] = change.default;
  }
  return out;
}
