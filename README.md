<div align="center">
<h3>OpenTelemetry-native</h3>
<h1>AI Observability, Monitoring and Evaluation Framework</h1>

**[Shield360](https://shield360.ai) | [Quickstart](#-getting-started-with-llm-observability) | [Report a Bug](https://github.com/ThinkfleetAI/shield360-js/issues/new)**

[![npm](https://img.shields.io/npm/v/shield360)](https://www.npmjs.com/package/shield360)
[![Downloads](https://img.shields.io/npm/dw/shield360)](https://www.npmjs.com/package/shield360)
[![License](https://img.shields.io/badge/License-Apache%202.0-f80)](LICENSE)

</div>

Shield360 SDK is a monitoring framework built on top of **OpenTelemetry** that gives your complete Observability for your AI stack, from LLMs to vector databases, with just one line of code with tracing and metrics. It also allows you to send the generated traces and metrics to your existing monitoring tools like Grafana, New Relic, and more.

This project proudly follows and maintains the [Semantic Conventions](https://github.com/open-telemetry/semantic-conventions/tree/main/docs/gen-ai) with the OpenTelemetry community, consistently updating to align with the latest standards in Observability.

## ⚡ Features

- 🔎 **Auto Instrumentation**: Works with 12+ LLM providers, vector databases, and AI frameworks with just one line of code.
- 🔭 **OpenTelemetry-Native Observability SDKs**: Vendor-neutral SDKs that can send traces and metrics to your existing observability tool like Prometheus and Jaeger.
- 💲 **Cost Tracking for Custom and Fine-Tuned Models**: Pass custom pricing files for accurate budgeting of custom and fine-tuned models.
- 🚀 **Support for Shield360 Features**: Includes support for prompt management and secrets management features available in Shield360.


## Auto Instrumentation Capabilities

| LLMs                                                                                        |
| ------------------------------------------------------------------------------------------- |
| [✅ OpenAI](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/integrations/openai.mdx)                             |
| [✅ Anthropic](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/integrations/anthropic.mdx)                       |
| [✅ Cohere](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/integrations/cohere.mdx)                             |
| [✅ Groq](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/integrations/groq.mdx)                                 |
| [✅ Mistral](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/integrations/mistral.mdx)                           |
| [✅ Google AI Studio](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/integrations/google-ai-studio.mdx)         |
| [✅ Google Vertex AI](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/integrations/vertexai.mdx) *(via `@google-cloud/vertexai`)* |
| [✅ Together AI](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/integrations/together.mdx)                      |
| [✅ Ollama](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/integrations/ollama.mdx)                             |
| [✅ AWS Bedrock](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/integrations/bedrock.mdx)                        |
| [✅ Hugging Face](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/integrations/huggingface.mdx) *(Inference API + local Transformers.js)* |
| [✅ Replicate](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/integrations/replicate.mdx)                      |
| [✅ Azure OpenAI](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/integrations/azure-openai.mdx) *(via OpenAI SDK)* |

| Audio / Speech                                                                              |
| ------------------------------------------------------------------------------------------- |
| [✅ ElevenLabs](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/integrations/elevenlabs.mdx)                   |

| Vector Databases                                                                            |
| ------------------------------------------------------------------------------------------- |
| [✅ Chroma](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/integrations/chromadb.mdx)                           |
| [✅ Pinecone](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/integrations/pinecone.mdx)                         |
| [✅ Qdrant](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/integrations/qdrant.mdx)                             |
| [✅ Milvus](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/integrations/milvus.mdx)                             |

| Frameworks                                                                                  |
| ------------------------------------------------------------------------------------------- |
| [✅ LangChain](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/integrations/langchain.mdx)                       |
| [✅ LlamaIndex](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/integrations/llama-index.mdx)                    |
| [✅ Vercel AI SDK](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/integrations/vercel-ai.mdx)                   |

## Supported Destinations

- [✅ OpenTelemetry Collector](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/destinations/otelcol.mdx)
- [✅ Prometheus + Tempo](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/destinations/prometheus-tempo.mdx)
- [✅ Prometheus + Jaeger](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/destinations/prometheus-jaeger.mdx)
- [✅ Grafana Cloud](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/destinations/grafanacloud.mdx)
- [✅ New Relic](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/destinations/new-relic.mdx)
- [✅ Elastic](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/destinations/elastic.mdx)
- [✅ HyperDX](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/destinations/hyperdx.mdx)
- [✅ DataDog](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/destinations/datadog.mdx)
- [✅ SigNoz](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/destinations/signoz.mdx)
- [✅ OneUptime](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/destinations/oneuptime.mdx)
- [✅ Dynatrace](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/destinations/dynatrace.mdx)
- [✅ OpenObserve](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/destinations/openobserve.mdx)
- [✅ Highlight.io](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/destinations/highlight.mdx)

## Supported Metrics

The following metrics are supported across all integrations:

- **genaiClientUsageTokens**: Histogram for total input/output tokens used.
- **genaiClientOperationDuration**: Histogram for GenAI operation duration.
- **genaiServerTbt**: Histogram for time per output token after the first token.
- **genaiServerTtft**: Histogram for time to first token for successful responses.
- **genaiRequests**: Counter for number of GenAI requests.
- **genaiPromptTokens**: Counter for number of prompt tokens processed.
- **genaiCompletionTokens**: Counter for number of completion tokens processed.
- **genaiReasoningTokens**: Counter for number of reasoning thought tokens processed.
- **genaiCost**: Histogram for distribution of GenAI request costs (USD).

These metrics allow you to monitor usage, performance, and cost for supported GenAI operations.

## 💿 Installation

```bash
npm install shield360
```

## 🚀 Getting Started

### Step 1: Install Shield360

Open your command line or terminal and run:

```bash
npm install shield360
```

### Step 2: Initialize Shield360 in your Application

Integrate Shield360 into your AI applications by adding the following lines to your code.

```typescript
import Shield360 from 'shield360';

Shield360.init();
```

Configure the telemetry data destination as follows:

| Purpose                                   | Parameter/Environment Variable                   | For Sending to Shield360         |
|-------------------------------------------|--------------------------------------------------|--------------------------------|
| Send data to an HTTP OTLP endpoint        | `otlpEndpoint` or `OTEL_EXPORTER_OTLP_ENDPOINT` | `"http://127.0.0.1:4318"`     |
| Authenticate telemetry backends           | `otlpHeaders` or `OTEL_EXPORTER_OTLP_HEADERS`   | Not required by default       |

> 💡 Info: If the `otlp_endpoint` or `OTEL_EXPORTER_OTLP_ENDPOINT` is not provided, the Shield360 SDK will output traces directly to your console, which is recommended during the development phase.

#### Example

---

<details>
  <summary>Initialize using Function Arguments</summary>
  
  ---

Add the following two lines to your application code:

```typescript
import Shield360 from 'shield360';

Shield360.init({ 
  otlpEndpoint: 'YOUR_OTEL_ENDPOINT',
  otlpHeaders: 'YOUR_OTEL_ENDPOINT_AUTH'
});
```

</details>

---

<details>

  <summary>Initialize using Environment Variables</summary>

---

Add the following two lines to your application code:

```typescript
import Shield360 from "shield360"

Shield360.init()
```

Then, configure the your OTLP endpoint using environment variable:

```env
export OTEL_EXPORTER_OTLP_ENDPOINT = "YOUR_OTEL_ENDPOINT"
export OTEL_EXPORTER_OTLP_HEADERS = "YOUR_OTEL_ENDPOINT_AUTH"
```

</details>

---

### Step 3: Visualize and Optimize!
Now that your LLM observability data is being collected and sent to configured OpenTelemetry destination, the next step is to visualize and analyze this data. This will help you understand your LLM application's performance and behavior and identify where it can be improved.

If you want to use Shield360's Observability Dashboard to monitor LLM usage—like cost, tokens, and user interactions—please check out our [Quickstart Guide](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/quickstart-ai-observability.mdx).

If you're sending metrics and traces to other observability tools, take a look at our [Connections Guide](https://github.com/ThinkfleetAI/shield360-js/blob/main/docs/destinations/overview.mdx) to start using a pre-built dashboard we have created for these tools.


## Zero-code setup

Turn on Shield360, telemetry and runtime protection (RASP), without changing or rebuilding the app. Install the package next to the app and preload `shield360/register`; everything is configured with environment variables.

```bash
npm install shield360

export OTEL_SERVICE_NAME=orders-api
export SHIELD360_URL=https://app.shield360.ai
export SHIELD360_API_KEY=...                      # from Settings > API keys
export SHIELD360_RASP=monitor                     # or block; leave unset for telemetry only
export SHIELD360_CONFIG_PUBLIC_KEY='{"kty":"OKP",...}'  # Runtime protection settings

node --require shield360/register app.js          # CommonJS
node --import shield360/register app.mjs          # ES modules
NODE_OPTIONS="--require shield360/register" npm start
```

What the preload does, before the app's first line runs:

- Calls `Shield360.init()` with the settings from the environment (`OTEL_SERVICE_NAME`, `OTEL_DEPLOYMENT_ENVIRONMENT`, `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_RESOURCE_ATTRIBUTES`, `SHIELD360_URL`, `SHIELD360_API_KEY`, `SHIELD360_DISABLED_INSTRUMENTORS` and the other `SHIELD360_*` variables `init()` reads).
- With `SHIELD360_RASP=monitor|block`, installs the RASP sink hooks before the app takes its own references to `child_process`, `fs` and the database drivers, and captures every request served by an `http` or `https` server (Express, Fastify, Koa, Nest and raw `http`), so no middleware is needed. Adding `raspExpress()` or another framework middleware as well is fine: it takes over the request with its richer view and nothing is reported twice.
- Registers the OpenTelemetry ESM loader hook (`module.register`, Node.js 18.19 / 20.6 and later), so instrumentations also patch packages the app loads with `import`. Set `SHIELD360_ESM_HOOK=off` to leave it out.

Rules it keeps:

- **Fail open.** If Shield360 cannot start, it prints one warning and the app starts without it.
- **No double start.** If the app also calls `Shield360.init()` itself, that call does nothing (one log line says so); the environment settings stay in force.

Limits:

- In block mode without framework middleware, a virtual patch that matches the request answers 403 before the app sees it, and so does a block in a raw `http` handler, synchronous or `async` (a block after an `await` is answered, not left as an unhandled rejection). Frameworks catch errors from their route handlers themselves, so a block raised at a sink inside an Express, Koa or Fastify handler gets the framework's error response (a 500 in Express) unless that framework's RASP middleware or error handler is added.
- `NODE_OPTIONS` is inherited by child Node.js processes, which start Shield360 too. Use `node --require` on the app's command when that is not wanted.
- Bundled apps (esbuild, webpack, `ncc`) and single-executable apps inline their dependencies, so instrumentations that patch packages by name do not see them. The RASP hooks on Node's built-in modules still apply. Keep instrumented packages external, such as the database driver (`external: ['pg']` in esbuild, installed beside the bundle), or call `Shield360.init()` in code.
- `NODE_OPTIONS="--require shield360/register"` also works for ES module apps. Node runs the preload again in its module-hooks thread, and the preload does nothing there.
- Packages imported as ES modules are patched only through the loader hook; with `SHIELD360_ESM_HOOK=off`, only CommonJS loads are instrumented.

| Variable | Default | Meaning |
|---|---|---|
| `SHIELD360_RASP` | unset (off) | `monitor` or `block` turns RASP on; `off` always wins. |
| `SHIELD360_ESM_HOOK` | on | `off` skips the ES module loader hook. New for the zero-code entry. |

## Configuration

### Observability - `Shield360.init()`

Below is a detailed overview of the configuration options available, allowing you to adjust Shield360's behavior and functionality to align with your specific observability needs:

| Argument                 | Description                                                                          | Default Value                                                      | Required |
| ------------------------ | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------ | -------- |
| `environment`            | The deployment environment of the application.                                       | `"default"`                                                        | No      |
| `applicationName`       | Identifies the name of your application.                                             | `"default"`                                                        | No      |
| `tracer`                 | An instance of OpenTelemetry Tracer for tracing operations.                          | `undefined`                                                             | No       |
| `otlpEndpoint`          | Specifies the OTLP endpoint for transmitting telemetry data.                         | `undefined`                                                             | No       |
| `otlpHeaders`           | Defines headers for the OTLP exporter, useful for backends requiring authentication. | `undefined`                                                             | No       |
| `disableBatch`          | A flag to disable batch span processing, favoring immediate dispatch.                | `true`                                                            | No       |
| `captureMessageContent` | Records prompt and completion text. Off unless set here or with `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true`. | `false`                                                             | No       |
| `disabledInstrumentations` | List of instrumentations to disable.                                                    | `undefined`                                                             | No       |
| `instrumentations`        | Object of instrumentation modules for manual patching                                          | `undefined`                                                            | No       |
| `pricingJson`           | URL or file path of the pricing JSON file.                                           | Bundled `pricing.json` | No       |
| `collectGpuStats`       | Flag to enable or disable GPU metrics collection (NVIDIA via `nvidia-smi`, AMD via `rocm-smi`). | `false`                                                            | No       |
| `captureCodeLocation`   | Adds the calling function, file and line to GenAI spans. Also `SHIELD360_CAPTURE_CODE_LOCATION=false`. | `true` | No |
| `codeRoot`              | Directory stripped from reported file paths. Also `SHIELD360_CODE_ROOT`. | git root, then working directory | No |
| `serviceVersion`        | Release recorded as the `service.version` resource attribute. Also `SHIELD360_SERVICE_VERSION` or `SHIELD360_RELEASE`. | `undefined` | No |

> **Message content is off by default.** Prompt and completion text is recorded only when you pass `captureMessageContent: true` (or set `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true`). Even then, Shield360 stores it only if your organization's [Data retention](https://shield360.ai) setting allows it. Before this release the default was on.

### Code location and build attributes

Every GenAI span (one with `gen_ai.operation.name`) records where your code made the call:

| Attribute | Value |
| --- | --- |
| `code.function.name` | Calling function, such as `BillingService.summarise`. Left out for anonymous functions. |
| `code.file.path` | File path relative to `codeRoot`, the git root or the working directory. No home directory (yours or another user's) or CI workspace prefix is sent. |
| `code.line.number` | Line of the call. |

Frames inside Shield360, OpenTelemetry, `node_modules` and Node internals are skipped. Only names, paths and line numbers are recorded, never argument values or source text. Turn it off with `captureCodeLocation: false` or `SHIELD360_CAPTURE_CODE_LOCATION=false` (`0`, `no` and `off` also work); the init option wins over the environment variable.

At startup Shield360 also adds these resource attributes, so costs and traces can be tied to a release:

| Attribute | Sources, first match wins |
| --- | --- |
| `service.version` | `serviceVersion`, `SHIELD360_SERVICE_VERSION`, `SHIELD360_RELEASE`, `OTEL_SERVICE_VERSION`, `OTEL_RESOURCE_ATTRIBUTES` |
| `vcs.ref.head.revision` | `SHIELD360_GIT_COMMIT`, `OTEL_RESOURCE_ATTRIBUTES`, CI variables |
| `vcs.repository.url.full` | `SHIELD360_GIT_REPOSITORY_URL`, `OTEL_RESOURCE_ATTRIBUTES`, CI variables |
| `vcs.ref.head.name` | `SHIELD360_GIT_BRANCH`, `OTEL_RESOURCE_ATTRIBUTES`, CI variables |

CI variables are read from GitHub Actions, GitLab CI, Vercel, Netlify, Render, Railway, Heroku, AWS CodeBuild, Buildkite, CircleCI, Bitbucket Pipelines, Azure Pipelines and Jenkins. An explicit `OTEL_RESOURCE_ATTRIBUTES` value beats CI auto-detection. Values from different providers are never mixed. Commit SHAs that are not 7 to 64 hex characters are dropped, and repository URLs are reduced to `https://host/owner/repo` with any credentials removed.

Shield360 groups an application's calls by release (Telemetry → Releases) and compares each release with the one before it. With no release set, the commit the SDK detected is used.

### User feedback - `Shield360.feedback()`

Send what one of your users thought of an AI response, against the trace that produced it. Call it from your server with the environment's API key, never from a browser. It never throws; it resolves to `false` when the rating was not accepted.

```typescript
const traceId = Shield360.getCurrentTraceId(); // keep this with the response

// later, when the user rates it
await Shield360.feedback({ traceId, score: 1 }); // thumbs up (-1 is thumbs down)
await Shield360.feedback({ traceId, score: 4, comment: 'Close, but missed the date' }); // stars 1-5
await Shield360.feedback({ traceId, score: 1, scale: 'stars' }); // one star
```

| Option | Description |
| --- | --- |
| `score` | `1` or `-1` (thumbs), or `1` to `5` (stars). |
| `traceId` | The trace rated. Defaults to the active span's trace. |
| `spanId` | The span rated, when it was one call in the trace. Optional |
| `comment` | What the user wrote. Kept only when your organization's Data retention setting stores end users' free text, with secrets and personal data masked. Optional |
| `scale` | `'thumbs'` or `'stars'`. Optional |
| `userId`, `tenantId` | Your end user and their tenant. Kept only as a keyed hash. Optional |
| `metadata` | A flat object of up to 20 short values. Optional |
| `feedbackId` | Your id for the rating; sending it again replaces the earlier one. Optional |

Ratings show on the trace and under Telemetry → Feedback, by release and by feature flag variant.

### Shield360 Prompt Hub - `Shield360.getPrompt()`

Below are the parameters for use with the SDK for Shield360 Prompt Hub for prompt management:

| Parameter        | Description                                                                                                                        |
|------------------|------------------------------------------------------------------------------------------------------------------------------------|
| `url`            | Sets the Shield360 URL. Defaults to the `SHIELD360_URL` environment variable or `http://127.0.0.1:3000` if not set.                    |
| `apiKey`         | Sets the Shield360 API Key. Can also be provided via the `SHIELD360_API_KEY` environment variable.                                     |
| `name`           | Sets the name to fetch a unique prompt. Use this or `promptId`.                                                                    |
| `promptId`       | Sets the ID to fetch a unique prompt. Use this or `name`. Optional                                                                 |
| `version`        | Sets the version to retrieve a specific prompt. Optional                                                                           | 
| `shouldCompile`        | Boolean value that compiles the prompt using the provided variables. Optional                                                      |
| `variables`      | Sets the variables for prompt compilation. Optional                                                                                | 
| `metaProperties` | Sets the meta-properties for storing in the prompt's access history metadata.                                                      | 


### Shield360 Vault - `Shield360.getSecrets()`

Below are the parameters for use with the SDK for Shield360 Vault for secret management:

| Parameter        | Description                                                                                                  |
|------------------|------------------------------------------------------------------------------------------------------------------------------------|
| `url`            | Sets the Shield360 URL. Defaults to the `SHIELD360_URL` environment variable or `http://127.0.0.1:3000` if not set.                    |
| `apiKey`         | Sets the Shield360 API Key. Can also be provided via the `SHIELD360_API_KEY` environment variable.                                     |
| `key`            | Sets the key to fetch a specific secret.     Optional                                                   |
| `tags`       | Sets the tags for fetching only the secrets that have the mentioned tags assigned. Optional                      |
| `shouldSetEnv`        | Boolean value that sets all the secrets as environment variables for the application. Optional                                                      |



### Shield360 Rule Engine - `Shield360.evaluateRule()`

Evaluate trace attributes against the Shield360 Rule Engine to retrieve matching rules and associated entities (contexts, prompts, evaluation configurations).

| Parameter          | Description                                                                                                                        |
|--------------------|------------------------------------------------------------------------------------------------------------------------------------|
| `url`              | Sets the Shield360 URL. Defaults to the `SHIELD360_URL` environment variable or `http://127.0.0.1:3000`.                               |
| `apiKey`           | Sets the Shield360 API Key. Can also be provided via the `SHIELD360_API_KEY` environment variable.                                     |
| `entityType`       | Type of entity to match: `"context"`, `"prompt"`, or `"evaluation"`.                                                               |
| `fields`           | Object of trace attributes to evaluate against rules. e.g. `{ "gen_ai.system": "openai" }`                                        |
| `includeEntityData`| If `true`, include full entity data in the response. Default: `false`. Optional                                                    |
| `entityInputs`     | Optional object of inputs for entity resolution (e.g. prompt variables).                                                           |

#### Example

```typescript
import Shield360 from 'shield360';

const result = await Shield360.evaluateRule({
  entityType: 'context',
  fields: {
    'gen_ai.system': 'openai',
    'gen_ai.request.model': 'gpt-4',
    'service.name': 'my-app',
  },
  includeEntityData: true,
});

if (!('err' in result)) {
  console.log('Matching rules:', result.matchingRuleIds);
  console.log('Entities:', result.entities);
}
```

### Score ingestion - `Shield360.logScore()`

Attach numeric, boolean, or categorical scores and user feedback to a GenAI span. When called inside an instrumented LLM request, the score auto-attaches to the active span.

| Parameter | Description |
|-----------|-------------|
| `name` | Score name, for example `user_feedback` or `quality`. |
| `value` | Numeric, boolean, or categorical score value. |
| `span` | Optional explicit OpenTelemetry span. |
| `traceId` | Optional trace ID for async feedback against a past trace. |
| `spanId` | Optional span ID for async feedback against a past trace. |
| `comment` | Optional explanation or reviewer comment. |
| `idempotencyKey` | Optional key to deduplicate score updates. |
| `metadata` | Optional object of extra event attributes. |

#### Example

```typescript
import Shield360 from 'shield360';

Shield360.init();

Shield360.logScore({ name: 'user_feedback', value: true, comment: 'Helpful response' });
Shield360.logScore({ name: 'quality', value: 0.85, metadata: { reviewer: 'human' } });
Shield360.logScore({ name: 'category', value: 'accurate' });
```

### Agent passports - `shield360/agents`

Check the AI agents that call your API or MCP server. A calling agent sends a Shield360 **agent passport** in the `Shield360-Agent` header: a short-lived signed token that says who the agent is, which organization runs it and, when it acts for a person, that it does. The verifier checks it offline against the issuer's published keys, applies your policy and can report each result to your Shield360 project's inbound decision log. A passport never grants access by itself: your own API keys, OAuth tokens and permissions still decide what the call may do.

```typescript
import { agentVerifier, AGENT_HEADER } from 'shield360/agents';

const verifier = agentVerifier({
  audience: 'api.example.com',                       // your API host or https origin (or several)
  // issuers: ['https://app.shield360.ai'],           // default
  policy: { mode: 'observe' },                        // local policy, merged over the defaults
  policyFrom: { apiKey: process.env.SHIELD360_INBOUND_API_KEY! }, // follow the console policy (cached 60 s)
  report: { apiKey: process.env.SHIELD360_INBOUND_API_KEY! },     // inbound decision log (batched, never blocks)
});

const result = await verifier.check(request, { route: '/v1/jobs', method: 'POST' });
// result.status: 'verified' | 'absent' | 'invalid'
// result.decision: 'allow' | 'deny'; result.blocked: deny in enforce mode
// result.agent: id, name and, when the issuer sends them, status, environment, risk, owner, reviewedAt, enrolledAt
// result.operator, result.scopes
// result.onBehalfOf: { id (a pairwise id), domain, assurance: 'delegated' | 'named' | 'unverified', mandate? }
```

`check` accepts a Fetch `Request`, a Node `IncomingMessage`, a `Headers` object or header record, or the passport string, and never throws. The API key is sent as `Authorization: Bearer <key>`; `baseUrl` defaults to `SHIELD360_URL` or `https://app.shield360.ai`.

| Policy field | Default | Meaning |
|--------------|---------|---------|
| `mode` | `observe` | `observe` never blocks and reports what `enforce` would do. |
| `requireAgent` | `false` | A call without a passport is denied (reason `absent`). |
| `operators` | `[]` | Allowed operator ids or verified domains; empty allows any verified operator. |
| `requireOnBehalfOf` | `false` | The passport must say the agent acts for a person. |
| `minAssurance` | `none` | The weakest on-behalf-of assurance accepted: `unverified`, `named` or `delegated` (strongest). A passport without a person, or with weaker assurance, is denied (reason `assurance_too_low`). A person without a stated assurance counts as `named`. |
| `online` | `false` | Also ask the issuer, on every call, whether the passport is still good (kill switch, revoked token). Pass `{ online: true }` to `check` for single sensitive operations. |

Reason codes, in the order they are checked: `malformed`, `unsupported_alg`, `untrusted_issuer`, `unknown_key`, `bad_signature`, `expired`, `not_yet_valid`, `lifetime_too_long`, `wrong_audience`, `replayed`, `revoked`, `unknown_passport`, then the policy's `absent`, `operator_not_allowed`, `on_behalf_of_required`, `assurance_too_low`. An online check can keep a passport valid but lower its assurance (for example `reason: 'mandate_revoked'`); the result then carries the lower assurance and no mandate. An unreachable issuer on an online check is `issuer_unreachable` and does not deny unless `onlineFailure: 'deny'`.

Each passport is accepted once. The default replay store is in memory, per process; with several instances pass a shared one:

```typescript
const replay = { seen: async (jti: string, expiresAtMs: number) => (await redis.set(`passport:${jti}`, '1', { NX: true, PXAT: expiresAtMs })) === null };
agentVerifier({ audience: 'api.example.com', replay });
```

#### Express

```typescript
app.use(verifier.middleware()); // sets req.shield360Agent; answers 403 { error: 'agent_not_allowed', reason } only when blocked
app.get('/v1/jobs', (req, res) => {
  const agent = (req as { shield360Agent?: AgentCheck }).shield360Agent; // import type { AgentCheck } from 'shield360/agents'
  res.json({ agent: agent?.agent });
});
```

#### Next.js route handlers and other Fetch servers

```typescript
export async function POST(request: Request) {
  const agent = await verifier.check(request, { route: '/api/jobs', method: 'POST' });
  if (agent.blocked) return Response.json({ error: 'agent_not_allowed', reason: agent.reason }, { status: 403 });
  // ... your own authentication and authorization still apply
}
```

Call `await verifier.close()` on shutdown to send queued reports.

## Application logs

Off by default. Set `SHIELD360_CAPTURE_LOGS=true` (or the init option) to send the application's own log records to Shield360, on the same endpoint and key as traces. `SHIELD360_LOG_LEVEL` sets the lowest level sent (`info` by default; `trace`, `debug`, `info`, `warn`, `error`, `fatal`). Records carry the active trace and span ids, `service.name` and `deployment.environment`; credentials and opaque tokens in messages and attributes are masked before they leave the process; at most 500 records a second per bridge are sent, in batches, and a failure to send never reaches the application.

```typescript
import Shield360 from 'shield360';

Shield360.init({ captureLogs: true, logLevel: 'info' }); // or SHIELD360_CAPTURE_LOGS=true

console.warn('cache miss', { key: 'k' });                 // console output is copied (still printed)
const log = Shield360.logger('checkout');                 // or a logger of your own
log.info('order placed', { 'order.id': 'o-1' });
```

With application logs on, `init()` bridges these with no code changes:

- **console**: `console.debug`, `log`, `info`, `warn` and `error` are copied as well as printed. `Shield360.releaseConsole()` stops this.
- **winston** (3.x): every `winston.createLogger()` also gets the Shield360 transport, and the logger's own transports are kept.
- **pino** (7 to 10): every `pino()` logger writes to its own destination and to Shield360 through `pino.multistream`.

**Loggers that write lines themselves.** Some apps have their own logger that writes JSON lines straight to `process.stdout` and `process.stderr`, which none of the bridges above see. For them, set `SHIELD360_CAPTURE_STDIO=true` as well (or `captureStdio: true`). Every line written to stdout and stderr is then copied, and the output is unchanged:

- a JSON line keeps its level (a name or a pino number), `msg` or `message` as the body, `err` or `error` as `exception.*`, and its other fields as attributes;
- a plain line is `info` on stdout and `error` on stderr;
- a line split across writes is joined first.

The scope is `stdout` or `stderr`. It replaces the console, winston and pino bridges, which write to the same streams, so each line is sent once. `Shield360.releaseStdio()` stops it.

The winston and pino bridges hook `require` the way OpenTelemetry's instrumentations do, so create those loggers after `init()`. For ES modules, or for loggers created earlier, add the bridge yourself:

```typescript
import pino from 'pino';
import winston from 'winston';
import Transport from 'winston-transport';

const p = pino({}, pino.multistream([{ stream: process.stdout }, { stream: Shield360.pinoStream() }]));
const Shield360Transport = Shield360.winstonTransport(Transport);
const w = winston.createLogger({ transports: [new winston.transports.Console(), new Shield360Transport()] });
```

The record's scope is the logger name (`console`, `winston`, `pino`, or the name you give). Other attributes:

- `code.function.name`, `code.file.path` and `code.line.number` for the call site, unless `captureCodeLocation` is off;
- `exception.*` for an `Error`;
- your fields.

The SDK's own scopes (`shield360`, `opentelemetry`) and the telemetry pipeline's own messages are never sent. Masking follows the contract every Shield360 SDK shares (`sdk/rasp/README.md`, "Masking"). Credential pairs (`password=…`, `"api_key": "…"`, `Authorization: Bearer …`), bearer credentials and opaque tokens (keys, hashes, base64, JWTs, UUIDs) are masked. So is the whole value of a field named like a credential (`password`, `x-api-key`, `sessionId`), with lists and maps masked item by item. Readable identifiers survive: class names, package and file paths, and stack frames.

## Budget check

Ask Shield360 whether this app may spend on a model call. App budgets (Costs → Budgets → App, by service name) and whole-project budgets with enforcement rules apply. Uses `shield360Url`, `shield360ApiKey` and `applicationName` from `init()`.

```typescript
const check = await Shield360.budgets.check({ model: 'gpt-4o', estimatedCostUsd: 0.02 });
if (!check.allowed) throw new Error(check.reason);
```

`check()` never throws, reuses a decision for its ttl while the calls checked with it fit in its headroom, and fails open unless `failClosed` is set (or `SHIELD360_BUDGET_FAIL_CLOSED=1`). Pass `budgetCheck: true` to `init()` (or set `SHIELD360_BUDGET_CHECK=1`) to check before every call to a supported provider; a blocked call throws `BudgetExceededError`.

## Guard reports and heartbeat

When `init` is given `guards` and a Shield360 URL and API key (`shield360Url` / `shield360ApiKey`, or `SHIELD360_URL` / `SHIELD360_API_KEY`), the SDK reports to Shield360's `/api/guard/events`:

- **Guard decisions:** every decision other than allow (which guard, what it did, the kind of data found). Never the text that was checked.
- **A heartbeat:** once at start and then about every 5 minutes (jittered), the app's service name, each guard kind's mode (`off`, `warn` or `block`), whether prompt-injection checks are on, and the SDK's name and version. No text, host or user. Shield360 uses it to show that the app's guards are on even when they had nothing to stop, for example for the [Secured by Shield360 badge](https://shield360.ai).

Both go through the same background queue, never throw and never delay a call. Turn the heartbeat off with `guardHeartbeat: false` in `init`, or `SHIELD360_GUARD_HEARTBEAT=false`.

## Runtime protection (RASP)

Off by default. When on, the SDK keeps the untrusted input of the request it is serving (query, route params, body, cookies, and the `user-agent`, `referer` and `x-forwarded-for` headers), plus the model output its LLM instrumentation sees, in memory for that request only. The contract every Shield360 SDK follows is [`sdk/rasp/README.md`](../rasp/README.md).

### Turn it on

```typescript
import Shield360, { raspExpress, raspExpressErrorHandler } from 'shield360';

Shield360.init({
  applicationName: 'orders-api',
  shield360Url: process.env.SHIELD360_URL,
  shield360ApiKey: process.env.SHIELD360_API_KEY,
  rasp: { enabled: true, configPublicKey: process.env.SHIELD360_CONFIG_PUBLIC_KEY },
});

app.use(express.json());
app.use(raspExpress());       // after the body parsers
// ...routes...
app.use(raspExpressErrorHandler());
```

Or set `SHIELD360_RASP=monitor` (or `block`) without changing code. `SHIELD360_RASP=off` always wins. To add it without any code at all, middleware included, see [Zero-code setup](#zero-code-setup).

| Framework | Use |
|---|---|
| Express 4/5 | `app.use(raspExpress())`, and `raspExpressErrorHandler()` last |
| Fastify | `fastify.register(raspFastify)` (applies to every route) |
| Koa | `app.use(raspKoa())` |
| Node `http` | `http.createServer(raspHttp(handler))`; after reading the body yourself, call `recordRequestBody(body, contentType)` |
| Next.js route handlers (Node.js runtime) | `export const POST = withRasp(async (request) => { ... })` |

Custom request rules run in a head phase and a body phase (see "When rules run" in [`sdk/rasp/README.md`](../rasp/README.md)). A request without a body (no `Content-Length` or `Transfer-Encoding`, or `Content-Length: 0`; for Fastify also any `GET` or `HEAD`, whose body Fastify never parses; for Next.js, a request with no body stream) has a known, empty body, so its body phase runs at once. The body stays unknown, and its body phase waits, until a parser sets `req.body` (Express, Koa, raw `http`), the handler calls `recordRequestBody` (raw `http`), or Fastify's `preHandler` sees the parsed body. It never becomes known when no parser reads it, for Fastify multipart without `attachFieldsToBody`, or for a Next.js body already read before `withRasp`.

Options (`rasp: { ... }`): `mode` (`monitor` by default, or `block`, `off`), `attacks` (a mode per attack type), `allow` (`commands`, `outboundHosts`, `fileRoots`), `modelOutput` (default `true`), `remote` (default `true`), `configPublicKey`, `allowUnpinnedConfig`, `cacheDir`, `components` (default `true`). `Shield360.disableRasp()` is the runtime kill switch.

### Pin the config key

With a Shield360 URL and API key, the SDK polls the app's signed settings (`GET /api/rasp/config`). It trusts them only when they verify against the key you pin. Copy the environment's public key from the app's **Runtime protection** settings in Shield360 into `configPublicKey` or `SHIELD360_CONFIG_PUBLIC_KEY`, as a JWK, a JWKS (`{"keys":[...]}`, so a key rotation can list the old and new key), or the bare base64url `x`.

- The keys in the config response are never trusted on their own.
- With no pinned key, the SDK does not fetch the signed config. It runs its built-in defaults in monitor mode (a local `block` is lowered to `monitor`) and logs one warning.
- Trust on first use is for development only: `allowUnpinnedConfig: true` or `SHIELD360_CONFIG_TOFU=dev` pins the first key the server sends. Both are ignored when `NODE_ENV` or `ENVIRONMENT` is `production`.

The last verified config is cached (OS temp dir, `shield360-rasp/`) and verified again when loaded.

### What this release covers

- Request capture for the frameworks above, and model output (OpenAI chat and Responses, Anthropic messages) recorded as untrusted input.
- The detection engine (SQL token structure, path containment, address class, deserialization and eval taint, XML external entities, reflected XSS that is never blocked). These are pure functions that later sink hooks call.
- Virtual patches: the built-in rules in [`sdk/rasp/rules/default-rules.json`](../rasp/rules/default-rules.json) are checked against each request before the handler. A blocked request gets a `403` with `{"error","attack","rule","event"}`.
- `child_process`: `exec`, `execSync`, `spawn`, `spawnSync`, `execFile`, `execFileSync` and `fork` are checked before the process starts, for command injection (shell command lines and `sh -c` scripts), an executable taken from the request, a shell or downloader started during a request (`shell_spawn`, unless listed in `allow.commands`), and a download piped into a shell. `util.promisify(exec)` is checked too. Initialise Shield360 before loading the app's modules: a function copied out of `child_process` before then (`const { exec } = require('child_process')`) is not checked.
- `fs` and `fs.promises`: reads, opens, writes, appends, deletes, renames (both paths), copies (source and target), directory listings and read/write streams are checked before the call for path traversal (`../` from the request, an absolute path from the request, NUL bytes, paths outside `allow.fileRoots`, well-known secret files) and script writes (`file_write`). A blocked promise call rejects; a blocked callback or sync call throws. File descriptors are not checked.
- Events (`shield360.rasp.event`, folded and capped at 100 a minute) and a report of the app's package names and versions, sent to Shield360 with the guard reports. Events name the location of an input (`query.id`), never its value.

Outbound HTTP: `http`/`https` `request` and `get`, and the global `fetch`, are checked before anything is sent for SSRF from request or model input (internal, metadata, obfuscated and out-of-band hosts, unsafe schemes) and, when `allow.outboundHosts` is set, for hosts outside it (the Shield360 URL and OTLP endpoint are always allowed). `http`/`https` check again at the connection's own DNS lookup, so a name that resolves to an internal address is refused (DNS rebinding). `fetch` resolves the name once before the call, and its own connection may resolve again.

Databases: SQL text sent through `pg`, `mysql2`, `mysql`, `sqlite3`, `better-sqlite3`, `mssql`, `tedious`, `oracledb` and `ibm_db` is checked for SQL injection before the driver sends it (structural, per dialect; bound parameters are never part of the text, so parameterised queries pass), and MongoDB filter, update, replacement and pipeline documents (`mongodb` `Collection` methods) for operators that came from the request (`nosql_injection`). Drivers are hooked when the app loads them, including ones loaded before `init`; the SDK's own database tracing keeps working alongside.

| Database | Driver and methods | Dialect |
|---|---|---|
| SQL Server | `mssql` `Request.query`, `batch`, `execute` (on the base Request the drivers share), `PreparedStatement.prepare`; `tedious` `Connection.execSql`, `execSqlBatch`, `prepare` (the Request's SQL text). A query `mssql` checked is not checked again in the `tedious` call it makes. | `mssql` |
| Oracle | `oracledb` `Connection.execute`, `executeMany`, `queryStream` (not checked again in the `execute` it runs) | `oracle` |
| Db2 | `ibm_db` `Database.query`, `querySync`, `queryResult`, `queryResultSync` (and `queryStream` through it), `prepare`, `prepareSync` (string or `{ sql }`) | `db2` |

Code, deserialization and XML: `vm` (`runInThisContext`, `runInNewContext`, `runInContext`, `compileFunction`, `new vm.Script`) and the `Function` constructor are checked for code built from request or model input (`code_injection`); `node-serialize` `unserialize`, `funcster` `deepDeserialize` and `js-yaml` `load`/`loadAll` with a schema that can build functions for tainted data (`deserialization`); and `libxmljs`/`libxmljs2` `parseXml` for external entities (`xxe`, by whether the parser resolves them). `eval` is not hooked: replacing it would break direct `eval` in the app (code relying on the caller's scope, such as webpack's eval source maps).

Responses: HTML responses (`Content-Type` containing `html`, up to 1 MiB) are checked for request input reflected verbatim (`xss`, monitor only: it never blocks or changes the response).

Sink rules: the signed config can name further library functions to check with any of the checks above (for example a driver's raw query method as a SQL sink), as data, without an SDK release. They report only unless a rule says `block` and the attack type is in block mode. See "Sink rules" in [`sdk/rasp/README.md`](../rasp/README.md).

Uploads: file names of multipart uploads (raw bodies, or multer's `req.file` / `req.files` with `raspExpress`) are request input, and an upload named like a script (`.php`, `.jsp`, `.sh`, `.exe`…) is reported (`file_write.upload`; blocks when `file_write` blocks). A later write named after the upload is caught by `file_write.script`.

Module loading: `require` (and functions from `module.createRequire`) is checked during a request for a module name taken whole from input, or a path from input inside the specifier (`code_injection`, rule `code.include`). Dynamic `import()` is not covered.

Security baseline: once per process, shortly after start, RASP reports risky set-up as `baseline` events (report only): TLS checks off, a debugger in production, development mode under a production environment, running as root, an unpinned config key in production, and a Node.js line past its end of life. See "Security baseline" in [`sdk/rasp/README.md`](../rasp/README.md).

Deception (decoy paths): off unless the app's **Runtime protection** settings in Shield360 list decoys, paths no real user requests such as `/wp-admin` (the signed config's `deception` block; there is no local way to define them). The middleware checks every request against them first, before anything else. A request for a decoy never reaches your handlers: it gets the 404 your app gives an unknown path (Express's default `Cannot GET /path` page, or `raspExpress({ notFound })` for your own page; Fastify's `reply.callNotFound()`; Koa's `Not Found`; an empty 404 for Next.js route handlers; a plain-text `404 Not Found` for raw `http`), and its client address (the one custom rules see as `request.ip`) is marked suspicious for the configured time. Later requests from that address are reported as `deception.suspicious`; with the decoys' action `block` they get the `403` block response, with `monitor` they go on to the app. Without a pinned key, `block` is lowered to `monitor`, and `attacks.deception: off` turns deception off. The zero-code capture answers decoys itself (plain-text `404 Not Found`, socket peer address) only for a plain `http` listener. For an Express, Koa or Fastify app (Nest included) it leaves deception to the framework's adapter, which knows the trusted client address and the app's own 404, so add `raspExpress()`, `raspKoa()` or `raspFastify` for decoys there. Marks are held in memory per process (at most 10,000 addresses; when full, expired marks go first, then the mark closest to expiring): replicas and cluster workers do not share them. Next.js route handlers have no client address, so a decoy hit there marks nothing. See "Deception" in [`sdk/rasp/README.md`](../rasp/README.md).

RASP fails open everywhere: the only error it raises on purpose is `RaspBlockedError`.

## Cost per end customer

Building a SaaS product on AI? Tag each call with your own customer (and, optionally, the end user inside it) and Shield360 shows cost and margin per end customer. Every span started while a customer is in effect gets `shield360.customer.tenant_id` and `shield360.customer.user_id`, whichever instrumentation started it.

```typescript
import Shield360 from 'shield360';

// A process-wide default, e.g. in a single-tenant worker. null clears it.
Shield360.setCustomer({ tenantId: 'acme' });

// Per request: wins over the default, follows async work, and nests.
await Shield360.withCustomer({ tenantId: req.tenantId, userId: req.userId }, async () => {
  await openai.chat.completions.create({ model: 'gpt-4o', messages });
});

Shield360.getCustomer(); // the customer in effect here, or null
```

Ids may be strings or numbers; they are trimmed and must be 1–256 characters with no control characters. Invalid ids are dropped silently (never thrown, never logged), and a `userId` without a valid `tenantId` is dropped too. A span that already carries `shield360.customer.tenant_id` is left as it is. If you pass your own `tracer` to `init()`, add `CustomerSpanProcessor` to your provider yourself.

The SDK sends ids as given and never hashes them: user ids are stored only as a keyed hash on Shield360's side; tenant ids are kept as given unless the organisation opts to hash them.

## AI app security

`init({ aiSecurity: true })` turns on checks on the app's own AI traffic, mapped to the OWASP Top 10 for LLM Applications (2025). Every check reports by default and changes nothing; enforcing is set per check (in code, or per app in Shield360 under the app's **Security** tab), and every check fails open. Events carry kinds, masked tokens and keyed fingerprints, never the checked text.

```typescript
Shield360.init({ applicationName: 'support-bot', aiSecurity: { policy: { output: { mode: 'enforce' } } } });

const refund = Shield360.aiSecurity.defineTool({
  name: 'refund_order',
  permissions: { roles: ['support_lead'] },          // checked for the end user before it runs
  execute: async ({ orderId }) => refundOrder(orderId),
});

await Shield360.aiSecurity.withEndUser({ tenantId: 'acme', userId: 'u-42', roles: ['agent'] }, async () => {
  const page = Shield360.aiSecurity.scanContext(fetchedHtml, { source: 'document' }); // indirect injection
  const answer = Shield360.aiSecurity.scanOutput(modelText, { systemPrompt });        // PII, secrets, leaks
});
```

With `aiSecurity` on, OpenAI, Anthropic, LangChain retrievers and tools, LlamaIndex retrievers and the MCP client are checked automatically (tool results, user turns, answers and streams, retrieved chunks, MCP tool lists). Checks: `scanContext`, `checkPrompt`, `scanOutput` / `streamScanner`, `withCanary`, `defineTool` / `authorizeTool`, `checkLimits` / `recordUsage`, `checkMcpTools`, `checkRetrieval`. The platform's policy is an Ed25519-signed JWS fetched every minute in the background. It is applied only when it verifies under a key you pin: `configPublicKey` (a JWK, PEM or JWKS) or `SHIELD360_CONFIG_PUBLIC_KEY`; copy the environment's key from the app's Security tab. Without a pin the checks run in monitor mode with the policy from code. `allowUnpinnedConfig: true` trusts the first key seen, for development only.

## 🌱 Contributing

Whether it's big or small, we love contributions 💚. Check out our [Contribution guide](https://github.com/ThinkfleetAI/shield360-js#readme) to get started

Unsure where to start? Here are a few ways to get involved:

- Have a question or some feedback? Reach us at [shield360.ai](https://shield360.ai).

Your input helps us grow and improve, and we're here to support you every step of the way.

## 💚 Community & Support

Connect with the Shield360 community and maintainers for support, discussions, and updates:

- 🌟 If you like it, Leave a star on our [GitHub](https://github.com/ThinkfleetAI/shield360-js)
- 🐞 Report bugs on our [GitHub Issues](https://github.com/ThinkfleetAI/shield360-js/issues) to help us improve Shield360.
