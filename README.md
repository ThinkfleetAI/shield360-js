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
| `serviceVersion`        | Release recorded as the `service.version` resource attribute. Also `SHIELD360_SERVICE_VERSION`. | `undefined` | No |

> **Message content is off by default.** Prompt and completion text is recorded only when you pass `captureMessageContent: true` (or set `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true`). Even then, Shield360 stores it only if your organisation's [Data retention](https://shield360.ai) setting allows it. Before this release the default was on.

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
| `service.version` | `serviceVersion`, `SHIELD360_SERVICE_VERSION`, `OTEL_SERVICE_VERSION`, `OTEL_RESOURCE_ATTRIBUTES` |
| `vcs.ref.head.revision` | `SHIELD360_GIT_COMMIT`, `OTEL_RESOURCE_ATTRIBUTES`, CI variables |
| `vcs.repository.url.full` | `SHIELD360_GIT_REPOSITORY_URL`, `OTEL_RESOURCE_ATTRIBUTES`, CI variables |
| `vcs.ref.head.name` | `SHIELD360_GIT_BRANCH`, `OTEL_RESOURCE_ATTRIBUTES`, CI variables |

CI variables are read from GitHub Actions, GitLab CI, Vercel, Netlify, Render, Railway, Heroku, AWS CodeBuild, Buildkite, CircleCI, Bitbucket Pipelines, Azure Pipelines and Jenkins. An explicit `OTEL_RESOURCE_ATTRIBUTES` value beats CI auto-detection. Values from different providers are never mixed. Commit SHAs that are not 7 to 64 hex characters are dropped, and repository URLs are reduced to `https://host/owner/repo` with any credentials removed.

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

## 🌱 Contributing

Whether it's big or small, we love contributions 💚. Check out our [Contribution guide](https://github.com/ThinkfleetAI/shield360-js#readme) to get started

Unsure where to start? Here are a few ways to get involved:

- Have a question or some feedback? Reach us at [shield360.ai](https://shield360.ai).

Your input helps us grow and improve, and we're here to support you every step of the way.

## 💚 Community & Support

Connect with the Shield360 community and maintainers for support, discussions, and updates:

- 🌟 If you like it, Leave a star on our [GitHub](https://github.com/ThinkfleetAI/shield360-js)
- 🐞 Report bugs on our [GitHub Issues](https://github.com/ThinkfleetAI/shield360-js/issues) to help us improve Shield360.
