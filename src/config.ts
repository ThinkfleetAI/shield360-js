import { Shield360ConfigInterface, PricingObject } from './types';
import type { Pipeline } from './guard/pipeline';

export default class Shield360Config {
  static environment: Shield360ConfigInterface['environment'];
  static applicationName: Shield360ConfigInterface['applicationName'];
  static pricingInfo: PricingObject;
  static tracer: Shield360ConfigInterface['tracer'];
  static otlpEndpoint?: Shield360ConfigInterface['otlpEndpoint'];
  static otlpHeaders?: Shield360ConfigInterface['otlpHeaders'];
  static disableBatch?: Shield360ConfigInterface['disableBatch'];
  static captureMessageContent?: Shield360ConfigInterface['captureMessageContent'];
  static pricingJson?: Shield360ConfigInterface['pricingJson'];
  static disableMetrics?: boolean;
  static disableEvents?: boolean;
  static maxContentLength?: number | null;
  static customSpanAttributes?: Record<string, string> | null;
  static shield360ApiKey?: string;
  static shield360Url?: string;
  static guardPipeline?: Pipeline;

  static updateConfig({
    environment = 'default',
    applicationName = 'default',
    tracer,
    otlpEndpoint,
    otlpHeaders,
    disableBatch = false,
    captureMessageContent = true,
    pricingJson,
    disableMetrics = false,
    disableEvents = false,
    maxContentLength = null,
    customSpanAttributes = null,
    shield360ApiKey,
    shield360Url,
  }: Partial<Shield360ConfigInterface> & {
    disableMetrics?: boolean;
    disableEvents?: boolean;
    maxContentLength?: number | null;
    customSpanAttributes?: Record<string, string> | null;
    shield360ApiKey?: string;
    shield360Url?: string;
  }) {
    this.environment = environment;
    this.applicationName = applicationName;
    this.tracer = tracer as Shield360ConfigInterface['tracer'];
    this.otlpEndpoint = otlpEndpoint;
    this.otlpHeaders = otlpHeaders;
    this.disableBatch = disableBatch;
    this.captureMessageContent = captureMessageContent;
    this.pricingJson = pricingJson;
    this.disableMetrics = disableMetrics;
    this.disableEvents = disableEvents;
    this.maxContentLength = maxContentLength;
    this.customSpanAttributes = customSpanAttributes;
    this.shield360ApiKey = shield360ApiKey;
    this.shield360Url = shield360Url;
  }
}
