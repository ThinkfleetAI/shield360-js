/**
 * Trace Comparison Tests for Replicate Integration
 *
 * Verifies that the TypeScript SDK generates consistent traces for
 * Replicate model runs, aligned with OTel semantic conventions and
 * the OpenAI reference implementation pattern.
 */

import ReplicateWrapper from '../replicate/wrapper';
import Shield360Config from '../../config';
import Shield360Helper from '../../helpers';
import BaseWrapper from '../base-wrapper';
import SemanticConvention from '../../semantic-convention';

jest.mock('../../config');
jest.mock('../../helpers');
jest.mock('../base-wrapper');

describe('Replicate Trace Comparison', () => {
  let mockSpan: any;

  beforeEach(() => {
    mockSpan = {
      setAttribute: jest.fn(),
      addEvent: jest.fn(),
      end: jest.fn(),
      setStatus: jest.fn(),
    };

    (Shield360Config as any).environment = 'shield360-testing';
    (Shield360Config as any).applicationName = 'shield360-test';
    (Shield360Config as any).captureMessageContent = true;
    (Shield360Config as any).pricingInfo = {};
    (Shield360Config as any).disableEvents = false;

    (Shield360Helper as any).getChatModelCost = jest.fn().mockReturnValue(0.001);
    (Shield360Helper as any).generalTokens = jest.fn().mockReturnValue(10);
    (Shield360Helper as any).handleException = jest.fn();
    (Shield360Helper as any).buildInputMessages = jest.fn().mockReturnValue('[{"role":"user","parts":[{"type":"text","content":"What is the capital of France?"}]}]');
    (Shield360Helper as any).buildOutputMessages = jest.fn().mockReturnValue('[{"role":"assistant","parts":[{"type":"text","content":"Paris."}],"finish_reason":"stop"}]');
    (Shield360Helper as any).emitInferenceEvent = jest.fn();

    (BaseWrapper as any).recordMetrics = jest.fn();
    (BaseWrapper as any).setBaseSpanAttributes = jest.fn().mockImplementation((span: any, attrs: any) => {
      span.setAttribute(SemanticConvention.GEN_AI_PROVIDER_NAME_OTEL, attrs.aiSystem);
      span.setAttribute(SemanticConvention.GEN_AI_REQUEST_MODEL, attrs.model);
      if (attrs.cost !== undefined) {
        span.setAttribute(SemanticConvention.GEN_AI_USAGE_COST, attrs.cost);
      }
      if (attrs.serverAddress) {
        span.setAttribute(SemanticConvention.SERVER_ADDRESS, attrs.serverAddress);
      }
      if (attrs.serverPort !== undefined) {
        span.setAttribute(SemanticConvention.SERVER_PORT, attrs.serverPort);
      }
      span.setAttribute(SemanticConvention.GEN_AI_SDK_VERSION, '1.9.0');
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('run() — core attributes', () => {
    const identifier = 'meta/llama-2-70b-chat';
    const mockArgs = [
      identifier,
      { input: { prompt: 'What is the capital of France?' } },
    ];

    it('should set gen_ai.provider.name = "replicate"', async () => {
      await ReplicateWrapper._run({
        args: mockArgs,
        genAIEndpoint: 'replicate.run',
        response: 'Paris.',
        span: mockSpan,
      });

      expect(mockSpan.setAttribute).toHaveBeenCalledWith(
        SemanticConvention.GEN_AI_PROVIDER_NAME_OTEL,
        'replicate'
      );
    });

    it('should set gen_ai.request.model stripped of version hash', async () => {
      await ReplicateWrapper._run({
        args: mockArgs,
        genAIEndpoint: 'replicate.run',
        response: 'Paris.',
        span: mockSpan,
      });

      expect(mockSpan.setAttribute).toHaveBeenCalledWith(
        SemanticConvention.GEN_AI_REQUEST_MODEL,
        'meta/llama-2-70b-chat'
      );
    });

    it('should strip version hash from identifier with colon', async () => {
      const argsWithVersion = [
        'stability-ai/sdxl:abc123def456',
        { input: { prompt: 'A sunset over mountains' } },
      ];

      await ReplicateWrapper._run({
        args: argsWithVersion,
        genAIEndpoint: 'replicate.run',
        response: ['https://example.com/image.png'],
        span: mockSpan,
      });

      expect(mockSpan.setAttribute).toHaveBeenCalledWith(
        SemanticConvention.GEN_AI_REQUEST_MODEL,
        'stability-ai/sdxl'
      );
    });

    it('should set gen_ai.response.model', async () => {
      await ReplicateWrapper._run({
        args: mockArgs,
        genAIEndpoint: 'replicate.run',
        response: 'Paris.',
        span: mockSpan,
      });

      expect(mockSpan.setAttribute).toHaveBeenCalledWith(
        SemanticConvention.GEN_AI_RESPONSE_MODEL,
        'meta/llama-2-70b-chat'
      );
    });

    it('should set gen_ai.request.is_stream = false', async () => {
      await ReplicateWrapper._run({
        args: mockArgs,
        genAIEndpoint: 'replicate.run',
        response: 'Paris.',
        span: mockSpan,
      });

      expect(mockSpan.setAttribute).toHaveBeenCalledWith(
        SemanticConvention.GEN_AI_REQUEST_IS_STREAM,
        false
      );
    });

    it('should set gen_ai.response.finish_reasons = ["stop"]', async () => {
      await ReplicateWrapper._run({
        args: mockArgs,
        genAIEndpoint: 'replicate.run',
        response: 'Paris.',
        span: mockSpan,
      });

      expect(mockSpan.setAttribute).toHaveBeenCalledWith(
        SemanticConvention.GEN_AI_RESPONSE_FINISH_REASON,
        ['stop']
      );
    });

    it('should set server.address and server.port', async () => {
      await ReplicateWrapper._run({
        args: mockArgs,
        genAIEndpoint: 'replicate.run',
        response: 'Paris.',
        span: mockSpan,
      });

      expect(mockSpan.setAttribute).toHaveBeenCalledWith(
        SemanticConvention.SERVER_ADDRESS,
        'api.replicate.com'
      );
      expect(mockSpan.setAttribute).toHaveBeenCalledWith(
        SemanticConvention.SERVER_PORT,
        443
      );
    });

    it('should set token usage attributes', async () => {
      await ReplicateWrapper._run({
        args: mockArgs,
        genAIEndpoint: 'replicate.run',
        response: 'Paris.',
        span: mockSpan,
      });

      expect(mockSpan.setAttribute).toHaveBeenCalledWith(
        SemanticConvention.GEN_AI_USAGE_INPUT_TOKENS,
        10
      );
      expect(mockSpan.setAttribute).toHaveBeenCalledWith(
        SemanticConvention.GEN_AI_USAGE_OUTPUT_TOKENS,
        10
      );
    });
  });

  describe('run() — output types', () => {
    const mockArgs = [
      'meta/llama-2-70b-chat',
      { input: { prompt: 'What is the capital of France?' } },
    ];

    it('should set output_type=text for string responses', async () => {
      await ReplicateWrapper._run({
        args: mockArgs,
        genAIEndpoint: 'replicate.run',
        response: 'Paris.',
        span: mockSpan,
      });

      expect(mockSpan.setAttribute).toHaveBeenCalledWith(
        SemanticConvention.GEN_AI_OUTPUT_TYPE,
        SemanticConvention.GEN_AI_OUTPUT_TYPE_TEXT
      );
    });

    it('should set output_type=text for array responses (text chunks)', async () => {
      await ReplicateWrapper._run({
        args: mockArgs,
        genAIEndpoint: 'replicate.run',
        response: ['Par', 'is', '.'],
        span: mockSpan,
      });

      expect(mockSpan.setAttribute).toHaveBeenCalledWith(
        SemanticConvention.GEN_AI_OUTPUT_TYPE,
        SemanticConvention.GEN_AI_OUTPUT_TYPE_TEXT
      );
    });

    it('should set output_type=json for object responses', async () => {
      await ReplicateWrapper._run({
        args: mockArgs,
        genAIEndpoint: 'replicate.run',
        response: { answer: 'Paris', confidence: 0.99 },
        span: mockSpan,
      });

      expect(mockSpan.setAttribute).toHaveBeenCalledWith(
        SemanticConvention.GEN_AI_OUTPUT_TYPE,
        SemanticConvention.GEN_AI_OUTPUT_TYPE_JSON
      );
    });
  });

  describe('run() — no sentinel values', () => {
    it('should NOT set total_tokens or client.token.usage on span', async () => {
      const mockArgs = [
        'meta/llama-2-70b-chat',
        { input: { prompt: 'Test' } },
      ];

      await ReplicateWrapper._run({
        args: mockArgs,
        genAIEndpoint: 'replicate.run',
        response: 'Response',
        span: mockSpan,
      });

      const setAttributeCalls = (mockSpan.setAttribute as jest.Mock).mock.calls;
      const attributeKeys = setAttributeCalls.map(([key]: [string]) => key);

      expect(attributeKeys).not.toContain(SemanticConvention.GEN_AI_USAGE_TOTAL_TOKENS);
      expect(attributeKeys).not.toContain(SemanticConvention.GEN_AI_CLIENT_TOKEN_USAGE);
    });
  });

  describe('run() — content capture', () => {
    const mockArgs = [
      'meta/llama-2-70b-chat',
      { input: { prompt: 'What is the capital of France?' } },
    ];

    it('should capture input/output messages when captureMessageContent=true', async () => {
      (Shield360Config as any).captureMessageContent = true;

      await ReplicateWrapper._run({
        args: mockArgs,
        genAIEndpoint: 'replicate.run',
        response: 'Paris.',
        span: mockSpan,
      });

      expect(Shield360Helper.buildInputMessages).toHaveBeenCalled();
      expect(Shield360Helper.buildOutputMessages).toHaveBeenCalled();
      expect(mockSpan.setAttribute).toHaveBeenCalledWith(
        SemanticConvention.GEN_AI_INPUT_MESSAGES,
        expect.any(String)
      );
      expect(mockSpan.setAttribute).toHaveBeenCalledWith(
        SemanticConvention.GEN_AI_OUTPUT_MESSAGES,
        expect.any(String)
      );
    });

    it('should NOT capture messages when captureMessageContent=false', async () => {
      (Shield360Config as any).captureMessageContent = false;

      await ReplicateWrapper._run({
        args: mockArgs,
        genAIEndpoint: 'replicate.run',
        response: 'Paris.',
        span: mockSpan,
      });

      const setAttributeCalls = (mockSpan.setAttribute as jest.Mock).mock.calls;
      const attributeKeys = setAttributeCalls.map(([key]: [string]) => key);

      expect(attributeKeys).not.toContain(SemanticConvention.GEN_AI_INPUT_MESSAGES);
      expect(attributeKeys).not.toContain(SemanticConvention.GEN_AI_OUTPUT_MESSAGES);
    });
  });

  describe('run() — events', () => {
    const mockArgs = [
      'meta/llama-2-70b-chat',
      { input: { prompt: 'Test' } },
    ];

    it('should emit inference event via LoggerProvider', async () => {
      await ReplicateWrapper._run({
        args: mockArgs,
        genAIEndpoint: 'replicate.run',
        response: 'Response',
        span: mockSpan,
      });

      expect(Shield360Helper.emitInferenceEvent).toHaveBeenCalledWith(
        mockSpan,
        expect.objectContaining({
          [SemanticConvention.GEN_AI_OPERATION]: SemanticConvention.GEN_AI_OPERATION_TYPE_TEXT_COMPLETION,
          [SemanticConvention.GEN_AI_REQUEST_MODEL]: 'meta/llama-2-70b-chat',
          [SemanticConvention.GEN_AI_RESPONSE_MODEL]: 'meta/llama-2-70b-chat',
          [SemanticConvention.SERVER_ADDRESS]: 'api.replicate.com',
          [SemanticConvention.SERVER_PORT]: 443,
          [SemanticConvention.GEN_AI_RESPONSE_FINISH_REASON]: ['stop'],
          [SemanticConvention.GEN_AI_USAGE_INPUT_TOKENS]: 10,
          [SemanticConvention.GEN_AI_USAGE_OUTPUT_TOKENS]: 10,
        })
      );
    });

    it('should include message content in event when captureMessageContent=true', async () => {
      (Shield360Config as any).captureMessageContent = true;

      await ReplicateWrapper._run({
        args: mockArgs,
        genAIEndpoint: 'replicate.run',
        response: 'Response',
        span: mockSpan,
      });

      expect(Shield360Helper.emitInferenceEvent).toHaveBeenCalledWith(
        mockSpan,
        expect.objectContaining({
          [SemanticConvention.GEN_AI_INPUT_MESSAGES]: expect.any(String),
          [SemanticConvention.GEN_AI_OUTPUT_MESSAGES]: expect.any(String),
        })
      );
    });

    it('should NOT include message content in event when captureMessageContent=false', async () => {
      (Shield360Config as any).captureMessageContent = false;

      await ReplicateWrapper._run({
        args: mockArgs,
        genAIEndpoint: 'replicate.run',
        response: 'Response',
        span: mockSpan,
      });

      const eventCall = (Shield360Helper.emitInferenceEvent as jest.Mock).mock.calls[0];
      const eventAttrs = eventCall[1];
      expect(eventAttrs).not.toHaveProperty(SemanticConvention.GEN_AI_INPUT_MESSAGES);
      expect(eventAttrs).not.toHaveProperty(SemanticConvention.GEN_AI_OUTPUT_MESSAGES);
    });

    it('should NOT emit events when disableEvents=true', async () => {
      (Shield360Config as any).disableEvents = true;

      await ReplicateWrapper._run({
        args: mockArgs,
        genAIEndpoint: 'replicate.run',
        response: 'Response',
        span: mockSpan,
      });

      expect(Shield360Helper.emitInferenceEvent).not.toHaveBeenCalled();
    });
  });

  describe('run() — metrics', () => {
    it('should record metrics via BaseWrapper.recordMetrics', async () => {
      const mockArgs = [
        'meta/llama-2-70b-chat',
        { input: { prompt: 'Test' } },
      ];

      await ReplicateWrapper._run({
        args: mockArgs,
        genAIEndpoint: 'replicate.run',
        response: 'Response',
        span: mockSpan,
      });

      expect(BaseWrapper.recordMetrics).toHaveBeenCalledWith(
        mockSpan,
        expect.objectContaining({
          genAIEndpoint: 'replicate.run',
          model: 'meta/llama-2-70b-chat',
          aiSystem: 'replicate',
        })
      );
    });

    it('should use Shield360Config.pricingInfo for cost calculation', async () => {
      (Shield360Config as any).pricingInfo = { chat: { 'meta/llama-2-70b-chat': { promptPrice: 0.05, completionPrice: 0.08 } } };

      const mockArgs = [
        'meta/llama-2-70b-chat',
        { input: { prompt: 'Test' } },
      ];

      await ReplicateWrapper._run({
        args: mockArgs,
        genAIEndpoint: 'replicate.run',
        response: 'Response',
        span: mockSpan,
      });

      expect(Shield360Helper.getChatModelCost).toHaveBeenCalledWith(
        'meta/llama-2-70b-chat',
        expect.any(Object),
        10,
        10
      );
    });

    it('should end span and record metrics', async () => {
      const mockArgs = [
        'meta/llama-2-70b-chat',
        { input: { prompt: 'Test' } },
      ];

      await ReplicateWrapper._run({
        args: mockArgs,
        genAIEndpoint: 'replicate.run',
        response: 'Response',
        span: mockSpan,
      });

      expect(mockSpan.end).toHaveBeenCalled();
      expect(BaseWrapper.recordMetrics).toHaveBeenCalled();
    });
  });

  describe('Span Creation Attributes', () => {
    it('should use aiSystem from SemanticConvention.GEN_AI_SYSTEM_REPLICATE', () => {
      expect(ReplicateWrapper.aiSystem).toBe(SemanticConvention.GEN_AI_SYSTEM_REPLICATE);
      expect(ReplicateWrapper.aiSystem).toBe('replicate');
    });

    it('should set correct server address and port', () => {
      expect(ReplicateWrapper.serverAddress).toBe('api.replicate.com');
      expect(ReplicateWrapper.serverPort).toBe(443);
    });
  });
});
