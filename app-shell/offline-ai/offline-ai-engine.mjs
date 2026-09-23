import { env, pipeline } from './vendor/transformers.web.min.js';

const MODEL_ID = 'malguard-qwen2.5-0.5b-instruct';

env.allowRemoteModels = false;
env.allowLocalModels = true;
env.localModelPath = '/models/';
if (env.backends?.onnx?.wasm) {
  env.backends.onnx.wasm.wasmPaths = '/assets/offline-ai/vendor/';
  env.backends.onnx.wasm.numThreads = 1;
}

let generatorPromise = null;

function normalizeMessages(input) {
  const list = Array.isArray(input) ? input : [];
  const messages = list
    .filter(item => item && (item.role === 'user' || item.role === 'assistant' || item.role === 'system'))
    .map(item => ({
      role: item.role,
      content: String(item.text ?? item.content ?? '').slice(0, 20000)
    }))
    .filter(item => item.content.trim());

  if (!messages.some(item => item.role === 'system')) {
    messages.unshift({
      role: 'system',
      content: 'You are MalGuard AI running fully offline. Answer in the user language. Stay defensive for cybersecurity. Never claim fresh web data, cloud access, or a tool execution that did not happen. If current internet information is required, state that offline mode cannot retrieve it.'
    });
  }
  return messages.slice(-12);
}

async function getGenerator() {
  if (!generatorPromise) {
    generatorPromise = pipeline('text-generation', MODEL_ID, {
      dtype: 'q4',
      device: navigator.gpu ? 'webgpu' : 'wasm'
    });
  }
  return generatorPromise;
}

function extractText(output) {
  const generated = output?.[0]?.generated_text;
  if (Array.isArray(generated)) {
    const last = generated[generated.length - 1];
    return typeof last?.content === 'string' ? last.content.trim() : '';
  }
  return typeof generated === 'string' ? generated.trim() : '';
}

export async function offlineChat(payload = {}) {
  const generator = await getGenerator();
  const messages = normalizeMessages(payload.messages);
  if (!messages.some(item => item.role === 'user')) {
    throw new Error('A user message is required');
  }

  const output = await generator(messages, {
    max_new_tokens: 320,
    do_sample: false
  });
  const text = extractText(output);
  if (!text) throw new Error('Local model returned no text');

  return {
    text,
    model: 'Qwen2.5 0.5B · Offline',
    provider: 'local',
    build: 'offline-local-v1',
    webSearchUsed: false,
    fallbackUsed: false,
    offline: true
  };
}
