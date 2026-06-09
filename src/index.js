// XHTTP Worker - 可直接部署到 Cloudflare Workers
// 版本: 1.1.0

import { connect } from 'cloudflare:sockets';

// ============ 默认配置（可通过环境变量覆盖）============
const DEFAULT_CONFIG = {
  uuid: '96c50e3a-5b87-49dd-bd20-03c7f2735e40',
  fallbackAddress: 'ProxyIP.US.CMLiussss.net',
  maxConcurrent: 32,
  bufferSize: 128 * 1024,
  connectTimeoutMs: 5000,
  idleTimeoutMs: 45000,
  maxRetries: 2
};

let CONFIG = { ...DEFAULT_CONFIG };
let ACTIVE_CONNECTIONS = 0;

// ============ 地址类型常量 ============
const ADDRESS_TYPE_IPV4 = 1;
const ADDRESS_TYPE_URL = 2;
const ADDRESS_TYPE_IPV6 = 3;

// ============ 工具函数 ============

function xhttp_sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function validate_uuid_xhttp(id, uuid) {
  for (let index = 0; index < 16; index++) {
    if (id[index] !== uuid[index]) {
      return false;
    }
  }
  return true;
}

class XhttpCounter {
  #total

  constructor() {
    this.#total = 0;
  }

  get() {
    return this.#total;
  }

  add(size) {
    this.#total += size;
  }
}

function concat_typed_arrays(first, ...args) {
  let len = first.length;
  for (let a of args) {
    len += a.length;
  }
  const r = new first.constructor(len);
  r.set(first, 0);
  len = first.length;
  for (let a of args) {
    r.set(a, len);
    len += a.length;
  }
  return r;
}

function parse_uuid_xhttp(uuid) {
  uuid = uuid.replaceAll('-', '');
  const r = [];
  for (let index = 0; index < 16; index++) {
    const v = parseInt(uuid.substr(index * 2, 2), 16);
    r.push(v);
  }
  return r;
}

function get_xhttp_buffer(size) {
  return new Uint8Array(new ArrayBuffer(size || CONFIG.bufferSize));
}

// ============ XHTTP 协议头解析 ============

async function read_xhttp_header(readable, uuid_str) {
  const reader = readable.getReader({ mode: 'byob' });

  try {
    let r = await reader.readAtLeast(1 + 16 + 1, get_xhttp_buffer());
    let rlen = 0;
    let idx = 0;
    let cache = r.value;
    rlen += r.value.length;

    const version = cache[0];
    const id = cache.slice(1, 1 + 16);
    const uuid = parse_uuid_xhttp(uuid_str);
    if (!validate_uuid_xhttp(id, uuid)) {
      return `invalid UUID`;
    }
    const pb_len = cache[1 + 16];
    const addr_plus1 = 1 + 16 + 1 + pb_len + 1 + 2 + 1;

    if (addr_plus1 + 1 > rlen) {
      if (r.done) {
        return `header too short`;
      }
      idx = addr_plus1 + 1 - rlen;
      r = await reader.readAtLeast(idx, get_xhttp_buffer());
      rlen += r.value.length;
      cache = concat_typed_arrays(cache, r.value);
    }

    const cmd = cache[1 + 16 + 1 + pb_len];
    if (cmd !== 1) {
      return `unsupported command: ${cmd}`;
    }
    const port = (cache[addr_plus1 - 1 - 2] << 8) + cache[addr_plus1 - 1 - 1];
    const atype = cache[addr_plus1 - 1];
    let header_len = -1;
    if (atype === ADDRESS_TYPE_IPV4) {
      header_len = addr_plus1 + 4;
    } else if (atype === ADDRESS_TYPE_IPV6) {
      header_len = addr_plus1 + 16;
    } else if (atype === ADDRESS_TYPE_URL) {
      header_len = addr_plus1 + 1 + cache[addr_plus1];
    }

    if (header_len < 0) {
      return 'read address type failed';
    }

    idx = header_len - rlen;
    if (idx > 0) {
      if (r.done) {
        return `read address failed`;
      }
      r = await reader.readAtLeast(idx, get_xhttp_buffer());
      rlen += r.value.length;
      cache = concat_typed_arrays(cache, r.value);
    }

    let hostname = '';
    idx = addr_plus1;
    switch (atype) {
      case ADDRESS_TYPE_IPV4:
        hostname = cache.slice(idx, idx + 4).join('.');
        break;
      case ADDRESS_TYPE_URL:
        hostname = new TextDecoder().decode(
          cache.slice(idx + 1, idx + 1 + cache[idx]),
        );
        break;
      case ADDRESS_TYPE_IPV6:
        hostname = cache
          .slice(idx, idx + 16)
          .reduce(
            (s, b2, i2, a) =>
              i2 % 2
                ? s.concat(((a[i2 - 1] << 8) + b2).toString(16))
                : s,
            [],
          )
          .join(':');
        break;
    }

    if (hostname.length < 1) {
      return 'failed to parse hostname';
    }

    const data = cache.slice(header_len);
    return {
      hostname,
      port,
      data,
      resp: new Uint8Array([version, 0]),
      reader,
      done: r.done,
    };
  } catch (error) {
    try { reader.releaseLock(); } catch (_) {}
    throw error;
  }
}

// ============ 上传器：客户端 -> 远程 ============

async function upload_to_remote_xhttp(counter, writer, httpx) {
  async function inner_upload(d) {
    if (!d || d.length === 0) {
      return;
    }
    counter.add(d.length);
    try {
      await writer.write(d);
    } catch (error) {
      throw error;
    }
  }

  try {
    await inner_upload(httpx.data);
    let chunkCount = 0;
    while (!httpx.done) {
      const r = await httpx.reader.read(get_xhttp_buffer());
      if (r.done) break;
      await inner_upload(r.value);
      httpx.done = r.done;
      chunkCount++;
      if (chunkCount % 10 === 0) {
        await xhttp_sleep(0);
      }
      if (!r.value || r.value.length === 0) {
        await xhttp_sleep(2);
      }
    }
  } catch (error) {
    throw error;
  }
}

function create_xhttp_uploader(httpx, writable) {
  const counter = new XhttpCounter();
  const writer = writable.getWriter();

  const done = (async () => {
    try {
      await upload_to_remote_xhttp(counter, writer, httpx);
    } catch (error) {
      throw error;
    } finally {
      try {
        await writer.close();
      } catch (error) {}
    }
  })();

  return {
    counter,
    done,
    abort: () => {
      try { writer.abort(); } catch (_) {}
    }
  };
}

// ============ 下载器：远程 -> 客户端 ============

function create_xhttp_downloader(resp, remote_readable) {
  const counter = new XhttpCounter();
  let stream;

  const done = new Promise((resolve, reject) => {
    stream = new TransformStream(
      {
        start(controller) {
          counter.add(resp.length);
          controller.enqueue(resp);
        },
        transform(chunk, controller) {
          counter.add(chunk.length);
          controller.enqueue(chunk);
        },
        cancel(reason) {
          reject(`download cancelled: ${reason}`);
        },
      },
      null,
      new ByteLengthQueuingStrategy({ highWaterMark: CONFIG.bufferSize }),
    );

    let lastActivity = Date.now();
    const idleTimer = setInterval(() => {
      if (Date.now() - lastActivity > CONFIG.idleTimeoutMs) {
        try {
          stream.writable.abort?.('idle timeout');
        } catch (_) {}
        clearInterval(idleTimer);
        reject('idle timeout');
      }
    }, 5000);

    const reader = remote_readable.getReader();
    const writer = stream.writable.getWriter();

    ;(async () => {
      try {
        let chunkCount = 0;
        while (true) {
          const r = await reader.read();
          if (r.done) {
            break;
          }
          lastActivity = Date.now();
          await writer.write(r.value);
          chunkCount++;
          if (chunkCount % 5 === 0) {
            await xhttp_sleep(0);
          }
        }
        await writer.close();
        resolve();
      } catch (err) {
        reject(err);
      } finally {
        try {
          reader.releaseLock();
        } catch (_) {}
        try {
          writer.releaseLock();
        } catch (_) {}
        clearInterval(idleTimer);
      }
    })();
  });

  return {
    readable: stream.readable,
    counter,
    done,
    abort: () => {
      try { stream.readable.cancel(); } catch (_) {}
      try { stream.writable.abort(); } catch (_) {}
    }
  };
}

// ============ 远程连接管理 ============

async function connect_to_remote_xhttp(httpx, ...remotes) {
  let attempt = 0;
  let lastErr;

  const connectionList = [httpx.hostname, ...remotes.filter(r => r && r !== httpx.hostname)];

  for (const hostname of connectionList) {
    if (!hostname) continue;

    attempt = 0;
    while (attempt < CONFIG.maxRetries) {
      attempt++;
      try {
        const remote = connect({ hostname, port: httpx.port });
        const timeoutPromise = xhttp_sleep(CONFIG.connectTimeoutMs).then(() => {
          throw new Error('connect timeout');
        });

        await Promise.race([remote.opened, timeoutPromise]);

        const uploader = create_xhttp_uploader(httpx, remote.writable);
        const downloader = create_xhttp_downloader(httpx.resp, remote.readable);

        return {
          downloader,
          uploader,
          close: () => {
            try { remote.close(); } catch (_) {}
          }
        };
      } catch (err) {
        lastErr = err;
        if (attempt < CONFIG.maxRetries) {
          await xhttp_sleep(500 * attempt);
        }
      }
    }
  }

  return null;
}

// ============ XHTTP 客户端处理 ============

async function handle_xhttp_client(body, uuid) {
  if (ACTIVE_CONNECTIONS >= CONFIG.maxConcurrent) {
    return { error: 429 };
  }

  ACTIVE_CONNECTIONS++;

  let cleaned = false;
  const cleanup = () => {
    if (!cleaned) {
      ACTIVE_CONNECTIONS = Math.max(0, ACTIVE_CONNECTIONS - 1);
      cleaned = true;
    }
  };

  try {
    const httpx = await read_xhttp_header(body, uuid);
    if (typeof httpx !== 'object' || !httpx) {
      return null;
    }

    const fallbackList = [];
    if (CONFIG.fallbackAddress) {
      fallbackList.push(CONFIG.fallbackAddress);
    }

    const remoteConnection = await connect_to_remote_xhttp(httpx, ...fallbackList);
    if (remoteConnection === null) {
      return null;
    }

    const connectionClosed = Promise.race([
      (async () => {
        try {
          await remoteConnection.downloader.done;
        } catch (err) {}
      })(),
      (async () => {
        try {
          await remoteConnection.uploader.done;
        } catch (err) {}
      })(),
      xhttp_sleep(CONFIG.idleTimeoutMs).then(() => {})
    ]).finally(() => {
      try { remoteConnection.close(); } catch (_) {}
      try { remoteConnection.downloader.abort(); } catch (_) {}
      try { remoteConnection.uploader.abort(); } catch (_) {}
      cleanup();
    });

    return {
      readable: remoteConnection.downloader.readable,
      closed: connectionClosed
    };
  } catch (error) {
    cleanup();
    return null;
  }
}

// ============ 从环境变量加载配置 ============

function loadConfigFromEnv(env) {
  const cfg = { ...DEFAULT_CONFIG };
  if (env.UUID || env.U) cfg.uuid = env.UUID || env.U;
  if (env.FALLBACK || env.F) cfg.fallbackAddress = env.FALLBACK || env.F;
  if (env.MAX_CONCURRENT) cfg.maxConcurrent = parseInt(env.MAX_CONCURRENT);
  if (env.BUFFER_SIZE) cfg.bufferSize = parseInt(env.BUFFER_SIZE);
  if (env.CONNECT_TIMEOUT) cfg.connectTimeoutMs = parseInt(env.CONNECT_TIMEOUT);
  if (env.IDLE_TIMEOUT) cfg.idleTimeoutMs = parseInt(env.IDLE_TIMEOUT);
  if (env.MAX_RETRIES) cfg.maxRetries = parseInt(env.MAX_RETRIES);
  return cfg;
}

// ============ 主入口 ============

export default {
  async fetch(request, env, ctx) {
    CONFIG = loadConfigFromEnv(env);

    if (!CONFIG.uuid) {
      return new Response('UUID is required. Set UUID or U environment variable.', { status: 400 });
    }

    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    const r = await handle_xhttp_client(request.body, CONFIG.uuid);
    if (!r) {
      return new Response('Internal Server Error', { status: 500 });
    }

    if (r.error === 429) {
      return new Response('Too many connections', { status: 429 });
    }

    ctx.waitUntil(r.closed);
    return new Response(r.readable, {
      headers: {
        'X-Accel-Buffering': 'no',
        'Cache-Control': 'no-store',
        'Connection': 'keep-alive',
        'User-Agent': 'Go-http-client/2.0',
        'Content-Type': 'application/grpc',
      },
    });
  }
};
