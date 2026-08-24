import { connect } from 'cloudflare:sockets'

// configurations
const UUID = '96c50e3a-5b87-49dd-bd20-03c7f2735e40' // vless UUID
const PROXY = 'ProxyIP.US.CMLiussss.net' // (optional) reverse proxy for CF websites. e.g. example.com
const LOG_LEVEL = 'none' // debug, info, error, none

// source code
const TIME_ZONE = 8 * 60 * 60 * 1000 // logging timestamp forwards 8 hours
const BUFFER_SIZE = 64 * 1024 // read/write buffer size in bytes
const UPLOAD_PACK_SIZE = 20 * 1024 // upload batching target size (borrowed from _worker.js)

function to_size(size) {
    const KiB = 1024
    const min = 1.1 * KiB
    let i = 0
    const SIZE_UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
    for (; i < SIZE_UNITS.length; i++) {
        if (size < min) {
            break
        }
        size = size / KiB
    }
    return `${Math.floor(size)} ${SIZE_UNITS[i]}`
}

// Unrolled 16-byte comparison, borrowed from GrainTCP `matchID`.
// Eliminates the per-byte loop overhead in hot paths.
function validate_uuid(id, u) {
    return (
        id[0] === u[0] &&
        id[1] === u[1] &&
        id[2] === u[2] &&
        id[3] === u[3] &&
        id[4] === u[4] &&
        id[5] === u[5] &&
        id[6] === u[6] &&
        id[7] === u[7] &&
        id[8] === u[8] &&
        id[9] === u[9] &&
        id[10] === u[10] &&
        id[11] === u[11] &&
        id[12] === u[12] &&
        id[13] === u[13] &&
        id[14] === u[14] &&
        id[15] === u[15]
    )
}

class Counter {
    #total

    constructor() {
        this.#total = 0
    }

    get() {
        return this.#total
    }

    add(size) {
        this.#total += size
    }
}

function concat_typed_arrays(first, ...args) {
    let len = first.length
    for (let a of args) {
        len += a.length
    }
    const r = new first.constructor(len)
    r.set(first, 0)
    len = first.length
    for (let a of args) {
        r.set(a, len)
        len += a.length
    }
    return r
}

class Logger {
    #id
    #level

    constructor(log_level) {
        this.#id = random_id()

        if (typeof log_level !== 'string') {
            log_level = 'info'
        }
        const levels = ['debug', 'info', 'error', 'none']
        this.#level = levels.indexOf(log_level.toLowerCase())
    }

    is_debug() {
        return this.#level < 1
    }

    debug(...args) {
        if (this.is_debug()) {
            this.#log(`[debug]`, ...args)
        }
    }

    info(...args) {
        if (this.#level < 2) {
            this.#log(`[info ]`, ...args)
        }
    }

    error(...args) {
        if (this.#level < 3) {
            this.#log(`[error]`, ...args)
        }
    }

    #log(prefix, ...args) {
        const now = new Date(Date.now() + TIME_ZONE).toISOString()
        console.log(now, prefix, `(${this.#id})`, ...args)
    }
}

function random_id() {
    const min = 10000
    const max = min * 10 - 1
    return Math.floor(Math.random() * (max - min + 1)) + min
}

function parse_uuid(uuid) {
    uuid = uuid.replaceAll('-', '')
    const r = []
    for (let index = 0; index < 16; index++) {
        const v = parseInt(uuid.substr(index * 2, 2), 16)
        r.push(v)
    }
    return r
}

function get_buffer(size) {
    return new Uint8Array(new ArrayBuffer(size || BUFFER_SIZE))
}

// enums
const ADDRESS_TYPE_IPV4 = 1
const ADDRESS_TYPE_URL = 2
const ADDRESS_TYPE_IPV6 = 3

async function read_vless_header(readable, uuid_str) {
    const reader = readable.getReader({ mode: 'byob' })

    let r = await reader.readAtLeast(1 + 16 + 1, get_buffer())
    let rlen = 0
    let idx = 0
    let cache = r.value
    rlen += r.value.length

    const version = cache[0]
    const id = cache.subarray(1, 1 + 16)
    const uuid = parse_uuid(uuid_str)
    if (!validate_uuid(id, uuid)) {
        return `invalid UUID`
    }
    const pb_len = cache[1 + 16]
    const addr_plus1 = 1 + 16 + 1 + pb_len + 1 + 2 + 1

    if (addr_plus1 + 1 > rlen) {
        if (r.done) {
            return `header too short`
        }
        idx = addr_plus1 + 1 - rlen
        r = await reader.readAtLeast(idx, get_buffer())
        rlen += r.value.length
        cache = concat_typed_arrays(cache, r.value)
    }

    const cmd = cache[1 + 16 + 1 + pb_len]
    if (cmd !== 1) {
        return `unsupported command: ${cmd}`
    }
    const port = (cache[addr_plus1 - 1 - 2] << 8) + cache[addr_plus1 - 1 - 1]
    const atype = cache[addr_plus1 - 1]
    let header_len = -1
    if (atype === ADDRESS_TYPE_IPV4) {
        header_len = addr_plus1 + 4
    } else if (atype === ADDRESS_TYPE_IPV6) {
        header_len = addr_plus1 + 16
    } else if (atype === ADDRESS_TYPE_URL) {
        header_len = addr_plus1 + 1 + cache[addr_plus1]
    }

    if (header_len < 0) {
        return 'read address type failed'
    }

    idx = header_len - rlen
    if (idx > 0) {
        if (r.done) {
            return `read address failed`
        }
        r = await reader.readAtLeast(idx, get_buffer())
        rlen += r.value.length
        cache = concat_typed_arrays(cache, r.value)
    }

    let hostname = ''
    idx = addr_plus1
    switch (atype) {
        case ADDRESS_TYPE_IPV4:
            hostname = cache.subarray(idx, idx + 4).join('.')
            break
        case ADDRESS_TYPE_URL:
            hostname = new TextDecoder().decode(
                cache.subarray(idx + 1, idx + 1 + cache[idx]),
            )
            break
        case ADDRESS_TYPE_IPV6:
            hostname = cache
                .subarray(idx, idx + 16)
                .reduce(
                    (s, b2, i2, a) =>
                        i2 % 2
                            ? s.concat(((a[i2 - 1] << 8) + b2).toString(16))
                            : s,
                    [],
                )
                .join(':')
            break
    }

    if (hostname.length < 1) {
        return 'failed to parse hostname'
    }

    // IMPORTANT: must use slice() (copy), NOT subarray() (view).
    // `cache` may be a BYOB buffer that gets detached by subsequent
    // reader.read() calls. A view would point to detached memory.
    const data = cache.slice(header_len)
    return {
        hostname,
        port,
        data,
        resp: new Uint8Array([version, 0]),
        reader,
        done: r.done,
    }
}

// Upload batching packer, borrowed from _worker.js `创建上行Grain合包流`.
// Batches small chunks into UPLOAD_PACK_SIZE (20KB) packets before
// writing to the remote, reducing writer.write() invocations and
// improving large file upload smoothness.
function create_upload_packer(writer, log, target_size = UPLOAD_PACK_SIZE) {
    const buf = new Uint8Array(target_size)
    let buf_len = 0
    let timer = null
    let in_flight = null
    let flush_chain = Promise.resolve()
    let pack_count = 0
    let direct_count = 0
    let buffered_count = 0

    const clear_timer = () => {
        if (timer) {
            clearTimeout(timer)
            timer = null
        }
    }

    const serial_write = async (chunk) => {
        if (in_flight) await in_flight
        in_flight = writer.write(chunk)
        try { await in_flight } finally { in_flight = null }
    }

    const flush = async () => {
        if (buf_len) {
            const chunk = buf.slice(0, buf_len)
            buf_len = 0
            if (log.is_debug()) {
                log.debug(`upload pack flush: ${to_size(chunk.byteLength)} (${++pack_count} packs)`)
            }
            await serial_write(chunk)
        }
    }

    const queue_flush = () => {
        flush_chain = flush_chain.then(() => flush()).catch(() => { })
    }

    const start_timer = () => {
        if (timer) return
        timer = setTimeout(() => {
            timer = null
            queue_flush()
        }, 1)
    }

    return {
        write: async (chunk) => {
            const data = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk)
            if (!data.byteLength) return
            if (data.byteLength >= target_size) {
                // large chunk: flush partial + send directly
                clear_timer()
                if (buf_len) await flush()
                if (log.is_debug()) {
                    log.debug(`upload direct: ${to_size(data.byteLength)} (${++direct_count} direct)`)
                }
                await serial_write(data)
                return
            }
            if (buf_len + data.byteLength >= target_size) {
                // merged reaches target: send combined
                const output = new Uint8Array(buf_len + data.byteLength)
                output.set(buf.subarray(0, buf_len), 0)
                output.set(data, buf_len)
                buf_len = 0
                clear_timer()
                if (log.is_debug()) {
                    log.debug(`upload pack merged: ${to_size(output.byteLength)} (${++pack_count} packs)`)
                }
                await serial_write(output)
            } else {
                // small chunk: buffer it, start 1ms flush timer
                buf.set(data, buf_len)
                buf_len += data.byteLength
                buffered_count++
                if (log.is_debug() && buffered_count % 100 === 0) {
                    log.debug(`upload buffered: ${buffered_count} chunks, ${to_size(buf_len)} pending`)
                }
                start_timer()
            }
        },
        end: async () => {
            clear_timer()
            try {
                await flush_chain
                await flush()
            } finally {
                if (log.is_debug()) {
                    log.debug(`upload packer done: ${pack_count} packs, ${direct_count} direct, ${buffered_count} buffered`)
                }
            }
        }
    }
}

// Upload data from client to remote.
// Uses the upload packer to batch small chunks into 20KB packets.
// Logs every 100 chunks to avoid to_size() CPU overhead in debug mode.
async function upload_to_remote(counter, log, writer, vless) {
    let chunk_count = 0
    const packer = create_upload_packer(writer, log)

    const write = async (data) => {
        if (!data || data.byteLength < 1) return
        counter.add(data.byteLength)
        if (log.is_debug() && ++chunk_count % 100 === 0) {
            log.debug(`upload ${to_size(counter.get())} total`)
        }
        await packer.write(data)
    }

    // write the residual payload from the header first
    await write(vless.data)

    while (!vless.done) {
        const r = await vless.reader.read(get_buffer())
        vless.done = r.done
        await write(r.value)
    }
    await packer.end()
}

function create_uploader(log, vless, writable) {
    const counter = new Counter()
    const done = new Promise((resolve, reject) => {
        const writer = writable.getWriter()
        upload_to_remote(counter, log, writer, vless)
            .then(resolve)
            .catch(reject)
            .finally(() => {
                // Close the upload writer as soon as upload completes.
                // This sends FIN to the remote, signalling that the
                // request body is complete. The remote will then start
                // sending its response (the download direction).
                writer
                    .close()
                    .then(() => log.debug(`upload writer closed`))
                    .catch((err) => log.debug(`upload writer error: ${err}`))
            })
    })

    return {
        counter,
        done,
    }
}

// Download data from remote back to client.
// Uses pipeTo() + TransformStream.
//
// IMPORTANT: pipeTo() is handled by the Cloudflare runtime, NOT by
// JS code. When fetch() returns, the Worker's JS environment is
// frozen, but pipeTo() continues to transfer data at the runtime
// level. A JS BYOB read loop would stop when the Worker freezes,
// causing the download to be interrupted.
//
// Each chunk is enqueued immediately (no batching) to preserve
// real-time delivery critical for the VLESS handshake.
function create_downloader(log, resp, remote_readable) {
    const counter = new Counter()
    let stream

    const done = new Promise((resolve, reject) => {
        let chunk_count = 0
        stream = new TransformStream(
            {
                start(controller) {
                    log.debug(`copy vless response`)
                    counter.add(resp.length)
                    controller.enqueue(resp)
                },
                transform(chunk, controller) {
                    counter.add(chunk.byteLength)
                    // Log every 100 chunks to avoid to_size() CPU
                    // overhead in debug mode. to_size() has a loop
                    // and division - calling it 51,200 times for a
                    // 200MB file (4KB chunks) consumes significant
                    // CPU time and triggers the CPU limit.
                    if (log.is_debug() && ++chunk_count % 100 === 0) {
                        log.debug(`download ${to_size(counter.get())} total`)
                    }
                    controller.enqueue(chunk)
                },
                cancel(reason) {
                    reject(`download cancelled: ${reason}`)
                },
            },
            null,
            new ByteLengthQueuingStrategy({ highWaterMark: 1024 * 1024 }),
        )
        remote_readable.pipeTo(stream.writable).catch(reject).finally(resolve)
    })

    return {
        readable: stream.readable,
        counter,
        done,
    }
}

async function connect_to_remote(log, vless, ...remotes) {
    const hostname = remotes.shift()
    if (!hostname || hostname.length < 1) {
        log.info('all attempts failed')
        return null
    }

    if (vless.hostname === hostname) {
        log.info(`direct connect [${vless.hostname}]:${vless.port}`)
    } else {
        log.info(`proxy [${vless.hostname}]:${vless.port} through ${hostname}`)
    }

    const retry = () => connect_to_remote(log, vless, ...remotes)
    let remote
    try {
        remote = connect({ hostname: hostname, port: vless.port })
        const info = await remote.opened
        log.debug(`connection opened:`, info)
    } catch (err) {
        log.error(`retry [${vless.hostname}] reason: ${err}`)
        return await retry()
    }

    const uploader = create_uploader(log, vless, remote.writable)
    const downloader = create_downloader(log, vless.resp, remote.readable)
    return {
        downloader,
        uploader,
    }
}

async function handle_xhttp_client(log, body, cfg) {
    const vless = await read_vless_header(body, cfg.UUID)
    if (typeof vless !== 'object' || !vless) {
        // to-do: drain connection
        log.error(`failed to parse vless header: ${vless}`)
        return null
    }

    const r = await connect_to_remote(log, vless, vless.hostname, cfg.PROXY)
    if (r === null) {
        log.error('create remote stream failed')
        return null
    }

    const connection_closed = new Promise((resolve, _) => {
        r.downloader.done
            .then(() => log.debug(`download complete`))
            .catch((err) => log.error(`download error: ${err}`))
            .finally(() => r.uploader.done)
            .then(() => log.debug(`upload complete`))
            .catch((err) => log.debug(`upload error: ${err}`))
            .finally(() => {
                const total_upload = to_size(r.uploader.counter.get())
                const total_download = to_size(r.downloader.counter.get())
                log.info(
                    `connection closed. uploaded: ${total_upload} downloaded: ${total_download}`,
                )
                resolve()
            })
    })

    return {
        readable: r.downloader.readable,
        closed: connection_closed,
    }
}

async function handle_post(request, cfg) {
    const log = new Logger(cfg.LOG_LEVEL)
    try {
        return await handle_xhttp_client(log, request.body, cfg)
    } catch (err) {
        log.error(`error: ${err}`)
    }
    return null
}

function create_config(url, uuid) {
    const config = JSON.parse(config_template)
    const vless = config['outbounds'][0]['settings']['vnext'][0]
    const stream = config['outbounds'][0]['streamSettings']

    // workers are TLS only!
    const host = url.hostname
    const path = url.pathname
    vless['address'] = host
    vless['users'][0]['id'] = uuid
    stream['xhttpSettings']['host'] = host
    stream['xhttpSettings']['path'] = path.endsWith('/') ? path : `${path}/`
    stream['tlsSettings']['serverName'] = host

    return JSON.stringify(config)
}

const config_template = `{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "agentin",
      "port": 1080,
      "listen": "127.0.0.1",
      "protocol": "socks",
      "settings": {}
    }
  ],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "localhost",
            "port": 443,
            "users": [
              {
                "id": "",
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "tag": "agentout",
      "streamSettings": {
        "network": "xhttp",
        "xhttpSettings": {
          "mode": "stream-one",
          "host": "localhost",
          "path": "/path/",
          "noGRPCHeader": false,
          "keepAlivePeriod": 300
        },
        "security": "tls",
        "tlsSettings": {
          "serverName": "localhost",
          "alpn": [
            "h2"
          ]
        }
      }
    }
  ]
}`

async function fetch(request, env, ctx) {
    const cfg = {
        UUID: env.UUID || UUID,
        PROXY: env.PROXY || PROXY,
        LOG_LEVEL: env.LOG_LEVEL || LOG_LEVEL,
    }

    if (!cfg.UUID) {
        return new Response(`Error: UUID is empty`)
    }

    if (request.method === 'POST') {
        const r = await handle_post(request, cfg)
        if (r) {
            // IMPORTANT: Do NOT use ctx.waitUntil(r.closed) here.
            // waitUntil() only keeps the Worker alive for a few seconds
            // after fetch() returns. For large file downloads that take
            // longer, the waitUntil task gets cancelled, which tears down
            // the entire connection. Just return the stream directly and
            // let Cloudflare's streaming response handle the long-lived
            // connection.
            return new Response(r.readable, {
                headers: {
                    'X-Accel-Buffering': 'no',
                    'Cache-Control': 'no-store',
                    Connection: 'Keep-Alive',
                    'User-Agent': 'Go-http-client/2.0',
                    'Content-Type': 'application/grpc',
                    // 'Content-Type': 'text/event-stream',
                    // 'Transfer-Encoding': 'chunked',
                },
            })
        }
    }

    if (request.method === 'GET') {
        const url = new URL(request.url)
        const items = [url.pathname, url.search]
        for (let item of items) {
            if (item.indexOf(`${cfg.UUID}`) >= 0) {
                const config = create_config(url, cfg.UUID)
                return new Response(config, {
                    headers: {
                        'Content-Type': 'application/json',
                    },
                })
            }
        }
    }
    return new Response(`Hello world!`)
}

export default {
    fetch,

    // for unit testing
    parse_uuid,
    validate_uuid,
    concat_typed_arrays,
}
