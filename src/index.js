import { connect } from 'cloudflare:sockets'

// configurations
const UUID = '96c50e3a-5b87-49dd-bd20-03c7f2735e40' // vless UUID
const PROXY = 'ProxyIP.US.CMLiussss.net' // (optional) reverse proxy for CF websites. e.g. example.com
const LOG_LEVEL = 'none' // debug, info, error, none — set to 'debug' temporarily for diagnosis

// source code
const TIME_ZONE = 8 * 60 * 60 * 1000 // logging timestamp forwards 8 hours
const BUFFER_SIZE = 64 * 1024 // read/write buffer size in bytes
const UPLOAD_PACK_TARGET = 20 * 1024 // upload pack target size in bytes; small chunks are merged up to this size before a single writer.write
const UPLOAD_PACK_FLUSH_MS = 1 // max latency (ms) to hold a partial buffer before forcing a flush

// XHTTP obfs padding: HPACK Huffman code lengths (0x00-0xFF)
const HPACK_HUFFMAN_CODE_LEN = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
    5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
    13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
    15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
    6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
    30
]

const XHTTP_BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

// Derive padding header name and query key from UUID
function get_xhttp_padding_ident(uuid_str) {
    // uuid_str: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' (36 chars)
    // header: uuid[1:7] (6 chars), key: '_' + uuid[25:31] (6 chars)
    return {
        header: uuid_str.slice(1, 7),
        key: '_' + uuid_str.slice(25, 31),
    }
}

// Calculate HPACK Huffman encoded byte length of a string
function calc_hpack_huffman_bytes(str) {
    const bytes = new TextEncoder().encode(str)
    let total_bits = 0
    for (let i = 0; i < bytes.length; i++) {
        total_bits += HPACK_HUFFMAN_CODE_LEN[bytes[i]]
    }
    return Math.ceil(total_bits / 8)
}

// Extract padding value from request (supports queryInHeader placement)
function extract_xhttp_padding(request, header_name, key_name) {
    const header_val = request.headers.get(header_name)
    if (header_val) {
        try {
            // queryInHeader: header value is a URL, extract query param
            const parsed = new URL(header_val, 'https://x.invalid')
            const query_val = parsed.searchParams.get(key_name)
            if (query_val) {
                console.log(`[xhttp-obfs] extracted from header URL query: key='${key_name}', padding_len=${query_val.length}`)
                return query_val
            }
        } catch (e) { }
        console.log(`[xhttp-obfs] using direct header value: header='${header_name}', padding_len=${header_val.length}`)
        return header_val // direct header value
    }
    // fallback: request URL query string
    const url = new URL(request.url)
    const query_padding = url.searchParams.get(key_name) || ''
    if (query_padding) {
        console.log(`[xhttp-obfs] extracted from URL query: key='${key_name}', padding_len=${query_padding.length}`)
    }
    return query_padding
}

// Validate padding: HPACK Huffman length in [98, 1002]
function validate_xhttp_padding(request, header_name, key_name) {
    const padding = extract_xhttp_padding(request, header_name, key_name)
    if (!padding) {
        console.log(`[xhttp-obfs] no padding present -> PASS (allow empty)`)
        return true // no padding = pass
    }
    const huff_len = calc_hpack_huffman_bytes(padding)
    const ok = huff_len >= 98 && huff_len <= 1002
    console.log(`[xhttp-obfs] validation: huffman_len=${huff_len} bytes, range=[98,1002] -> ${ok ? 'PASS' : 'FAIL'}`)
    if (!ok) {
        console.log(`[xhttp-obfs] FAIL detail: padding_chars=${padding.length}, first_50='${padding.slice(0, 50)}...'`)n    }
    return ok
}

// Generate random Base62 padding string
function gen_xhttp_padding_str(len) {
    let out = ''
    for (let i = 0; i < len; i++) {
        out += XHTTP_BASE62[Math.floor(Math.random() * 62)]
    }
    return out
}

// Build response headers with obfs padding (queryInHeader format)
function build_xhttp_response_headers(uuid_str) {
    const { header, key } = get_xhttp_padding_ident(uuid_str)
    const padding = gen_xhttp_padding_str(100 + Math.floor(Math.random() * 901)) // 100-1000
    const huff_len = calc_hpack_huffman_bytes(padding)
    console.log(`[xhttp-obfs] response: header='${header}', key='${key}', padding_chars=${padding.length}, huffman=${huff_len} bytes`)
    const url = new URL('https://x.invalid/')
    url.searchParams.set(key, padding)
    const headers = {
        'X-Accel-Buffering': 'no',
        'Cache-Control': 'no-store',
        Connection: 'Keep-Alive',
        'User-Agent': 'Go-http-client/2.0',
        'Content-Type': 'application/grpc',
    }
    headers[header] = url.toString()
    return headers
}

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

    get id() {
        return this.#id
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

// Upload pack stream: merges small chunks into ~UPLOAD_PACK_TARGET-byte writes
// before pushing them to the remote writer. Large chunks bypass the buffer.
// A 1ms timer forces a flush so low-throughput clients don't stall the
// downstream (download) direction.
//
// IMPORTANT: holds the OUTER writer directly (no IdentityTransformStream).
// The previous version created an internal stream and fed it into another
// writer, which left the data buffered inside an unread stream and never
// reached the remote socket (hang on end()).
//
// Modeled after `创建上行Grain合包流` from 新建文本文档.js, simplified for the
// single VLESS xhttp upload path.
function create_upload_pack_stream(writer, id = '?', target = UPLOAD_PACK_TARGET, flush_ms = UPLOAD_PACK_FLUSH_MS) {
    const buffer = new Uint8Array(target)
    let buffered = 0
    let timer = null
    let in_flight = null
    let closed = false
    let write_count = 0
    let byte_count = 0
    let timer_count = 0
    let merge_count = 0
    let direct_count = 0

    // Diagnostic helper: timestamped, id-tagged line in the same format as Logger.
    const log_pack = (msg) => {
        console.log(
            new Date(Date.now() + TIME_ZONE).toISOString(),
            '[debug]',
            `(${id})`,
            'pack',
            msg,
        )
    }

    const clear_timer = () => {
        if (timer) {
            clearTimeout(timer)
            timer = null
        }
    }

    // Serialize writes to the underlying writer so concurrent write() callers
    // never interleave bytes on the wire.
    const serial_write = async (chunk, branch) => {
        if (closed) throw new Error('pack stream closed')
        if (in_flight) await in_flight
        if (closed) throw new Error('pack stream closed')
        const p = writer.write(chunk)
        in_flight = p
        try {
            await p
        } finally {
            if (in_flight === p) in_flight = null
        }
        // [A] write completed
        log_pack(`write: ${chunk.byteLength}B (branch=${branch})`)
    }

    const flush = async (branch = 'timer') => {
        if (buffered) {
            const chunk = buffer.slice(0, buffered)
            buffered = 0
            await serial_write(chunk, branch)
        }
    }

    const start_timer = () => {
        if (timer || closed) return
        timer = setTimeout(() => {
            timer = null
            timer_count++
            // [B] timer fired
            log_pack(`timer: buffered=${buffered}B`)
            if (buffered) {
                flush('timer').catch((err) => {
                    console.log(
                        new Date(Date.now() + TIME_ZONE).toISOString(),
                        '[error]',
                        `(${id})`,
                        'pack timer flush failed:',
                        err?.message || err,
                    )
                })
            }
        }, flush_ms)
    }

    return {
        write: async (chunk) => {
            if (closed) throw new Error('pack stream closed')
            const data = chunk instanceof Uint8Array
                ? chunk
                : (chunk instanceof ArrayBuffer
                    ? new Uint8Array(chunk)
                    : (ArrayBuffer.isView(chunk)
                        ? new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength)
                        : new Uint8Array(chunk || 0)))
            // [D] write entry: incoming chunk size
            log_pack(`write-in: chunkSize=${data.byteLength}B`)
            if (!data.byteLength) return
            if (data.byteLength >= target) {
                clear_timer()
                if (buffered) await flush('merge')
                write_count++
                direct_count++
                byte_count += data.byteLength
                log_pack(`branch: direct (${data.byteLength}B >= target ${target}B)`)
                await serial_write(data, 'direct')
                return
            }
            if (buffered + data.byteLength >= target) {
                merge_count++
                const output = new Uint8Array(buffered + data.byteLength)
                output.set(buffer.subarray(0, buffered), 0)
                output.set(data, buffered)
                const totalSize = output.byteLength
                buffered = 0
                clear_timer()
                write_count++
                byte_count += totalSize
                // [C-merge] merge branch triggered
                log_pack(`branch: merge (${totalSize}B = buffered ${totalSize - data.byteLength}B + new ${data.byteLength}B)`)
                await serial_write(output, 'merge')
            } else {
                buffer.set(data, buffered)
                buffered += data.byteLength
                // [C-buffer] buffer branch triggered
                log_pack(`branch: buffer (now ${buffered}B / target ${target}B)`)
                start_timer()
            }
        },
        end: async () => {
            if (closed) return
            closed = true
            clear_timer()
            try {
                await flush('end')
                await writer.close()
            } finally {
                try {
                    writer.releaseLock()
                } catch (e) { }
            }
            // [E] final stats
            log_pack(
                `end: writes=${write_count} bytes=${byte_count} merges=${merge_count} ` +
                `direct=${direct_count} timers=${timer_count} residual_buffered=${buffered}B`,
            )
        },
        // diagnostic snapshot
        _stats: () => ({ write_count, byte_count, timer_count, merge_count, direct_count, buffered, closed }),
    }
}

// Upload data from client to remote.
// Reads from the VLESS body stream and feeds chunks through the pack stream,
// which coalesces small writes into ~20KB packets before hitting the remote
// socket. Reduces syscall count and CPU overhead on large uploads.
// Logs every 100 chunks to avoid to_size() CPU overhead in debug mode.
async function upload_to_remote(counter, log, writer, vless) {
    let chunk_count = 0
    log.debug(`upload start: vless.data=${vless.data ? vless.data.byteLength : 0}B, vless.done=${vless.done}`)
    const pack = create_upload_pack_stream(writer, log.id)

    const write = async (data) => {
        if (!data || data.byteLength < 1) return
        counter.add(data.byteLength)
        if (log.is_debug() && ++chunk_count % 100 === 0) {
            log.debug(`upload ${to_size(counter.get())} total`)
        }
        await pack.write(data)
    }

    // write the residual payload from the header first
    if (vless.data && vless.data.byteLength > 0) {
        log.debug(`upload header residual: ${vless.data.byteLength}B`)
        await write(vless.data)
    }

    let read_iter = 0
    while (!vless.done) {
        read_iter++
        log.debug(`upload read #${read_iter} ...`)
        const r = await vless.reader.read(get_buffer())
        vless.done = r.done
        log.debug(`upload read #${read_iter} done=${r.done}, value=${r.value ? r.value.byteLength : 0}B`)
        if (r.value && r.value.byteLength > 0) {
            await write(r.value)
        }
        if (r.done) break
    }

    log.debug(`upload draining pack: ${JSON.stringify(pack._stats())}`)
    // Flush any buffered bytes and close the underlying writer. This sends
    // FIN to the remote, signalling the request body is complete; the remote
    // will then start sending its response (the download direction).
    await pack.end()
    log.debug(`upload end: stats=${JSON.stringify(pack._stats())}, total=${to_size(counter.get())}`)
}

function create_uploader(log, vless, writable) {
    const counter = new Counter()
    const done = new Promise((resolve, reject) => {
        const writer = writable.getWriter()
        log.debug(`upload writer acquired`)
        upload_to_remote(counter, log, writer, vless)
            .then((v) => {
                log.debug(`upload_to_remote resolved`)
                resolve(v)
            })
            .catch((err) => {
                log.error(`upload_to_remote rejected: ${err?.message || err}`)
                reject(err)
            })
            .finally(() => {
                // pack.end() inside upload_to_remote has already flushed the
                // buffer and closed the writer on the success path. Here we
                // only defensively close on the failure path (where pack.end()
                // did not run) and always release the lock.
                try {
                    writer.close()
                } catch (e) {
                    log.debug(`upload writer close error (ignored): ${e?.message || e}`)
                }
                try {
                    writer.releaseLock()
                } catch (e) {
                    log.debug(`upload writer releaseLock error (ignored): ${e?.message || e}`)
                }
                log.debug(`upload writer closed (total uploaded ${to_size(counter.get())})`)
            })
    })

    return {
        counter,
        done,
    }
}

// Download data from remote back to client.
// Architecture:
//   remote_readable ──pipeTo──▶ head (TransformStream, only start() injects resp) ──pipeTo──▶ pass (IdentityTransformStream, zero JS overhead)
//
// `head` exists only to enqueue the VLESS response header
// (`[version, 0]`) before any body bytes; its transform callback is
// omitted so every chunk passes through with no JS work.
// `pass` is a true IdentityTransformStream — the final readable that
// the HTTP response body reads from. Each body chunk traverses only
// runtime-native pipeTo hops, preserving real-time delivery critical
// for the VLESS handshake.
//
// IMPORTANT: pipeTo() is handled by the Cloudflare runtime, NOT by
// JS code. When fetch() returns, the Worker's JS environment is
// frozen, but pipeTo() continues to transfer data at the runtime
// level. A JS BYOB read loop would stop when the Worker freezes,
// causing the download to be interrupted.
//
// counter.add() on the per-chunk hot path is intentionally omitted
// to minimize CPU cost; counter.get() reflects only resp.length
// (the 2-byte VLESS response header) plus a one-time add of the
// head's bytes (resp.length only — body bytes are not counted).
function create_downloader(log, resp, remote_readable) {
    const counter = new Counter()
    counter.add(resp.length)

    // head: injects resp via start(); everything else is passthrough.
    const head = new TransformStream(
        {
            start(controller) {
                log.debug(`copy vless response`)
                controller.enqueue(resp)
            },
        },
        null,
        new ByteLengthQueuingStrategy({ highWaterMark: 1024 * 1024 }),
    )

    // pass: true IdentityTransformStream — the runtime handles every
    // chunk natively with no JS callback.
    const pass = typeof IdentityTransformStream !== 'undefined'
        ? new IdentityTransformStream()
        : new TransformStream()

    // Wire the two stages. Both pipeTo calls return promises we
    // intentionally let fire-and-forget; combined failure is observed
    // via the response stream's own error propagation.
    const done = Promise.all([
        remote_readable.pipeTo(head.writable).catch(() => { }),
        head.readable.pipeTo(pass.writable).catch(() => { }),
    ])

    return {
        readable: pass.readable,
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
                // counter.add() on the per-chunk hot path is intentionally
                // omitted to minimize CPU cost; total_download reflects only
                // the VLESS response header size (2 bytes).
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
        // XHTTP obfs padding validation
        const { header, key } = get_xhttp_padding_ident(cfg.UUID)
        log.debug(`xhttp-obfs: derived header='${header}', key='${key}'`)
        
        // Extract padding for detailed logging
        const extracted = extract_xhttp_padding(request, header, key)
        if (extracted) {
            const huffLen = calc_hpack_huffman_bytes(extracted)
            log.debug(`xhttp-obfs: extracted padding len=${extracted.length} chars, huffman=${huffLen} bytes`)
        } else {
            log.debug(`xhttp-obfs: no padding found in request`)
        }
        
        if (!validate_xhttp_padding(request, header, key)) {
            log.error(`xhttp-obfs: validation FAILED (header='${header}', key='${key}')`)
            return null
        }
        log.debug(`xhttp-obfs: validation PASSED`)
        
        const result = await handle_xhttp_client(log, request.body, cfg)
        if (result) {
            // Attach response headers with obfs padding
            result.response_headers = build_xhttp_response_headers(cfg.UUID)
            const { header: rh, key: rk } = get_xhttp_padding_ident(cfg.UUID)
            log.debug(`xhttp-obfs: response header '${rh}' set with queryInHeader padding`)
        }
        return result
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

    // inject xPadding obfs config (extra)
    console.log(`[xhttp-obfs] subscription: header='${header}', key='${key}' -> extra injected`)
    const { header, key } = get_xhttp_padding_ident(uuid)
    stream['xhttpSettings']['extra'] = {
        xPaddingObfsMode: true,
        xPaddingMethod: 'tokenish',
        xPaddingPlacement: 'queryInHeader',
        xPaddingHeader: header,
        xPaddingKey: key
    }

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
                headers: r.response_headers || {
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
