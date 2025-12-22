import { connect } from 'cloudflare:sockets'

// -----------------------------------------------------------------------------
// 配置区域
// -----------------------------------------------------------------------------
const UUID_STR = '96c50e3a-5b87-49dd-bd20-03c7f2735e40'
const PROXY = 'ProxyIP.Multacom.CMLiussss.net'

// -----------------------------------------------------------------------------
// 全局预处理 (只运行一次)
// -----------------------------------------------------------------------------
// 将 UUID 预先转换为 Uint8Array，避免每次请求都解析
const UUID_BYTES = new Uint8Array(16)
for (let i = 0; i < 16; i++) {
    UUID_BYTES[i] = parseInt(UUID_STR.replace(/-/g, '').substr(i * 2, 2), 16)
}

// -----------------------------------------------------------------------------
// 工具函数
// -----------------------------------------------------------------------------

/**
 * 高效合并两个 Uint8Array
 */
function join_array(a, b) {
    const c = new Uint8Array(a.length + b.length)
    c.set(a)
    c.set(b, a.length)
    return c
}

/**
 * 验证 UUID (二进制比较，速度更快)
 */
function validate_uuid(id) {
    for (let i = 0; i < 16; i++) {
        if (id[i] !== UUID_BYTES[i]) return false
    }
    return true
}

// VLESS 协议常量
const VLESS_VERSION = 0
const CMD_TCP = 1
const ADDR_TYPE_IPV4 = 1
const ADDR_TYPE_DOMAIN = 2
const ADDR_TYPE_IPV6 = 3

/**
 * 解析 VLESS 头部
 * @param {ReadableStreamDefaultReader} reader 
 */
async function parse_vless_header(reader) {
    let buffer = new Uint8Array(0)
    
    // 1. 读取足够的数据以解析 UUID 和头部基础信息
    // 最小长度: Version(1) + UUID(16) + AddrLen(1) = 18 字节
    while (buffer.length < 18) {
        const { value, done } = await reader.read()
        if (done) return null // 连接过早关闭
        buffer = join_array(buffer, value)
    }

    // 校验 Version
    if (buffer[0] !== VLESS_VERSION) return { error: 'Invalid Version' }

    // 校验 UUID
    if (!validate_uuid(buffer.subarray(1, 17))) return { error: 'Invalid UUID' }

    // 获取附加信息长度
    const optLen = buffer[17]
    // 加上 命令(1) + 端口(2) + 地址类型(1) = 4 字节
    let currentNeed = 18 + optLen + 4 
    
    while (buffer.length < currentNeed) {
        const { value, done } = await reader.read()
        if (done) return null
        buffer = join_array(buffer, value)
    }

    const cmd = buffer[18 + optLen]
    if (cmd !== CMD_TCP) return { error: `Unsupported Command: ${cmd}` } // 暂只支持 TCP

    const portIndex = 18 + optLen + 1
    const port = (buffer[portIndex] << 8) | buffer[portIndex + 1]
    const addrType = buffer[portIndex + 2]
    const addrStartIndex = portIndex + 3

    let address = ''
    let bodyStartIndex = 0

    // 解析地址
    if (addrType === ADDR_TYPE_IPV4) {
        currentNeed = addrStartIndex + 4
        while (buffer.length < currentNeed) {
            const { value, done } = await reader.read()
            if (done) return null
            buffer = join_array(buffer, value)
        }
        address = buffer.subarray(addrStartIndex, addrStartIndex + 4).join('.')
        bodyStartIndex = addrStartIndex + 4
    } else if (addrType === ADDR_TYPE_DOMAIN) {
        // 还要读一个字节的域名长度
        if (buffer.length < addrStartIndex + 1) {
            const { value, done } = await reader.read()
            if (done) return null
            buffer = join_array(buffer, value)
        }
        const domainLen = buffer[addrStartIndex]
        currentNeed = addrStartIndex + 1 + domainLen
        while (buffer.length < currentNeed) {
            const { value, done } = await reader.read()
            if (done) return null
            buffer = join_array(buffer, value)
        }
        address = new TextDecoder().decode(buffer.subarray(addrStartIndex + 1, addrStartIndex + 1 + domainLen))
        bodyStartIndex = addrStartIndex + 1 + domainLen
    } else if (addrType === ADDR_TYPE_IPV6) {
        currentNeed = addrStartIndex + 16
        while (buffer.length < currentNeed) {
            const { value, done } = await reader.read()
            if (done) return null
            buffer = join_array(buffer, value)
        }
        // IPv6 解析简化处理 (实际连接用不上格式化后的 IPv6 字符串，connect 接受 hostname)
        // 这里简单处理为 hex 字符串，如果 connect 不支持 IPv6 字符串需要转换
        const ipv6 = buffer.subarray(addrStartIndex, addrStartIndex + 16)
        address = Array.from(ipv6).map(b => b.toString(16).padStart(2, '0')).join(':') // 简单占位
        address = `[${address.match(/.{1,4}/g).join(':')}]` // 修正标准格式
        bodyStartIndex = addrStartIndex + 16
    } else {
        return { error: `Unknown Address Type: ${addrType}` }
    }

    return {
        address,
        port,
        headData: buffer.subarray(bodyStartIndex), // 头部解析完后剩余的数据（Early Data）
        version: buffer[0]
    }
}

// -----------------------------------------------------------------------------
// 主逻辑
// -----------------------------------------------------------------------------

export default {
    async fetch(request, env, ctx) {
        // 读取环境变量配置
        const _UUID = env.UUID || UUID_STR
        const _PROXY = env.PROXY || PROXY
        
        // 1. 处理订阅配置 (GET)
        if (request.method === 'GET') {
            const url = new URL(request.url)
            if (url.pathname.includes(_UUID) || url.search.includes(_UUID)) {
                return new Response(generate_config(url, _UUID), {
                    headers: { 'Content-Type': 'application/json' }
                })
            }
            return new Response('Worker is running.', { status: 200 })
        }

        // 2. 仅处理 POST 请求 (xhttp/vless)
        if (request.method !== 'POST') {
            return new Response('Method Not Allowed', { status: 405 })
        }

        try {
            // 获取请求体的 Reader (BYOB 模式在这里意义不大，因为 parse 需要 buffer 拼接)
            const requestReader = request.body.getReader()
            
            // 解析 VLESS 头部
            const vless = await parse_vless_header(requestReader)
            if (!vless) return new Response('Header too short', { status: 400 })
            if (vless.error) {
                // 如果解析失败，释放锁并返回错误
                requestReader.releaseLock() 
                return new Response(vless.error, { status: 400 })
            }

            // 连接目标服务器 (优先直连，失败或配置了 Proxy 则走 Proxy - 这里简化为原逻辑的直接连接)
            // 原代码逻辑：const hostname = remotes.shift() ... 这里直接连解析出的地址
            // 如果需要 Proxy 逻辑，可以在 connect 中传入 proxyIP
            let remoteSocket
            try {
                // 尝试连接目标
                // 注意：Cloudflare connect() 不支持所有的 IP 连接，部分端口被封锁
                remoteSocket = connect({ hostname: vless.address, port: vless.port })
                // 等待连接建立，如果失败会抛出异常
                await remoteSocket.opened
            } catch (e) {
                // 如果直连失败且有 Proxy，可以在这里尝试连接 Proxy (略，保持极速版精简)
                // 如需回退逻辑：连接 _PROXY, 并在握手后发送 connect 请求
                console.error(`Connect failed to ${vless.address}:${vless.port}`, e)
                requestReader.releaseLock()
                return new Response('Connect Failed', { status: 502 })
            }

            // -------------------------------------------------------------------------
            // 极速核心：双向流转发
            // -------------------------------------------------------------------------

            // 1. 上行 (Client -> Remote)
            // 因为我们已经读取了 header 导致 stream 被锁定，且读出了一部分 data (headData)
            // 我们需要手动将 headData 写入，然后将剩余的流 pipe 过去
            const remoteWriter = remoteSocket.writable.getWriter()
            
            // 启动上行转发循环 (由于 requestReader 已经被获取，无法直接 pipeTo，只能手动 pump)
            // 使用 waitUntil 防止 Worker 在响应返回后立即冻结
            ctx.waitUntil((async () => {
                try {
                    // 写入头部携带的 Early Data
                    if (vless.headData.length > 0) {
                        await remoteWriter.write(vless.headData)
                    }
                    
                    // 循环读取并写入
                    while (true) {
                        const { done, value } = await requestReader.read()
                        if (done) break
                        await remoteWriter.write(value)
                    }
                } catch (e) {
                    // console.error('Upload error:', e)
                } finally {
                    remoteWriter.close()
                    // requestReader 不需要 close，因为它来自 request
                }
            })())

            // 2. 下行 (Remote -> Client)
            // 这是优化的重点：直接返回 ReadableStream，让 Cloudflare 内部处理零拷贝传输
            // 构造 VLESS 响应头 (Version + 0)
            const responseHeader = new Uint8Array([vless.version, 0])
            
            // 使用 TransformStream 将响应头和远程数据拼接
            const { readable: clientReadable, writable: clientWritable } = new TransformStream()
            const clientWriter = clientWritable.getWriter()
            
            // 异步启动下行管道
            ctx.waitUntil((async () => {
                try {
                    // 先发响应头
                    await clientWriter.write(responseHeader)
                    clientWriter.releaseLock() // 释放锁以便 pipeTo 使用
                    
                    // 直接对接流，由底层运行时处理
                    await remoteSocket.readable.pipeTo(clientWritable) 
                } catch (e) {
                    // console.error('Download error:', e)
                }
            })())

            return new Response(clientReadable, {
                status: 200,
                headers: {
                    'Connection': 'keep-alive',
                    'Content-Type': 'application/octet-stream', // 标准流类型
                    'X-Accel-Buffering': 'no' // 禁用 Nginx 缓冲
                }
            })

        } catch (err) {
            return new Response(err.message, { status: 500 })
        }
    }
}

// -----------------------------------------------------------------------------
// 辅助：生成配置 JSON
// -----------------------------------------------------------------------------
function generate_config(url, uuid) {
    const host = url.hostname
    const path = url.pathname.endsWith('/') ? url.pathname : `${url.pathname}/`
    
    // 简化模板
    const config = {
        "log": { "loglevel": "warning" },
        "inbounds": [{ "port": 1080, "listen": "127.0.0.1", "protocol": "socks", "settings": {} }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": 443,
                    "users": [{ "id": uuid, "encryption": "none" }]
                }]
            },
            "streamSettings": {
                "network": "xhttp", // 对应 Xray 1.8.24+ 的 xhttp (HTTP/2)
                "xhttpSettings": {
                    "mode": "stream-one", // 或 stream-up
                    "host": host,
                    "path": path,
                },
                "security": "tls",
                "tlsSettings": { "serverName": host }
            }
        }]
    }
    return JSON.stringify(config, null, 2)
}
