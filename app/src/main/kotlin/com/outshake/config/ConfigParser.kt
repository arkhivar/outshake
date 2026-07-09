package com.outshake.config

import org.yaml.snakeyaml.Yaml
import java.util.Base64

/**
 * Parses Outline-compatible access keys into a normalized [ParsedConfig].
 *
 * Everything here is pure (no Android / no network) so it is fully unit-testable.
 * The network fetch for ssconf:// lives in the caller; use [ssConfToUrl] to resolve the
 * URL and [parseDynamicBody] to parse the fetched body.
 */
object ConfigParser {

    fun isSsConf(key: String): Boolean = key.trim().startsWith("ssconf://", ignoreCase = true)
    fun isStatic(key: String): Boolean = key.trim().startsWith("ss://", ignoreCase = true)

    // ---------------------------------------------------------------------
    // Static ss:// keys
    // ---------------------------------------------------------------------

    /** Parse a static `ss://` key (both SIP002 and legacy base64 blob forms). */
    fun parseStatic(rawKey: String): ParsedConfig {
        val key = rawKey.trim()
        if (!isStatic(key)) throw ConfigException("Not an ss:// key")
        var body = key.substring("ss://".length)

        // Fragment = human name (URL-encoded).
        var name = ""
        val hash = body.indexOf('#')
        if (hash >= 0) {
            name = urlDecode(body.substring(hash + 1))
            body = body.substring(0, hash)
        }
        if (body.isEmpty()) throw ConfigException("Empty ss:// key")

        return if (body.contains('@')) {
            parseSip002(body, name)
        } else {
            parseLegacy(body, name)
        }
    }

    /** SIP002: ss://base64(method:pass)@host:port/?plugin&prefix ... or ss://method:pass@host:port */
    private fun parseSip002(body: String, name: String): ParsedConfig {
        val at = body.lastIndexOf('@')
        val userInfoRaw = body.substring(0, at)
        var hostPart = body.substring(at + 1)

        // Strip and capture query (may hold the prefix).
        var query = ""
        val q = hostPart.indexOf('?')
        if (q >= 0) {
            query = hostPart.substring(q + 1)
            hostPart = hostPart.substring(0, q)
        }
        // Strip any trailing path (e.g. "/").
        val slash = hostPart.indexOf('/')
        if (slash >= 0) hostPart = hostPart.substring(0, slash)

        val methodPassword = decodeUserInfo(userInfoRaw)
        val colon = methodPassword.indexOf(':')
        if (colon < 0) throw ConfigException("Malformed ss:// user info (expected method:password)")
        val method = methodPassword.substring(0, colon)
        val password = methodPassword.substring(colon + 1)

        val (host, port) = splitHostPort(hostPart)
        val cipher = resolveCipher(method)
        val prefix = extractPrefixFromQuery(query)
        return ParsedConfig(displayName(name, host, port), TransportConfig(host, port, cipher, password, prefix))
    }

    /** Legacy: ss://base64(method:password@host:port) */
    private fun parseLegacy(body: String, name: String): ParsedConfig {
        val decoded = try {
            String(base64Decode(body), Charsets.UTF_8)
        } catch (e: Exception) {
            throw ConfigException("Malformed ss:// key (invalid base64)")
        }
        val at = decoded.lastIndexOf('@')
        if (at < 0) throw ConfigException("Malformed ss:// key (missing '@')")
        val methodPassword = decoded.substring(0, at)
        val hostPart = decoded.substring(at + 1)
        val colon = methodPassword.indexOf(':')
        if (colon < 0) throw ConfigException("Malformed ss:// key (expected method:password)")
        val method = methodPassword.substring(0, colon)
        val password = methodPassword.substring(colon + 1)
        val (host, port) = splitHostPort(hostPart)
        val cipher = resolveCipher(method)
        return ParsedConfig(displayName(name, host, port), TransportConfig(host, port, cipher, password, null))
    }

    private fun decodeUserInfo(userInfo: String): String {
        // SIP002 mandates base64(method:password); tolerate a literal method:password too.
        return try {
            val decoded = String(base64Decode(userInfo), Charsets.UTF_8)
            if (decoded.contains(':')) decoded else urlDecode(userInfo)
        } catch (e: Exception) {
            urlDecode(userInfo)
        }
    }

    // ---------------------------------------------------------------------
    // Dynamic ssconf:// keys
    // ---------------------------------------------------------------------

    /** Resolve an `ssconf://` key to the https URL that must be fetched. */
    fun ssConfToUrl(rawKey: String): String {
        val key = rawKey.trim()
        if (!isSsConf(key)) throw ConfigException("Not an ssconf:// key")
        var rest = key.substring("ssconf://".length)
        // Drop a fragment if present (name hint) — not part of the URL.
        val hash = rest.indexOf('#')
        if (hash >= 0) rest = rest.substring(0, hash)
        if (rest.isEmpty()) throw ConfigException("Empty ssconf:// key")
        return "https://$rest"
    }

    /** Optional display-name hint from the ssconf fragment. */
    fun ssConfName(rawKey: String): String {
        val hash = rawKey.indexOf('#')
        return if (hash >= 0) urlDecode(rawKey.substring(hash + 1)) else ""
    }

    /**
     * Parse the body fetched from an ssconf URL. Supports: an `ss://` line, a JSON object,
     * or a YAML document (including the newer Outline transport graph).
     */
    fun parseDynamicBody(body: String, nameHint: String = ""): ParsedConfig {
        val text = body.trim()
        if (text.isEmpty()) throw ConfigException("Dynamic config was empty")

        if (text.startsWith("ss://", ignoreCase = true)) {
            val line = text.lineSequence().first { it.isNotBlank() }.trim()
            val parsed = parseStatic(line)
            return if (nameHint.isNotBlank()) parsed.copy(name = nameHint) else parsed
        }

        val loaded: Any = try {
            Yaml().load<Any>(text)
        } catch (e: Exception) {
            throw ConfigException("Dynamic config is not valid JSON/YAML: ${e.message}")
        } ?: throw ConfigException("Dynamic config was empty")

        if (loaded !is Map<*, *>) {
            throw ConfigException("Dynamic config must be a JSON/YAML object")
        }
        return normalizeMap(loaded, nameHint)
    }

    @Suppress("UNCHECKED_CAST")
    private fun normalizeMap(root: Map<*, *>, nameHint: String): ParsedConfig {
        // SIP008-style { "servers": [ {...} ] } — use the first server.
        (root["servers"] as? List<*>)?.let { servers ->
            val first = servers.firstOrNull() as? Map<*, *>
                ?: throw ConfigException("Dynamic config 'servers' list is empty")
            return normalizeMap(first, nameHint)
        }

        // Newer Outline transport graph: { transport: { $type: tcpudp, tcp: {...}, udp: {...} } }
        val transport = root["transport"]
        val node: Map<*, *> = when (transport) {
            is Map<*, *> -> resolveTransportGraph(transport)
            is String -> throw ConfigException("Inline transport strings are not supported")
            else -> root
        }

        // If the node itself declares a transport type, it must be shadowsocks.
        val type = (node["\$type"] ?: node["type"])?.toString()
        if (type != null && !type.equals("shadowsocks", ignoreCase = true)) {
            throw ConfigException("Unsupported transport type: '$type' (only shadowsocks is supported)")
        }

        val method = firstString(node, "method", "cipher")
            ?: throw ConfigException("Dynamic config missing 'method'/'cipher'")
        val password = firstString(node, "password", "secret")
            ?: throw ConfigException("Dynamic config missing 'password'/'secret'")

        var host = firstString(node, "server", "host")
        var port = firstInt(node, "server_port", "port")
        val endpoint = firstString(node, "endpoint")
        if (endpoint != null) {
            val (h, p) = splitHostPort(endpoint)
            host = h; port = p
        }
        if (host.isNullOrBlank()) throw ConfigException("Dynamic config missing 'server'/'endpoint'")
        if (port == null) throw ConfigException("Dynamic config missing 'server_port'/'port'")
        if (port !in 1..65535) throw ConfigException("Invalid port: $port")

        val cipher = resolveCipher(method)
        val prefix = firstString(node, "prefix")?.let { prefixStringToBytes(it) }
        val name = displayName(nameHint, host, port)
        return ParsedConfig(name, TransportConfig(host, port, cipher, password, prefix))
    }

    /** Resolve a `transport:` graph node down to the shadowsocks leaf (TCP branch preferred). */
    private fun resolveTransportGraph(transport: Map<*, *>): Map<*, *> {
        val type = (transport["\$type"] ?: transport["type"])?.toString()
        when {
            type.equals("tcpudp", ignoreCase = true) || transport.containsKey("tcp") -> {
                val tcp = transport["tcp"] as? Map<*, *>
                    ?: throw ConfigException("Transport 'tcpudp' missing a 'tcp' branch")
                return resolveTransportGraph(tcp)
            }
            type.equals("shadowsocks", ignoreCase = true) -> return transport
            type == null -> return transport // bare shadowsocks-like map
            else -> throw ConfigException("Unsupported transport type: '$type' (only shadowsocks is supported)")
        }
    }

    // ---------------------------------------------------------------------
    // Prefix handling
    // ---------------------------------------------------------------------

    /** Extract & decode the `prefix` query param (percent-encoded raw bytes) from a static key. */
    fun extractPrefixFromQuery(query: String): ByteArray? {
        if (query.isBlank()) return null
        for (pair in query.split('&')) {
            val eq = pair.indexOf('=')
            if (eq < 0) continue
            val k = pair.substring(0, eq)
            if (k.equals("prefix", ignoreCase = true)) {
                return percentDecodeToBytes(pair.substring(eq + 1))
            }
        }
        return null
    }

    /** JSON/YAML prefix string: each character is one byte (ISO-8859-1 / Latin-1). */
    fun prefixStringToBytes(s: String): ByteArray {
        val out = ByteArray(s.length)
        for (i in s.indices) out[i] = (s[i].code and 0xFF).toByte()
        return out
    }

    /** Percent-decode a URL query value into raw bytes (literal chars kept as Latin-1). */
    fun percentDecodeToBytes(s: String): ByteArray {
        val out = ArrayList<Byte>(s.length)
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c == '%' && i + 2 < s.length -> {
                    val hex = s.substring(i + 1, i + 3)
                    out.add(hex.toInt(16).toByte())
                    i += 3
                }
                c == '+' -> { out.add(' '.code.toByte()); i++ }
                else -> { out.add((c.code and 0xFF).toByte()); i++ }
            }
        }
        return out.toByteArray()
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private fun resolveCipher(method: String): Cipher =
        Cipher.fromId(method.trim())
            ?: throw ConfigException("Unsupported cipher: '$method' (supported: chacha20-ietf-poly1305, aes-256-gcm, aes-128-gcm)")

    private fun splitHostPort(hostPort: String): Pair<String, Int> {
        val hp = hostPort.trim()
        // IPv6 literal in brackets: [::1]:8388
        if (hp.startsWith("[")) {
            val close = hp.indexOf(']')
            if (close < 0) throw ConfigException("Malformed IPv6 host: $hp")
            val host = hp.substring(1, close)
            val rest = hp.substring(close + 1)
            if (!rest.startsWith(":")) throw ConfigException("Missing port for host $host")
            return host to parsePort(rest.substring(1))
        }
        val colon = hp.lastIndexOf(':')
        if (colon < 0) throw ConfigException("Missing port in '$hp'")
        val host = hp.substring(0, colon)
        if (host.isBlank()) throw ConfigException("Missing host in '$hp'")
        return host to parsePort(hp.substring(colon + 1))
    }

    private fun parsePort(s: String): Int {
        val p = s.trim().toIntOrNull() ?: throw ConfigException("Invalid port: '$s'")
        if (p !in 1..65535) throw ConfigException("Port out of range: $p")
        return p
    }

    private fun displayName(name: String, host: String, port: Int): String =
        if (name.isNotBlank()) name else "$host:$port"

    private fun firstString(map: Map<*, *>, vararg keys: String): String? {
        for (k in keys) {
            val v = map[k]
            if (v != null && v.toString().isNotBlank()) return v.toString()
        }
        return null
    }

    private fun firstInt(map: Map<*, *>, vararg keys: String): Int? {
        for (k in keys) {
            when (val v = map[k]) {
                is Number -> return v.toInt()
                is String -> v.trim().toIntOrNull()?.let { return it }
                else -> {}
            }
        }
        return null
    }

    private fun urlDecode(s: String): String =
        try {
            java.net.URLDecoder.decode(s, "UTF-8")
        } catch (e: Exception) {
            s
        }

    private fun base64Decode(s: String): ByteArray {
        val cleaned = s.trim().replace("\n", "").replace("\r", "")
        val padded = when (cleaned.length % 4) {
            2 -> "$cleaned=="
            3 -> "$cleaned="
            else -> cleaned
        }
        return try {
            Base64.getUrlDecoder().decode(padded)
        } catch (e: Exception) {
            Base64.getDecoder().decode(padded)
        }
    }
}
