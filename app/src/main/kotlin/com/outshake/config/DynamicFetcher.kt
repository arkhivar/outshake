package com.outshake.config

import java.io.BufferedReader
import java.net.HttpURLConnection
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/** Fetches the remote body referenced by an ssconf:// key. Network errors become ConfigException. */
object DynamicFetcher {

    fun fetch(url: String): String {
        val connection = try {
            (URL(url).openConnection() as HttpURLConnection)
        } catch (e: Exception) {
            throw ConfigException("Invalid dynamic config URL: ${e.message}")
        }
        try {
            connection.connectTimeout = 15000
            connection.readTimeout = 15000
            connection.instanceFollowRedirects = true
            connection.setRequestProperty("Accept", "application/json, text/yaml, text/plain, */*")
            connection.setRequestProperty("User-Agent", "Outshake/1.0")

            val code = try {
                connection.responseCode
            } catch (e: javax.net.ssl.SSLException) {
                throw ConfigException("TLS error fetching dynamic config: ${e.message}")
            } catch (e: Exception) {
                throw ConfigException("Network error fetching dynamic config: ${e.message}")
            }
            if (code !in 200..299) {
                throw ConfigException("Dynamic config server returned HTTP $code")
            }
            val body = connection.inputStream.bufferedReader().use(BufferedReader::readText)
            if (body.isBlank()) throw ConfigException("Dynamic config response was empty")
            return body
        } finally {
            connection.disconnect()
        }
    }
}
