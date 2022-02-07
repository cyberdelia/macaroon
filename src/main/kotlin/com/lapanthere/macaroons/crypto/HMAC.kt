package com.lapanthere.macaroons.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

private const val ALGORITHM = "HmacSHA256"
private val MAGIC_KEY = "macaroons-key-generator".toByteArray()

internal fun hmac(key: ByteArray, message: ByteArray): ByteArray {
    val spec = SecretKeySpec(key, ALGORITHM)
    val mac = Mac.getInstance(ALGORITHM)
    mac.init(spec)
    return mac.doFinal(message)
}

internal fun deriveKey(key: ByteArray): ByteArray = hmac(MAGIC_KEY, key)

internal fun hmac(key: ByteArray, vararg messages: ByteArray): ByteArray =
    hmac(key, messages.reduce { aggregate, message -> aggregate + hmac(key, message) })
