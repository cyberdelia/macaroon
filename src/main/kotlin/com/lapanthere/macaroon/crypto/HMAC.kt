package com.lapanthere.macaroon.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

private const val ALGORITHM = "HmacSHA256"
private val MAGIC_KEY = "macaroon-key-generator".toByteArray()

internal fun hmac(
    key: ByteArray,
    message: ByteArray,
): ByteArray {
    val spec = SecretKeySpec(key, ALGORITHM)
    val mac = Mac.getInstance(ALGORITHM)
    mac.init(spec)
    return mac.doFinal(message)
}

internal fun deriveKey(key: ByteArray): ByteArray = hmac(MAGIC_KEY, key)

internal fun emptyKey() = ByteArray(KEY_LEN)

internal fun hmac(
    key: ByteArray,
    message1: ByteArray,
    message2: ByteArray,
): ByteArray = hmac(key, hmac(key, message1) + hmac(key, message2))
