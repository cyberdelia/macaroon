@file:JvmName("Keys")
package com.lapanthere.macaroon

import com.lapanthere.macaroon.crypto.HSalsa20
import com.lapanthere.macaroon.crypto.KEY_LEN
import org.bouncycastle.math.ec.rfc7748.X25519
import java.security.SecureRandom
import kotlin.experimental.and
import kotlin.experimental.or

private val HSALSA20_SEED = ByteArray(16)

private sealed interface Key {
    operator fun get(index: Int): Byte
    operator fun set(index: Int, value: Byte)
    val size: Int
    operator fun iterator(): ByteIterator
}

/**
 * Represents a 32 bytes secret key.
 */
@JvmInline
public value class SecretKey(public val bytes: ByteArray) : Key {
    init {
        require(bytes.size == KEY_LEN) { "must be 32 bytes long" }
    }

    override fun get(index: Int): Byte = bytes[index]

    override fun set(index: Int, value: Byte): Unit = bytes.set(index, value)

    override val size: Int
        get() = bytes.size

    override fun iterator(): ByteIterator = bytes.iterator()
}

/**
 * Represents a 32 bytes private key.
 */
@JvmInline
public value class PrivateKey(public val bytes: ByteArray) : Key {
    init {
        require(bytes.size == KEY_LEN) { "must be 32 bytes long" }
    }

    override fun get(index: Int): Byte = bytes[index]

    override fun set(index: Int, value: Byte): Unit = bytes.set(index, value)

    override val size: Int
        get() = bytes.size

    override fun iterator(): ByteIterator = bytes.iterator()
}

/**
 * Represents a public key of 32 bytes.
 */
@JvmInline
public value class PublicKey(public val bytes: ByteArray) : Key {
    init {
        require(size == KEY_LEN) { "must be 32 bytes long" }
    }

    override fun get(index: Int): Byte = bytes[index]

    override fun set(index: Int, value: Byte): Unit = bytes.set(index, value)

    override val size: Int
        get() = bytes.size

    override fun iterator(): ByteIterator = bytes.iterator()
}

/**
 * Generates a 32-byte secret key.
 *
 * @return a 32-byte secret key
 */
public fun generateSecretKey(): SecretKey {
    val k = ByteArray(KEY_LEN)
    val random = SecureRandom()
    random.nextBytes(k)
    return SecretKey(k)
}

/**
 * Generates a Curve25519 private key.
 *
 * @return a Curve25519 private key
 */
public fun generatePrivateKey(): PrivateKey {
    val k = generateSecretKey()
    k[0] = k[0] and 248.toByte()
    k[31] = k[31] and 127.toByte()
    k[31] = k[31] or 64.toByte()
    return PrivateKey(k.bytes)
}

/**
 * Generates a Curve25519 public key given a Curve25519 private key.
 *
 * @param privateKey a Curve25519 private key
 * @return the public key matching `privateKey`
 */
public fun generatePublicKey(privateKey: PrivateKey): PublicKey {
    val publicKey = ByteArray(KEY_LEN)
    X25519.scalarMultBase(privateKey.bytes, 0, publicKey, 0)
    return PublicKey(publicKey)
}

/**
 * Calculate the X25519/HSalsa20 shared secret for the given public key and private key.
 *
 * @param publicKey the recipient's public key
 * @param privateKey the sender's private key
 * @return a 32-byte secret key only re-calculable by the sender and recipient
 */
public fun sharedSecret(publicKey: PublicKey, privateKey: PrivateKey): SecretKey {
    val s = ByteArray(KEY_LEN)
    X25519.scalarMult(privateKey.bytes, 0, publicKey.bytes, 0, s, 0)
    val k = ByteArray(KEY_LEN)
    HSalsa20.hsalsa20(k, HSALSA20_SEED, s)
    return SecretKey(k)
}
