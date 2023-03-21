package com.lapanthere.macaroon

import com.lapanthere.macaroon.crypto.KEY_LEN
import com.lapanthere.macaroon.crypto.SecretBox
import com.lapanthere.macaroon.crypto.deriveKey
import com.lapanthere.macaroon.crypto.emptyKey
import com.lapanthere.macaroon.crypto.hmac
import com.lapanthere.macaroon.predicates.Predicate
import com.lapanthere.macaroon.serialization.Deserializer
import com.lapanthere.macaroon.serialization.Serializer
import java.io.Serializable

private const val MAX_CAVEAT_SIZE: Int = 32768
private const val MAX_CAVEATS: Int = 65536

public class Macaroon internal constructor(
    public val location: String? = null,
    public val identifier: String,
    public val caveats: List<Caveat> = emptyList(),
    public val signature: ByteArray,
) : Serializable {
    public companion object {
        @JvmStatic
        public fun from(serialized: ByteArray): Macaroon = Deserializer.deserialize(serialized)
    }

    init {
        require(signature.size == KEY_LEN) { "invalid signature" }
    }

    public fun serialize(): ByteArray = Serializer.serialize(this)

    public fun verify(key: SecretKey, builderAction: Verifier.Builder.() -> Unit = {}): Boolean =
        buildVerifier(this, builderAction).isValid(key)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Macaroon) return false

        if (location != other.location) return false
        if (identifier != other.identifier) return false
        if (!signature.contentEquals(other.signature)) return false
        if (caveats != other.caveats) return false

        return true
    }

    override fun hashCode(): Int {
        var result = location.hashCode()
        result = 31 * result + identifier.hashCode()
        result = 31 * result + signature.contentHashCode()
        result = 31 * result + caveats.hashCode()
        return result
    }

    override fun toString(): String = """
        |location $location
        |identifier $identifier
        |${caveats.joinToString("\n") { "$it" }}
        |signature ${signature.toHex()}
    """.trimMargin()

    public class Builder private constructor(
        private var location: String?,
        private var identifier: String,
        private var signature: ByteArray,
        private var caveats: MutableList<Caveat> = mutableListOf(),
    ) {
        public constructor(macaroon: Macaroon) : this(
            macaroon.location,
            macaroon.identifier,
            macaroon.signature,
            macaroon.caveats.toMutableList(),
        )

        public constructor(
            location: String?,
            identifier: String,
            key: ByteArray, // Not a SecretKey for Java compatibility.
        ) : this(
            location,
            identifier,
            signature = hmac(deriveKey(key), identifier.toByteArray()),
        )

        public fun bind(macaroon: Macaroon): Builder {
            location = macaroon.location
            identifier = macaroon.identifier
            caveats = macaroon.caveats.toMutableList()
            signature = hmac(emptyKey(), signature, macaroon.signature)
            return this
        }

        public fun require(predicate: Predicate): Builder =
            require(predicate.toString())

        public fun require(caveat: String): Builder {
            val bytes = caveat.toByteArray()
            require(bytes.size < MAX_CAVEAT_SIZE) { "caveat is too large" }
            check(caveats.size < MAX_CAVEATS) { "too many caveats" }
            signature = hmac(signature, bytes)
            caveats.add(Caveat(identifier = caveat))
            return this
        }

        public fun require(location: String, key: SecretKey, identifier: String): Builder {
            check(caveats.size < MAX_CAVEATS) { "too many caveats" }

            val derived = deriveKey(key.bytes)
            val box = SecretBox(signature)
            val nonce = box.nonce(derived)
            val ciphertext = box.seal(nonce, derived)
            val vid = nonce + ciphertext

            signature = hmac(signature, vid, identifier.toByteArray())
            caveats.add(Caveat(location = location, identifier = identifier, vid = vid))
            return this
        }

        public fun build(): Macaroon = Macaroon(location, identifier, caveats.toMutableList(), signature)
    }
}

/**
 * Build a Macaroon.
 *
 * @param location   location
 * @param key        secret key to be used for encryption
 * @param identifier identifier
 * @return a new Macaroon
 */
public fun buildMacaroon(
    location: String,
    key: SecretKey,
    identifier: String,
    builderAction: Macaroon.Builder.() -> Unit = {},
): Macaroon = Macaroon.Builder(location, identifier, key.bytes).apply(builderAction).build()

/**
 * Build a Macaroon based on an existing Macaroon.
 *
 * @param macaroon an existing Macaroon
 * @return a new Macaroon
 */
public fun buildMacaroon(
    macaroon: Macaroon,
    builderAction: Macaroon.Builder.() -> Unit = {},
): Macaroon = Macaroon.Builder(macaroon).apply(builderAction).build()

/**
 * Return a Macaroon based on its serialized form.
 *
 * @return the corresponding Macaroon
 */
public fun Macaroon(serialized: ByteArray): Macaroon = Deserializer.deserialize(serialized)

private fun ByteArray.toHex(): String = joinToString(separator = "") { eachByte -> "%02x".format(eachByte) }
