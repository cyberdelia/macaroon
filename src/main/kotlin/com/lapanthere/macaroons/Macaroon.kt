package com.lapanthere.macaroons

import com.lapanthere.macaroons.crypto.KEY_LEN
import com.lapanthere.macaroons.crypto.SecretBox
import com.lapanthere.macaroons.crypto.deriveKey
import com.lapanthere.macaroons.crypto.hmac

private const val MAX_CAVEAT_SIZE: Int = 32768
private const val MAX_CAVEATS: Int = 65536

public class Macaroon internal constructor(
    public val location: String,
    public val identifier: String,
    public val caveats: List<Caveat> = emptyList(),
    public val signature: ByteArray
) {
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

    public class Builder internal constructor(
        private var location: String,
        private var identifier: String,
        private var caveats: MutableList<Caveat> = mutableListOf(),
        private var signature: ByteArray
    ) {
        internal constructor(
            location: String,
            identifier: String,
            key: ByteArray,
            vararg caveats: Caveat
        ) : this(
            location, identifier, caveats.toMutableList(), hmac(deriveKey(key), identifier.toByteArray())
        )

        public fun bind(macaroon: Macaroon): Builder {
            location = macaroon.location
            identifier = macaroon.identifier
            caveats = macaroon.caveats.toMutableList()
            signature = hmac(ByteArray(KEY_LEN), signature, macaroon.signature)
            return this
        }

        public fun addCaveat(caveat: String): Builder {
            val bytes = caveat.toByteArray()
            require(bytes.size < MAX_CAVEAT_SIZE)
            check(caveats.size < MAX_CAVEATS)
            signature = hmac(signature, bytes)
            caveats.add(Caveat(Type.CID, bytes))
            return this
        }

        public fun addCaveat(location: String, key: ByteArray, identifier: String): Builder {
            check(caveats.size <= MAX_CAVEATS - 3)

            val derived = deriveKey(key)
            val box = SecretBox(signature)
            val nonce = box.nonce(derived)
            val ciphertext = box.seal(nonce, derived)
            val vid = nonce + ciphertext

            signature = hmac(signature, vid, identifier.toByteArray())

            caveats.add(Caveat(Type.CID, identifier))
            caveats.add(Caveat(Type.VID, vid))
            caveats.add(Caveat(Type.CL, location))
            return this
        }

        public fun build(): Macaroon = Macaroon(location, identifier, caveats.toMutableList(), signature)
    }
}

public fun buildMacaroon(
    location: String,
    key: ByteArray,
    identifier: String,
    builderAction: Macaroon.Builder.() -> Unit = {}
): Macaroon = Macaroon.Builder(location, identifier, key).apply(builderAction).build()

public fun buildMacaroon(
    macaroon: Macaroon,
    builderAction: Macaroon.Builder.() -> Unit = {}
): Macaroon =
    Macaroon.Builder(macaroon.location, macaroon.identifier, macaroon.caveats.toMutableList(), macaroon.signature)
        .apply(builderAction)
        .build()
