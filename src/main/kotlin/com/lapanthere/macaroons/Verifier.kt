package com.lapanthere.macaroons

import com.lapanthere.macaroons.crypto.NONCE_SIZE
import com.lapanthere.macaroons.crypto.SecretBox
import com.lapanthere.macaroons.crypto.deriveKey
import com.lapanthere.macaroons.crypto.hmac
import java.security.MessageDigest

public interface CaveatVerifier {
    public fun verify(caveat: Caveat): Boolean
}

public class Verifier internal constructor(
    private val macaroon: Macaroon,
    private val bounded: List<Macaroon> = emptyList(),
    private val predicates: List<Caveat> = emptyList(),
    private val verifiers: List<CaveatVerifier> = emptyList()
) {
    public fun isValid(key: ByteArray): Boolean {
        var signature = hmac(deriveKey(key), macaroon.identifier.toByteArray())
        val iterator = macaroon.caveats.listIterator()
        while (iterator.hasNext()) {
            val caveat = iterator.next()
            val next = if (iterator.hasNext()) {
                iterator.next()
            } else {
                null
            }
            when {
                caveat.type == Type.CID && next?.type == Type.VID -> {
                    val bound = bounded.firstOrNull { it.identifier.toByteArray().contentEquals(caveat.descriptor) }
                        ?: return false
                    val box = SecretBox(signature)
                    val plaintext = box.open(
                        next.descriptor.sliceArray(0..NONCE_SIZE), next.descriptor.sliceArray(
                            NONCE_SIZE..next.descriptor.size
                        )
                    ) ?: return false

                    // TODO: re-run this function/logic on the bound macaroon with the plaintext as caveat.

                    signature = hmac(signature, next.descriptor, caveat.descriptor)
                }
                caveat.type == Type.CID && (predicates.contains(caveat) || verifiers.verify(caveat)) -> {
                    signature = hmac(signature, caveat.descriptor)
                }
                else -> continue
            }
        }
        return signature.isEqual(macaroon.signature)
    }

    private fun List<CaveatVerifier>.verify(caveat: Caveat): Boolean = any { it.verify(caveat) }

    public class Builder internal constructor(
        private val macaroon: Macaroon,
        private val bounded: MutableList<Macaroon> = mutableListOf(),
        private val predicates: MutableList<Caveat> = mutableListOf(),
        private val verifiers: MutableList<CaveatVerifier> = mutableListOf()
    ) {
        public fun satisfy(caveat: String): Builder {
            predicates.add(Caveat(Type.CID, caveat.toByteArray()))
            return this
        }

        public fun satisfy(macaroon: Macaroon): Builder {
            bounded.add(macaroon)
            return this
        }

        public fun satisfy(verifier: CaveatVerifier): Builder {
            verifiers.add(verifier)
            return this
        }

        public fun build(): Verifier = Verifier(macaroon, bounded, predicates, verifiers)
    }
}

public fun buildVerifier(macaroon: Macaroon, builderAction: Verifier.Builder.() -> Unit = {}): Verifier =
    Verifier.Builder(macaroon).apply(builderAction).build()

// Expose constant time comparison.
private fun ByteArray.isEqual(other: ByteArray): Boolean = MessageDigest.isEqual(this, other)
