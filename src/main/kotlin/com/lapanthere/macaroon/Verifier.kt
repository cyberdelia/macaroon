package com.lapanthere.macaroon

import com.lapanthere.macaroon.crypto.NONCE_SIZE
import com.lapanthere.macaroon.crypto.SecretBox
import com.lapanthere.macaroon.crypto.deriveKey
import com.lapanthere.macaroon.crypto.emptyKey
import com.lapanthere.macaroon.crypto.hmac
import com.lapanthere.macaroon.predicates.CollectionPredicateVerifier
import com.lapanthere.macaroon.predicates.PredicateVerifier
import java.security.MessageDigest
import java.time.Instant

/**
 * Provides a custom way to verify a Caveat.
 */
public fun interface CaveatVerifier {
    public fun verify(caveat: Caveat): Boolean
}

private class ValidationException(message: String) : RuntimeException(message)

public class Verifier private constructor(
    private val root: Macaroon,
    private val bounded: List<Macaroon> = emptyList(),
    private val predicates: List<Caveat> = emptyList(),
    private val verifiers: List<CaveatVerifier> = emptyList()
) {
    /**
     * Returns true if the macaroon is valid for the given secret.
     *
     * @param key a 32-bytes secret.
     * @return true if the verification succeeded
     */
    @JvmName("isValid")
    public fun isValid(key: SecretKey): Boolean = try {
        validateMacaroon(root, deriveKey(key.bytes))
    } catch (e: ValidationException) {
        false
    }

    private fun calculateSignature(macaroon: Macaroon, key: ByteArray): ByteArray {
        var signature = hmac(key, macaroon.identifier.toByteArray())
        macaroon.caveats.forEach { caveat ->
            signature = when {
                caveat.vid != null -> {
                    val bound = bounded.firstOrNull { it.identifier == caveat.identifier }
                        ?: throw ValidationException("invalid third-party caveat")

                    if (!validateBoundMacaroon(bound, caveat.vid, signature)) {
                        throw ValidationException("invalid third-party caveat")
                    }

                    hmac(signature, caveat.vid, caveat.identifier.toByteArray())
                }
                (predicates.contains(caveat) || verifiers.verify(caveat)) ->
                    hmac(signature, caveat.identifier.toByteArray())
                else -> throw ValidationException("invalid caveat")
            }
        }
        return signature
    }

    private fun validateMacaroon(macaroon: Macaroon, key: ByteArray): Boolean =
        calculateSignature(macaroon, key).isEqual(macaroon.signature)

    private fun validateBoundMacaroon(macaroon: Macaroon, vid: ByteArray, signature: ByteArray): Boolean {
        val box = SecretBox(signature)
        val plaintext = box.open(
            vid.sliceArray(0 until NONCE_SIZE),
            vid.sliceArray(NONCE_SIZE until vid.size)
        )
        return if (plaintext != null) {
            val calculatedSignature = calculateSignature(macaroon, plaintext)
            val boundSignature = hmac(emptyKey(), root.signature, calculatedSignature)
            boundSignature.isEqual(macaroon.signature)
        } else {
            false
        }
    }

    private fun List<CaveatVerifier>.verify(caveat: Caveat): Boolean = any { it.verify(caveat) }

    public class Builder internal constructor(
        private val macaroon: Macaroon,
        private val bounded: MutableList<Macaroon> = mutableListOf(),
        private val predicates: MutableList<Caveat> = mutableListOf(),
        private val verifiers: MutableList<CaveatVerifier> = mutableListOf()
    ) {
        public constructor(macaroon: Macaroon) : this(
            macaroon, mutableListOf(), mutableListOf(), mutableListOf()
        )

        public fun satisfy(caveat: String): Builder {
            predicates.add(Caveat(identifier = caveat))
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

        public inline fun <reified T : Comparable<T>> satisfy(field: String, value: T): Builder =
            satisfy(field, value, T::class.java)

        public fun satisfy(field: String, boolean: Boolean): Builder =
            satisfy(field, boolean, Boolean::class.java)

        public fun satisfy(field: String, string: String): Builder =
            satisfy(field, string, String::class.java)

        public fun satisfy(field: String, int: Int): Builder =
            satisfy(field, int, Int::class.java)

        public fun satisfy(field: String, long: Long): Builder =
            satisfy(field, long, Long::class.java)

        public fun satisfy(field: String, double: Double): Builder =
            satisfy(field, double, Double::class.java)

        public fun satisfy(field: String, float: Float): Builder =
            satisfy(field, float, Float::class.java)

        public fun satisfy(field: String, instant: Instant): Builder =
            satisfy(field, instant, Instant::class.java)

        public fun <T : Comparable<T>> satisfy(field: String, value: T, javaClass: Class<T>): Builder =
            satisfy(PredicateVerifier(field, value, javaClass.kotlin))

        public inline fun <reified T : Any> satisfy(field: String, values: Collection<T>): Builder =
            satisfy(field, values, T::class.java)

        public inline fun <reified T : Any> satisfy(field: String, vararg values: T): Builder =
            satisfy(field, values.toList(), T::class.java)

        public fun <T : Any> satisfy(field: String, values: Collection<T>, javaClass: Class<T>): Builder =
            satisfy(CollectionPredicateVerifier(field, values, javaClass.kotlin))

        public fun build(): Verifier = Verifier(macaroon, bounded, predicates, verifiers)
    }
}

/**
 * Build a Verifier for the given Macaroon.
 *
 * @param macaroon the macaroon to verify.
 * @return a new Verifier
 */
public fun buildVerifier(macaroon: Macaroon, builderAction: Verifier.Builder.() -> Unit = {}): Verifier =
    Verifier.Builder(macaroon).apply(builderAction).build()

// Expose constant time comparison.
private fun ByteArray.isEqual(other: ByteArray): Boolean = MessageDigest.isEqual(this, other)
