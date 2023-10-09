package com.lapanthere.macaroon

import com.lapanthere.macaroon.predicates.field
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

data class Constructable(val value: String) : Comparable<Constructable> {
    override fun toString(): String = value

    override fun compareTo(other: Constructable): Int = value.compareTo(other.value)
}

internal class VerifierTest {
    private val location = "macaroon/verifier"
    private val secret = generateSecretKey()
    private val identifier = "verifier-test"

    @Test
    fun `verify a simple macaroon`() {
        val macaroon = buildMacaroon(location, secret, identifier)
        val verifier = buildVerifier(macaroon)
        assertTrue(verifier.isValid(secret))
        assertTrue(macaroon.verify(secret))
    }

    @Test
    fun `fails with the wrong secret`() {
        val macaroon = buildMacaroon(location, secret, identifier)
        val verifier = buildVerifier(macaroon)
        assertFalse(verifier.isValid(generateSecretKey()))
    }

    @Test
    fun `satisfy exact first party`() {
        val macaroon =
            buildMacaroon(location, secret, identifier) {
                require("account = 3735928559")
            }

        val verifier =
            buildVerifier(macaroon) {
                satisfy("account = 3735928559")
            }

        assertTrue(verifier.isValid(secret))
    }

    @Test
    fun `satisfy a first party`() {
        val macaroon =
            buildMacaroon(location, secret, identifier) {
                require("account = 3735928559")
                require("credit_allowed = true")
            }

        assertFalse(buildVerifier(macaroon).isValid(secret))

        assertFalse(
            buildVerifier(macaroon) {
                satisfy("account = 3735928559")
            }.isValid(secret),
        )
    }

    @Test
    fun `satisfy with attenuation`() {
        val macaroon =
            buildMacaroon(location, secret, identifier) {
                require("account = 3735928559")
            }

        assertFalse(buildVerifier(macaroon).isValid(secret))

        assertTrue(
            buildVerifier(macaroon) {
                satisfy("account = 3735928559")
                satisfy("IP = 127.0.0.1")
                satisfy("browser = Chrome")
                satisfy("action = deposit")
            }.isValid(secret),
        )
    }

    @Test
    fun `satisfy with a caveat verifier`() {
        val macaroon =
            buildMacaroon(location, secret, identifier) {
                require("action = read")
            }

        val verifier =
            buildVerifier(macaroon) {
                satisfy(
                    object : CaveatVerifier {
                        override fun verify(caveat: Caveat): Boolean = caveat.value.contains("action = read")
                    },
                )
            }
        assertTrue(verifier.isValid(secret))
    }

    @Test
    fun `satisfy a third-party macaroon`() {
        val key = generateSecretKey()

        val macaroon =
            buildMacaroon(location, secret, identifier) {
                require("account = 1234")
                require("macaroon/third-party", key, "third-party")
            }

        val discharge =
            buildMacaroon("macaroon/third-party", key, "third-party") {
                require("action = read")
            }

        val requestMacaroon =
            buildMacaroon(macaroon) {
                bind(discharge)
            }

        val verifier =
            buildVerifier(macaroon) {
                satisfy("account = 1234")
                satisfy("action = read")
                satisfy(requestMacaroon)
            }

        assertTrue(verifier.isValid(secret))
    }

    @Test
    fun `does not satisfy a un-binded third-party macaroon`() {
        val key = generateSecretKey()

        val macaroon =
            buildMacaroon(location, generateSecretKey(), identifier) {
                require("account = 1234")
                require("macaroon/third-party", key, "third-party")
            }

        val discharge =
            buildMacaroon("macaroon/third-party", key, "third-party") {
                require("action = read")
            }

        val verifier =
            buildVerifier(macaroon) {
                satisfy("account = 1234")
                satisfy("action = read")
                satisfy(discharge)
            }
        assertFalse(verifier.isValid(secret))
    }

    @Test
    fun `satisfy a comparable predicate`() {
        val macaroon =
            buildMacaroon(location, secret, identifier) {
                require("admin = true")
                require("account > 10")
                require(field("value") eq Constructable("value"))
                require(field("time") lt Instant.now().plusSeconds(60))
            }

        assertTrue(
            buildVerifier(macaroon) {
                satisfy("admin", true)
                satisfy("account", 15)
                satisfy("time", Instant.now())
                satisfy("value", Constructable("value"))
            }.isValid(secret),
        )

        assertFalse(
            buildVerifier(macaroon) {
                satisfy("admin", false)
                satisfy("account", 5)
                satisfy("time", Instant.now())
                satisfy("value", Constructable("different"))
            }.isValid(secret),
        )
    }

    @Test
    fun `satisfy a collection predicate`() {
        val macaroon =
            buildMacaroon(location, secret, identifier) {
                require(field("actions").containsAll("read", "write"))
                require(field("excludes").notContains(5, 7))
            }

        assertTrue(
            buildVerifier(macaroon) {
                satisfy("actions", "read", "write")
                satisfy("excludes", 4, 6)
            }.isValid(secret),
        )

        assertFalse(
            buildVerifier(macaroon) {
                satisfy("actions", "delete", "create")
                satisfy("excludes", 5, 7)
            }.isValid(secret),
        )
    }
}
