package com.lapanthere.macaroons

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

internal class VerifierTest {
    private val location = "http://mybank/"
    private val secret = "this is our super secret key; only we should know it".toByteArray()
    private val identifier = "we used our secret key"

    @Test
    fun `verify a simple macaroon`() {
        val macaroon = buildMacaroon(location, secret, identifier)
        val verifier = buildVerifier(macaroon)
        assertTrue(verifier.isValid(secret))
    }

    @Test
    fun `fails with the wrong secret`() {
        val macaroon = buildMacaroon(location, secret, identifier)
        val verifier = buildVerifier(macaroon)
        assertFalse(verifier.isValid("not a secret".toByteArray()))
    }

    @Test
    fun `satisfy exact first party`() {
        val macaroon = buildMacaroon(location, secret, identifier) {
            addCaveat("account = 3735928559")
        }

        val verifier = buildVerifier(macaroon) {
            satisfy("account = 3735928559")
        }

        assertTrue(verifier.isValid(secret))
    }

    @Test
    fun `satisfy a first party`() {
        val macaroon = buildMacaroon(location, secret, identifier) {
            addCaveat("account = 3735928559")
            addCaveat("credit_allowed = true")
        }

        assertFalse(buildVerifier(macaroon).isValid(secret))

        assertFalse(buildVerifier(macaroon) {
            satisfy("account = 3735928559")
        }.isValid(secret))
    }

    @Test
    fun `satisfy with attenuation`() {
        val macaroon = buildMacaroon(location, secret, identifier) {
            addCaveat("account = 3735928559")
        }

        assertFalse(buildVerifier(macaroon).isValid(secret))

        assertTrue(buildVerifier(macaroon) {
            satisfy("account = 3735928559")
            satisfy("IP = 127.0.0.1")
            satisfy("browser = Chrome")
            satisfy("action = deposit")
        }.isValid(secret))
    }

    @Test
    fun `satisfy with a caveat verifier`() {
        val macaroon = buildMacaroon(location, secret, identifier) {
            addCaveat("action = read")
        }

        val verifier = buildVerifier(macaroon) {
            satisfy(object : CaveatVerifier {
                override fun verify(caveat: Caveat): Boolean =
                    caveat.descriptor.decodeToString().contains("action = read")
            })
        }
        assertTrue(verifier.isValid(secret))
    }
}
