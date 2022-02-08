package com.lapanthere.macaroon

import com.lapanthere.macaroon.predicates.field
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

internal class MacaroonTest {
    private val location = "macaroon/builder"
    private val secret = generateSecretKey()
    private val identifier = "macaroon-test"

    @Test
    fun `create macaroon directly`() {
        val macaroon = buildMacaroon(location, secret, identifier)
        assertEquals(location, macaroon.location)
        assertEquals(identifier, macaroon.identifier)
    }

    @Test
    fun `add first part caveat`() {
        val macaroon = buildMacaroon(location, secret, identifier) {
            require("account = 3735928559")
        }
        assertEquals(location, macaroon.location)
        assertEquals(identifier, macaroon.identifier)
        assertEquals(Caveat(identifier = "account = 3735928559"), macaroon.caveats.first())
    }

    @Test
    fun `can be create from an existing macaroon`() {
        val macaroon = buildMacaroon(
            buildMacaroon(location, secret, identifier) {
                require("account = 3735928559")
            }
        )
        assertEquals(location, macaroon.location)
        assertEquals(identifier, macaroon.identifier)
        assertEquals(Caveat("account = 3735928559"), macaroon.caveats.first())
    }

    @Test
    fun `supports many first part caveats`() {
        val macaroon = buildMacaroon(
            buildMacaroon(location, secret, identifier) {
                require("account = 3735928559")
                require("time < 2015-01-01T00:00")
                require("email = alice@example.org")
            }
        )
        assertEquals(location, macaroon.location)
        assertEquals(identifier, macaroon.identifier)
        assertEquals(Caveat("account = 3735928559"), macaroon.caveats[0])
        assertEquals(Caveat("time < 2015-01-01T00:00"), macaroon.caveats[1])
        assertEquals(Caveat("email = alice@example.org"), macaroon.caveats[2])
    }

    @Test
    fun `support third party caveat`() {
        val thirdPartyLocation = "http://auth.mybank/"
        val thirdPartyKey = generateSecretKey()
        val thirdPartyIdentifier = "this was how we remind auth of key/pred"
        val macaroon = buildMacaroon(
            buildMacaroon(location, secret, identifier) {
                require("account = 3735928559")
                require(thirdPartyLocation, thirdPartyKey, thirdPartyIdentifier)
            }
        )
        assertEquals(location, macaroon.location)
        assertEquals(identifier, macaroon.identifier)
        assertEquals(Caveat("account = 3735928559"), macaroon.caveats[0])
        val thirdPartyCaveat = macaroon.caveats[1]
        assertEquals(thirdPartyIdentifier, thirdPartyCaveat.value)
        assertEquals(thirdPartyLocation, thirdPartyCaveat.location)
    }

    @Test
    fun `can bind macaroon`() {
        val discharged = buildMacaroon(
            buildMacaroon(location, secret, identifier) {
                require("account = 3735928559")
                require(
                    "http://auth.mybank/",
                    generateSecretKey(),
                    "this was how we remind auth of key/pred"
                )
            }
        )

        val macaroon = buildMacaroon(
            buildMacaroon(location, secret, identifier) {
                require("account = 3735928559")
                bind(discharged)
            }
        )
        assertEquals(location, macaroon.location)
        assertEquals(identifier, macaroon.identifier)
        assertEquals(Caveat("account = 3735928559"), macaroon.caveats[0])
        assertNotEquals(discharged.signature, macaroon.signature)
    }

    @Test
    fun `complex predicates`() {
        val expirationTime = Instant.now().plusSeconds(60)
        val macaroon = buildMacaroon(location, secret, identifier) {
            require(field("time") lt expirationTime)
            require(field("actions") containsAll listOf("read", "write"))
        }
        assertEquals(location, macaroon.location)
        assertEquals(identifier, macaroon.identifier)
        assertEquals(Caveat("time < $expirationTime"), macaroon.caveats.first())
        assertEquals(Caveat("actions in read,write"), macaroon.caveats.last())
    }
}
