package com.lapanthere.macaroons

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

internal class MacaroonTest {
    private val location = "http://mybank/"
    private val secret = "this is our super secret key; only we should know it".toByteArray()
    private val identifier = "we used our secret key"

    @Test
    fun `create macaroon directly`() {
        val macaroon = buildMacaroon(location, secret, identifier)
        assertEquals(location, macaroon.location)
        assertEquals(identifier, macaroon.identifier)
        assertEquals(
            "e3d9e02908526c4c0039ae15114115d97fdd68bf2ba379b342aaf0f617d0552f",
            macaroon.signature.toHex()
        )
    }

    @Test
    fun `add first part caveat`() {
        val macaroon = buildMacaroon(location, secret, identifier) {
            addCaveat("account = 3735928559")
        }
        assertEquals(location, macaroon.location)
        assertEquals(identifier, macaroon.identifier)
        assertEquals(Caveat(Type.CID, "account = 3735928559"), macaroon.caveats.first())
        assertEquals(
            "1efe4763f290dbce0c1d08477367e11f4eee456a64933cf662d79772dbb82128",
            macaroon.signature.toHex()
        )
    }

    @Test
    fun `can be create from an existing macaroon`() {
        val macaroon = buildMacaroon(buildMacaroon(location, secret, identifier) {
            addCaveat("account = 3735928559")
        })
        assertEquals(location, macaroon.location)
        assertEquals(identifier, macaroon.identifier)
        assertEquals(Caveat(Type.CID, "account = 3735928559"), macaroon.caveats.first())
        assertEquals(
            "1efe4763f290dbce0c1d08477367e11f4eee456a64933cf662d79772dbb82128",
            macaroon.signature.toHex()
        )
    }

    @Test
    fun `supports many first part caveats`() {
        val macaroon = buildMacaroon(buildMacaroon(location, secret, identifier) {
            addCaveat("account = 3735928559")
            addCaveat("time < 2015-01-01T00:00")
            addCaveat("email = alice@example.org")
        })
        assertEquals(location, macaroon.location)
        assertEquals(identifier, macaroon.identifier)
        assertEquals(Caveat(Type.CID, "account = 3735928559"), macaroon.caveats[0])
        assertEquals(Caveat(Type.CID, "time < 2015-01-01T00:00"), macaroon.caveats[1])
        assertEquals(Caveat(Type.CID, "email = alice@example.org"), macaroon.caveats[2])
        assertEquals(
            "882e6d59496ed5245edb7ab5b8839ecd63e5d504e54839804f164070d8eed952",
            macaroon.signature.toHex()
        )
    }

    @Test
    fun `support third party caveat`() {
        val thirdPartyLocation = "http://auth.mybank/"
        val thirdPartyKey = "4; guaranteed random by a fair toss of the dice".toByteArray()
        val thirdPartyIdentifier = "this was how we remind auth of key/pred"
        val macaroon = buildMacaroon(buildMacaroon(location, secret, identifier) {
            addCaveat("account = 3735928559")
            addCaveat(thirdPartyLocation, thirdPartyKey, thirdPartyIdentifier)
        })
        assertEquals(location, macaroon.location)
        assertEquals(identifier, macaroon.identifier)
        assertEquals(Caveat(Type.CID, "account = 3735928559"), macaroon.caveats[0])
        assertEquals(Caveat(Type.CID, thirdPartyIdentifier), macaroon.caveats[1])
        assertEquals(Caveat(Type.CL, thirdPartyLocation), macaroon.caveats[3])
        assertEquals(4, macaroon.caveats.size)
    }

    @Test
    fun `can bind macaroon`() {
        val discharged = buildMacaroon(buildMacaroon(location, secret, identifier) {
            addCaveat("account = 3735928559")
            addCaveat("http://auth.mybank/", "4; guaranteed random by a fair toss of the dice".toByteArray(), "this was how we remind auth of key/pred")
        })

        val macaroon = buildMacaroon(buildMacaroon(location, secret, identifier) {
            addCaveat("account = 3735928559")
            bind(discharged)
        })
        assertEquals(location, macaroon.location)
        assertEquals(identifier, macaroon.identifier)
        assertEquals(Caveat(Type.CID, "account = 3735928559"), macaroon.caveats[0])
        assertNotEquals(discharged.signature, macaroon.signature)
    }
}

internal fun ByteArray.toHex(): String = joinToString(separator = "") { eachByte -> "%02x".format(eachByte) }

