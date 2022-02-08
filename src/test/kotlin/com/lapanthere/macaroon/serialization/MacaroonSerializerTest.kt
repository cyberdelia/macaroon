package com.lapanthere.macaroon.serialization

import com.lapanthere.macaroon.Macaroon
import com.lapanthere.macaroon.buildMacaroon
import com.lapanthere.macaroon.generateSecretKey
import kotlin.test.Test
import kotlin.test.assertEquals

internal class MacaroonSerializerTest {
    @Test
    fun `round-trip serialization`() {
        val macaroon = buildMacaroon("macaroon/sample", generateSecretKey(), "macaroon test") {
            require("account = 1234")
            require("macaroon/party", generateSecretKey(), "group = admin")
        }

        val serialized = Serializer.serialize(macaroon)
        val deserialized = Macaroon(serialized)

        assertEquals(macaroon, deserialized)
    }
}
