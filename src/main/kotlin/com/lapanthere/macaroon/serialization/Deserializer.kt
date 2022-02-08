package com.lapanthere.macaroon.serialization

import com.lapanthere.macaroon.Caveat
import com.lapanthere.macaroon.Macaroon
import com.lapanthere.macaroon.serialization.Field.END_OF_SECTION
import com.lapanthere.macaroon.serialization.Field.IDENTIFIER
import com.lapanthere.macaroon.serialization.Field.LOCATION
import com.lapanthere.macaroon.serialization.Field.SIGNATURE
import com.lapanthere.macaroon.serialization.Field.VERIFIER_ID
import java.io.ByteArrayInputStream
import java.io.Closeable
import java.io.DataInputStream
import java.util.Base64

internal object Deserializer {
    fun deserialize(data: ByteArray): Macaroon = Decoder(data).use {
        require(it.readInt() == 2) { "invalid serialization version" }
        val location = it.readString(LOCATION)
        val identifier = it.readString(IDENTIFIER)
        require(identifier != null)
        require(it.readInt() == END_OF_SECTION.value) { "invalid macaroon" }

        val caveats = mutableListOf<Caveat>()
        while (it.peekField() != END_OF_SECTION) {
            val caveatLocation = it.readString(LOCATION)
            val caveatIdentifier = it.readString(IDENTIFIER)
            require(caveatIdentifier != null) { "invalid macaroon" }
            val vid = it.readBytes(VERIFIER_ID)
            require(it.readInt() == END_OF_SECTION.value) { "invalid macaroon" }
            caveats.add(Caveat(caveatIdentifier, caveatLocation, vid))
        }

        require(it.readInt() == END_OF_SECTION.value) { "invalid macaroon" }
        val signature = it.readBytes(SIGNATURE)
        require(signature != null) { "invalid macaroon" }
        Macaroon(location, identifier, caveats, signature)
    }

    private class Decoder(b: ByteArray) : Closeable {
        private val inputStream = DataInputStream(
            Base64.getUrlDecoder().wrap(ByteArrayInputStream(b)).buffered()
        )

        fun readInt(): Int = inputStream.readUnsignedByte()

        fun peekField(): Field? {
            inputStream.mark(1)
            val value = inputStream.readUnsignedByte()
            inputStream.reset()
            return Field.findValue(value)
        }

        fun readBytes(field: Field): ByteArray? {
            return when (peekField()) {
                field -> {
                    inputStream.readUnsignedByte()
                    val length = readVarInt()
                    val byteArray = ByteArray(length)
                    inputStream.readFully(byteArray)
                    byteArray
                }
                else -> null
            }
        }

        fun readString(field: Field): String? = readBytes(field)?.toString(Charsets.UTF_8)

        fun readVarInt(): Int {
            var result = 0L
            var shift = 0
            var b: Long = inputStream.readUnsignedByte().toLong()
            while (b and 128 != 0L && shift <= 64) {
                result = result or (b and 127L shl shift)
                shift += 7
                b = inputStream.readUnsignedByte().toLong()
            }
            return (result or (b shl shift)).toInt()
        }

        override fun close() {
            inputStream.close()
        }
    }
}
