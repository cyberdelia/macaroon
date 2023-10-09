package com.lapanthere.macaroon.serialization

import com.lapanthere.macaroon.Macaroon
import com.lapanthere.macaroon.serialization.Field.END_OF_SECTION
import com.lapanthere.macaroon.serialization.Field.IDENTIFIER
import com.lapanthere.macaroon.serialization.Field.LOCATION
import com.lapanthere.macaroon.serialization.Field.SIGNATURE
import com.lapanthere.macaroon.serialization.Field.VERIFIER_ID
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.util.Base64

internal enum class Field(val value: Int) {
    LOCATION(1),
    IDENTIFIER(2),
    VERIFIER_ID(4),
    SIGNATURE(6),
    END_OF_SECTION(0),
    ;

    companion object {
        @JvmStatic
        fun findValue(value: Int): Field? = values().find { v -> v.value == value }
    }
}

internal object Serializer {
    fun serialize(macaroon: Macaroon): ByteArray =
        Encoder().use {
            it.write(2)
            it.write(LOCATION, macaroon.location)
            it.write(IDENTIFIER, macaroon.identifier)
            it.write(END_OF_SECTION)

            macaroon.caveats.forEach { caveat ->
                it.write(LOCATION, caveat.location)
                it.write(IDENTIFIER, caveat.identifier)
                it.write(VERIFIER_ID, caveat.vid)
                it.write(END_OF_SECTION)
            }

            it.write(END_OF_SECTION)
            it.write(SIGNATURE, macaroon.signature)
            it
        }.toByteArray()

    private class Encoder : Closeable {
        private val outputStream = ByteArrayOutputStream()
        private val wrappedStream = Base64.getUrlEncoder().withoutPadding().wrap(outputStream)

        fun write(b: ByteArray) {
            write(b.size)
            wrappedStream.write(b)
        }

        fun write(
            field: Field,
            value: ByteArray?,
        ) {
            if (value != null) {
                write(field)
                write(value)
            }
        }

        fun write(
            field: Field,
            value: String?,
        ) {
            if (value != null) {
                write(field)
                write(value)
            }
        }

        fun write(s: String) = write(s.toByteArray())

        fun write(section: Field) = write(section.value)

        fun write(i: Int) {
            var value = i
            while (value > 128) {
                wrappedStream.write((value and 127) or 128)
                value = value ushr 7
            }
            wrappedStream.write(value and 127)
        }

        fun toByteArray(): ByteArray = outputStream.toByteArray()

        override fun close() {
            wrappedStream.close()
            outputStream.close()
        }
    }
}
