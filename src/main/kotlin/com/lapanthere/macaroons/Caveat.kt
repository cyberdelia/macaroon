package com.lapanthere.macaroons

public enum class Type {
    LOCATION, IDENTIFIER, SIGNATURE, CID, VID, CL
}

public data class Caveat internal constructor(public val type: Type, public val descriptor: ByteArray) {
    internal constructor(type: Type, descriptor: String) : this(type, descriptor.toByteArray())

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + descriptor.contentHashCode()
        return result
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Caveat) return false

        if (type != other.type) return false
        if (!descriptor.contentEquals(other.descriptor)) return false

        return true
    }
}
