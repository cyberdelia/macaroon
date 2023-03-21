package com.lapanthere.macaroon

import java.io.Serializable
import java.util.Base64

public data class Caveat internal constructor(
    public val identifier: String,
    public val location: String? = null,
    public val vid: ByteArray? = null,
) : Serializable {
    public val value: String
        get() = identifier

    public val isThirdParty: Boolean = vid != null
    public val isFirstParty: Boolean = !isThirdParty

    override fun toString(): String = when {
        vid != null -> """
            cid $identifier
            vid ${Base64.getUrlEncoder().withoutPadding().encodeToString(vid)}
            cl  $location
        """
        else ->
            """
            cid $value
            """
    }.trimIndent()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Caveat) return false

        if (identifier != other.identifier) return false
        if (location != other.location) return false
        if (vid != null) {
            if (other.vid == null) return false
            if (!vid.contentEquals(other.vid)) return false
        } else if (other.vid != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = identifier.hashCode()
        result = 31 * result + (location?.hashCode() ?: 0)
        result = 31 * result + (vid?.contentHashCode() ?: 0)
        return result
    }
}
