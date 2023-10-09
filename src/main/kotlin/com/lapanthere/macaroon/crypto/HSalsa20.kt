package com.lapanthere.macaroon.crypto

import org.bouncycastle.crypto.engines.Salsa20Engine
import org.bouncycastle.util.Pack
import java.nio.charset.StandardCharsets

/** An implementation of the HSalsa20 hash based on the Bouncy Castle Salsa20 core.  */
internal object HSalsa20 {
    private val SIGMA = "expand 32-byte k".toByteArray(StandardCharsets.US_ASCII)
    private val SIGMA_0 = Pack.littleEndianToInt(SIGMA, 0)
    private val SIGMA_4 = Pack.littleEndianToInt(SIGMA, 4)
    private val SIGMA_8 = Pack.littleEndianToInt(SIGMA, 8)
    private val SIGMA_12 = Pack.littleEndianToInt(SIGMA, 12)

    fun hsalsa20(
        output: ByteArray,
        input: ByteArray,
        k: ByteArray,
    ) {
        val x = IntArray(16)
        val in0 = Pack.littleEndianToInt(input, 0)
        val in4 = Pack.littleEndianToInt(input, 4)
        val in8 = Pack.littleEndianToInt(input, 8)
        val in12 = Pack.littleEndianToInt(input, 12)
        x[0] = SIGMA_0
        x[1] = Pack.littleEndianToInt(k, 0)
        x[2] = Pack.littleEndianToInt(k, 4)
        x[3] = Pack.littleEndianToInt(k, 8)
        x[4] = Pack.littleEndianToInt(k, 12)
        x[5] = SIGMA_4
        x[6] = in0
        x[7] = in4
        x[8] = in8
        x[9] = in12
        x[10] = SIGMA_8
        x[11] = Pack.littleEndianToInt(k, 16)
        x[12] = Pack.littleEndianToInt(k, 20)
        x[13] = Pack.littleEndianToInt(k, 24)
        x[14] = Pack.littleEndianToInt(k, 28)
        x[15] = SIGMA_12
        Salsa20Engine.salsaCore(20, x, x)
        x[0] -= SIGMA_0
        x[5] -= SIGMA_4
        x[10] -= SIGMA_8
        x[15] -= SIGMA_12
        x[6] -= in0
        x[7] -= in4
        x[8] -= in8
        x[9] -= in12
        Pack.intToLittleEndian(x[0], output, 0)
        Pack.intToLittleEndian(x[5], output, 4)
        Pack.intToLittleEndian(x[10], output, 8)
        Pack.intToLittleEndian(x[15], output, 12)
        Pack.intToLittleEndian(x[6], output, 16)
        Pack.intToLittleEndian(x[7], output, 20)
        Pack.intToLittleEndian(x[8], output, 24)
        Pack.intToLittleEndian(x[9], output, 28)
    }
}
