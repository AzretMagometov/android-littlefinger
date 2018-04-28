package com.elegion.littlefinger.crypto

import android.util.Base64


/**
 * @author Azret Magometov
 */
internal class AesData(purpose: Purpose, inputText: String, val key: String) {
    val bytes: ByteArray
    val iv: ByteArray

    init {
        when (purpose) {
            Purpose.DECODE -> if (inputText.contains(SEPARATOR)) {
                val temp = inputText.split(SEPARATOR.toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
                bytes = Base64.decode(temp[0], Base64.NO_WRAP)
                iv = Base64.decode(temp[1], Base64.NO_WRAP)
            } else {
                throw IllegalArgumentException("Input string isn't valid. Missing SEPARATOR. Are you trying to decode not encoded string?")
            }

            Purpose.ENCODE -> {
                bytes = inputText.toByteArray()
                iv = ByteArray(0)
            }
        }
    }

    companion object {

        private const val SEPARATOR = "-SEPARATOR-"

        fun makeString(bytes: ByteArray, iv: ByteArray): String {
            val encodedString = Base64.encodeToString(bytes, Base64.NO_WRAP)
            val initialVector = Base64.encodeToString(iv, Base64.NO_WRAP)
            return "$encodedString$SEPARATOR$initialVector"
        }
    }

}