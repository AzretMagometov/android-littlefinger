package com.elegion.littlefinger.crypto

import android.annotation.TargetApi
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.GeneralSecurityException
import java.security.InvalidAlgorithmParameterException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.spec.InvalidParameterSpecException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec


/**
 * @author Azret Magometov
 */

@TargetApi(Build.VERSION_CODES.M)
class AesCryptographer {
    private val mKeyStoreManager = KeyStoreManager()
    private lateinit var mAesData: AesData

    @Throws(Exception::class)
    fun encode(cipher: Cipher): String {
        try {
            val bytes = cipher.doFinal(mAesData.bytes)
            val iv = cipher.parameters.getParameterSpec(IvParameterSpec::class.java).iv
            return AesData.makeString(bytes, iv)
        } catch (exception: IllegalBlockSizeException) {
            throw Exception("exception while encoding with cipher", exception)
        } catch (exception: BadPaddingException) {
            throw Exception("exception while encoding with cipher", exception)
        } catch (exception: InvalidParameterSpecException) {
            throw Exception("exception while encoding with cipher", exception)
        }

    }

    @Throws(Exception::class)
    fun decode(cipher: Cipher): String {
        try {
            val bytes = mAesData.bytes
            return String(cipher.doFinal(bytes))
        } catch (exception: IllegalBlockSizeException) {
            throw Exception("exception while decoding with cipher", exception)
        } catch (exception: BadPaddingException) {
            throw Exception("exception while decoding with cipher", exception)
        }

    }

    @Throws(Exception::class)
    fun getCryptoObject(text: String, purpose: Purpose, key: String): FingerprintManager.CryptoObject {
        mAesData = AesData(purpose, text, key)
        val cipher: Cipher = when (purpose) {
            Purpose.DECODE -> initDecodeCipher(mAesData.key, mAesData.iv)
            Purpose.ENCODE -> initEncodeCipher(mAesData.key)
        }
        return FingerprintManager.CryptoObject(cipher)
    }

    @Throws(Exception::class)
    private fun initDecodeCipher(key: String, iv: ByteArray): Cipher {
        val secretKey = mKeyStoreManager.getSecretKey(key)
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))
            return cipher
        } catch (e: KeyPermanentlyInvalidatedException) {
            mKeyStoreManager.deleteKey(key)
            throw e
        } catch (e: GeneralSecurityException) {
            throw Exception("An exception happens while initializing Cipher", e)
        }

    }

    @Throws(Exception::class)
    private fun initEncodeCipher(key: String): Cipher {
        if (!mKeyStoreManager.containsKey(key)) {
            generateKey(key)
        }

        val secretKey = mKeyStoreManager.getSecretKey(key)

        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            return cipher
        } catch (e: KeyPermanentlyInvalidatedException) {
            mKeyStoreManager.deleteKey(key)
            throw e
        } catch (e: GeneralSecurityException) {
            Log.e(TAG, "initEncodeCipher: ", e)
            throw Exception("An exception happens while initializing Cipher", e)
        }

    }

    @Throws(Exception::class)
    private fun generateKey(alias: String) {
        try {
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
            if (keyGenerator != null) {
                val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                        .setUserAuthenticationRequired(true)

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    builder.setInvalidatedByBiometricEnrollment(false)
                }

                keyGenerator.init(builder.build())
                keyGenerator.generateKey()
            }
        } catch (e: NoSuchAlgorithmException) {
            throw Exception("Can't generate key $alias", e)
        } catch (e: NoSuchProviderException) {
            throw Exception("Can't generate key $alias", e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw Exception("Can't generate key $alias", e)
        }

    }

    companion object {

        private val TAG = AesCryptographer::class.java.simpleName

        private const val TRANSFORMATION = "AES/CBC/PKCS7Padding"
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"

    }

}
