package com.elegion.littlefinger.crypto

import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.support.annotation.RequiresApi
import android.util.Base64
import java.security.*
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource


/**
 * @author Azret Magometov
 */
@RequiresApi(api = Build.VERSION_CODES.M)
class RsaCryptographer{

    private val mKeyStoreManager = KeyStoreManager()

    @Throws(Exception::class)
    fun encode(inputString: String, key: String): String {
        try {
            val encodingCipher = initEncodeCipher(key)
            val bytes = encodingCipher.doFinal(inputString.toByteArray())
            return Base64.encodeToString(bytes, Base64.NO_WRAP)
        } catch (exception: IllegalBlockSizeException) {
            throw Exception("Can't encode", exception)
        } catch (exception: BadPaddingException) {
            throw Exception("Can't encode", exception)
        }

    }

    @Throws(Exception::class)
    private fun createKey(key: String) {
        if (!mKeyStoreManager.containsKey(key)) {
            generateKeyPair(key)
        }
    }

    @Throws(Exception::class)
    fun decode(encodedString: String, cipher: Cipher): String {
        try {
            val bytes = Base64.decode(encodedString, Base64.NO_WRAP)
            return String(cipher.doFinal(bytes))
        } catch (exception: IllegalBlockSizeException) {
            throw Exception("Can't decode", exception)
        } catch (exception: BadPaddingException) {
            throw Exception("Can't decode", exception)
        }

    }

    @Throws(Exception::class)
    fun getCryptoObject(key: String): FingerprintManager.CryptoObject {
        val cipher = initDecodeCipher(key)
        return FingerprintManager.CryptoObject(cipher)
    }

    @Throws(Exception::class)
    private fun initDecodeCipher(key: String): Cipher {
        val privateKey = mKeyStoreManager.getPrivateKey(key)

        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, privateKey)
            return cipher
        } catch (e: KeyPermanentlyInvalidatedException) {
            mKeyStoreManager.deleteKey(key)
            throw e
        } catch (e: GeneralSecurityException) {
            throw Exception("Exception while initializing decoding cipher", e)
        }

    }

    @Throws(Exception::class)
    private fun initEncodeCipher(key: String): Cipher {
        try {
            createKey(key)

            val publicKey = mKeyStoreManager.getPublicKey(key)
            // workaround for using public key
            // from https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.html
            val unrestricted = KeyFactory.getInstance(publicKey.algorithm).generatePublic(X509EncodedKeySpec(publicKey.encoded))
            // from https://code.google.com/p/android/issues/detail?id=197719

            val spec = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)

            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, unrestricted, spec)

            return cipher

        } catch (e: GeneralSecurityException) {
            throw Exception("An exception happens while initializing Cipher", e)
        }

    }

    @Throws(Exception::class)
    private fun generateKeyPair(alias: String) {
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEY_STORE)
            if (keyPairGenerator != null) {
                val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                        .setUserAuthenticationRequired(true)

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    builder.setInvalidatedByBiometricEnrollment(false)
                }

                keyPairGenerator.initialize(builder.build())
                keyPairGenerator.generateKeyPair()
            }
        } catch (e: InvalidAlgorithmParameterException) {
            throw Exception("An exception happens while generating a new KeyPair", e)
        } catch (e: NoSuchAlgorithmException) {
            throw Exception("An exception happens while generating a new KeyPair", e)
        } catch (e: NoSuchProviderException) {
            throw Exception("An exception happens while generating a new KeyPair", e)
        }

    }

    companion object {
        private val TAG = RsaCryptographer::class.java.simpleName

        private val ANDROID_KEY_STORE = "AndroidKeyStore"

        private val TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"

    }

}