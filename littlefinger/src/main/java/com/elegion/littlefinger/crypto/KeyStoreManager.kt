package com.elegion.littlefinger.crypto

import android.annotation.TargetApi
import android.os.Build
import android.support.annotation.RequiresApi
import android.util.Log
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.SecretKey


/**
 * @author Azret Magometov
 */
@RequiresApi(api = Build.VERSION_CODES.M)
internal class KeyStoreManager{

    private var mKeyStore: IKeyStore

    init {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
            mKeyStore = RealKeyStore(keyStore)
        } catch (e: Exception) {
            mKeyStore = StubKeyStore()
            Log.d(TAG, "KeyStoreManager: ", e)
        }
    }

    fun isValidToUse() = mKeyStore.isValidToUse()

    @Throws(Exception::class)
    fun getPrivateKey(alias: String) = mKeyStore.getPrivateKey(alias)

    @Throws(Exception::class)
    fun getSecretKey(alias: String) = mKeyStore.getSecretKey(alias)

    @Throws(Exception::class)
    fun deleteKey(alias: String) = mKeyStore.deleteEntry(alias)

    @Throws(Exception::class)
    fun getPublicKey(alias: String) = mKeyStore.getPublicKey(alias)

    @Throws(Exception::class)
    fun containsKey(key: String) = mKeyStore.containAlias(key)


    companion object {

        private val TAG = KeyStoreManager::class.java.simpleName

        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
    }
}


interface IKeyStore {

    fun isValidToUse(): Boolean

    fun containAlias(key: String): Boolean

    fun deleteEntry(alias: String)

    fun getPrivateKey(alias: String): PrivateKey

    fun getPublicKey(alias: String): PublicKey

    fun getSecretKey(alias: String): SecretKey

}


class StubKeyStore : IKeyStore {
    override fun isValidToUse() = false

    override fun containAlias(key: String): Boolean {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun deleteEntry(alias: String) {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun getPrivateKey(alias: String): PrivateKey {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun getPublicKey(alias: String): PublicKey {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun getSecretKey(alias: String): SecretKey {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

}


@TargetApi(Build.VERSION_CODES.M)
class RealKeyStore(private val keyStore: KeyStore) : IKeyStore {

    init {
        keyStore.load(null)
    }

    override fun isValidToUse() = true

    override fun containAlias(key: String) = load { keyStore.containsAlias(key) }

    override fun getPrivateKey(alias: String) = load { keyStore.getKey(alias, null) as PrivateKey }

    override fun getPublicKey(alias: String) = load { keyStore.getCertificate(alias).publicKey as PublicKey }

    override fun getSecretKey(alias: String) = load { keyStore.getKey(alias, null) as SecretKey }

    override fun deleteEntry(alias: String) = load { if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias) }


    private fun <K> load(after: () -> K): K {
        try {
            keyStore.load(null)
            return after()
        } catch (e: GeneralSecurityException) {
            throw Exception("Keystore exception while getting public key", e)
        } catch (e: IOException) {
            throw Exception("Keystore exception while getting public key", e)
        }
    }


}

