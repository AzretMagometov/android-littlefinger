package com.elegion.littlefinger

import android.content.Context
import android.os.Build
import com.elegion.littlefinger.crypto.AesCryptographer
import com.elegion.littlefinger.crypto.CryptoAlgorithm
import com.elegion.littlefinger.crypto.Purpose
import com.elegion.littlefinger.crypto.RsaCryptographer
import com.elegion.littlefinger.fingerprint.*


/**
 * @author Azret Magometov
 */
class LittleFinger(context: Context) {

    private val mFingerprintManagerHelper = FingerprintManagerHelper(context)

    val isFingerprintSupported: Boolean
        get() = mFingerprintManagerHelper.isFingerprintSupported()

    val isReadyToUse: Boolean
        get() = mFingerprintManagerHelper.getSensorState().mState == State.READY_TO_USE

    val sensorState: AuthResult
        get() = mFingerprintManagerHelper.getSensorState()

    fun authenticate(callback: (AuthResult) -> (Unit)) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            mFingerprintManagerHelper.startAuth(null, callback)
        } else {
            callback(AuthResult.getNotSupportedResult())
        }
    }

    fun encode(textToEncode: String, key: String, algorithm: CryptoAlgorithm, callback: CompleteCallback) {
        if (isReadyToUse) {
            performCryptoOperation(textToEncode, key, algorithm, Purpose.ENCODE, callback)
        } else {
            callback.onCompleted(sensorState)
        }
    }

    fun decode(textToDecode: String, key: String, algorithm: CryptoAlgorithm, callback: CompleteCallback) {
        if (isReadyToUse) {
            performCryptoOperation(textToDecode, key, algorithm, Purpose.DECODE, callback)
        } else {
            callback.onCompleted(sensorState)
        }
    }

    private fun performCryptoOperation(inputText: String, key: String, algorithm: CryptoAlgorithm, purpose: Purpose, callback: CompleteCallback) {
        if (algorithm == CryptoAlgorithm.AES) {
            performCryptoOperationWithAes(purpose, inputText, key, callback)
        }

        if (algorithm == CryptoAlgorithm.RSA) {
            if (purpose == Purpose.ENCODE) {
                encodeWithRsa(inputText, key, callback)
            } else if (purpose == Purpose.DECODE) {
                decodeWithRsa(inputText, key, callback)
            }
        }
    }

    fun cancelAuth() {
        mFingerprintManagerHelper.cancelAuth(null)
    }

    fun cancelAuth(cancelCallback: CancelCallback?) {
        mFingerprintManagerHelper.cancelAuth(cancelCallback)
    }

    private fun encodeWithRsa(textToEncode: String, key: String, callback: CompleteCallback) {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
            val cryptographer = RsaCryptographer()
            try {
                val encoded = cryptographer.encode(textToEncode, key)
                callback.onCompleted(AuthResult.getCryptoOperationResult(encoded))
            } catch (e: Exception) {
                callback.onCompleted(AuthResult.getExceptionResult(e))
            }

        } else {
            callback.onCompleted(AuthResult.getNotSupportedResult())
        }
    }

    private fun decodeWithRsa(textToDecode: String, key: String, callback: CompleteCallback) {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
            val cryptographer = RsaCryptographer()
            try {
                val cryptoObject = cryptographer.getCryptoObject(key)
                mFingerprintManagerHelper.startAuth(cryptoObject, { result ->
                    when (result.mState) {
                        State.SUCCESS -> try {
                            val decoded = cryptographer.decode(textToDecode, result.mCryptoObject!!.cipher)
                            callback.onCompleted(AuthResult.getCryptoOperationResult(decoded))
                        } catch (e: Exception) {
                            callback.onCompleted(AuthResult.getExceptionResult(e))
                        }

                        else -> callback.onCompleted(result)
                    }
                })
            } catch (e: Exception) {
                callback.onCompleted(AuthResult.getExceptionResult(e))
            }

        } else {
            callback.onCompleted(AuthResult.getNotSupportedResult())
        }
    }

    private fun performCryptoOperationWithAes(purpose: Purpose, text: String, key: String, callback: CompleteCallback) {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
            val aesCryptographer = AesCryptographer()
            try {
                val cryptoObject = aesCryptographer.getCryptoObject(text, purpose, key)
                mFingerprintManagerHelper.startAuth(cryptoObject, { result ->
                    when (result.mState) {
                        State.SUCCESS -> try {
                            val cipher = result.mCryptoObject!!.cipher
                            val resultString = if (purpose == Purpose.ENCODE)
                                aesCryptographer.encode(cipher)
                            else
                                aesCryptographer.decode(cipher)
                            callback.onCompleted(AuthResult.getCryptoOperationResult(resultString))
                        } catch (e: Exception) {
                            callback.onCompleted(AuthResult.getExceptionResult(e))
                        }

                        else -> callback.onCompleted(result)
                    }
                })
            } catch (e: Exception) {
                callback.onCompleted(AuthResult.getExceptionResult(e))
            }

        } else {
            callback.onCompleted(AuthResult.getNotSupportedResult())
        }
    }

}