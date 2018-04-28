package com.elegion.littlefinger.fingerprint

import android.hardware.fingerprint.FingerprintManager
import android.security.keystore.KeyPermanentlyInvalidatedException


/**
 * @author Azret Magometov
 */

class AuthResult private constructor(val mState: State = State.UNDEFINED,
                                     val mErrorCode: Int = -1,
                                     val mCanceledByUser: Boolean = false,
                                     val mCryptoObject: FingerprintManager.CryptoObject? = null,
                                     val mThrowable: Throwable? = null,
                                     val mData: String? = null) {


    val isKeyInvalidated = mState == State.EXCEPTION && mThrowable is KeyPermanentlyInvalidatedException

    companion object {

        fun getNotSupportedResult() = AuthResult(mState = State.NOT_SUPPORTED, mThrowable = IllegalStateException("Device does not support fingerprints"))

        fun getUnsecuredResult() = AuthResult(mState = State.UNSECURED, mThrowable = IllegalStateException("Device is not secured"))

        fun getNoEnrolledFpResult() = AuthResult(mState = State.NO_ENROLLED_FP, mThrowable = IllegalStateException("There is no enrolled fingerprints on this device"))

        fun getReadyToUseResult() = AuthResult(mState = State.READY_TO_USE, mData = "Touch the sensor")

        fun getRecognizedResult(cryptoObject: FingerprintManager.CryptoObject) = AuthResult(mState = State.SUCCESS, mData = "Recognition success", mCryptoObject = cryptoObject)

        fun getHelpResult(code: Int, message: String) = AuthResult(mState = State.HELP, mThrowable = IllegalStateException(message), mErrorCode = code)

        fun getFailedResult() = AuthResult(mState = State.FAIL, mThrowable = IllegalStateException("Can't recognize. User should touch sensor again"))

        fun getErrorResult(code: Int, message: String, canceledByUser: Boolean) = AuthResult(mState = State.ERROR, mThrowable = IllegalStateException(message), mErrorCode = code, mCanceledByUser = canceledByUser)

        fun getExceptionResult(throwable: Throwable) = AuthResult(mState = State.EXCEPTION, mThrowable = throwable)

        fun getCryptoOperationResult(data: String) = AuthResult(mState = State.SUCCESS, mData = data)

    }

}

interface CompleteCallback {
    fun onCompleted(result: AuthResult)
}

interface CancelCallback {
    fun onCancel()
}

enum class State {
    //'prepare to use' states
    NOT_SUPPORTED,
    UNSECURED,
    NO_ENROLLED_FP,
    READY_TO_USE,

    //'auth callback result' states
    SUCCESS,
    HELP,
    FAIL,
    ERROR,

    //exception container
    EXCEPTION,
    UNDEFINED
}





