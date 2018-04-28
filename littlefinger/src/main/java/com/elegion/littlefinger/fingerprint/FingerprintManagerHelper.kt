package com.elegion.littlefinger.fingerprint

import android.annotation.TargetApi
import android.app.KeyguardManager
import android.content.Context
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.os.CancellationSignal
import android.os.Handler
import android.support.annotation.RequiresApi
import android.util.Log


/**
 * @author Azret Magometov
 */


class FingerprintManagerHelper(context: Context) {

    private val mFingerprintManager =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                RealFingerprintManager(context.getSystemService(Context.FINGERPRINT_SERVICE) as FingerprintManager)
            } else {
                StubFingerprintManager()
            }

    private val mKeyguardManager: KeyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager

    private var mCancellationSignal: CancellationSignal? = null

    private var mCanceledByUser = false


    fun isFingerprintSupported() = mFingerprintManager.isHardwareDetected()

    @TargetApi(Build.VERSION_CODES.M)
    fun getSensorState(): AuthResult {
        if (!isFingerprintSupported()) {
            return AuthResult.getNotSupportedResult()
        }

        if (!mKeyguardManager.isKeyguardSecure) {
            return AuthResult.getUnsecuredResult()
        }

        return if (!mFingerprintManager.hasEnrolledFingerprints()) {
            AuthResult.getNoEnrolledFpResult()
        } else {
            AuthResult.getReadyToUseResult()
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    fun startAuth(cryptoObject: FingerprintManager.CryptoObject?, callback: (AuthResult) -> (Unit)) {

        val sensorState = getSensorState()

        if (sensorState.mState != State.READY_TO_USE) {
            callback(AuthResult.getExceptionResult(IllegalStateException("Sensor isn't ready to use. Check sensor state")))
            return
        }

        mCancellationSignal = CancellationSignal()
        mCanceledByUser = false

        mFingerprintManager.authenticate(cryptoObject, mCancellationSignal, 0,
                object : FingerprintManager.AuthenticationCallback() {

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        mCancellationSignal = null
                        callback(AuthResult.getErrorResult(errorCode, errString as String, mCanceledByUser))
                    }

                    override fun onAuthenticationHelp(helpCode: Int, helpString: CharSequence) {
                        callback(AuthResult.getHelpResult(helpCode, helpString as String))
                    }

                    override fun onAuthenticationSucceeded(authenticationResult: FingerprintManager.AuthenticationResult) {
                        mCancellationSignal = null
                        callback(AuthResult.getRecognizedResult(authenticationResult.cryptoObject))
                    }

                    override fun onAuthenticationFailed() {
                        callback(AuthResult.getFailedResult())
                    }
                }, null)

    }

    fun cancelAuth(callback: CancelCallback?) {
        if (mCancellationSignal != null && !mCancellationSignal!!.isCanceled) {
            mCanceledByUser = true
            mCancellationSignal!!.cancel()
            callback?.onCancel()
        }
    }
}

interface IFingerprintManager {
    fun isHardwareDetected(): Boolean
    fun hasEnrolledFingerprints(): Boolean
    fun authenticate(cryptoObject: FingerprintManager.CryptoObject?, cancellationSignal: CancellationSignal?, flags: Int, authenticationCallback: FingerprintManager.AuthenticationCallback, handler: Handler?)
}

class StubFingerprintManager : IFingerprintManager {
    override fun isHardwareDetected() = false
    override fun hasEnrolledFingerprints() = false
    override fun authenticate(cryptoObject: FingerprintManager.CryptoObject?, cancellationSignal: CancellationSignal?, flags: Int, authenticationCallback: FingerprintManager.AuthenticationCallback, handler: Handler?) {
        Log.v(this.javaClass.simpleName, "Nothing to do")
    }
}

@RequiresApi(Build.VERSION_CODES.M)
class RealFingerprintManager(private val fingerprintManager: FingerprintManager) : IFingerprintManager {
    override fun isHardwareDetected() = fingerprintManager.isHardwareDetected
    override fun hasEnrolledFingerprints() = fingerprintManager.hasEnrolledFingerprints()
    override fun authenticate(cryptoObject: FingerprintManager.CryptoObject?, cancellationSignal: CancellationSignal?, flags: Int, authenticationCallback: FingerprintManager.AuthenticationCallback, handler: Handler?) = fingerprintManager.authenticate(cryptoObject, cancellationSignal, flags, authenticationCallback, handler)
}


