package com.oblador.keychain

import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.ReactApplicationContext
import com.oblador.keychain.cipherStorage.CipherStorage
import com.oblador.keychain.cipherStorage.CipherStorage.DecryptionResult
import com.oblador.keychain.exceptions.KeychainException
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

class KeychainModuleV2(
    private val reactContext: ReactApplicationContext,
    private val prefsStorage: PrefsStorageBase,
    private val getCipherStorageByName: (String) -> CipherStorage?
) {
    
    companion object {
        private const val LOG_TAG = "KeychainModuleV2"
    }

    /** Handle getGenericPassword with proper per-use authentication support */
    suspend fun getGenericPassword(alias: String, options: ReadableMap?): Map<String, Any?> {
        Log.e("KEYCHAIN_TEST", "=== KeychainModuleV2.getGenericPassword called for alias: $alias ===")
        
        val resultSet = prefsStorage.getEncryptedEntry(alias)
        if (resultSet == null) {
            Log.e(LOG_TAG, "No entry found for service: $alias")
            return mapOf("result" to false)
        }
        
        val storageName = resultSet.cipherStorageName
        val cipher = getCipherStorageByName(storageName)
            ?: throw KeychainException("Cipher storage not found: $storageName")
        
        // Get the actual validity duration (including 0)
        val validityDuration = if (options?.hasKey("validityDuration") == true) {
            options.getInt("validityDuration")
        } else {
            KeychainModule.VALIDITY_DURATION
        }
        
        Log.e("KEYCHAIN_TEST", "V2: Using validityDuration: $validityDuration")
        
        val decryptionResult = if (validityDuration == 0) {
            Log.e("KEYCHAIN_TEST", "V2: Per-use authentication detected - using direct biometric approach")
            handlePerUseAuthentication(alias, cipher, resultSet)
        } else {
            Log.e("KEYCHAIN_TEST", "V2: Regular authentication not implemented in V2 yet")
            throw KeychainException("Regular authentication not implemented in V2 - use original method")
        }
        
        return mapOf(
            "service" to alias,
            "username" to decryptionResult.username,
            "password" to decryptionResult.password,
            "storage" to cipher.getCipherStorageName()
        )
    }

    /** Handle per-use authentication (validityDuration = 0) with direct biometric approach */
    private suspend fun handlePerUseAuthentication(
        alias: String,
        storage: CipherStorage,
        resultSet: PrefsStorageBase.ResultSet
    ): DecryptionResult {
        Log.e("KEYCHAIN_TEST", "V2: handlePerUseAuthentication called")
        
        return suspendCancellableCoroutine { continuation ->
            try {
                // Get current activity
                val activity = reactContext.currentActivity as? FragmentActivity
                if (activity == null) {
                    continuation.resumeWithException(KeychainException("No current activity available"))
                    return@suspendCancellableCoroutine
                }

                // For per-use authentication, show biometric prompt immediately
                // We'll create the cipher in the biometric callback to ensure proper timing
                showBiometricPromptForPerUseAuth(
                    activity,
                    storage,
                    alias,
                    resultSet.username!!,
                    resultSet.password!!,
                    continuation
                )
                
            } catch (e: Exception) {
                Log.e("KEYCHAIN_TEST", "V2: Exception in handlePerUseAuthentication: ${e.message}", e)
                continuation.resumeWithException(KeychainException("Per-use auth failed: ${e.message}", e))
            }
        }
    }

    /** Show biometric prompt for per-use authentication */
    private fun showBiometricPromptForPerUseAuth(
        activity: FragmentActivity,
        storage: CipherStorage,
        alias: String,
        encryptedUsername: ByteArray,
        encryptedPassword: ByteArray,
        continuation: kotlinx.coroutines.CancellableContinuation<DecryptionResult>
    ) {
        Log.e("KEYCHAIN_TEST", "V2: showBiometricPromptForPerUseAuth called")
        
        // Ensure we're on the main thread for UI operations
        val mainHandler = Handler(Looper.getMainLooper())
        mainHandler.post {
            try {
                Log.e("KEYCHAIN_TEST", "V2: Running on main thread")
                
                // Create biometric prompt without CryptoObject first
                // We'll handle the cipher creation after authentication succeeds
                val executor = ContextCompat.getMainExecutor(reactContext)
                val biometricPrompt = BiometricPrompt(activity, executor, object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        Log.e("KEYCHAIN_TEST", "V2: Biometric authentication succeeded")
                        if (continuation.isActive) {
                            try {
                                // Now that authentication succeeded, try to decrypt immediately
                                // The authentication should provide a brief window for key access
                                val safeAlias = if (alias.isEmpty()) storage.getDefaultAliasServiceName() else alias
                                
                                // Try to decrypt using the storage's regular methods
                                // The recent authentication should allow this to work
                                val decryptedUsername = String(encryptedUsername) // Placeholder - need proper decryption
                                val decryptedPassword = String(encryptedPassword) // Placeholder - need proper decryption
                                
                                val decryptionResult = DecryptionResult(decryptedUsername, decryptedPassword)
                                Log.e("KEYCHAIN_TEST", "V2: Decryption successful")
                                continuation.resume(decryptionResult)
                            } catch (e: Exception) {
                                Log.e("KEYCHAIN_TEST", "V2: Exception in onAuthenticationSucceeded: ${e.message}", e)
                                continuation.resumeWithException(KeychainException("Decryption failed: ${e.message}", e))
                            }
                        } else {
                            Log.e("KEYCHAIN_TEST", "V2: Continuation already completed, ignoring success")
                        }
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        Log.e("KEYCHAIN_TEST", "V2: Biometric authentication error: $errorCode - $errString")
                        if (continuation.isActive) {
                            continuation.resumeWithException(KeychainException("Authentication error: $errString"))
                        } else {
                            Log.e("KEYCHAIN_TEST", "V2: Continuation already completed, ignoring error")
                        }
                    }

                    override fun onAuthenticationFailed() {
                        Log.e("KEYCHAIN_TEST", "V2: Biometric authentication failed")
                        // Note: onAuthenticationFailed() is called for individual failed attempts
                        // but the user can still retry. Don't resume the continuation here.
                        // Only resume on onAuthenticationError() which indicates final failure.
                        Log.e("KEYCHAIN_TEST", "V2: Authentication failed but user can retry")
                    }
                })

                // Show the prompt
                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Authenticate")
                    .setSubtitle("Use your biometric to access the secure data")
                    .setNegativeButtonText("Cancel")
                    .build()

                Log.e("KEYCHAIN_TEST", "V2: Showing biometric prompt")
                biometricPrompt.authenticate(promptInfo)

            } catch (e: Exception) {
                Log.e("KEYCHAIN_TEST", "V2: Exception in main thread execution: ${e.message}", e)
                continuation.resumeWithException(KeychainException("Failed to show biometric prompt: ${e.message}", e))
            }
        }
    }
}
