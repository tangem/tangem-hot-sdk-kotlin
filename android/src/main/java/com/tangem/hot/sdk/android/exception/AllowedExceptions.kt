package com.tangem.hot.sdk.android.exception

import com.tangem.common.core.TangemSdkError
import com.tangem.hot.sdk.exception.NoContextualAuthAvailable
import com.tangem.hot.sdk.exception.WrongPasswordException

internal fun isAllowedException(exception: Throwable): Boolean {
    return exception is WrongPasswordException ||
        exception is NoContextualAuthAvailable ||
        exception is TangemSdkError.AuthenticationCanceled ||
        exception is TangemSdkError.AuthenticationFailed ||
        exception is TangemSdkError.AuthenticationLockout ||
        exception is TangemSdkError.AuthenticationUnavailable ||
        exception is TangemSdkError.AuthenticationAlreadyInProgress ||
        exception is TangemSdkError.AuthenticationNotInitialized ||
        exception is TangemSdkError.AuthenticationPermanentLockout
}