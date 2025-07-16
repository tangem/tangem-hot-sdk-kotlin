package com.tangem.hot.sdk.android.exception

import com.tangem.hot.sdk.exception.WrongPasswordException

internal fun isAllowedException(exception: Throwable): Boolean {
    return exception is WrongPasswordException
}