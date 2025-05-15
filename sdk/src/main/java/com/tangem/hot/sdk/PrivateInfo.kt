package com.tangem.hot.sdk

interface PrivateInfo {
    val state : State

    suspend fun startUsing()
    fun vanish()

    enum class State {
        NotUsing, Using, Vanished
    }
}