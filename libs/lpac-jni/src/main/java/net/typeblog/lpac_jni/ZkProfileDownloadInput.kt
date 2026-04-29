package net.typeblog.lpac_jni

data class ZkProfileDownloadInput(
    val mnoAddress: String,
    val pcaAddress: String,
    val confirmationCode: String? = null,
)