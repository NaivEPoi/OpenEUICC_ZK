package net.typeblog.lpac_jni

sealed class ProfileDownloadState {
    class Registering : ProfileDownloadState()
    class CertInitializing : ProfileDownloadState()
    class Ordering : ProfileDownloadState()
    class Preparing : ProfileDownloadState()
    class Connecting : ProfileDownloadState()
    class Authenticating : ProfileDownloadState()
    class ConfirmingDownload(val metadata: RemoteProfileInfo?) : ProfileDownloadState()
    class Downloading : ProfileDownloadState()
    class Finalizing : ProfileDownloadState()
    class ZkRegistering : ProfileDownloadState()
    class ZkInitializingCertificate : ProfileDownloadState()
    class ZkOrdering : ProfileDownloadState()
}
