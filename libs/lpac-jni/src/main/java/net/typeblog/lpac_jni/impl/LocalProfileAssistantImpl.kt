package net.typeblog.lpac_jni.impl

import android.util.Log
import net.typeblog.lpac_jni.ProfileDownloadInput
import net.typeblog.lpac_jni.ApduInterface
import net.typeblog.lpac_jni.EuiccInfo2
import net.typeblog.lpac_jni.HttpInterface
import net.typeblog.lpac_jni.HttpInterface.HttpResponse
import net.typeblog.lpac_jni.LocalProfileAssistant
import net.typeblog.lpac_jni.LocalProfileInfo
import net.typeblog.lpac_jni.LocalProfileNotification
import net.typeblog.lpac_jni.LpacJni
import net.typeblog.lpac_jni.ProfileClass
import net.typeblog.lpac_jni.ProfileDownloadCallback
import net.typeblog.lpac_jni.ProfileDownloadState
import net.typeblog.lpac_jni.Version
import net.typeblog.lpac_jni.ZkProfileDownloadInput
import java.security.SecureRandom
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

class LocalProfileAssistantImpl(
    private val isdrAid: ByteArray,
    rawApduInterface: ApduInterface,
    rawHttpInterface: HttpInterface
) : LocalProfileAssistant {
    companion object {
        private const val TAG = "LocalProfileAssistantImpl"

        // AID of the ZkEsimApplet (zk/esim/applet/ZkEsimApplet) installed on the eUICC.
        // The applet handles tags BF44/BF45/BF46/BF47 used by the ZK pre-download phases.
        // Stock SGP.22 ISD-R does not understand these tags and would return SW=6982.
        private val ZK_APPLET_AID = byteArrayOf(
            0xD0.toByte(), 0x70, 0x02, 0xCA.toByte(),
            0x44, 0x90.toByte(), 0x01, 0x01,
        )
    }

    /**
     * A thin wrapper over ApduInterface to acquire exceptions and errors transparently
     */
    private class ApduInterfaceWrapper(val apduInterface: ApduInterface) :
        ApduInterface by apduInterface {
        var lastApduResponse: ByteArray? = null
        var lastApduException: Exception? = null

        override fun transmit(handle: Int, tx: ByteArray): ByteArray =
            try {
                apduInterface.transmit(handle, tx).also {
                    lastApduException = null
                    lastApduResponse = it
                }
            } catch (e: Exception) {
                lastApduResponse = null
                lastApduException = e
                throw e
            }
    }

    /**
     * Same for HTTP for diagnostics
     */
    private class HttpInterfaceWrapper(val httpInterface: HttpInterface) :
        HttpInterface by httpInterface {
        /**
         * The last HTTP response we have received from the SM-DP+ server.
         *
         * This is intended for error diagnosis. However, note that most SM-DP+ servers
         * respond with 200 even when there is an error. This needs to be taken into
         * account when designing UI.
         */
        var lastHttpResponse: HttpResponse? = null

        /**
         * The last exception that has been thrown during a HTTP connection
         */
        var lastHttpException: Exception? = null

        override fun transmit(url: String, tx: ByteArray, headers: Array<String>): HttpResponse =
            try {
                httpInterface.transmit(url, tx, headers).also {
                    lastHttpException = null
                    lastHttpResponse = it
                }
            } catch (e: Exception) {
                lastHttpResponse = null
                lastHttpException = e
                throw e
            }
    }

    // Controls concurrency of every single method in this class, since
    // the C-side is explicitly NOT thread-safe
    private val lock = ReentrantLock()

    private val apduInterface = ApduInterfaceWrapper(rawApduInterface)
    private val httpInterface = HttpInterfaceWrapper(rawHttpInterface)

    private var finalized = false
    private var contextHandle: Long = LpacJni.createContext(isdrAid, apduInterface, httpInterface)

    init {
        if (LpacJni.euiccInit(contextHandle) < 0) {
            throw IllegalArgumentException("Failed to initialize LPA")
        }

        val pkids = euiccInfo2?.euiccCiPKIdListForVerification ?: setOf()
        httpInterface.usePublicKeyIds(pkids.toTypedArray())
    }

    override fun setEs10xMss(mss: Byte) {
        LpacJni.euiccSetMss(contextHandle, mss)
    }

    override val valid: Boolean
        get() = !finalized && apduInterface.valid && try {
            // If we can read both eID and euiccInfo2 properly, we are likely looking at
            // a valid LocalProfileAssistant
            eID
            euiccInfo2!!
            true
        } catch (e: Exception) {
            false
        }

    override val profiles: List<LocalProfileInfo>
        get() = lock.withLock {
            val head = LpacJni.es10cGetProfilesInfo(contextHandle)
            var curr = head
            val ret = mutableListOf<LocalProfileInfo>()
            while (curr != 0L) {
                val state = LocalProfileInfo.State.fromString(LpacJni.profileGetStateString(curr))
                val clazz = ProfileClass.fromString(LpacJni.profileGetClassString(curr))
                ret.add(
                    LocalProfileInfo(
                        LpacJni.profileGetIccid(curr),
                        state,
                        LpacJni.profileGetName(curr),
                        LpacJni.profileGetNickname(curr),
                        LpacJni.profileGetServiceProvider(curr),
                        LpacJni.profileGetIsdpAid(curr),
                        clazz
                    )
                )
                curr = LpacJni.profilesNext(curr)
            }

            LpacJni.profilesFree(curr)
            return ret
        }

    override val notifications: List<LocalProfileNotification>
        get() = lock.withLock {
            val head = LpacJni.es10bListNotification(contextHandle)
            var curr = head

            try {
                val ret = mutableListOf<LocalProfileNotification>()
                while (curr != 0L) {
                    ret.add(
                        LocalProfileNotification(
                            LpacJni.notificationGetSeq(curr),
                            LocalProfileNotification.Operation.fromString(
                                LpacJni.notificationGetOperationString(
                                    curr
                                )
                            ),
                            LpacJni.notificationGetAddress(curr),
                            LpacJni.notificationGetIccid(curr),
                        )
                    )
                    curr = LpacJni.notificationsNext(curr)
                }
                return ret.sortedBy { it.seqNumber }.reversed()
            } finally {
                LpacJni.notificationsFree(head)
            }
        }

    override val eID: String
        get() = lock.withLock { LpacJni.es10cGetEid(contextHandle)!! }

    override val euiccInfo2: EuiccInfo2?
        get() = lock.withLock {
            val cInfo = LpacJni.es10cexGetEuiccInfo2(contextHandle)
            if (cInfo == 0L) return null

            try {
                return EuiccInfo2(
                    Version(LpacJni.euiccInfo2GetSGP22Version(cInfo)),
                    Version(LpacJni.euiccInfo2GetProfileVersion(cInfo)),
                    Version(LpacJni.euiccInfo2GetEuiccFirmwareVersion(cInfo)),
                    Version(LpacJni.euiccInfo2GetGlobalPlatformVersion(cInfo)),
                    LpacJni.euiccInfo2GetSasAcreditationNumber(cInfo),
                    Version(LpacJni.euiccInfo2GetPpVersion(cInfo)),
                    LpacJni.euiccInfo2GetFreeNonVolatileMemory(cInfo).toInt(),
                    LpacJni.euiccInfo2GetFreeVolatileMemory(cInfo).toInt(),
                    buildSet {
                        var cursor = LpacJni.euiccInfo2GetEuiccCiPKIdListForSigning(cInfo)
                        while (cursor != 0L) {
                            add(LpacJni.stringDeref(cursor))
                            cursor = LpacJni.stringArrNext(cursor)
                        }
                    },
                    buildSet {
                        var cursor = LpacJni.euiccInfo2GetEuiccCiPKIdListForVerification(cInfo)
                        while (cursor != 0L) {
                            add(LpacJni.stringDeref(cursor))
                            cursor = LpacJni.stringArrNext(cursor)
                        }
                    },
                )
            } finally {
                LpacJni.euiccInfo2Free(cInfo)
            }
        }

    override fun enableProfile(iccid: String, refresh: Boolean): Boolean = lock.withLock {
        LpacJni.es10cEnableProfile(contextHandle, iccid, refresh) == 0
    }

    override fun disableProfile(iccid: String, refresh: Boolean): Boolean = lock.withLock {
        LpacJni.es10cDisableProfile(contextHandle, iccid, refresh) == 0
    }

    override fun deleteProfile(iccid: String): Boolean = lock.withLock {
        LpacJni.es10cDeleteProfile(contextHandle, iccid) == 0
    }

    override fun downloadProfile(input: ProfileDownloadInput, callback: ProfileDownloadCallback) = lock.withLock {
        if (input.mnoAddress.isBlank() || input.pcaAddress.isBlank()) {
            throw LocalProfileAssistant.ProfileDownloadException(
                lpaErrorReason = "ZK_SERVER_ADDRESS_MISSING",
                httpInterface.lastHttpResponse,
                httpInterface.lastHttpException,
                apduInterface.lastApduResponse,
                apduInterface.lastApduException,
            )
        }

        val res = LpacJni.downloadProfile(
            contextHandle,
            input.address,
            input.matchingId,
            input.imei,
            input.confirmationCode,
            input.mnoAddress,
            input.pcaAddress,
            callback
        )

        if (res != 0) {
            val reason = LpacJni.downloadErrCodeToString(-res)

            // The ZK test workflow re-installs the same profile every run, so the eUICC
            // returns ICCID_ALREADY_EXISTS on the second attempt. Treat that as success.
            if (reason == "ES10B_ERROR_REASON_INSTALL_FAILED_DUE_TO_ICCID_ALREADY_EXISTS_ON_EUICC") {
                LpacJni.cancelSessions(contextHandle)
                return@withLock
            }

            // Construct the error now to store any error information we _can_ access
            val err = LocalProfileAssistant.ProfileDownloadException(
                lpaErrorReason = reason,
                httpInterface.lastHttpResponse,
                httpInterface.lastHttpException,
                apduInterface.lastApduResponse,
                apduInterface.lastApduException,
            )

            // Cancel only after the final ES9+/ES10 download session has actually started.
            if (LpacJni.downloadNeedsCancel(contextHandle)) {
                LpacJni.cancelSessions(contextHandle)
            }

            throw err
        }
    }

    override fun downloadProfileZk(
        input: ZkProfileDownloadInput,
        callback: ProfileDownloadCallback,
    ) = lock.withLock {
        fun fail(code: Int): Nothing {
            val err = LocalProfileAssistant.ProfileDownloadException(
                lpaErrorReason = LpacJni.downloadErrCodeToString(-code),
                httpInterface.lastHttpResponse,
                httpInterface.lastHttpException,
                apduInterface.lastApduResponse,
                apduInterface.lastApduException,
            )
            LpacJni.cancelSessions(contextHandle)
            throw err
        }

        // The ZK APDUs (BF44/45/46/47) live in a separate JavaCard applet, not in the
        // SGP.22 ISD-R. Switch the channel's AID for phases 1-3 and switch back for
        // phase 4 (standard SM-DP+ download via the real ISD-R).
        fun useAid(aid: ByteArray) {
            LpacJni.euiccFini(contextHandle)
            LpacJni.setIsdrAid(contextHandle, aid)
            if (LpacJni.euiccInit(contextHandle) < 0) fail(-1)
        }

        useAid(ZK_APPLET_AID)
        try {
            callback.onStatusUpdate(ProfileDownloadState.ZkRegistering())
            val r1 = LpacJni.zkRegister(contextHandle, input.mnoAddress)
            if (r1 != 0) fail(r1)

            callback.onStatusUpdate(ProfileDownloadState.ZkInitializingCertificate())
            val seed = ByteArray(32).also { SecureRandom().nextBytes(it) }
            val r2 = LpacJni.zkCertInit(contextHandle, input.pcaAddress, seed)
            if (r2 != 0) fail(r2)

            callback.onStatusUpdate(ProfileDownloadState.ZkOrdering())
            val order = LpacJni.zkOrder(contextHandle, input.mnoAddress) ?: fail(-1)
            val smdp = order.smdpAddress ?: fail(-1)
            val matchingId = order.matchingId

            // Phase 4: standard SM-DP+ download against the address returned by zkOrder.
            // Restore the original ISD-R AID so es10b/es9p/es10c work normally.
            useAid(isdrAid)

            downloadProfile(
                ProfileDownloadInput(
                    address = smdp,
                    matchingId = matchingId,
                    imei = null,
                    confirmationCode = input.confirmationCode,
                ),
                callback,
            )
        } finally {
            // If we threw during phases 1-3 the channel is still pointed at the ZK
            // applet; restore ISD-R so subsequent ops on this LPA instance work.
            // No-op if useAid(isdrAid) already ran.
            runCatching { useAid(isdrAid) }
        }
    }

    override fun deleteNotification(seqNumber: Long): Boolean = lock.withLock {
        LpacJni.es10bDeleteNotification(contextHandle, seqNumber) == 0
    }

    override fun handleNotification(seqNumber: Long): Boolean = lock.withLock {
        LpacJni.handleNotification(contextHandle, seqNumber).also {
            Log.d(TAG, "handleNotification $seqNumber = $it")
        } == 0
    }

    override fun setNickname(iccid: String, nickname: String) = lock.withLock {
        val encoded = try {
            Charsets.UTF_8.encode(nickname).array()
        } catch (e: CharacterCodingException) {
            throw LocalProfileAssistant.ProfileNameIsInvalidUTF8Exception()
        }

        if (encoded.size >= 64) {
            throw LocalProfileAssistant.ProfileNameTooLongException()
        }

        val encodedNullTerminated = encoded + byteArrayOf(0)

        if (LpacJni.es10cSetNickname(contextHandle, iccid, encodedNullTerminated) != 0) {
            throw LocalProfileAssistant.ProfileRenameException()
        }
    }

    override fun euiccMemoryReset() {
        lock.withLock {
            LpacJni.es10cEuiccMemoryReset(contextHandle)
        }
    }

    override fun close() = lock.withLock {
        if (!finalized) {
            LpacJni.euiccFini(contextHandle)
            LpacJni.destroyContext(contextHandle)
            finalized = true
        }
    }
}
