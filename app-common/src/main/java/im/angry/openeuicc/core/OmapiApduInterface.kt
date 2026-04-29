package im.angry.openeuicc.core

import android.se.omapi.Channel
import android.se.omapi.SEService
import android.se.omapi.Session
import android.util.Log
import im.angry.openeuicc.util.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import net.typeblog.lpac_jni.ApduInterface
import java.util.concurrent.atomic.AtomicInteger

class OmapiApduInterface(
    private val service: SEService,
    private val port: UiccPortInfoCompat,
    private val verboseLoggingFlow: Flow<Boolean>
) : ApduInterface, ApduInterfaceAtrProvider {
    companion object {
        const val TAG = "OmapiApduInterface"
    }

    private lateinit var session: Session
    private val index = AtomicInteger(0)
    private val channels = mutableMapOf<Int, Channel>()
    // Track the AID used to open each channel handle so we can re-open the same applet
    // when working around the Pixel HAL's 3-chunk limit on chained responses.
    private val aidByHandle = mutableMapOf<Int, ByteArray>()
    // Channels we've replaced (via refreshChannel) but haven't closed yet — closing
    // immediately can trigger a card-side RESET on this device, which clears the
    // applet's CLEAR_ON_RESET transient response buffer mid-drain. We hold them
    // open until logicalChannelClose runs and clean them up then.
    private val staleChannels = mutableListOf<Channel>()

    override val valid: Boolean
        get() = service.isConnected && (this::session.isInitialized && !session.isClosed)

    override val atr: ByteArray?
        get() = session.atr

    override fun connect() {
        session = service.getUiccReaderCompat(port.logicalSlotIndex + 1).openSession()
    }

    override fun disconnect() {
        session.close()
    }

    override fun logicalChannelOpen(aid: ByteArray): Int {
        val channel = session.openLogicalChannel(aid)
        check(channel != null) { "Failed to open logical channel (${aid.encodeHex()})" }
        // Hypothesis: the SE driver auto-injects the real card-level channel into CLA.
        // Returning 0 here keeps lpac's CLA-injection (cla |= handle & 0x0F) at 0x80,
        // matching what lpac CLI would see on the basic channel. We only ever have one
        // channel open per OmapiApduInterface instance at a time, so reusing slot 0 in
        // the map is safe.
        val handle = 0
        synchronized(channels) {
            channels[handle] = channel
            aidByHandle[handle] = aid
        }
        Log.d(TAG, "logicalChannelOpen aid=${aid.encodeHex()} -> handle=$handle")
        return handle
    }

    override fun logicalChannelClose(handle: Int) {
        val channel = channels[handle]
        check(channel != null) { "Invalid logical channel handle $handle" }
        if (channel.isOpen) channel.close()
        synchronized(channels) {
            channels.remove(handle)
            aidByHandle.remove(handle)
        }
        // Now safe to drop any channels we kept alive during refreshes.
        synchronized(staleChannels) {
            for (c in staleChannels) {
                try {
                    if (c.isOpen) c.close()
                } catch (_: Exception) {
                }
            }
            staleChannels.clear()
        }
    }

    override fun transmit(handle: Int, tx: ByteArray): ByteArray {
        val channel = channels[handle]
        check(channel != null) { "Invalid logical channel handle $handle" }

        Log.d(TAG, "OMAPI APDU (handle=$handle): ${tx.encodeHex()}")

        try {
            for (i in 0..10) {
                val first = channel.transmit(tx)
                Log.d(TAG, "OMAPI APDU response (${first.size}B): ${first.encodeHex()}")

                if (first.size == 2 && first[0] == 0x66.toByte() && first[1] == 0x01.toByte()) {
                    Log.d(TAG, "Received checksum error 0x6601, retrying (count = $i)")
                    continue
                }

                return drainResponse(handle, first)
            }

            throw RuntimeException("Retransmit attempts exhausted; this was likely caused by checksum errors")
        } catch (e: Exception) {
            Log.e(TAG, "OMAPI APDU exception")
            e.printStackTrace()
            throw e
        }
    }

    // Drain a chained response from the card.
    //
    // Two card-side chaining patterns are supported:
    //   * Standard SW=61XX → GET RESPONSE
    //   * Proprietary SW=91XX (used by ZkEsimApplet) → GET RESPONSE. The Android OMAPI
    //     HAL on Pixel rewrites 91XX to 9000, so we detect truncation by parsing the
    //     outer TLV length and comparing to received bytes.
    //
    // The Pixel HAL further bounds chained reads at ~3 GET RESPONSEs per APDU exchange
    // and returns 6881 ("logical channel not supported") on the 4th. We recover by
    // closing and re-opening the OMAPI logical channel — that resets the HAL exchange
    // state. The on-card pendingResponse buffer (CLEAR_ON_RESET) and offsets/active
    // (persistent fields) all survive a reselect, so the applet picks up where it left
    // off when the next GET RESPONSE arrives on the new channel.
    private fun drainResponse(handle: Int, first: ByteArray): ByteArray {
        if (first.size < 2) return first

        val accumulated = ArrayList<Byte>(first.size * 2)
        var res = first

        while (true) {
            val sw1 = res[res.size - 2].toInt() and 0xFF
            val sw2 = res[res.size - 1].toInt() and 0xFF

            // Append data portion (everything except the 2 SW bytes).
            for (i in 0 until res.size - 2) accumulated.add(res[i])

            // Standard chained-response signal.
            if (sw1 == 0x61) {
                val le = if (sw2 == 0) 0x00 else sw2
                res = issueGetResponse(handle, le.toByte()) ?: run {
                    accumulated.add(sw1.toByte())
                    accumulated.add(sw2.toByte())
                    return accumulated.toBytes()
                }
                continue
            }

            // Heuristic: 9000 with apparently-truncated TLV → ask for more anyway.
            if (sw1 == 0x90 && sw2 == 0x00) {
                val soFar = accumulated.toBytes()
                val expected = parseOuterTlvTotalLen(soFar)
                if (expected != null && expected > soFar.size) {
                    Log.w(
                        TAG,
                        "Response looks truncated: declared=$expected, got=${soFar.size} — issuing GET RESPONSE"
                    )
                    val maybeMore = issueGetResponse(handle, 0x00) ?: run {
                        accumulated.add(sw1.toByte())
                        accumulated.add(sw2.toByte())
                        return accumulated.toBytes()
                    }
                    val mSw1 = if (maybeMore.size >= 2) maybeMore[maybeMore.size - 2].toInt() and 0xFF else 0
                    val mSw2 = if (maybeMore.size >= 2) maybeMore[maybeMore.size - 1].toInt() and 0xFF else 0

                    // Pixel HAL returns 6881 after ~3 chained reads. Refresh the OMAPI
                    // channel and try once more — applet pendingResponse state survives.
                    if (maybeMore.size == 2 && mSw1 == 0x68 && mSw2 == 0x81) {
                        Log.w(TAG, "GET RESPONSE returned 6881; refreshing OMAPI channel and retrying")
                        if (refreshChannel(handle)) {
                            val retry = issueGetResponse(handle, 0x00)
                            if (retry != null && retry.size >= 2) {
                                res = retry
                                continue
                            }
                        }
                        // Refresh failed or retry empty — give up with what we have.
                        accumulated.add(sw1.toByte())
                        accumulated.add(sw2.toByte())
                        return accumulated.toBytes()
                    }

                    // 6D00 / 6A88 / 6F00 → card genuinely has no more data; stop draining.
                    if (mSw1 == 0x6D || mSw1 == 0x6A || mSw1 == 0x6F) {
                        accumulated.add(sw1.toByte())
                        accumulated.add(sw2.toByte())
                        return accumulated.toBytes()
                    }
                    res = maybeMore
                    continue
                }
            }

            // Terminal status — append SW and return.
            accumulated.add(sw1.toByte())
            accumulated.add(sw2.toByte())
            return accumulated.toBytes()
        }
    }

    private fun issueGetResponse(handle: Int, le: Byte): ByteArray? {
        val channel = channels[handle] ?: return null
        val getResp = byteArrayOf(0x80.toByte(), 0xC0.toByte(), 0x00, 0x00, le)
        return try {
            val res = channel.transmit(getResp)
            Log.d(TAG, "GET RESPONSE -> (${res.size}B): ${res.encodeHex()}")
            res
        } catch (e: Exception) {
            Log.w(TAG, "GET RESPONSE failed: ${e.message}")
            null
        }
    }

    // Open a NEW logical channel to the same AID without closing the old one,
    // and route subsequent transmits through it. Closing the previous channel
    // immediately triggers a card-side RESET on this device, which wipes the
    // applet's CLEAR_ON_RESET transient response buffer mid-drain. Holding both
    // channels open keeps the buffer intact so sendChunk can still read from it.
    // Stale channels are closed later in logicalChannelClose.
    private fun refreshChannel(handle: Int): Boolean {
        val aid = synchronized(channels) { aidByHandle[handle] } ?: run {
            Log.w(TAG, "refreshChannel: no AID recorded for handle=$handle")
            return false
        }
        val fresh = try {
            session.openLogicalChannel(aid)
        } catch (e: Exception) {
            Log.e(TAG, "refreshChannel: openLogicalChannel(${aid.encodeHex()}) threw: ${e.message}")
            null
        }
        if (fresh == null) {
            Log.e(TAG, "refreshChannel: openLogicalChannel(${aid.encodeHex()}) returned null")
            return false
        }
        val previous = synchronized(channels) {
            val p = channels[handle]
            channels[handle] = fresh
            p
        }
        if (previous != null) {
            synchronized(staleChannels) { staleChannels.add(previous) }
        }
        Log.d(TAG, "refreshChannel: opened aid=${aid.encodeHex()} on handle=$handle (kept old channel alive)")
        return true
    }

    // Parses the outermost DER-style TLV header and returns the total bytes the
    // entire TLV should occupy (header + value). Returns null if not parseable.
    private fun parseOuterTlvTotalLen(data: ByteArray): Int? {
        if (data.size < 2) return null
        val tag0 = data[0].toInt() and 0xFF
        val tagLen = if ((tag0 and 0x1F) == 0x1F) 2 else 1
        if (data.size < tagLen + 1) return null
        val firstLen = data[tagLen].toInt() and 0xFF
        if (firstLen < 0x80) {
            return tagLen + 1 + firstLen
        }
        val numLenBytes = firstLen and 0x7F
        if (numLenBytes == 0 || numLenBytes > 4) return null
        if (data.size < tagLen + 1 + numLenBytes) return null
        var len = 0
        for (i in 0 until numLenBytes) {
            len = (len shl 8) or (data[tagLen + 1 + i].toInt() and 0xFF)
        }
        return tagLen + 1 + numLenBytes + len
    }

    private fun ArrayList<Byte>.toBytes(): ByteArray = ByteArray(size).also { for (i in indices) it[i] = this[i] }
}
