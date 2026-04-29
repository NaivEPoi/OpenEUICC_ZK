#include <euicc/base64.h>
#include <euicc/es10b.h>
#include <euicc/es12p.h>
#include <euicc/euicc.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "lpac-jni.h"

static jclass zk_order_result_class;
static jmethodID zk_order_result_constructor;

void lpac_zk_init(void) {
    LPAC_JNI_SETUP_ENV;

    jclass _zk_order_result_class =
            (*env)->FindClass(env, "net/typeblog/lpac_jni/ZkOrderResult");
    zk_order_result_class = (*env)->NewGlobalRef(env, _zk_order_result_class);
    zk_order_result_constructor = (*env)->GetMethodID(env, zk_order_result_class, "<init>",
                                                      "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");
}

static int b64_decode_alloc(const char *b64, uint8_t **out, int *out_len) {
    int alloc_len;

    *out = NULL;
    *out_len = 0;
    alloc_len = euicc_base64_decode_len(b64);
    if (alloc_len <= 0) {
        return -1;
    }
    *out = malloc((size_t) alloc_len);
    if (*out == NULL) {
        return -1;
    }
    *out_len = euicc_base64_decode(*out, b64);
    if (*out_len < 0) {
        free(*out);
        *out = NULL;
        *out_len = 0;
        return -1;
    }
    return 0;
}

JNIEXPORT jint JNICALL
Java_net_typeblog_lpac_1jni_LpacJni_zkRegister(JNIEnv *env, jobject thiz, jlong handle,
                                               jstring mno_addr) {
    struct euicc_ctx *ctx = (struct euicc_ctx *) handle;
    const char *_mno_addr = NULL;
    uint8_t *mno_nonce_commitment = NULL;
    int mno_nonce_commitment_len = 0;
    uint8_t *mno_partial_signature = NULL;
    int mno_partial_signature_len = 0;
    char *mno_partial_signature_b64 = NULL;
    struct es12p_register_challenge_result mno_challenge;
    struct es10b_zk_register_challenge_result euicc_challenge;
    int ret;

    memset(&mno_challenge, 0, sizeof(mno_challenge));
    memset(&euicc_challenge, 0, sizeof(euicc_challenge));

    _mno_addr = (*env)->GetStringUTFChars(env, mno_addr, NULL);

    ret = es12p_register_challenge(ctx, _mno_addr, &mno_challenge);
    syslog(LOG_INFO, "es12p_register_challenge = %d", ret);
    if (ret < 0) goto out;

    if (b64_decode_alloc(mno_challenge.mnoNonceCommitment, &mno_nonce_commitment,
                         &mno_nonce_commitment_len) < 0) {
        ret = -1;
        goto out;
    }

    ret = es10b_zk_register_challenge_r(ctx, &euicc_challenge, mno_nonce_commitment,
                                        (uint32_t) mno_nonce_commitment_len);
    syslog(LOG_INFO, "es10b_zk_register_challenge_r = %d", ret);
    if (ret < 0) goto out;

    ret = es12p_register_credential(ctx, _mno_addr, mno_challenge.requestId,
                                    euicc_challenge.blindedEligibilityChallenge,
                                    euicc_challenge.deviceAuthSignature,
                                    &mno_partial_signature_b64);
    syslog(LOG_INFO, "es12p_register_credential = %d", ret);
    if (ret < 0) goto out;

    if (b64_decode_alloc(mno_partial_signature_b64, &mno_partial_signature,
                         &mno_partial_signature_len) < 0) {
        ret = -1;
        goto out;
    }

    ret = es10b_zk_register_credential_r(ctx, mno_partial_signature,
                                         (uint32_t) mno_partial_signature_len);
    syslog(LOG_INFO, "es10b_zk_register_credential_r = %d", ret);
    if (ret < 0) goto out;

    ret = 0;

out:
    free(mno_nonce_commitment);
    free(mno_partial_signature);
    free(mno_partial_signature_b64);
    es12p_register_challenge_result_free(&mno_challenge);
    es10b_zk_register_challenge_result_free(&euicc_challenge);
    if (_mno_addr != NULL)
        (*env)->ReleaseStringUTFChars(env, mno_addr, _mno_addr);
    return ret;
}

JNIEXPORT jint JNICALL
Java_net_typeblog_lpac_1jni_LpacJni_zkCertInit(JNIEnv *env, jobject thiz, jlong handle,
                                               jstring pca_addr, jbyteArray session_key_seed) {
    struct euicc_ctx *ctx = (struct euicc_ctx *) handle;
    const char *_pca_addr = NULL;
    jbyte *_seed = NULL;
    jsize _seed_len = 0;
    uint8_t *pseudonym_certificate = NULL;
    int pseudonym_certificate_len = 0;
    char *pseudonym_certificate_b64 = NULL;
    struct es10b_zk_cert_init_result cert_init;
    int ret;

    memset(&cert_init, 0, sizeof(cert_init));

    _pca_addr = (*env)->GetStringUTFChars(env, pca_addr, NULL);
    _seed = (*env)->GetByteArrayElements(env, session_key_seed, NULL);
    _seed_len = (*env)->GetArrayLength(env, session_key_seed);

    ret = es10b_zk_cert_init_request_r(ctx, &cert_init, (const uint8_t *) _seed,
                                       (uint32_t) _seed_len);
    syslog(LOG_INFO, "es10b_zk_cert_init_request_r = %d", ret);
    if (ret < 0) goto out;

    ret = es12p_cert_init_request(ctx, _pca_addr, cert_init.userPublicKey,
                                  cert_init.bindingSignature,
                                  cert_init.credentialBindingHash,
                                  &pseudonym_certificate_b64);
    syslog(LOG_INFO, "es12p_cert_init_request = %d", ret);
    if (ret < 0) goto out;

    if (b64_decode_alloc(pseudonym_certificate_b64, &pseudonym_certificate,
                         &pseudonym_certificate_len) < 0) {
        ret = -1;
        goto out;
    }

    ret = es10b_zk_cert_install_r(ctx, pseudonym_certificate,
                                  (uint32_t) pseudonym_certificate_len);
    syslog(LOG_INFO, "es10b_zk_cert_install_r = %d", ret);
    if (ret < 0) goto out;

    ret = 0;

out:
    free(pseudonym_certificate);
    free(pseudonym_certificate_b64);
    es10b_zk_cert_init_result_free(&cert_init);
    if (_seed != NULL)
        (*env)->ReleaseByteArrayElements(env, session_key_seed, _seed, JNI_ABORT);
    if (_pca_addr != NULL)
        (*env)->ReleaseStringUTFChars(env, pca_addr, _pca_addr);
    return ret;
}

JNIEXPORT jobject JNICALL
Java_net_typeblog_lpac_1jni_LpacJni_zkOrder(JNIEnv *env, jobject thiz, jlong handle,
                                            jstring mno_addr) {
    struct euicc_ctx *ctx = (struct euicc_ctx *) handle;
    const char *_mno_addr = NULL;
    char *b64_zk_resp = NULL;
    uint8_t *bf43_raw = NULL;
    int bf43_alloc_len;
    int bf43_len;
    int ret;
    int should_ack = 0;
    struct es12p_challenge_result challenge;
    struct es12p_zk_request_result zk_result;
    jobject result = NULL;

    memset(&challenge, 0, sizeof(challenge));
    memset(&zk_result, 0, sizeof(zk_result));

    _mno_addr = (*env)->GetStringUTFChars(env, mno_addr, NULL);

    ret = es12p_get_mno_challenge(ctx, _mno_addr, &challenge);
    syslog(LOG_INFO, "es12p_get_mno_challenge = %d", ret);
    if (ret < 0) goto out;
    should_ack = 1;

    ret = es10b_zk_profile_request_r(ctx, &b64_zk_resp, challenge.mnoChallenge,
                                     (uint32_t) sizeof(challenge.mnoChallenge));
    syslog(LOG_INFO, "es10b_zk_profile_request_r = %d", ret);
    if (ret < 0) goto out;

    ret = es12p_zk_request(ctx, _mno_addr, challenge.requestId, b64_zk_resp, &zk_result);
    syslog(LOG_INFO, "es12p_zk_request = %d", ret);
    if (ret < 0) goto out;

    bf43_alloc_len = euicc_base64_decode_len(zk_result.setEligibilityDataB64);
    if (bf43_alloc_len <= 0) {
        ret = -1;
        goto out;
    }
    bf43_raw = malloc((size_t) bf43_alloc_len);
    if (bf43_raw == NULL) {
        ret = -1;
        goto out;
    }
    bf43_len = euicc_base64_decode(bf43_raw, zk_result.setEligibilityDataB64);
    if (bf43_len < 0) {
        ret = -1;
        goto out;
    }

    ret = es10b_set_eligibility_data_r(ctx, bf43_raw, (uint32_t) bf43_len);
    syslog(LOG_INFO, "es10b_set_eligibility_data_r = %d", ret);
    if (ret < 0) goto out;

    es12p_ack(ctx, _mno_addr, challenge.requestId, 1);
    should_ack = 0;

    {
        jstring matching_id = toJString(env, zk_result.matchingId);
        jstring smdp_address = toJString(env, zk_result.smdpAddress);
        jstring iccid = toJString(env, zk_result.iccid);
        result = (*env)->NewObject(env, zk_order_result_class, zk_order_result_constructor,
                                   matching_id, smdp_address, iccid);
        if (matching_id != NULL) (*env)->DeleteLocalRef(env, matching_id);
        if (smdp_address != NULL) (*env)->DeleteLocalRef(env, smdp_address);
        if (iccid != NULL) (*env)->DeleteLocalRef(env, iccid);
    }

out:
    if (ret < 0 && should_ack) {
        es12p_ack(ctx, _mno_addr, challenge.requestId, 0);
    }
    free(b64_zk_resp);
    free(bf43_raw);
    es12p_challenge_result_free(&challenge);
    es12p_zk_request_result_free(&zk_result);
    if (_mno_addr != NULL)
        (*env)->ReleaseStringUTFChars(env, mno_addr, _mno_addr);
    return result;
}