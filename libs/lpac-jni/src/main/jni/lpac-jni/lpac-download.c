#include <euicc/es9p.h>
#include <euicc/es10b.h>
#include <euicc/es8p.h>
#include <euicc/base64.h>
#include <euicc/es12p.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "lpac-download.h"

jobject download_state_preparing;
jobject download_state_connecting;
jobject download_state_authenticating;
jobject download_state_downloading;
jobject download_state_finalizing;
jobject download_state_registering;
jobject download_state_cert_initializing;
jobject download_state_ordering;

jmethodID on_state_update;
jclass confirming_download_class;
jmethodID confirming_download_constructor;
jclass remote_profile_info_class;
jmethodID remote_profile_info_constructor;
jobject profile_class_testing;
jobject profile_class_provisioning;
jobject profile_class_operational;

static jobject create_global_state(JNIEnv *env, const char *class_name) {
    jclass state_class = (*env)->FindClass(env, class_name);
    jmethodID state_constructor = (*env)->GetMethodID(env, state_class, "<init>", "()V");
    jobject state = (*env)->NewObject(env, state_class, state_constructor);
    jobject global_state = (*env)->NewGlobalRef(env, state);
    (*env)->DeleteLocalRef(env, state);
    return global_state;
}

void lpac_download_init() {
    LPAC_JNI_SETUP_ENV;

    download_state_preparing = create_global_state(env,
                                                   "net/typeblog/lpac_jni/ProfileDownloadState$Preparing");
    download_state_connecting = create_global_state(env,
                                                    "net/typeblog/lpac_jni/ProfileDownloadState$Connecting");
    download_state_authenticating = create_global_state(env,
                                                        "net/typeblog/lpac_jni/ProfileDownloadState$Authenticating");
    download_state_downloading = create_global_state(env,
                                                     "net/typeblog/lpac_jni/ProfileDownloadState$Downloading");
    download_state_finalizing = create_global_state(env,
                                                    "net/typeblog/lpac_jni/ProfileDownloadState$Finalizing");
    download_state_registering = create_global_state(env,
                                                     "net/typeblog/lpac_jni/ProfileDownloadState$Registering");
    download_state_cert_initializing = create_global_state(env,
                                                           "net/typeblog/lpac_jni/ProfileDownloadState$CertInitializing");
    download_state_ordering = create_global_state(env,
                                                  "net/typeblog/lpac_jni/ProfileDownloadState$Ordering");

    jclass download_callback_class = (*env)->FindClass(env,
                                                       "net/typeblog/lpac_jni/ProfileDownloadCallback");
    on_state_update = (*env)->GetMethodID(env, download_callback_class, "onStatusUpdate",
                                          "(Lnet/typeblog/lpac_jni/ProfileDownloadState;)Z");

    jclass _confirming_download_class = (*env)->FindClass(env,
                                                          "net/typeblog/lpac_jni/ProfileDownloadState$ConfirmingDownload");
    confirming_download_class = (*env)->NewGlobalRef(env, _confirming_download_class);
    confirming_download_constructor = (*env)->GetMethodID(env,
                                                          confirming_download_class,
                                                          "<init>",
                                                          "(Lnet/typeblog/lpac_jni/RemoteProfileInfo;)V");

    jclass profile_class_class = (*env)->FindClass(env, "net/typeblog/lpac_jni/ProfileClass");
    jfieldID profile_class_testing_field = (*env)->GetStaticFieldID(env, profile_class_class,
                                                                    "Testing",
                                                                    "Lnet/typeblog/lpac_jni/ProfileClass;");
    profile_class_testing = (*env)->GetStaticObjectField(env, profile_class_class,
                                                         profile_class_testing_field);
    profile_class_testing = (*env)->NewGlobalRef(env, profile_class_testing);
    jfieldID profile_class_provisioning_field = (*env)->GetStaticFieldID(env, profile_class_class,
                                                                         "Provisioning",
                                                                         "Lnet/typeblog/lpac_jni/ProfileClass;");
    profile_class_provisioning = (*env)->GetStaticObjectField(env, profile_class_class,
                                                              profile_class_provisioning_field);
    profile_class_provisioning = (*env)->NewGlobalRef(env, profile_class_provisioning);
    jfieldID profile_class_operational_field = (*env)->GetStaticFieldID(env, profile_class_class,
                                                                        "Operational",
                                                                        "Lnet/typeblog/lpac_jni/ProfileClass;");
    profile_class_operational = (*env)->GetStaticObjectField(env, profile_class_class,
                                                             profile_class_operational_field);
    profile_class_operational = (*env)->NewGlobalRef(env, profile_class_operational);

    jclass _remote_profile_info_class = (*env)->FindClass(env,
                                                          "net/typeblog/lpac_jni/RemoteProfileInfo");
    remote_profile_info_class = (*env)->NewGlobalRef(env, _remote_profile_info_class);
    remote_profile_info_constructor = (*env)->GetMethodID(env, remote_profile_info_class, "<init>",
                                                          "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lnet/typeblog/lpac_jni/ProfileClass;)V");
}

static jobject profile_class_from_es10c_profile_class(enum es10c_profile_class profile_class) {
    switch (profile_class) {
        case ES10C_PROFILE_CLASS_TEST:
            return profile_class_testing;
        case ES10C_PROFILE_CLASS_PROVISIONING:
            return profile_class_provisioning;
        case ES10C_PROFILE_CLASS_OPERATIONAL:
        default:
            // In es10c profiles are considered operational if the field is missing (null).
            return profile_class_operational;
    }
}

static jobject create_remote_profile_info(JNIEnv *env,
                                          struct es8p_metadata *profile_metadata) {
    jobject profile_class = NULL;
    jstring metadata_iccid = NULL;
    jstring metadata_profile_name = NULL;
    jstring metadata_provider_name = NULL;
    jobject remote_profile_info = NULL;

    metadata_iccid = toJString(env, profile_metadata->iccid);
    metadata_profile_name = toJString(env, profile_metadata->profileName);
    metadata_provider_name = toJString(env, profile_metadata->serviceProviderName);
    profile_class = profile_class_from_es10c_profile_class(profile_metadata->profileClass);

    remote_profile_info = (*env)->NewObject(env, remote_profile_info_class,
                                            remote_profile_info_constructor,
                                            metadata_iccid,
                                            metadata_profile_name,
                                            metadata_provider_name,
                                            profile_class);

    if (metadata_iccid != NULL)
        (*env)->DeleteLocalRef(env, metadata_iccid);
    if (metadata_profile_name != NULL)
        (*env)->DeleteLocalRef(env, metadata_profile_name);
    if (metadata_provider_name != NULL)
        (*env)->DeleteLocalRef(env, metadata_provider_name);

    return remote_profile_info;
}

static int b64_decode_alloc(const char *b64, uint8_t **out, int *out_len) {
    int alloc_len;

    *out = NULL;
    *out_len = 0;
    alloc_len = euicc_base64_decode_len(b64);
    if (alloc_len <= 0) {
        return -1;
    }
    *out = malloc((size_t)alloc_len);
    if (!*out) {
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

static int random_bytes(uint8_t *out, size_t len) {
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp) {
        return -1;
    }
    if (fread(out, 1, len, fp) != len) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

JNIEXPORT jint JNICALL
Java_net_typeblog_lpac_1jni_LpacJni_downloadProfile(JNIEnv *env, jobject thiz, jlong handle,
                                                    jstring smdp, jstring matching_id,
                                                    jstring imei, jstring confirmation_code,
                                                    jstring mno_address, jstring pca_address,
                                                    jobject callback) {
    struct euicc_ctx *ctx = (struct euicc_ctx *) handle;
    struct es12p_register_challenge_result mno_register_challenge;
    struct es10b_zk_register_challenge_result euicc_register_challenge;
    struct es10b_zk_cert_init_result cert_init;
    struct es12p_challenge_result order_challenge;
    struct es12p_zk_request_result zk_order;
    struct es10b_load_bound_profile_package_result es10b_load_bound_profile_package_result;
    const char *_confirmation_code = NULL;
    const char *_smdp = NULL;
    const char *_imei = NULL;
    const char *_mno_address = NULL;
    const char *_pca_address = NULL;
    uint8_t *mno_nonce_commitment = NULL;
    int mno_nonce_commitment_len = 0;
    uint8_t *mno_partial_signature = NULL;
    int mno_partial_signature_len = 0;
    char *mno_partial_signature_b64 = NULL;
    uint8_t session_key_seed[32];
    uint8_t *pseudonym_certificate = NULL;
    int pseudonym_certificate_len = 0;
    char *pseudonym_certificate_b64 = NULL;
    char *b64_zk_response = NULL;
    uint8_t *bf43_raw = NULL;
    int bf43_alloc_len;
    int bf43_len;
    jboolean confirmed = JNI_TRUE;
    int should_ack_mno = 0;
    int ret;

    memset(&mno_register_challenge, 0, sizeof(mno_register_challenge));
    memset(&euicc_register_challenge, 0, sizeof(euicc_register_challenge));
    memset(&cert_init, 0, sizeof(cert_init));
    memset(&order_challenge, 0, sizeof(order_challenge));
    memset(&zk_order, 0, sizeof(zk_order));
    memset(&es10b_load_bound_profile_package_result, 0,
           sizeof(es10b_load_bound_profile_package_result));
    LPAC_JNI_CTX(ctx)->download_needs_cancel = JNI_FALSE;

    if (confirmation_code != NULL)
        _confirmation_code = (*env)->GetStringUTFChars(env, confirmation_code, NULL);
    _smdp = (*env)->GetStringUTFChars(env, smdp, NULL);
    if (imei != NULL)
        _imei = (*env)->GetStringUTFChars(env, imei, NULL);
    _mno_address = (*env)->GetStringUTFChars(env, mno_address, NULL);
    _pca_address = (*env)->GetStringUTFChars(env, pca_address, NULL);

    confirmed = (*env)->CallBooleanMethod(env, callback, on_state_update,
                                          download_state_registering);
    if (!confirmed) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }

    ret = es12p_register_challenge(ctx, _mno_address, &mno_register_challenge);
    syslog(LOG_INFO, "es12p_register_challenge %d", ret);
    if (ret < 0) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }

    ret = b64_decode_alloc(mno_register_challenge.mnoNonceCommitment, &mno_nonce_commitment,
                           &mno_nonce_commitment_len);
    if (ret < 0) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }

    ret = es10b_zk_register_challenge_r(ctx, &euicc_register_challenge, mno_nonce_commitment,
                                        (uint32_t)mno_nonce_commitment_len);
    syslog(LOG_INFO, "es10b_zk_register_challenge_r %d", ret);
    if (ret < 0) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }

    ret = es12p_register_credential(ctx, _mno_address, mno_register_challenge.requestId,
                                    euicc_register_challenge.blindedEligibilityChallenge,
                                    euicc_register_challenge.deviceAuthSignature,
                                    &mno_partial_signature_b64);
    syslog(LOG_INFO, "es12p_register_credential %d", ret);
    if (ret < 0) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }

    ret = b64_decode_alloc(mno_partial_signature_b64, &mno_partial_signature,
                           &mno_partial_signature_len);
    if (ret < 0) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }

    ret = es10b_zk_register_credential_r(ctx, mno_partial_signature,
                                         (uint32_t)mno_partial_signature_len);
    syslog(LOG_INFO, "es10b_zk_register_credential_r %d", ret);
    if (ret < 0) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }

    confirmed = (*env)->CallBooleanMethod(env, callback, on_state_update,
                                          download_state_cert_initializing);
    if (!confirmed) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }

    ret = random_bytes(session_key_seed, sizeof(session_key_seed));
    if (ret < 0) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }

    ret = es10b_zk_cert_init_request_r(ctx, &cert_init, session_key_seed,
                                       sizeof(session_key_seed));
    syslog(LOG_INFO, "es10b_zk_cert_init_request_r %d", ret);
    if (ret < 0) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }

    ret = es12p_cert_init_request(ctx, _pca_address, cert_init.userPublicKey,
                                  cert_init.bindingSignature,
                                  cert_init.credentialBindingHash,
                                  &pseudonym_certificate_b64);
    syslog(LOG_INFO, "es12p_cert_init_request %d", ret);
    if (ret < 0) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }

    ret = b64_decode_alloc(pseudonym_certificate_b64, &pseudonym_certificate,
                           &pseudonym_certificate_len);
    if (ret < 0) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }

    ret = es10b_zk_cert_install_r(ctx, pseudonym_certificate,
                                  (uint32_t)pseudonym_certificate_len);
    syslog(LOG_INFO, "es10b_zk_cert_install_r %d", ret);
    if (ret < 0) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }

    confirmed = (*env)->CallBooleanMethod(env, callback, on_state_update, download_state_ordering);
    if (!confirmed) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }

    ret = es12p_get_mno_challenge(ctx, _mno_address, &order_challenge);
    syslog(LOG_INFO, "es12p_get_mno_challenge %d", ret);
    if (ret < 0) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }
    should_ack_mno = 1;

    ret = es10b_zk_profile_request_r(ctx, &b64_zk_response, order_challenge.mnoChallenge,
                                     sizeof(order_challenge.mnoChallenge));
    syslog(LOG_INFO, "es10b_zk_profile_request_r %d", ret);
    if (ret < 0) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }

    ret = es12p_zk_request(ctx, _mno_address, order_challenge.requestId, b64_zk_response,
                           &zk_order);
    syslog(LOG_INFO, "es12p_zk_request %d", ret);
    if (ret < 0) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }

    bf43_alloc_len = euicc_base64_decode_len(zk_order.setEligibilityDataB64);
    if (bf43_alloc_len <= 0) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }
    bf43_raw = malloc((size_t)bf43_alloc_len);
    if (bf43_raw == NULL) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }
    bf43_len = euicc_base64_decode(bf43_raw, zk_order.setEligibilityDataB64);
    if (bf43_len < 0) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }

    ret = es10b_set_eligibility_data_r(ctx, bf43_raw, (uint32_t)bf43_len);
    syslog(LOG_INFO, "es10b_set_eligibility_data_r %d", ret);
    if (ret < 0) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }

    es12p_ack(ctx, _mno_address, order_challenge.requestId, 1);
    should_ack_mno = 0;

    if (_smdp != NULL && strlen(_smdp) > 0) {
        free(zk_order.smdpAddress);
        zk_order.smdpAddress = strdup(_smdp);
        if (zk_order.smdpAddress == NULL) {
            ret = -ES10B_ERROR_REASON_UNDEFINED;
            goto out;
        }
    }

    confirmed = (*env)->CallBooleanMethod(env, callback, on_state_update, download_state_downloading);
    if (!confirmed) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }

    ctx->http.server_address = zk_order.smdpAddress;

    ret = es10b_get_euicc_challenge_and_info(ctx);
    syslog(LOG_INFO, "es10b_get_euicc_challenge_and_info %d", ret);
    if (ret < 0) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }

    ret = es9p_initiate_authentication(ctx);
    syslog(LOG_INFO, "es9p_initiate_authentication %d", ret);
    if (ret < 0) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }
    LPAC_JNI_CTX(ctx)->download_needs_cancel = JNI_TRUE;

    ret = es10b_authenticate_server(ctx, zk_order.matchingId, _imei);
    syslog(LOG_INFO, "es10b_authenticate_server %d", ret);
    if (ret < 0) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }

    ret = es9p_authenticate_client(ctx);
    syslog(LOG_INFO, "es9p_authenticate_client %d", ret);
    if (ret < 0) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }

    ret = es10b_prepare_download(ctx, _confirmation_code);
    syslog(LOG_INFO, "es10b_prepare_download %d", ret);
    if (ret < 0) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }

    ret = es9p_get_bound_profile_package(ctx);
    syslog(LOG_INFO, "es9p_get_bound_profile_package %d", ret);
    if (ret < 0) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }

    confirmed = (*env)->CallBooleanMethod(env, callback, on_state_update, download_state_finalizing);
    if (!confirmed) {
        ret = -ES10B_ERROR_REASON_UNDEFINED;
        goto out;
    }

    ret = es10b_load_bound_profile_package(ctx, &es10b_load_bound_profile_package_result);
    syslog(LOG_INFO, "es10b_load_bound_profile_package %d, reason %d", ret, es10b_load_bound_profile_package_result.errorReason);
    if (ret) {
        ret = - (int) es10b_load_bound_profile_package_result.errorReason;
        if (ret == 0) {
            ret = -ES10B_ERROR_REASON_UNDEFINED;
        }
        goto out;
    }

    euicc_http_cleanup(ctx);
    LPAC_JNI_CTX(ctx)->download_needs_cancel = JNI_FALSE;

    out:
    // We expect Java side to call cancelSessions after any error -- thus, `euicc_http_cleanup` is done there
    // This is so that Java side can access the last HTTP and/or APDU errors when we return.
    if (ret != 0 && should_ack_mno && order_challenge.requestId != NULL) {
        es12p_ack(ctx, _mno_address, order_challenge.requestId, 0);
    }
    if (_confirmation_code != NULL)
        (*env)->ReleaseStringUTFChars(env, confirmation_code, _confirmation_code);
    (*env)->ReleaseStringUTFChars(env, smdp, _smdp);
    if (_imei != NULL)
        (*env)->ReleaseStringUTFChars(env, imei, _imei);
    (*env)->ReleaseStringUTFChars(env, mno_address, _mno_address);
    (*env)->ReleaseStringUTFChars(env, pca_address, _pca_address);
    free(mno_nonce_commitment);
    free(mno_partial_signature);
    free(mno_partial_signature_b64);
    free(pseudonym_certificate);
    free(pseudonym_certificate_b64);
    free(b64_zk_response);
    free(bf43_raw);
    es12p_register_challenge_result_free(&mno_register_challenge);
    es10b_zk_register_challenge_result_free(&euicc_register_challenge);
    es10b_zk_cert_init_result_free(&cert_init);
    es12p_challenge_result_free(&order_challenge);
    es12p_zk_request_result_free(&zk_order);
    return ret;
}


JNIEXPORT void JNICALL
Java_net_typeblog_lpac_1jni_LpacJni_cancelSessions(JNIEnv *env, jobject thiz, jlong handle) {
    struct euicc_ctx *ctx = (struct euicc_ctx *) handle;
    es9p_cancel_session(ctx);
    es10b_cancel_session(ctx, ES10B_CANCEL_SESSION_REASON_UNDEFINED);
    euicc_http_cleanup(ctx);
    LPAC_JNI_CTX(ctx)->download_needs_cancel = JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_net_typeblog_lpac_1jni_LpacJni_downloadNeedsCancel(JNIEnv *env, jobject thiz,
                                                        jlong handle) {
    struct euicc_ctx *ctx = (struct euicc_ctx *) handle;
    return LPAC_JNI_CTX(ctx)->download_needs_cancel;
}

#define QUOTE(S) #S
#define ERRCODE_ENUM_TO_STRING(VARIANT) case VARIANT: return toJString(env, QUOTE(VARIANT))

JNIEXPORT jstring JNICALL
Java_net_typeblog_lpac_1jni_LpacJni_downloadErrCodeToString(JNIEnv *env, jobject thiz, jint code) {
    switch (code) {
        ERRCODE_ENUM_TO_STRING(ES10B_ERROR_REASON_INCORRECT_INPUT_VALUES);
        ERRCODE_ENUM_TO_STRING(ES10B_ERROR_REASON_INVALID_SIGNATURE);
        ERRCODE_ENUM_TO_STRING(ES10B_ERROR_REASON_INVALID_TRANSACTION_ID);
        ERRCODE_ENUM_TO_STRING(ES10B_ERROR_REASON_UNSUPPORTED_CRT_VALUES);
        ERRCODE_ENUM_TO_STRING(ES10B_ERROR_REASON_UNSUPPORTED_REMOTE_OPERATION_TYPE);
        ERRCODE_ENUM_TO_STRING(ES10B_ERROR_REASON_UNSUPPORTED_PROFILE_CLASS);
        ERRCODE_ENUM_TO_STRING(ES10B_ERROR_REASON_SCP03T_STRUCTURE_ERROR);
        ERRCODE_ENUM_TO_STRING(ES10B_ERROR_REASON_SCP03T_SECURITY_ERROR);
        ERRCODE_ENUM_TO_STRING(
                ES10B_ERROR_REASON_INSTALL_FAILED_DUE_TO_ICCID_ALREADY_EXISTS_ON_EUICC);
        ERRCODE_ENUM_TO_STRING(
                ES10B_ERROR_REASON_INSTALL_FAILED_DUE_TO_INSUFFICIENT_MEMORY_FOR_PROFILE);
        ERRCODE_ENUM_TO_STRING(ES10B_ERROR_REASON_INSTALL_FAILED_DUE_TO_INTERRUPTION);
        ERRCODE_ENUM_TO_STRING(ES10B_ERROR_REASON_INSTALL_FAILED_DUE_TO_PE_PROCESSING_ERROR);
        ERRCODE_ENUM_TO_STRING(ES10B_ERROR_REASON_INSTALL_FAILED_DUE_TO_ICCID_MISMATCH);
        ERRCODE_ENUM_TO_STRING(
                ES10B_ERROR_REASON_TEST_PROFILE_INSTALL_FAILED_DUE_TO_INVALID_NAA_KEY);
        ERRCODE_ENUM_TO_STRING(ES10B_ERROR_REASON_PPR_NOT_ALLOWED);
        ERRCODE_ENUM_TO_STRING(ES10B_ERROR_REASON_INSTALL_FAILED_DUE_TO_UNKNOWN_ERROR);
        default:
            return toJString(env, "ES10B_ERROR_REASON_UNDEFINED");
    }
}
