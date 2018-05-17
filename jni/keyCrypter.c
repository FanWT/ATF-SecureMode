#include "org_bitcoinj_jni_KeyCrypterJNI.h"
#include <android/log.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <malloc.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>

#define DERIVE_KEY_CMD 0
#define ENCRYPT_CMD 1
#define DECRYPT_CMD 3

struct en_de{
    signed char *encrypt_data;
    unsigned int encrypt_len;
    signed char *decrypt_data;
    unsigned int decrypt_len;
};
struct s {
    signed char *arg1;
    unsigned int len1;
    signed char *arg2;
    unsigned int len2;
    signed char *arg3;
    unsigned int len3;
};

typedef struct en_de *En_De;
int fd = -1;

JNIEXPORT jbyteArray JNICALL Java_org_bitcoinj_jni_KeyCrypterJNI_deriveKey_1jni(JNIEnv *env, jobject obj, jbyteArray password)
{
    if (fd < 0) {
        fd = open("/dev/vtz",O_RDONLY);
    }
    __android_log_print(ANDROID_LOG_INFO, "FWT_DEBUG", "fd %d %s",fd, strerror(errno));
    jbyte *passwd = (*env)->GetByteArrayElements(env, password, 0);
    En_De ende = malloc(sizeof(struct en_de));

    unsigned int decrypt_len = (*env)->GetArrayLength(env, password);
    (*ende).decrypt_data = (signed char*)passwd;
    (*ende).decrypt_len = decrypt_len;
    (*ende).encrypt_data = malloc(decrypt_len);
    (*ende).encrypt_len = decrypt_len;

    int ret = ioctl(fd, DERIVE_KEY_CMD, (unsigned long)ende);

    jbyteArray de = (*env)->NewByteArray(env,decrypt_len);
    (*env)->SetByteArrayRegion(env, de, 0, decrypt_len, (*ende).encrypt_data);
    return de;

}

JNIEXPORT jbyteArray JNICALL Java_org_bitcoinj_jni_KeyCrypterJNI_decrypt_1jni(JNIEnv *env, jobject obj, jbyteArray encrypt, jbyteArray aes)
{
    unsigned int encrypt_len = (*env)->GetArrayLength(env, encrypt);
    unsigned int aes_len = (*env)->GetArrayLength(env, aes);
    jbyte *encrypt_ptr = (*env)->GetByteArrayElements(env, encrypt, 0);
    jbyte *aes_ptr = (*env)->GetByteArrayElements(env, aes, 0);
    signed char *decrypt_ptr = malloc(encrypt_len);
    struct s ss = {encrypt_ptr, encrypt_len, aes_ptr, aes_len, decrypt_ptr, encrypt_len};

    int ret = ioctl(fd, DECRYPT_CMD, (unsigned long)(&ss));

    jbyteArray decrypt_array = (*env)->NewByteArray(env,encrypt_len);
    (*env)->SetByteArrayRegion(env, decrypt_array, 0, encrypt_len, decrypt_ptr);
    return decrypt_array;
}

JNIEXPORT jbyteArray JNICALL Java_org_bitcoinj_jni_KeyCrypterJNI_encrypt_1jni(JNIEnv *env, jobject obj, jbyteArray plain, jbyteArray aes)
{
    unsigned int plain_len = (*env)->GetArrayLength(env, plain);
    unsigned int aes_len = (*env)->GetArrayLength(env, aes);
    jbyte *plain_ptr = (*env)->GetByteArrayElements(env, plain, 0);
    jbyte *aes_ptr = (*env)->GetByteArrayElements(env, aes, 0);
    signed char *encrypt_ptr = malloc(plain_len);
    struct s ss = {plain_ptr, plain_len, aes_ptr, aes_len, encrypt_ptr, plain_len};

    int ret = ioctl(fd, ENCRYPT_CMD, (unsigned long)(&ss));

    jbyteArray encrypt_array = (*env)->NewByteArray(env,plain_len);
    (*env)->SetByteArrayRegion(env, encrypt_array, 0, plain_len, encrypt_ptr);
    return encrypt_array;
}