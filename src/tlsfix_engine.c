#include "tlsfix.h"
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#define MAXSH 256
static Shadow *gTab[MAXSH];
static unsigned gClock = 0;
static pthread_mutex_t gLock = PTHREAD_MUTEX_INITIALIZER;

static SSL_CTX *gCtx = NULL;          // shared client context
static BIO_METHOD *gBioMeth = NULL;   // custom BIO bridged to CFNetwork's IO funcs
static RSA_METHOD *gRsaMeth = NULL;   // custom RSA method: private op to SecKeyRawSign (mtls)
static int gRsaExIdx = -1;
static int gSslExIdx = -1;

static void sh_free_mem(Shadow *s) {
    if (!s) return;
    if (s->ssl) SSL_free(s->ssl);
    if (s->clientX509) X509_free(s->clientX509);
    if (s->clientChain) sk_X509_pop_free(s->clientChain, X509_free);
    if (s->clientKey) CFRelease(s->clientKey);
    free(s);
}
void sh_release(Shadow *s) {
    if (!s) return;
    int dead = 0;
    pthread_mutex_lock(&gLock);
    if (--s->refcount == 0) dead = 1;
    pthread_mutex_unlock(&gLock);
    if (dead) sh_free_mem(s);
}
Shadow *sh_get(SSLContextRef c) {
    if (ensure_ready() != 1) return NULL;
    Shadow *r = NULL;
    pthread_mutex_lock(&gLock);
    for (int i = 0; i < MAXSH; i++) if (gTab[i] && gTab[i]->ctx == c) { r = gTab[i]; r->lastUse = ++gClock; r->refcount++; break; }
    pthread_mutex_unlock(&gLock);
    return r;
}
Shadow *sh_create(SSLContextRef c) {
    Shadow *evicted = NULL; int freeEvicted = 0;
    pthread_mutex_lock(&gLock);
    Shadow *s = NULL;
    for (int i = 0; i < MAXSH; i++) if (gTab[i] && gTab[i]->ctx == c) { s = gTab[i]; s->lastUse = ++gClock; s->refcount++; break; }
    if (!s) {
        s = (Shadow *)calloc(1, sizeof(Shadow));
        if (s) {
            s->ctx = c; s->lastUse = ++gClock; s->refcount = 2;
            int slot = -1;
            for (int i = 0; i < MAXSH; i++) if (!gTab[i]) { slot = i; break; }
            if (slot < 0) {
                int lru = 0; for (int i = 1; i < MAXSH; i++) if (gTab[i]->lastUse < gTab[lru]->lastUse) lru = i;
                evicted = gTab[lru]; slot = lru;
                if (--evicted->refcount == 0) freeEvicted = 1;
            }
            gTab[slot] = s;
        }
    }
    pthread_mutex_unlock(&gLock);
    if (freeEvicted) sh_free_mem(evicted);
    return s;
}
void sh_free(SSLContextRef c) {
    if (ensure_ready() != 1) return;
    Shadow *s = NULL; int dead = 0;
    pthread_mutex_lock(&gLock);
    for (int i = 0; i < MAXSH; i++) if (gTab[i] && gTab[i]->ctx == c) { s = gTab[i]; gTab[i] = NULL; if (--s->refcount == 0) dead = 1; break; }
    pthread_mutex_unlock(&gLock);
    if (dead) sh_free_mem(s);
}

static int bio_bwrite(BIO *b, const char *buf, int len) {
    Shadow *s = (Shadow *)BIO_get_data(b);
    size_t n = (size_t)len;
    OSStatus os = s->wf(s->conn, buf, &n);
    BIO_clear_retry_flags(b);
    if (n > 0) return (int)n;
    if (os == errSSLWouldBlock || os == noErr) { BIO_set_retry_write(b); return -1; }
    return -1;
}
static int bio_bread(BIO *b, char *buf, int len) {
    Shadow *s = (Shadow *)BIO_get_data(b);
    size_t n = (size_t)len;
    OSStatus os = s->rf(s->conn, buf, &n);
    BIO_clear_retry_flags(b);
    if (n > 0) return (int)n;
    if (os == errSSLWouldBlock || os == noErr) { BIO_set_retry_read(b); return -1; }
    if (os == ST_ClosedGraceful) return 0;
    return -1;
}
static long bio_ctrl(BIO *b, int cmd, long num, void *ptr) { (void)b; (void)num; (void)ptr; return (cmd == BIO_CTRL_FLUSH) ? 1 : 0; }
static int bio_create(BIO *b) { BIO_set_init(b, 1); return 1; }
static int bio_destroy(BIO *b) { (void)b; return 1; }

static int rsa_seckey_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
    SecKeyRef key = (SecKeyRef)RSA_get_ex_data(rsa, gRsaExIdx);
    if (!key || padding != RSA_PKCS1_PADDING) return -1;
    size_t tlen = SecKeyGetBlockSize(key);
    OSStatus s = SecKeyRawSign(key, kSecPaddingPKCS1, from, (size_t)flen, to, &tlen);
    return (s == errSecSuccess) ? (int)tlen : -1;
}

void capture_identity(Shadow *s, CFArrayRef certRefs) {
    if (!certRefs || CFArrayGetCount(certRefs) < 1) { s->clientBypass = 1; return; }
    CFTypeRef first = CFArrayGetValueAtIndex(certRefs, 0);
    if (!first || CFGetTypeID(first) != SecIdentityGetTypeID()) { s->clientBypass = 1; return; }
    SecCertificateRef leaf = NULL; SecKeyRef key = NULL;
    if (SecIdentityCopyCertificate((SecIdentityRef)first, &leaf) != errSecSuccess || !leaf ||
        SecIdentityCopyPrivateKey((SecIdentityRef)first, &key) != errSecSuccess || !key) {
        if (leaf) CFRelease(leaf); if (key) CFRelease(key); s->clientBypass = 1; return;
    }
    X509 *x = NULL;
    CFDataRef d = SecCertificateCopyData(leaf);
    if (d) { const unsigned char *p = CFDataGetBytePtr(d); x = d2i_X509(NULL, &p, CFDataGetLength(d)); CFRelease(d); }
    CFRelease(leaf);
    if (!x) { CFRelease(key); s->clientBypass = 1; return; }
    EVP_PKEY *pub = X509_get_pubkey(x);
    int isRSA = (pub && EVP_PKEY_base_id(pub) == EVP_PKEY_RSA);
    if (pub) EVP_PKEY_free(pub);
    if (!isRSA) { X509_free(x); CFRelease(key); s->clientBypass = 1; return; }   // non-RSA -> system stack
    STACK_OF(X509) *chain = NULL;
    for (CFIndex i = 1, n = CFArrayGetCount(certRefs); i < n; i++) {
        SecCertificateRef ic = (SecCertificateRef)CFArrayGetValueAtIndex(certRefs, i);
        if (!ic || CFGetTypeID(ic) != SecCertificateGetTypeID()) continue;
        CFDataRef id = SecCertificateCopyData(ic);
        if (!id) continue;
        const unsigned char *p = CFDataGetBytePtr(id); X509 *ix = d2i_X509(NULL, &p, CFDataGetLength(id)); CFRelease(id);
        if (ix) { if (!chain) chain = sk_X509_new_null(); if (chain) sk_X509_push(chain, ix); else X509_free(ix); }
    }
    s->clientX509 = x; s->clientChain = chain; s->clientKey = key; s->clientBypass = 0;
}

// provide our client cert during the handshake; -1 suspends before sending it
static int cert_cb(SSL *ssl, void *arg) {
    (void)arg;
    Shadow *s = (Shadow *)SSL_get_ex_data(ssl, gSslExIdx);
    if (!s || !s->clientX509) return 1;
    if (s->breakAuth && !s->approved) return -1;
    EVP_PKEY *certpub = X509_get_pubkey(s->clientX509);
    if (!certpub) return 0;
    RSA *rpub = EVP_PKEY_get1_RSA(certpub); EVP_PKEY_free(certpub);
    if (!rpub) return 0;
    const BIGNUM *n = NULL, *e = NULL; RSA_get0_key(rpub, &n, &e, NULL);
    RSA *r = RSA_new();
    if (!r || !RSA_set0_key(r, BN_dup(n), BN_dup(e), NULL)) { RSA_free(rpub); if (r) RSA_free(r); return 0; }
    RSA_free(rpub);
    RSA_set_method(r, gRsaMeth);
    RSA_set_ex_data(r, gRsaExIdx, s->clientKey);
    EVP_PKEY *pk = EVP_PKEY_new();
    if (!pk) { RSA_free(r); return 0; }
    EVP_PKEY_assign_RSA(pk, r);
    int ok = (SSL_use_certificate(ssl, s->clientX509) == 1) && (SSL_use_PrivateKey(ssl, pk) == 1);
    EVP_PKEY_free(pk);
    if (ok && s->clientChain)
        for (int i = 0; i < sk_X509_num(s->clientChain); i++) SSL_add1_chain_cert(ssl, sk_X509_value(s->clientChain, i));
    return ok ? 1 : 0;
}

int ossl_init(Shadow *s) {
    s->ssl = SSL_new(gCtx);
    if (!s->ssl) return -1;
    SSL_set_ex_data(s->ssl, gSslExIdx, s);
    BIO *bio = BIO_new(gBioMeth);
    if (!bio) { SSL_free(s->ssl); s->ssl = NULL; return -1; }
    BIO_set_data(bio, s);
    BIO_set_init(bio, 1);
    SSL_set_bio(s->ssl, bio, bio);
    if (s->host[0]) { SSL_set_tlsext_host_name(s->ssl, s->host); SSL_set1_host(s->ssl, s->host); }
    SSL_set_connect_state(s->ssl);
    if (s->clientX509) {
        SSL_set_max_proto_version(s->ssl, TLS1_2_VERSION);
        SSL_set1_client_sigalgs_list(s->ssl, "RSA+SHA256:RSA+SHA384:RSA+SHA512:RSA+SHA1");
        SSL_set_cert_cb(s->ssl, cert_cb, NULL);
    }
    s->inited = 1;
    return 0;
}

// verification: the device's own system trust store
static int verify_chain(X509_STORE_CTX *sctx, void *arg) {
    (void)arg;
    SSL *ssl = (SSL *)X509_STORE_CTX_get_ex_data(sctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    Shadow *s = ssl ? (Shadow *)SSL_get_ex_data(ssl, gSslExIdx) : NULL;
    if (s && s->breakAuth) return 1;
    STACK_OF(X509) *chain = X509_STORE_CTX_get0_untrusted(sctx);
    if (!chain || sk_X509_num(chain) < 1) return 0;
    CFMutableArrayRef arr = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    for (int i = 0; i < sk_X509_num(chain); i++) {
        unsigned char *der = NULL; int dl = i2d_X509(sk_X509_value(chain, i), &der);
        if (dl > 0 && der) {
            CFDataRef d = CFDataCreate(NULL, der, dl);
            SecCertificateRef sc = d ? SecCertificateCreateWithData(NULL, d) : NULL;
            if (sc) { CFArrayAppendValue(arr, sc); CFRelease(sc); }
            if (d) CFRelease(d);
        }
        if (der) OPENSSL_free(der);
    }
    CFStringRef host = (s && s->host[0]) ? CFStringCreateWithCString(NULL, s->host, kCFStringEncodingUTF8) : NULL;
    SecPolicyRef pol = SecPolicyCreateSSL(true, host);
    SecTrustRef t = NULL; int ok = 0;
    if (SecTrustCreateWithCertificates(arr, pol, &t) == errSecSuccess && t) {
        SecTrustResultType rr = kSecTrustResultInvalid;
        if (SecTrustEvaluate(t, &rr) == errSecSuccess && (rr == kSecTrustResultProceed || rr == kSecTrustResultUnspecified)) ok = 1;
        CFRelease(t);
    }
    if (pol) CFRelease(pol);
    if (host) CFRelease(host);
    CFRelease(arr);
    return ok;
}

// peer chain handed back to the app
CFArrayRef sh_cert_array(Shadow *s) {
    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(s->ssl);
    if (!chain) return NULL;
    CFMutableArrayRef arr = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    for (int i = 0; i < sk_X509_num(chain); i++) {
        unsigned char *der = NULL; int dl = i2d_X509(sk_X509_value(chain, i), &der);
        if (dl > 0 && der) {
            CFDataRef d = CFDataCreate(NULL, der, dl);
            SecCertificateRef sc = d ? SecCertificateCreateWithData(NULL, d) : NULL;
            if (sc) { CFArrayAppendValue(arr, sc); CFRelease(sc); }
            if (d) CFRelease(d);
        }
        if (der) OPENSSL_free(der);
    }
    return arr;
}
int sh_build_trust(Shadow *s, SecTrustRef *trust) {
    CFArrayRef arr = sh_cert_array(s);
    if (!arr) return 0;
    CFStringRef hostStr = s->host[0] ? CFStringCreateWithCString(NULL, s->host, kCFStringEncodingUTF8) : NULL;
    SecPolicyRef pol = SecPolicyCreateSSL(true, hostStr);
    if (hostStr) CFRelease(hostStr);
    SecTrustRef t = NULL;
    OSStatus r = SecTrustCreateWithCertificates(arr, pol, &t);
    if (pol) CFRelease(pol);
    CFRelease(arr);
    if (r != errSecSuccess) return 0;
    SecTrustResultType rr = kSecTrustResultInvalid;
    SecTrustEvaluate(t, &rr);   // populate internal chain, a native handshake returns an evaluated trust, and CFNetwork's SocketStream path derefs it (SecTrustCopyExceptions)
    *trust = t;
    return 1;
}

static int g_state = 0;                          // 0 unchecked, 1 active, -1 setup failed
static pthread_once_t g_once = PTHREAD_ONCE_INIT;
static void do_ready(void) {
    setenv("OPENSSL_armcap", "0", 1);               // skip OpenSSL ARM CPU-feature probe (armv6)
    OPENSSL_init_ssl(0, NULL);
    gRsaExIdx = RSA_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    gRsaMeth = RSA_meth_dup(RSA_get_default_method());
    if (gRsaMeth) { RSA_meth_set1_name(gRsaMeth, "tlsfix-seckey"); RSA_meth_set_priv_enc(gRsaMeth, rsa_seckey_priv_enc); }
    gCtx = SSL_CTX_new(TLS_client_method());
    if (gCtx) {
        SSL_CTX_set_security_level(gCtx, 0);                          // allow legacy crypto / 1024-bit identities
        SSL_CTX_set_min_proto_version(gCtx, TLS1_VERSION);            // TLS 1.0 .. 1.3
        SSL_CTX_set_max_proto_version(gCtx, TLS1_3_VERSION);
        SSL_CTX_set_verify(gCtx, SSL_VERIFY_PEER, NULL);
        gSslExIdx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
        SSL_CTX_set_cert_verify_callback(gCtx, verify_chain, NULL);
    }
    gBioMeth = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "cfnetwork");
    if (gBioMeth) {
        BIO_meth_set_write(gBioMeth, bio_bwrite);
        BIO_meth_set_read(gBioMeth, bio_bread);
        BIO_meth_set_ctrl(gBioMeth, bio_ctrl);
        BIO_meth_set_create(gBioMeth, bio_create);
        BIO_meth_set_destroy(gBioMeth, bio_destroy);
    }
    g_state = (gCtx && gBioMeth) ? 1 : -1;
}
int ensure_ready(void) { pthread_once(&g_once, do_ready); return g_state; }
