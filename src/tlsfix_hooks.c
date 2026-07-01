#include "tlsfix.h"
#include <dlfcn.h>
#include <string.h>


extern void MSHookFunction(void *symbol, void *replace, void **result);

static OSStatus (*o_SetIOFuncs)(SSLContextRef, SSLReadFunc, SSLWriteFunc);
static OSStatus my_SetIOFuncs(SSLContextRef c, SSLReadFunc rf, SSLWriteFunc wf) {
    if (ensure_ready() != 1) return o_SetIOFuncs(c, rf, wf);
    OSStatus r = o_SetIOFuncs(c, rf, wf);
    Shadow *s = sh_create(c);
    if (s) { s->rf = rf; s->wf = wf; sh_release(s); }
    return r;
}
static OSStatus (*o_SetConnection)(SSLContextRef, SSLConnectionRef);
static OSStatus my_SetConnection(SSLContextRef c, SSLConnectionRef conn) {
    if (ensure_ready() != 1) return o_SetConnection(c, conn);
    OSStatus r = o_SetConnection(c, conn);
    Shadow *s = sh_create(c);
    if (s) { s->conn = conn; sh_release(s); }
    return r;
}
static OSStatus (*o_SetPeerDomainName)(SSLContextRef, const char *, size_t);
static OSStatus my_SetPeerDomainName(SSLContextRef c, const char *name, size_t len) {
    if (ensure_ready() != 1) return o_SetPeerDomainName(c, name, len);
    OSStatus r = o_SetPeerDomainName(c, name, len);
    Shadow *s = sh_create(c);
    if (s) {
        if (name && len) {
            size_t n = len < 255 ? len : 255; memcpy(s->host, name, n); s->host[n] = 0;
            if (s->inited && s->state != -1) { SSL_free(s->ssl); s->ssl = NULL; s->inited = 0; s->state = 0; } // late SNI -> re-init
        }
        sh_release(s);
    }
    return r;
}
static OSStatus (*o_SetSessionOption)(SSLContextRef, SSLSessionOption, Boolean);
static OSStatus my_SetSessionOption(SSLContextRef c, SSLSessionOption opt, Boolean val) {
    if (ensure_ready() == 1 && opt == kSSLSessionOptionBreakOnServerAuth) {
        Shadow *s = sh_create(c);
        if (s) { s->breakAuth = val ? 1 : 0; sh_release(s); }
    }
    return o_SetSessionOption(c, opt, val);
}
static OSStatus (*o_Handshake)(SSLContextRef);
static OSStatus my_Handshake(SSLContextRef c) {
    Shadow *s = sh_get(c);
    if (!s) return o_Handshake(c);
    OSStatus rv;
    if (!s->rf || !s->wf || !s->conn || s->clientBypass || s->state == -1) { rv = o_Handshake(c); goto done; }
    if (!s->inited) { if (ossl_init(s)) { s->state = -1; rv = o_Handshake(c); goto done; } s->state = 1; }
    if (s->state == 3) s->approved = 1;   // app approved the server after the auth break, let it proceed
    int ret = SSL_do_handshake(s->ssl);
    if (ret == 1) {
        // server-auth-only pinning has no client-cert pause point, so ask the app here (once) before connecting
        if (s->breakAuth && !s->approved) { s->state = 3; rv = ST_PeerAuth; goto done; }
        s->state = 2; rv = noErr; goto done;
    }
    int e = SSL_get_error(s->ssl, ret);
    // mutual TLS + pinning: cert_cb suspended us before sending our cert -> hand the server cert to the app
    if (e == SSL_ERROR_WANT_X509_LOOKUP) { s->state = 3; rv = ST_PeerAuth; goto done; }
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) rv = errSSLWouldBlock;
    else { s->state = -1; rv = ST_ClosedAbort; }
done:
    sh_release(s);
    return rv;
}
static OSStatus (*o_Read)(SSLContextRef, void *, size_t, size_t *);
static OSStatus my_Read(SSLContextRef c, void *data, size_t len, size_t *processed) {
    Shadow *s = sh_get(c);
    if (!s || s->state != 2) { OSStatus r = o_Read(c, data, len, processed); sh_release(s); return r; }
    *processed = 0;
    int n = SSL_read(s->ssl, data, (int)len);
    OSStatus rv;
    if (n > 0) { *processed = (size_t)n; rv = noErr; }
    else {
        int e = SSL_get_error(s->ssl, n);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) rv = errSSLWouldBlock;
        else if (e == SSL_ERROR_ZERO_RETURN) rv = ST_ClosedGraceful;
        else rv = ST_ClosedAbort;
    }
    sh_release(s);
    return rv;
}
static OSStatus (*o_Write)(SSLContextRef, const void *, size_t, size_t *);
static OSStatus my_Write(SSLContextRef c, const void *data, size_t len, size_t *processed) {
    Shadow *s = sh_get(c);
    if (!s || s->state != 2) { OSStatus r = o_Write(c, data, len, processed); sh_release(s); return r; }
    *processed = 0;
    int n = SSL_write(s->ssl, data, (int)len);
    OSStatus rv;
    if (n > 0) { *processed = (size_t)n; rv = noErr; }
    else {
        int e = SSL_get_error(s->ssl, n);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) rv = errSSLWouldBlock;
        else rv = ST_ClosedAbort;
    }
    sh_release(s);
    return rv;
}
// SSLDisposeContext is intentionally not hooked, function too small, MSHookFunction overwrites adjacent memory.
static OSStatus (*o_Close)(SSLContextRef);
static OSStatus my_Close(SSLContextRef c) {
    Shadow *s = sh_get(c);
    if (s && s->state == 2 && s->ssl) SSL_shutdown(s->ssl);
    sh_release(s);
    OSStatus r = o_Close(c);
    sh_free(c); 
    return r;
}
static OSStatus (*o_GetSessionState)(SSLContextRef, SSLSessionState *);
static OSStatus my_GetSessionState(SSLContextRef c, SSLSessionState *st) {
    Shadow *s = sh_get(c);
    OSStatus rv;
    if (s && s->state == 2) { if (st) *st = ST_Connected; rv = noErr; }
    else rv = o_GetSessionState(c, st);
    sh_release(s);
    return rv;
}
static OSStatus (*o_GetNegProto)(SSLContextRef, SSLProtocol *);
static OSStatus my_GetNegProto(SSLContextRef c, SSLProtocol *p) {
    Shadow *s = sh_get(c);
    OSStatus rv;
    // Spoofer must be active during ST_Connected (2) AND ST_PeerAuth (3)
    if (s && (s->state == 2 || s->state == 3)) { 
        if (p) *p = 4; // 4 = kTLSProtocol1
        rv = noErr; 
    }
    else rv = o_GetNegProto(c, p);
    
    sh_release(s);
    return rv;
}
static OSStatus (*o_GetNegCipher)(SSLContextRef, UInt32 *);
static OSStatus my_GetNegCipher(SSLContextRef c, UInt32 *cipher) {
    Shadow *s = sh_get(c);
    OSStatus rv;
    // Spoofer must be active during ST_Connected (2) AND ST_PeerAuth (3)
    if (s && (s->state == 2 || s->state == 3)) {
        if (cipher) *cipher = 0x002F; // TLS_RSA_WITH_AES_128_CBC_SHA
        rv = noErr;
    } 
    else rv = o_GetNegCipher(c, cipher);
    
    sh_release(s);
    return rv;
}
static OSStatus (*o_GetBuffered)(SSLContextRef, size_t *);
static OSStatus my_GetBuffered(SSLContextRef c, size_t *sz) {
    Shadow *s = sh_get(c);
    OSStatus rv;
    if (s && s->state == 2) { if (sz) *sz = (size_t)SSL_pending(s->ssl); rv = noErr; }
    else rv = o_GetBuffered(c, sz);
    sh_release(s);
    return rv;
}
static OSStatus (*o_CopyPeerTrust)(SSLContextRef, SecTrustRef *);
static OSStatus my_CopyPeerTrust(SSLContextRef c, SecTrustRef *trust) {
    Shadow *s = sh_get(c);
    OSStatus rv;
    if (!s || (s->state != 2 && s->state != 3) || !trust) rv = o_CopyPeerTrust(c, trust);
    else if (sh_build_trust(s, trust)) rv = noErr;
    else rv = o_CopyPeerTrust(c, trust);
    sh_release(s);
    return rv;
}
static OSStatus (*o_CopyPeerCerts)(SSLContextRef, CFArrayRef *);
static OSStatus my_CopyPeerCerts(SSLContextRef c, CFArrayRef *certs) {
    Shadow *s = sh_get(c);
    OSStatus rv;
    if (!s || (s->state != 2 && s->state != 3) || !certs) rv = o_CopyPeerCerts(c, certs);
    else { CFArrayRef arr = sh_cert_array(s); if (!arr) rv = o_CopyPeerCerts(c, certs); else { *certs = arr; rv = noErr; } }
    sh_release(s);
    return rv;
}
static OSStatus (*o_SetCertificate)(SSLContextRef, CFArrayRef);
static OSStatus my_SetCertificate(SSLContextRef c, CFArrayRef certRefs) {
    if (ensure_ready() != 1) return o_SetCertificate(c, certRefs);
    Shadow *s = sh_create(c);
    if (s) {
        capture_identity(s, certRefs);
        if (s->inited && s->state != -1) { SSL_free(s->ssl); s->ssl = NULL; s->inited = 0; s->state = 0; }
        sh_release(s);
    }
    return o_SetCertificate(c, certRefs);
}

static void hook(const char *name, void *repl, void **orig) {
    void *sym = dlsym(RTLD_DEFAULT, name);
    if (sym) MSHookFunction(sym, repl, orig);
}

__attribute__((constructor))
static void tlsfix_init(void) {
    const char *pn = getprogname();
    
    static const char *deny[] = { "SpringBoard", "backboardd", "launchd", "assertiond", "lockdownd",
                                  "securityd", "trustd", 0 };

    for (int i = 0; deny[i]; i++) if (pn && !strcmp(pn, deny[i])) return;
    hook("SSLSetIOFuncs",                  (void *)my_SetIOFuncs,        (void **)&o_SetIOFuncs);
    hook("SSLSetConnection",               (void *)my_SetConnection,     (void **)&o_SetConnection);
    hook("SSLSetPeerDomainName",           (void *)my_SetPeerDomainName, (void **)&o_SetPeerDomainName);
    hook("SSLSetSessionOption",            (void *)my_SetSessionOption,  (void **)&o_SetSessionOption);
    hook("SSLHandshake",                   (void *)my_Handshake,         (void **)&o_Handshake);
    hook("SSLRead",                        (void *)my_Read,              (void **)&o_Read);
    hook("SSLWrite",                       (void *)my_Write,             (void **)&o_Write);
    hook("SSLClose",                       (void *)my_Close,             (void **)&o_Close);
    hook("SSLGetSessionState",             (void *)my_GetSessionState,   (void **)&o_GetSessionState);
    hook("SSLGetNegotiatedProtocolVersion",(void *)my_GetNegProto,       (void **)&o_GetNegProto);
    hook("SSLGetNegotiatedCipher",         (void *)my_GetNegCipher,      (void **)&o_GetNegCipher);
    hook("SSLGetBufferedReadSize",         (void *)my_GetBuffered,       (void **)&o_GetBuffered);
    hook("SSLCopyPeerTrust",               (void *)my_CopyPeerTrust,     (void **)&o_CopyPeerTrust);
    hook("SSLCopyPeerCertificates",        (void *)my_CopyPeerCerts,     (void **)&o_CopyPeerCerts);
    hook("SSLSetCertificate",              (void *)my_SetCertificate,    (void **)&o_SetCertificate);
}
