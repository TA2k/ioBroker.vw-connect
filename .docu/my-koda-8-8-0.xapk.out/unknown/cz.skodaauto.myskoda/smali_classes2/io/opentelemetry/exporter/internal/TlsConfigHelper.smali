.class public Lio/opentelemetry/exporter/internal/TlsConfigHelper;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private keyManager:Ljavax/net/ssl/X509KeyManager;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private sslContext:Ljavax/net/ssl/SSLContext;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private trustManager:Ljavax/net/ssl/X509TrustManager;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public copy()Lio/opentelemetry/exporter/internal/TlsConfigHelper;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/TlsConfigHelper;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/exporter/internal/TlsConfigHelper;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/TlsConfigHelper;->keyManager:Ljavax/net/ssl/X509KeyManager;

    .line 7
    .line 8
    iput-object v1, v0, Lio/opentelemetry/exporter/internal/TlsConfigHelper;->keyManager:Ljavax/net/ssl/X509KeyManager;

    .line 9
    .line 10
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/TlsConfigHelper;->trustManager:Ljavax/net/ssl/X509TrustManager;

    .line 11
    .line 12
    iput-object v1, v0, Lio/opentelemetry/exporter/internal/TlsConfigHelper;->trustManager:Ljavax/net/ssl/X509TrustManager;

    .line 13
    .line 14
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/TlsConfigHelper;->sslContext:Ljavax/net/ssl/SSLContext;

    .line 15
    .line 16
    iput-object p0, v0, Lio/opentelemetry/exporter/internal/TlsConfigHelper;->sslContext:Ljavax/net/ssl/SSLContext;

    .line 17
    .line 18
    return-object v0
.end method

.method public getKeyManager()Ljavax/net/ssl/X509KeyManager;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/TlsConfigHelper;->keyManager:Ljavax/net/ssl/X509KeyManager;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSslContext()Ljavax/net/ssl/SSLContext;
    .locals 6
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/TlsConfigHelper;->sslContext:Ljavax/net/ssl/SSLContext;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-object v0

    .line 6
    :cond_0
    :try_start_0
    const-string v0, "TLS"

    .line 7
    .line 8
    invoke-static {v0}, Ljavax/net/ssl/SSLContext;->getInstance(Ljava/lang/String;)Ljavax/net/ssl/SSLContext;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/TlsConfigHelper;->keyManager:Ljavax/net/ssl/X509KeyManager;

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    const/4 v3, 0x1

    .line 16
    const/4 v4, 0x0

    .line 17
    if-nez v1, :cond_1

    .line 18
    .line 19
    move-object v5, v4

    .line 20
    goto :goto_0

    .line 21
    :cond_1
    new-array v5, v3, [Ljavax/net/ssl/KeyManager;

    .line 22
    .line 23
    aput-object v1, v5, v2

    .line 24
    .line 25
    :goto_0
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/TlsConfigHelper;->trustManager:Ljavax/net/ssl/X509TrustManager;

    .line 26
    .line 27
    if-nez p0, :cond_2

    .line 28
    .line 29
    move-object v1, v4

    .line 30
    goto :goto_1

    .line 31
    :cond_2
    new-array v1, v3, [Ljavax/net/ssl/TrustManager;

    .line 32
    .line 33
    aput-object p0, v1, v2

    .line 34
    .line 35
    :goto_1
    invoke-virtual {v0, v5, v1, v4}, Ljavax/net/ssl/SSLContext;->init([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V
    :try_end_0
    .catch Ljava/security/NoSuchAlgorithmException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/security/KeyManagementException; {:try_start_0 .. :try_end_0} :catch_0

    .line 36
    .line 37
    .line 38
    return-object v0

    .line 39
    :catch_0
    move-exception p0

    .line 40
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 41
    .line 42
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/Throwable;)V

    .line 43
    .line 44
    .line 45
    throw v0
.end method

.method public getTrustManager()Ljavax/net/ssl/X509TrustManager;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/TlsConfigHelper;->trustManager:Ljavax/net/ssl/X509TrustManager;

    .line 2
    .line 3
    return-object p0
.end method

.method public setKeyManagerFromCerts([B[B)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/TlsConfigHelper;->keyManager:Ljavax/net/ssl/X509KeyManager;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    :try_start_0
    invoke-static {p1, p2}, Lio/opentelemetry/exporter/internal/TlsUtil;->keyManager([B[B)Ljavax/net/ssl/X509KeyManager;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/TlsConfigHelper;->keyManager:Ljavax/net/ssl/X509KeyManager;
    :try_end_0
    .catch Ljavax/net/ssl/SSLException; {:try_start_0 .. :try_end_0} :catch_0

    .line 10
    .line 11
    return-void

    .line 12
    :catch_0
    move-exception p0

    .line 13
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 14
    .line 15
    const-string p2, "Error creating X509KeyManager with provided certs. Are they valid X.509 in PEM format?"

    .line 16
    .line 17
    invoke-direct {p1, p2, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 18
    .line 19
    .line 20
    throw p1

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string p1, "keyManager has been previously configured"

    .line 24
    .line 25
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0
.end method

.method public setSslContext(Ljavax/net/ssl/SSLContext;Ljavax/net/ssl/X509TrustManager;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/TlsConfigHelper;->sslContext:Ljavax/net/ssl/SSLContext;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/TlsConfigHelper;->trustManager:Ljavax/net/ssl/X509TrustManager;

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iput-object p2, p0, Lio/opentelemetry/exporter/internal/TlsConfigHelper;->trustManager:Ljavax/net/ssl/X509TrustManager;

    .line 10
    .line 11
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/TlsConfigHelper;->sslContext:Ljavax/net/ssl/SSLContext;

    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 15
    .line 16
    const-string p1, "sslContext or trustManager has been previously configured"

    .line 17
    .line 18
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    throw p0
.end method

.method public setTrustManagerFromCerts([B)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/TlsConfigHelper;->trustManager:Ljavax/net/ssl/X509TrustManager;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    :try_start_0
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/TlsUtil;->trustManager([B)Ljavax/net/ssl/X509TrustManager;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/TlsConfigHelper;->trustManager:Ljavax/net/ssl/X509TrustManager;
    :try_end_0
    .catch Ljavax/net/ssl/SSLException; {:try_start_0 .. :try_end_0} :catch_0

    .line 10
    .line 11
    return-void

    .line 12
    :catch_0
    move-exception p0

    .line 13
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 14
    .line 15
    const-string v0, "Error creating X509TrustManager with provided certs. Are they valid X.509 in PEM format?"

    .line 16
    .line 17
    invoke-direct {p1, v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 18
    .line 19
    .line 20
    throw p1

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string p1, "trustManager has been previously configured"

    .line 24
    .line 25
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0
.end method
