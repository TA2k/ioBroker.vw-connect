.class public abstract Lio/opentelemetry/exporter/internal/http/HttpSenderConfig;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


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

.method public static create(Ljava/lang/String;Lio/opentelemetry/exporter/internal/compression/Compressor;ZLjava/lang/String;JJLjava/util/function/Supplier;Lio/opentelemetry/sdk/common/export/ProxyOptions;Lio/opentelemetry/sdk/common/export/RetryPolicy;Ljavax/net/ssl/SSLContext;Ljavax/net/ssl/X509TrustManager;Ljava/util/concurrent/ExecutorService;)Lio/opentelemetry/exporter/internal/http/HttpSenderConfig;
    .locals 15
    .param p1    # Lio/opentelemetry/exporter/internal/compression/Compressor;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p9    # Lio/opentelemetry/sdk/common/export/ProxyOptions;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p10    # Lio/opentelemetry/sdk/common/export/RetryPolicy;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p11    # Ljavax/net/ssl/SSLContext;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p12    # Ljavax/net/ssl/X509TrustManager;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p13    # Ljava/util/concurrent/ExecutorService;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lio/opentelemetry/exporter/internal/compression/Compressor;",
            "Z",
            "Ljava/lang/String;",
            "JJ",
            "Ljava/util/function/Supplier<",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;>;>;",
            "Lio/opentelemetry/sdk/common/export/ProxyOptions;",
            "Lio/opentelemetry/sdk/common/export/RetryPolicy;",
            "Ljavax/net/ssl/SSLContext;",
            "Ljavax/net/ssl/X509TrustManager;",
            "Ljava/util/concurrent/ExecutorService;",
            ")",
            "Lio/opentelemetry/exporter/internal/http/HttpSenderConfig;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/http/AutoValue_HttpSenderConfig;

    .line 2
    .line 3
    move-object v1, p0

    .line 4
    move-object/from16 v2, p1

    .line 5
    .line 6
    move/from16 v3, p2

    .line 7
    .line 8
    move-object/from16 v4, p3

    .line 9
    .line 10
    move-wide/from16 v5, p4

    .line 11
    .line 12
    move-wide/from16 v7, p6

    .line 13
    .line 14
    move-object/from16 v9, p8

    .line 15
    .line 16
    move-object/from16 v10, p9

    .line 17
    .line 18
    move-object/from16 v11, p10

    .line 19
    .line 20
    move-object/from16 v12, p11

    .line 21
    .line 22
    move-object/from16 v13, p12

    .line 23
    .line 24
    move-object/from16 v14, p13

    .line 25
    .line 26
    invoke-direct/range {v0 .. v14}, Lio/opentelemetry/exporter/internal/http/AutoValue_HttpSenderConfig;-><init>(Ljava/lang/String;Lio/opentelemetry/exporter/internal/compression/Compressor;ZLjava/lang/String;JJLjava/util/function/Supplier;Lio/opentelemetry/sdk/common/export/ProxyOptions;Lio/opentelemetry/sdk/common/export/RetryPolicy;Ljavax/net/ssl/SSLContext;Ljavax/net/ssl/X509TrustManager;Ljava/util/concurrent/ExecutorService;)V

    .line 27
    .line 28
    .line 29
    return-object v0
.end method


# virtual methods
.method public abstract getCompressor()Lio/opentelemetry/exporter/internal/compression/Compressor;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public abstract getConnectTimeoutNanos()J
.end method

.method public abstract getContentType()Ljava/lang/String;
.end method

.method public abstract getEndpoint()Ljava/lang/String;
.end method

.method public abstract getExecutorService()Ljava/util/concurrent/ExecutorService;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public abstract getExportAsJson()Z
.end method

.method public abstract getHeadersSupplier()Ljava/util/function/Supplier;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/function/Supplier<",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;>;>;"
        }
    .end annotation
.end method

.method public abstract getProxyOptions()Lio/opentelemetry/sdk/common/export/ProxyOptions;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public abstract getRetryPolicy()Lio/opentelemetry/sdk/common/export/RetryPolicy;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public abstract getSslContext()Ljavax/net/ssl/SSLContext;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public abstract getTimeoutNanos()J
.end method

.method public abstract getTrustManager()Ljavax/net/ssl/X509TrustManager;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method
