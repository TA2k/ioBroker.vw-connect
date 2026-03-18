.class public final Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSenderProvider;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/exporter/internal/http/HttpSenderProvider;


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
.method public createSender(Lio/opentelemetry/exporter/internal/http/HttpSenderConfig;)Lio/opentelemetry/exporter/internal/http/HttpSender;
    .locals 15

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;

    .line 2
    .line 3
    invoke-virtual/range {p1 .. p1}, Lio/opentelemetry/exporter/internal/http/HttpSenderConfig;->getEndpoint()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-virtual/range {p1 .. p1}, Lio/opentelemetry/exporter/internal/http/HttpSenderConfig;->getCompressor()Lio/opentelemetry/exporter/internal/compression/Compressor;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    invoke-virtual/range {p1 .. p1}, Lio/opentelemetry/exporter/internal/http/HttpSenderConfig;->getExportAsJson()Z

    .line 12
    .line 13
    .line 14
    move-result v3

    .line 15
    invoke-virtual/range {p1 .. p1}, Lio/opentelemetry/exporter/internal/http/HttpSenderConfig;->getContentType()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v4

    .line 19
    invoke-virtual/range {p1 .. p1}, Lio/opentelemetry/exporter/internal/http/HttpSenderConfig;->getTimeoutNanos()J

    .line 20
    .line 21
    .line 22
    move-result-wide v5

    .line 23
    invoke-virtual/range {p1 .. p1}, Lio/opentelemetry/exporter/internal/http/HttpSenderConfig;->getConnectTimeoutNanos()J

    .line 24
    .line 25
    .line 26
    move-result-wide v7

    .line 27
    invoke-virtual/range {p1 .. p1}, Lio/opentelemetry/exporter/internal/http/HttpSenderConfig;->getHeadersSupplier()Ljava/util/function/Supplier;

    .line 28
    .line 29
    .line 30
    move-result-object v9

    .line 31
    invoke-virtual/range {p1 .. p1}, Lio/opentelemetry/exporter/internal/http/HttpSenderConfig;->getProxyOptions()Lio/opentelemetry/sdk/common/export/ProxyOptions;

    .line 32
    .line 33
    .line 34
    move-result-object v10

    .line 35
    invoke-virtual/range {p1 .. p1}, Lio/opentelemetry/exporter/internal/http/HttpSenderConfig;->getRetryPolicy()Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 36
    .line 37
    .line 38
    move-result-object v11

    .line 39
    invoke-virtual/range {p1 .. p1}, Lio/opentelemetry/exporter/internal/http/HttpSenderConfig;->getSslContext()Ljavax/net/ssl/SSLContext;

    .line 40
    .line 41
    .line 42
    move-result-object v12

    .line 43
    invoke-virtual/range {p1 .. p1}, Lio/opentelemetry/exporter/internal/http/HttpSenderConfig;->getTrustManager()Ljavax/net/ssl/X509TrustManager;

    .line 44
    .line 45
    .line 46
    move-result-object v13

    .line 47
    invoke-virtual/range {p1 .. p1}, Lio/opentelemetry/exporter/internal/http/HttpSenderConfig;->getExecutorService()Ljava/util/concurrent/ExecutorService;

    .line 48
    .line 49
    .line 50
    move-result-object v14

    .line 51
    invoke-direct/range {v0 .. v14}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;-><init>(Ljava/lang/String;Lio/opentelemetry/exporter/internal/compression/Compressor;ZLjava/lang/String;JJLjava/util/function/Supplier;Lio/opentelemetry/sdk/common/export/ProxyOptions;Lio/opentelemetry/sdk/common/export/RetryPolicy;Ljavax/net/ssl/SSLContext;Ljavax/net/ssl/X509TrustManager;Ljava/util/concurrent/ExecutorService;)V

    .line 52
    .line 53
    .line 54
    return-object v0
.end method
