.class public Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSenderProvider;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/exporter/internal/grpc/GrpcSenderProvider;


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
.method public createSender(Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;)Lio/opentelemetry/exporter/internal/grpc/GrpcSender;
    .locals 12
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
            ">(",
            "Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig<",
            "TT;>;)",
            "Lio/opentelemetry/exporter/internal/grpc/GrpcSender<",
            "TT;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getEndpoint()Ljava/net/URI;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getEndpointPath()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-virtual {p0, v1}, Ljava/net/URI;->resolve(Ljava/lang/String;)Ljava/net/URI;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-virtual {p0}, Ljava/net/URI;->toString()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getCompressor()Lio/opentelemetry/exporter/internal/compression/Compressor;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getTimeoutNanos()J

    .line 24
    .line 25
    .line 26
    move-result-wide v3

    .line 27
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getConnectTimeoutNanos()J

    .line 28
    .line 29
    .line 30
    move-result-wide v5

    .line 31
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getHeadersSupplier()Ljava/util/function/Supplier;

    .line 32
    .line 33
    .line 34
    move-result-object v7

    .line 35
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getRetryPolicy()Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 36
    .line 37
    .line 38
    move-result-object v8

    .line 39
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getSslContext()Ljavax/net/ssl/SSLContext;

    .line 40
    .line 41
    .line 42
    move-result-object v9

    .line 43
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getTrustManager()Ljavax/net/ssl/X509TrustManager;

    .line 44
    .line 45
    .line 46
    move-result-object v10

    .line 47
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getExecutorService()Ljava/util/concurrent/ExecutorService;

    .line 48
    .line 49
    .line 50
    move-result-object v11

    .line 51
    invoke-direct/range {v0 .. v11}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;-><init>(Ljava/lang/String;Lio/opentelemetry/exporter/internal/compression/Compressor;JJLjava/util/function/Supplier;Lio/opentelemetry/sdk/common/export/RetryPolicy;Ljavax/net/ssl/SSLContext;Ljavax/net/ssl/X509TrustManager;Ljava/util/concurrent/ExecutorService;)V

    .line 52
    .line 53
    .line 54
    return-object v0
.end method
