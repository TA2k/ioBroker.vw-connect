.class final Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;
.super Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
        ">",
        "Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig<",
        "TT;>;"
    }
.end annotation


# instance fields
.field private final compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final connectTimeoutNanos:J

.field private final endpoint:Ljava/net/URI;

.field private final endpointPath:Ljava/lang/String;

.field private final executorService:Ljava/util/concurrent/ExecutorService;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final headersSupplier:Ljava/util/function/Supplier;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Supplier<",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;>;>;"
        }
    .end annotation
.end field

.field private final managedChannel:Ljava/lang/Object;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final retryPolicy:Lio/opentelemetry/sdk/common/export/RetryPolicy;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final sslContext:Ljavax/net/ssl/SSLContext;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final stubFactory:Ljava/util/function/Supplier;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Supplier<",
            "Ljava/util/function/BiFunction<",
            "Lio/grpc/Channel;",
            "Ljava/lang/String;",
            "Lio/opentelemetry/exporter/internal/grpc/MarshalerServiceStub<",
            "TT;**>;>;>;"
        }
    .end annotation
.end field

.field private final timeoutNanos:J

.field private final trustManager:Ljavax/net/ssl/X509TrustManager;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ljava/net/URI;Ljava/lang/String;Lio/opentelemetry/exporter/internal/compression/Compressor;JJLjava/util/function/Supplier;Ljava/lang/Object;Ljava/util/function/Supplier;Lio/opentelemetry/sdk/common/export/RetryPolicy;Ljavax/net/ssl/SSLContext;Ljavax/net/ssl/X509TrustManager;Ljava/util/concurrent/ExecutorService;)V
    .locals 0
    .param p3    # Lio/opentelemetry/exporter/internal/compression/Compressor;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p9    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p11    # Lio/opentelemetry/sdk/common/export/RetryPolicy;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p12    # Ljavax/net/ssl/SSLContext;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p13    # Ljavax/net/ssl/X509TrustManager;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p14    # Ljava/util/concurrent/ExecutorService;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/net/URI;",
            "Ljava/lang/String;",
            "Lio/opentelemetry/exporter/internal/compression/Compressor;",
            "JJ",
            "Ljava/util/function/Supplier<",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;>;>;",
            "Ljava/lang/Object;",
            "Ljava/util/function/Supplier<",
            "Ljava/util/function/BiFunction<",
            "Lio/grpc/Channel;",
            "Ljava/lang/String;",
            "Lio/opentelemetry/exporter/internal/grpc/MarshalerServiceStub<",
            "TT;**>;>;>;",
            "Lio/opentelemetry/sdk/common/export/RetryPolicy;",
            "Ljavax/net/ssl/SSLContext;",
            "Ljavax/net/ssl/X509TrustManager;",
            "Ljava/util/concurrent/ExecutorService;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;-><init>()V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_3

    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->endpoint:Ljava/net/URI;

    .line 7
    .line 8
    if-eqz p2, :cond_2

    .line 9
    .line 10
    iput-object p2, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->endpointPath:Ljava/lang/String;

    .line 11
    .line 12
    iput-object p3, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;

    .line 13
    .line 14
    iput-wide p4, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->timeoutNanos:J

    .line 15
    .line 16
    iput-wide p6, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->connectTimeoutNanos:J

    .line 17
    .line 18
    if-eqz p8, :cond_1

    .line 19
    .line 20
    iput-object p8, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->headersSupplier:Ljava/util/function/Supplier;

    .line 21
    .line 22
    iput-object p9, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->managedChannel:Ljava/lang/Object;

    .line 23
    .line 24
    if-eqz p10, :cond_0

    .line 25
    .line 26
    iput-object p10, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->stubFactory:Ljava/util/function/Supplier;

    .line 27
    .line 28
    iput-object p11, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->retryPolicy:Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 29
    .line 30
    iput-object p12, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->sslContext:Ljavax/net/ssl/SSLContext;

    .line 31
    .line 32
    iput-object p13, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->trustManager:Ljavax/net/ssl/X509TrustManager;

    .line 33
    .line 34
    iput-object p14, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->executorService:Ljava/util/concurrent/ExecutorService;

    .line 35
    .line 36
    return-void

    .line 37
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 38
    .line 39
    const-string p1, "Null stubFactory"

    .line 40
    .line 41
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw p0

    .line 45
    :cond_1
    new-instance p0, Ljava/lang/NullPointerException;

    .line 46
    .line 47
    const-string p1, "Null headersSupplier"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    new-instance p0, Ljava/lang/NullPointerException;

    .line 54
    .line 55
    const-string p1, "Null endpointPath"

    .line 56
    .line 57
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p0

    .line 61
    :cond_3
    new-instance p0, Ljava/lang/NullPointerException;

    .line 62
    .line 63
    const-string p1, "Null endpoint"

    .line 64
    .line 65
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw p0
.end method


# virtual methods
.method public equals(Ljava/lang/Object;)Z
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p1, p0, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_7

    .line 9
    .line 10
    check-cast p1, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;

    .line 11
    .line 12
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->endpoint:Ljava/net/URI;

    .line 13
    .line 14
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getEndpoint()Ljava/net/URI;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    invoke-virtual {v1, v3}, Ljava/net/URI;->equals(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_7

    .line 23
    .line 24
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->endpointPath:Ljava/lang/String;

    .line 25
    .line 26
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getEndpointPath()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    if-eqz v1, :cond_7

    .line 35
    .line 36
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;

    .line 37
    .line 38
    if-nez v1, :cond_1

    .line 39
    .line 40
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getCompressor()Lio/opentelemetry/exporter/internal/compression/Compressor;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    if-nez v1, :cond_7

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_1
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getCompressor()Lio/opentelemetry/exporter/internal/compression/Compressor;

    .line 48
    .line 49
    .line 50
    move-result-object v3

    .line 51
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    if-eqz v1, :cond_7

    .line 56
    .line 57
    :goto_0
    iget-wide v3, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->timeoutNanos:J

    .line 58
    .line 59
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getTimeoutNanos()J

    .line 60
    .line 61
    .line 62
    move-result-wide v5

    .line 63
    cmp-long v1, v3, v5

    .line 64
    .line 65
    if-nez v1, :cond_7

    .line 66
    .line 67
    iget-wide v3, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->connectTimeoutNanos:J

    .line 68
    .line 69
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getConnectTimeoutNanos()J

    .line 70
    .line 71
    .line 72
    move-result-wide v5

    .line 73
    cmp-long v1, v3, v5

    .line 74
    .line 75
    if-nez v1, :cond_7

    .line 76
    .line 77
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->headersSupplier:Ljava/util/function/Supplier;

    .line 78
    .line 79
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getHeadersSupplier()Ljava/util/function/Supplier;

    .line 80
    .line 81
    .line 82
    move-result-object v3

    .line 83
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    if-eqz v1, :cond_7

    .line 88
    .line 89
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->managedChannel:Ljava/lang/Object;

    .line 90
    .line 91
    if-nez v1, :cond_2

    .line 92
    .line 93
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getManagedChannel()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    if-nez v1, :cond_7

    .line 98
    .line 99
    goto :goto_1

    .line 100
    :cond_2
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getManagedChannel()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v3

    .line 104
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result v1

    .line 108
    if-eqz v1, :cond_7

    .line 109
    .line 110
    :goto_1
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->stubFactory:Ljava/util/function/Supplier;

    .line 111
    .line 112
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getStubFactory()Ljava/util/function/Supplier;

    .line 113
    .line 114
    .line 115
    move-result-object v3

    .line 116
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    move-result v1

    .line 120
    if-eqz v1, :cond_7

    .line 121
    .line 122
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->retryPolicy:Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 123
    .line 124
    if-nez v1, :cond_3

    .line 125
    .line 126
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getRetryPolicy()Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 127
    .line 128
    .line 129
    move-result-object v1

    .line 130
    if-nez v1, :cond_7

    .line 131
    .line 132
    goto :goto_2

    .line 133
    :cond_3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getRetryPolicy()Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 134
    .line 135
    .line 136
    move-result-object v3

    .line 137
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 138
    .line 139
    .line 140
    move-result v1

    .line 141
    if-eqz v1, :cond_7

    .line 142
    .line 143
    :goto_2
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->sslContext:Ljavax/net/ssl/SSLContext;

    .line 144
    .line 145
    if-nez v1, :cond_4

    .line 146
    .line 147
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getSslContext()Ljavax/net/ssl/SSLContext;

    .line 148
    .line 149
    .line 150
    move-result-object v1

    .line 151
    if-nez v1, :cond_7

    .line 152
    .line 153
    goto :goto_3

    .line 154
    :cond_4
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getSslContext()Ljavax/net/ssl/SSLContext;

    .line 155
    .line 156
    .line 157
    move-result-object v3

    .line 158
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 159
    .line 160
    .line 161
    move-result v1

    .line 162
    if-eqz v1, :cond_7

    .line 163
    .line 164
    :goto_3
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->trustManager:Ljavax/net/ssl/X509TrustManager;

    .line 165
    .line 166
    if-nez v1, :cond_5

    .line 167
    .line 168
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getTrustManager()Ljavax/net/ssl/X509TrustManager;

    .line 169
    .line 170
    .line 171
    move-result-object v1

    .line 172
    if-nez v1, :cond_7

    .line 173
    .line 174
    goto :goto_4

    .line 175
    :cond_5
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getTrustManager()Ljavax/net/ssl/X509TrustManager;

    .line 176
    .line 177
    .line 178
    move-result-object v3

    .line 179
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 180
    .line 181
    .line 182
    move-result v1

    .line 183
    if-eqz v1, :cond_7

    .line 184
    .line 185
    :goto_4
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->executorService:Ljava/util/concurrent/ExecutorService;

    .line 186
    .line 187
    if-nez p0, :cond_6

    .line 188
    .line 189
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getExecutorService()Ljava/util/concurrent/ExecutorService;

    .line 190
    .line 191
    .line 192
    move-result-object p0

    .line 193
    if-nez p0, :cond_7

    .line 194
    .line 195
    goto :goto_5

    .line 196
    :cond_6
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcSenderConfig;->getExecutorService()Ljava/util/concurrent/ExecutorService;

    .line 197
    .line 198
    .line 199
    move-result-object p1

    .line 200
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 201
    .line 202
    .line 203
    move-result p0

    .line 204
    if-eqz p0, :cond_7

    .line 205
    .line 206
    :goto_5
    return v0

    .line 207
    :cond_7
    return v2
.end method

.method public getCompressor()Lio/opentelemetry/exporter/internal/compression/Compressor;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;

    .line 2
    .line 3
    return-object p0
.end method

.method public getConnectTimeoutNanos()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->connectTimeoutNanos:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getEndpoint()Ljava/net/URI;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->endpoint:Ljava/net/URI;

    .line 2
    .line 3
    return-object p0
.end method

.method public getEndpointPath()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->endpointPath:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getExecutorService()Ljava/util/concurrent/ExecutorService;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->executorService:Ljava/util/concurrent/ExecutorService;

    .line 2
    .line 3
    return-object p0
.end method

.method public getHeadersSupplier()Ljava/util/function/Supplier;
    .locals 0
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

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->headersSupplier:Ljava/util/function/Supplier;

    .line 2
    .line 3
    return-object p0
.end method

.method public getManagedChannel()Ljava/lang/Object;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->managedChannel:Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method

.method public getRetryPolicy()Lio/opentelemetry/sdk/common/export/RetryPolicy;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->retryPolicy:Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSslContext()Ljavax/net/ssl/SSLContext;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->sslContext:Ljavax/net/ssl/SSLContext;

    .line 2
    .line 3
    return-object p0
.end method

.method public getStubFactory()Ljava/util/function/Supplier;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/function/Supplier<",
            "Ljava/util/function/BiFunction<",
            "Lio/grpc/Channel;",
            "Ljava/lang/String;",
            "Lio/opentelemetry/exporter/internal/grpc/MarshalerServiceStub<",
            "TT;**>;>;>;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->stubFactory:Ljava/util/function/Supplier;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTimeoutNanos()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->timeoutNanos:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getTrustManager()Ljavax/net/ssl/X509TrustManager;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->trustManager:Ljavax/net/ssl/X509TrustManager;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 8

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->endpoint:Ljava/net/URI;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/net/URI;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const v1, 0xf4243

    .line 8
    .line 9
    .line 10
    xor-int/2addr v0, v1

    .line 11
    mul-int/2addr v0, v1

    .line 12
    iget-object v2, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->endpointPath:Ljava/lang/String;

    .line 13
    .line 14
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    xor-int/2addr v0, v2

    .line 19
    mul-int/2addr v0, v1

    .line 20
    iget-object v2, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;

    .line 21
    .line 22
    const/4 v3, 0x0

    .line 23
    if-nez v2, :cond_0

    .line 24
    .line 25
    move v2, v3

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    :goto_0
    xor-int/2addr v0, v2

    .line 32
    mul-int/2addr v0, v1

    .line 33
    iget-wide v4, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->timeoutNanos:J

    .line 34
    .line 35
    const/16 v2, 0x20

    .line 36
    .line 37
    ushr-long v6, v4, v2

    .line 38
    .line 39
    xor-long/2addr v4, v6

    .line 40
    long-to-int v4, v4

    .line 41
    xor-int/2addr v0, v4

    .line 42
    mul-int/2addr v0, v1

    .line 43
    iget-wide v4, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->connectTimeoutNanos:J

    .line 44
    .line 45
    ushr-long v6, v4, v2

    .line 46
    .line 47
    xor-long/2addr v4, v6

    .line 48
    long-to-int v2, v4

    .line 49
    xor-int/2addr v0, v2

    .line 50
    mul-int/2addr v0, v1

    .line 51
    iget-object v2, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->headersSupplier:Ljava/util/function/Supplier;

    .line 52
    .line 53
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    xor-int/2addr v0, v2

    .line 58
    mul-int/2addr v0, v1

    .line 59
    iget-object v2, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->managedChannel:Ljava/lang/Object;

    .line 60
    .line 61
    if-nez v2, :cond_1

    .line 62
    .line 63
    move v2, v3

    .line 64
    goto :goto_1

    .line 65
    :cond_1
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 66
    .line 67
    .line 68
    move-result v2

    .line 69
    :goto_1
    xor-int/2addr v0, v2

    .line 70
    mul-int/2addr v0, v1

    .line 71
    iget-object v2, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->stubFactory:Ljava/util/function/Supplier;

    .line 72
    .line 73
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 74
    .line 75
    .line 76
    move-result v2

    .line 77
    xor-int/2addr v0, v2

    .line 78
    mul-int/2addr v0, v1

    .line 79
    iget-object v2, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->retryPolicy:Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 80
    .line 81
    if-nez v2, :cond_2

    .line 82
    .line 83
    move v2, v3

    .line 84
    goto :goto_2

    .line 85
    :cond_2
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 86
    .line 87
    .line 88
    move-result v2

    .line 89
    :goto_2
    xor-int/2addr v0, v2

    .line 90
    mul-int/2addr v0, v1

    .line 91
    iget-object v2, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->sslContext:Ljavax/net/ssl/SSLContext;

    .line 92
    .line 93
    if-nez v2, :cond_3

    .line 94
    .line 95
    move v2, v3

    .line 96
    goto :goto_3

    .line 97
    :cond_3
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 98
    .line 99
    .line 100
    move-result v2

    .line 101
    :goto_3
    xor-int/2addr v0, v2

    .line 102
    mul-int/2addr v0, v1

    .line 103
    iget-object v2, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->trustManager:Ljavax/net/ssl/X509TrustManager;

    .line 104
    .line 105
    if-nez v2, :cond_4

    .line 106
    .line 107
    move v2, v3

    .line 108
    goto :goto_4

    .line 109
    :cond_4
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 110
    .line 111
    .line 112
    move-result v2

    .line 113
    :goto_4
    xor-int/2addr v0, v2

    .line 114
    mul-int/2addr v0, v1

    .line 115
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->executorService:Ljava/util/concurrent/ExecutorService;

    .line 116
    .line 117
    if-nez p0, :cond_5

    .line 118
    .line 119
    goto :goto_5

    .line 120
    :cond_5
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 121
    .line 122
    .line 123
    move-result v3

    .line 124
    :goto_5
    xor-int p0, v0, v3

    .line 125
    .line 126
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "GrpcSenderConfig{endpoint="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->endpoint:Ljava/net/URI;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", endpointPath="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->endpointPath:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", compressor="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", timeoutNanos="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->timeoutNanos:J

    .line 39
    .line 40
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", connectTimeoutNanos="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->connectTimeoutNanos:J

    .line 49
    .line 50
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", headersSupplier="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->headersSupplier:Ljava/util/function/Supplier;

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", managedChannel="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->managedChannel:Ljava/lang/Object;

    .line 69
    .line 70
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v1, ", stubFactory="

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->stubFactory:Ljava/util/function/Supplier;

    .line 79
    .line 80
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v1, ", retryPolicy="

    .line 84
    .line 85
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->retryPolicy:Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 89
    .line 90
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string v1, ", sslContext="

    .line 94
    .line 95
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->sslContext:Ljavax/net/ssl/SSLContext;

    .line 99
    .line 100
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    const-string v1, ", trustManager="

    .line 104
    .line 105
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->trustManager:Ljavax/net/ssl/X509TrustManager;

    .line 109
    .line 110
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    const-string v1, ", executorService="

    .line 114
    .line 115
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/AutoValue_GrpcSenderConfig;->executorService:Ljava/util/concurrent/ExecutorService;

    .line 119
    .line 120
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    const-string p0, "}"

    .line 124
    .line 125
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    return-object p0
.end method
