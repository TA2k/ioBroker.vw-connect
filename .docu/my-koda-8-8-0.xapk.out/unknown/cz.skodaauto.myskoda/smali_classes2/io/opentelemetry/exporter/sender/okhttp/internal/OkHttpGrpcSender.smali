.class public final Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/exporter/internal/grpc/GrpcSender;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
        ">",
        "Ljava/lang/Object;",
        "Lio/opentelemetry/exporter/internal/grpc/GrpcSender<",
        "TT;>;"
    }
.end annotation


# static fields
.field private static final GRPC_MESSAGE:Ljava/lang/String; = "grpc-message"

.field private static final GRPC_STATUS:Ljava/lang/String; = "grpc-status"


# instance fields
.field private final client:Ld01/h0;

.field private final compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;
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

.field private final managedExecutor:Z

.field private final url:Ld01/a0;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lio/opentelemetry/exporter/internal/compression/Compressor;JJLjava/util/function/Supplier;Lio/opentelemetry/sdk/common/export/RetryPolicy;Ljavax/net/ssl/SSLContext;Ljavax/net/ssl/X509TrustManager;Ljava/util/concurrent/ExecutorService;)V
    .locals 2
    .param p2    # Lio/opentelemetry/exporter/internal/compression/Compressor;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p8    # Lio/opentelemetry/sdk/common/export/RetryPolicy;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p9    # Ljavax/net/ssl/SSLContext;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p10    # Ljavax/net/ssl/X509TrustManager;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p11    # Ljava/util/concurrent/ExecutorService;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lio/opentelemetry/exporter/internal/compression/Compressor;",
            "JJ",
            "Ljava/util/function/Supplier<",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;>;>;",
            "Lio/opentelemetry/sdk/common/export/RetryPolicy;",
            "Ljavax/net/ssl/SSLContext;",
            "Ljavax/net/ssl/X509TrustManager;",
            "Ljava/util/concurrent/ExecutorService;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {p3, p4}, Ljava/time/Duration;->ofNanos(J)Ljava/time/Duration;

    .line 5
    .line 6
    .line 7
    move-result-object p3

    .line 8
    invoke-virtual {p3}, Ljava/time/Duration;->toMillis()J

    .line 9
    .line 10
    .line 11
    move-result-wide p3

    .line 12
    const-wide/32 v0, 0x7fffffff

    .line 13
    .line 14
    .line 15
    invoke-static {p3, p4, v0, v1}, Ljava/lang/Math;->min(JJ)J

    .line 16
    .line 17
    .line 18
    move-result-wide p3

    .line 19
    long-to-int p3, p3

    .line 20
    invoke-static {p5, p6}, Ljava/time/Duration;->ofNanos(J)Ljava/time/Duration;

    .line 21
    .line 22
    .line 23
    move-result-object p4

    .line 24
    invoke-virtual {p4}, Ljava/time/Duration;->toMillis()J

    .line 25
    .line 26
    .line 27
    move-result-wide p4

    .line 28
    invoke-static {p4, p5, v0, v1}, Ljava/lang/Math;->min(JJ)J

    .line 29
    .line 30
    .line 31
    move-result-wide p4

    .line 32
    long-to-int p4, p4

    .line 33
    if-nez p11, :cond_0

    .line 34
    .line 35
    invoke-static {}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpUtil;->newDispatcher()Ld01/t;

    .line 36
    .line 37
    .line 38
    move-result-object p5

    .line 39
    const/4 p6, 0x1

    .line 40
    iput-boolean p6, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->managedExecutor:Z

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    new-instance p5, Ld01/t;

    .line 44
    .line 45
    invoke-direct {p5, p11}, Ld01/t;-><init>(Ljava/util/concurrent/ExecutorService;)V

    .line 46
    .line 47
    .line 48
    const/4 p6, 0x0

    .line 49
    iput-boolean p6, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->managedExecutor:Z

    .line 50
    .line 51
    :goto_0
    new-instance p6, Ld01/g0;

    .line 52
    .line 53
    invoke-direct {p6}, Ld01/g0;-><init>()V

    .line 54
    .line 55
    .line 56
    const-string p11, "dispatcher"

    .line 57
    .line 58
    invoke-static {p5, p11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    iput-object p5, p6, Ld01/g0;->a:Ld01/t;

    .line 62
    .line 63
    int-to-long v0, p3

    .line 64
    invoke-static {v0, v1}, Ljava/time/Duration;->ofMillis(J)Ljava/time/Duration;

    .line 65
    .line 66
    .line 67
    move-result-object p3

    .line 68
    const-string p5, "duration"

    .line 69
    .line 70
    invoke-static {p3, p5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {p3}, Ljava/time/Duration;->toMillis()J

    .line 74
    .line 75
    .line 76
    move-result-wide v0

    .line 77
    sget-object p3, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 78
    .line 79
    const-string p11, "unit"

    .line 80
    .line 81
    invoke-static {p3, p11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    invoke-static {v0, v1, p3}, Le01/g;->b(JLjava/util/concurrent/TimeUnit;)I

    .line 85
    .line 86
    .line 87
    move-result p11

    .line 88
    iput p11, p6, Ld01/g0;->x:I

    .line 89
    .line 90
    int-to-long v0, p4

    .line 91
    invoke-static {v0, v1}, Ljava/time/Duration;->ofMillis(J)Ljava/time/Duration;

    .line 92
    .line 93
    .line 94
    move-result-object p4

    .line 95
    invoke-static {p4, p5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {p4}, Ljava/time/Duration;->toMillis()J

    .line 99
    .line 100
    .line 101
    move-result-wide p4

    .line 102
    invoke-virtual {p6, p4, p5, p3}, Ld01/g0;->b(JLjava/util/concurrent/TimeUnit;)V

    .line 103
    .line 104
    .line 105
    if-eqz p8, :cond_1

    .line 106
    .line 107
    new-instance p3, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;

    .line 108
    .line 109
    new-instance p4, Lio/opentelemetry/exporter/sender/okhttp/internal/a;

    .line 110
    .line 111
    const/4 p5, 0x0

    .line 112
    invoke-direct {p4, p5}, Lio/opentelemetry/exporter/sender/okhttp/internal/a;-><init>(I)V

    .line 113
    .line 114
    .line 115
    invoke-direct {p3, p8, p4}, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;-><init>(Lio/opentelemetry/sdk/common/export/RetryPolicy;Ljava/util/function/Function;)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {p6, p3}, Ld01/g0;->a(Ld01/c0;)V

    .line 119
    .line 120
    .line 121
    :cond_1
    const-string p3, "http://"

    .line 122
    .line 123
    invoke-virtual {p1, p3}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 124
    .line 125
    .line 126
    move-result p3

    .line 127
    const/4 p4, 0x0

    .line 128
    if-eqz p3, :cond_3

    .line 129
    .line 130
    sget-object p3, Ld01/p;->h:Ld01/p;

    .line 131
    .line 132
    invoke-static {p3}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 133
    .line 134
    .line 135
    move-result-object p3

    .line 136
    const-string p5, "connectionSpecs"

    .line 137
    .line 138
    invoke-static {p3, p5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    iget-object p5, p6, Ld01/g0;->s:Ljava/util/List;

    .line 142
    .line 143
    invoke-virtual {p3, p5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    move-result p5

    .line 147
    if-nez p5, :cond_2

    .line 148
    .line 149
    iput-object p4, p6, Ld01/g0;->D:Lbu/c;

    .line 150
    .line 151
    :cond_2
    invoke-static {p3}, Le01/g;->j(Ljava/util/List;)Ljava/util/List;

    .line 152
    .line 153
    .line 154
    move-result-object p3

    .line 155
    iput-object p3, p6, Ld01/g0;->s:Ljava/util/List;

    .line 156
    .line 157
    sget-object p3, Ld01/i0;->j:Ld01/i0;

    .line 158
    .line 159
    invoke-static {p3}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 160
    .line 161
    .line 162
    move-result-object p3

    .line 163
    invoke-virtual {p6, p3}, Ld01/g0;->c(Ljava/util/List;)V

    .line 164
    .line 165
    .line 166
    goto :goto_1

    .line 167
    :cond_3
    sget-object p3, Ld01/i0;->i:Ld01/i0;

    .line 168
    .line 169
    sget-object p5, Ld01/i0;->g:Ld01/i0;

    .line 170
    .line 171
    filled-new-array {p3, p5}, [Ld01/i0;

    .line 172
    .line 173
    .line 174
    move-result-object p3

    .line 175
    invoke-static {p3}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 176
    .line 177
    .line 178
    move-result-object p3

    .line 179
    invoke-virtual {p6, p3}, Ld01/g0;->c(Ljava/util/List;)V

    .line 180
    .line 181
    .line 182
    if-eqz p9, :cond_4

    .line 183
    .line 184
    if-eqz p10, :cond_4

    .line 185
    .line 186
    invoke-virtual {p9}, Ljavax/net/ssl/SSLContext;->getSocketFactory()Ljavax/net/ssl/SSLSocketFactory;

    .line 187
    .line 188
    .line 189
    move-result-object p3

    .line 190
    invoke-virtual {p6, p3, p10}, Ld01/g0;->e(Ljavax/net/ssl/SSLSocketFactory;Ljavax/net/ssl/X509TrustManager;)V

    .line 191
    .line 192
    .line 193
    :cond_4
    :goto_1
    new-instance p3, Ld01/h0;

    .line 194
    .line 195
    invoke-direct {p3, p6}, Ld01/h0;-><init>(Ld01/g0;)V

    .line 196
    .line 197
    .line 198
    iput-object p3, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->client:Ld01/h0;

    .line 199
    .line 200
    iput-object p7, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->headersSupplier:Ljava/util/function/Supplier;

    .line 201
    .line 202
    new-instance p3, Ld01/z;

    .line 203
    .line 204
    const/4 p5, 0x0

    .line 205
    invoke-direct {p3, p5}, Ld01/z;-><init>(I)V

    .line 206
    .line 207
    .line 208
    invoke-virtual {p3, p4, p1}, Ld01/z;->h(Ld01/a0;Ljava/lang/String;)V

    .line 209
    .line 210
    .line 211
    invoke-virtual {p3}, Ld01/z;->c()Ld01/a0;

    .line 212
    .line 213
    .line 214
    move-result-object p1

    .line 215
    iput-object p1, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->url:Ld01/a0;

    .line 216
    .line 217
    iput-object p2, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;

    .line 218
    .line 219
    return-void
.end method

.method public static synthetic a(Ld01/j0;Ljava/lang/String;Ljava/util/List;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->lambda$send$1(Ld01/j0;Ljava/lang/String;Ljava/util/List;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic access$000(Ld01/t0;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->grpcStatus(Ld01/t0;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic access$100(Ld01/t0;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->grpcMessage(Ld01/t0;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b(Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;Ld01/j0;Ljava/util/function/Consumer;Ljava/util/function/Consumer;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->lambda$send$2(Ld01/j0;Ljava/util/function/Consumer;Ljava/util/function/Consumer;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic c(Ld01/j0;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->lambda$send$0(Ld01/j0;Ljava/lang/String;Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static doUnescape([B)Ljava/lang/String;
    .locals 7

    .line 1
    array-length v0, p0

    .line 2
    invoke-static {v0}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    const/4 v1, 0x0

    .line 7
    move v2, v1

    .line 8
    :goto_0
    array-length v3, p0

    .line 9
    if-ge v2, v3, :cond_1

    .line 10
    .line 11
    aget-byte v3, p0, v2

    .line 12
    .line 13
    const/16 v4, 0x25

    .line 14
    .line 15
    if-ne v3, v4, :cond_0

    .line 16
    .line 17
    add-int/lit8 v3, v2, 0x2

    .line 18
    .line 19
    array-length v4, p0

    .line 20
    if-ge v3, v4, :cond_0

    .line 21
    .line 22
    :try_start_0
    new-instance v3, Ljava/lang/String;

    .line 23
    .line 24
    add-int/lit8 v4, v2, 0x1

    .line 25
    .line 26
    sget-object v5, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 27
    .line 28
    const/4 v6, 0x2

    .line 29
    invoke-direct {v3, p0, v4, v6, v5}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 30
    .line 31
    .line 32
    const/16 v4, 0x10

    .line 33
    .line 34
    invoke-static {v3, v4}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;I)I

    .line 35
    .line 36
    .line 37
    move-result v3

    .line 38
    int-to-byte v3, v3

    .line 39
    invoke-virtual {v0, v3}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 40
    .line 41
    .line 42
    add-int/lit8 v2, v2, 0x3

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :catch_0
    :cond_0
    aget-byte v3, p0, v2

    .line 46
    .line 47
    invoke-virtual {v0, v3}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 48
    .line 49
    .line 50
    add-int/lit8 v2, v2, 0x1

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_1
    new-instance p0, Ljava/lang/String;

    .line 54
    .line 55
    invoke-virtual {v0}, Ljava/nio/ByteBuffer;->array()[B

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    invoke-virtual {v0}, Ljava/nio/Buffer;->position()I

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    sget-object v3, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 64
    .line 65
    invoke-direct {p0, v2, v1, v0, v3}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 66
    .line 67
    .line 68
    return-object p0
.end method

.method private static grpcMessage(Ld01/t0;)Ljava/lang/String;
    .locals 3

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    const-string v0, "grpc-message"

    .line 5
    .line 6
    invoke-static {p0, v0}, Ld01/t0;->b(Ld01/t0;Ljava/lang/String;)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    if-nez v1, :cond_0

    .line 11
    .line 12
    :try_start_0
    iget-object v2, p0, Ld01/t0;->r:Ld01/y0;

    .line 13
    .line 14
    invoke-interface {v2}, Ld01/y0;->get()Ld01/y;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    invoke-virtual {v2, v0}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v1
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 22
    :catch_0
    :cond_0
    if-eqz v1, :cond_1

    .line 23
    .line 24
    invoke-static {v1}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->unescape(Ljava/lang/String;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :cond_1
    iget-object p0, p0, Ld01/t0;->f:Ljava/lang/String;

    .line 30
    .line 31
    return-object p0
.end method

.method private static grpcStatus(Ld01/t0;)Ljava/lang/String;
    .locals 2
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    const-string v0, "grpc-status"

    .line 5
    .line 6
    invoke-static {p0, v0}, Ld01/t0;->b(Ld01/t0;Ljava/lang/String;)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    if-nez v1, :cond_0

    .line 11
    .line 12
    :try_start_0
    iget-object p0, p0, Ld01/t0;->r:Ld01/y0;

    .line 13
    .line 14
    invoke-interface {p0}, Ld01/y0;->get()Ld01/y;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-virtual {p0, v0}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 22
    return-object p0

    .line 23
    :catch_0
    const/4 p0, 0x0

    .line 24
    return-object p0

    .line 25
    :cond_0
    return-object v1
.end method

.method public static isRetryable(Ld01/t0;)Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    const-string v0, "grpc-status"

    .line 5
    .line 6
    invoke-static {p0, v0}, Ld01/t0;->b(Ld01/t0;Ljava/lang/String;)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    if-nez p0, :cond_0

    .line 11
    .line 12
    const/4 p0, 0x0

    .line 13
    return p0

    .line 14
    :cond_0
    invoke-static {}, Lio/opentelemetry/exporter/internal/RetryUtil;->retryableGrpcStatusCodes()Ljava/util/Set;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-interface {v0, p0}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    return p0
.end method

.method private static synthetic lambda$send$0(Ld01/j0;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Ld01/j0;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static synthetic lambda$send$1(Ld01/j0;Ljava/lang/String;Ljava/util/List;)V
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/sender/okhttp/internal/c;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1, p0, p1}, Lio/opentelemetry/exporter/sender/okhttp/internal/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 5
    .line 6
    .line 7
    invoke-interface {p2, v0}, Ljava/lang/Iterable;->forEach(Ljava/util/function/Consumer;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method private lambda$send$2(Ld01/j0;Ljava/util/function/Consumer;Ljava/util/function/Consumer;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->client:Ld01/h0;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    new-instance v1, Ld01/k0;

    .line 7
    .line 8
    invoke-direct {v1, p1}, Ld01/k0;-><init>(Ld01/j0;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0, v1}, Ld01/h0;->newCall(Ld01/k0;)Ld01/j;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    new-instance v0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender$1;

    .line 16
    .line 17
    invoke-direct {v0, p0, p2, p3}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender$1;-><init>(Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;Ljava/util/function/Consumer;Ljava/util/function/Consumer;)V

    .line 18
    .line 19
    .line 20
    invoke-static {p1, v0}, Lcom/google/firebase/perf/network/FirebasePerfOkHttpClient;->enqueue(Ld01/j;Ld01/k;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method private static unescape(Ljava/lang/String;)Ljava/lang/String;
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    if-ge v0, v1, :cond_2

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Ljava/lang/String;->charAt(I)C

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    const/16 v2, 0x20

    .line 13
    .line 14
    if-lt v1, v2, :cond_1

    .line 15
    .line 16
    const/16 v2, 0x7e

    .line 17
    .line 18
    if-ge v1, v2, :cond_1

    .line 19
    .line 20
    const/16 v2, 0x25

    .line 21
    .line 22
    if-ne v1, v2, :cond_0

    .line 23
    .line 24
    add-int/lit8 v1, v0, 0x2

    .line 25
    .line 26
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    if-ge v1, v2, :cond_0

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    :goto_1
    sget-object v0, Ljava/nio/charset/StandardCharsets;->US_ASCII:Ljava/nio/charset/Charset;

    .line 37
    .line 38
    invoke-virtual {p0, v0}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    invoke-static {p0}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->doUnescape([B)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    :cond_2
    return-object p0
.end method


# virtual methods
.method public send(Lio/opentelemetry/exporter/internal/marshal/Marshaler;Ljava/util/function/Consumer;Ljava/util/function/Consumer;)V
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TT;",
            "Ljava/util/function/Consumer<",
            "Lio/opentelemetry/exporter/internal/grpc/GrpcResponse;",
            ">;",
            "Ljava/util/function/Consumer<",
            "Ljava/lang/Throwable;",
            ">;)V"
        }
    .end annotation

    .line 1
    new-instance v2, Ld01/j0;

    .line 2
    .line 3
    invoke-direct {v2}, Ld01/j0;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->url:Ld01/a0;

    .line 7
    .line 8
    const-string v1, "url"

    .line 9
    .line 10
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iput-object v0, v2, Ld01/j0;->a:Ld01/a0;

    .line 14
    .line 15
    iget-object v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->headersSupplier:Ljava/util/function/Supplier;

    .line 16
    .line 17
    invoke-interface {v0}, Ljava/util/function/Supplier;->get()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, Ljava/util/Map;

    .line 22
    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    new-instance v1, Lio/opentelemetry/exporter/sender/okhttp/internal/b;

    .line 26
    .line 27
    const/4 v3, 0x0

    .line 28
    invoke-direct {v1, v2, v3}, Lio/opentelemetry/exporter/sender/okhttp/internal/b;-><init>(Ld01/j0;I)V

    .line 29
    .line 30
    .line 31
    invoke-interface {v0, v1}, Ljava/util/Map;->forEach(Ljava/util/function/BiConsumer;)V

    .line 32
    .line 33
    .line 34
    :cond_0
    const-string v0, "te"

    .line 35
    .line 36
    const-string v1, "trailers"

    .line 37
    .line 38
    invoke-virtual {v2, v0, v1}, Ld01/j0;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    iget-object v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;

    .line 42
    .line 43
    if-eqz v0, :cond_1

    .line 44
    .line 45
    const-string v1, "grpc-encoding"

    .line 46
    .line 47
    invoke-interface {v0}, Lio/opentelemetry/exporter/internal/compression/Compressor;->getEncoding()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    invoke-virtual {v2, v1, v0}, Ld01/j0;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    :cond_1
    new-instance v0, Lio/opentelemetry/exporter/sender/okhttp/internal/GrpcRequestBody;

    .line 55
    .line 56
    iget-object v1, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;

    .line 57
    .line 58
    invoke-direct {v0, p1, v1}, Lio/opentelemetry/exporter/sender/okhttp/internal/GrpcRequestBody;-><init>(Lio/opentelemetry/exporter/internal/marshal/Marshaler;Lio/opentelemetry/exporter/internal/compression/Compressor;)V

    .line 59
    .line 60
    .line 61
    const-string p1, "POST"

    .line 62
    .line 63
    invoke-virtual {v2, p1, v0}, Ld01/j0;->e(Ljava/lang/String;Ld01/r0;)V

    .line 64
    .line 65
    .line 66
    new-instance v0, Lc8/r;

    .line 67
    .line 68
    const/4 v5, 0x2

    .line 69
    move-object v1, p0

    .line 70
    move-object v4, p2

    .line 71
    move-object v3, p3

    .line 72
    invoke-direct/range {v0 .. v5}, Lc8/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 73
    .line 74
    .line 75
    invoke-static {v0}, Lio/opentelemetry/api/internal/InstrumentationUtil;->suppressInstrumentation(Ljava/lang/Runnable;)V

    .line 76
    .line 77
    .line 78
    return-void
.end method

.method public shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->client:Ld01/h0;

    .line 2
    .line 3
    iget-object v0, v0, Ld01/h0;->a:Ld01/t;

    .line 4
    .line 5
    invoke-virtual {v0}, Ld01/t;->a()V

    .line 6
    .line 7
    .line 8
    iget-boolean v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->managedExecutor:Z

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    iget-object v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->client:Ld01/h0;

    .line 13
    .line 14
    iget-object v0, v0, Ld01/h0;->a:Ld01/t;

    .line 15
    .line 16
    invoke-virtual {v0}, Ld01/t;->b()Ljava/util/concurrent/ExecutorService;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-interface {v0}, Ljava/util/concurrent/ExecutorService;->shutdownNow()Ljava/util/List;

    .line 21
    .line 22
    .line 23
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->client:Ld01/h0;

    .line 24
    .line 25
    iget-object p0, p0, Ld01/h0;->E:Lbu/c;

    .line 26
    .line 27
    invoke-virtual {p0}, Lbu/c;->s()V

    .line 28
    .line 29
    .line 30
    invoke-static {}, Lio/opentelemetry/sdk/common/CompletableResultCode;->ofSuccess()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method
