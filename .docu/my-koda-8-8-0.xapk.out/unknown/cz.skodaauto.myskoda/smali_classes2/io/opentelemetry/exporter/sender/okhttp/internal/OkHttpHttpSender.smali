.class public final Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/exporter/internal/http/HttpSender;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$RawRequestBody;,
        Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$CompressedRequestBody;
    }
.end annotation


# instance fields
.field private final client:Ld01/h0;

.field private final compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final exportAsJson:Z

.field private final headerSupplier:Ljava/util/function/Supplier;
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

.field private final mediaType:Ld01/d0;

.field private final url:Ld01/a0;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lio/opentelemetry/exporter/internal/compression/Compressor;ZLjava/lang/String;JJLjava/util/function/Supplier;Lio/opentelemetry/sdk/common/export/ProxyOptions;Lio/opentelemetry/sdk/common/export/RetryPolicy;Ljavax/net/ssl/SSLContext;Ljavax/net/ssl/X509TrustManager;Ljava/util/concurrent/ExecutorService;)V
    .locals 10
    .param p2    # Lio/opentelemetry/exporter/internal/compression/Compressor;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p10    # Lio/opentelemetry/sdk/common/export/ProxyOptions;
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
            ")V"
        }
    .end annotation

    .line 1
    move-object/from16 v0, p11

    .line 2
    .line 3
    move-object/from16 v1, p13

    .line 4
    .line 5
    move-object/from16 v2, p14

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    invoke-static/range {p5 .. p6}, Ljava/time/Duration;->ofNanos(J)Ljava/time/Duration;

    .line 11
    .line 12
    .line 13
    move-result-object v3

    .line 14
    invoke-virtual {v3}, Ljava/time/Duration;->toMillis()J

    .line 15
    .line 16
    .line 17
    move-result-wide v3

    .line 18
    const-wide/32 v5, 0x7fffffff

    .line 19
    .line 20
    .line 21
    invoke-static {v3, v4, v5, v6}, Ljava/lang/Math;->min(JJ)J

    .line 22
    .line 23
    .line 24
    move-result-wide v3

    .line 25
    long-to-int v3, v3

    .line 26
    invoke-static/range {p7 .. p8}, Ljava/time/Duration;->ofNanos(J)Ljava/time/Duration;

    .line 27
    .line 28
    .line 29
    move-result-object v4

    .line 30
    invoke-virtual {v4}, Ljava/time/Duration;->toMillis()J

    .line 31
    .line 32
    .line 33
    move-result-wide v7

    .line 34
    invoke-static {v7, v8, v5, v6}, Ljava/lang/Math;->min(JJ)J

    .line 35
    .line 36
    .line 37
    move-result-wide v4

    .line 38
    long-to-int v4, v4

    .line 39
    const/4 v5, 0x0

    .line 40
    const/4 v6, 0x1

    .line 41
    if-nez v2, :cond_0

    .line 42
    .line 43
    invoke-static {}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpUtil;->newDispatcher()Ld01/t;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    iput-boolean v6, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;->managedExecutor:Z

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_0
    new-instance v7, Ld01/t;

    .line 51
    .line 52
    invoke-direct {v7, v2}, Ld01/t;-><init>(Ljava/util/concurrent/ExecutorService;)V

    .line 53
    .line 54
    .line 55
    iput-boolean v5, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;->managedExecutor:Z

    .line 56
    .line 57
    move-object v2, v7

    .line 58
    :goto_0
    new-instance v7, Ld01/g0;

    .line 59
    .line 60
    invoke-direct {v7}, Ld01/g0;-><init>()V

    .line 61
    .line 62
    .line 63
    const-string v8, "dispatcher"

    .line 64
    .line 65
    invoke-static {v2, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    iput-object v2, v7, Ld01/g0;->a:Ld01/t;

    .line 69
    .line 70
    int-to-long v8, v4

    .line 71
    invoke-static {v8, v9}, Ljava/time/Duration;->ofMillis(J)Ljava/time/Duration;

    .line 72
    .line 73
    .line 74
    move-result-object v2

    .line 75
    const-string v4, "duration"

    .line 76
    .line 77
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {v2}, Ljava/time/Duration;->toMillis()J

    .line 81
    .line 82
    .line 83
    move-result-wide v8

    .line 84
    sget-object v2, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 85
    .line 86
    invoke-virtual {v7, v8, v9, v2}, Ld01/g0;->b(JLjava/util/concurrent/TimeUnit;)V

    .line 87
    .line 88
    .line 89
    int-to-long v8, v3

    .line 90
    invoke-static {v8, v9}, Ljava/time/Duration;->ofMillis(J)Ljava/time/Duration;

    .line 91
    .line 92
    .line 93
    move-result-object v3

    .line 94
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {v3}, Ljava/time/Duration;->toMillis()J

    .line 98
    .line 99
    .line 100
    move-result-wide v3

    .line 101
    const-string v8, "unit"

    .line 102
    .line 103
    invoke-static {v2, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    invoke-static {v3, v4, v2}, Le01/g;->b(JLjava/util/concurrent/TimeUnit;)I

    .line 107
    .line 108
    .line 109
    move-result v2

    .line 110
    iput v2, v7, Ld01/g0;->x:I

    .line 111
    .line 112
    const/4 v2, 0x0

    .line 113
    if-eqz p10, :cond_2

    .line 114
    .line 115
    invoke-virtual/range {p10 .. p10}, Lio/opentelemetry/sdk/common/export/ProxyOptions;->getProxySelector()Ljava/net/ProxySelector;

    .line 116
    .line 117
    .line 118
    move-result-object v3

    .line 119
    const-string v4, "proxySelector"

    .line 120
    .line 121
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    iget-object v4, v7, Ld01/g0;->n:Ljava/net/ProxySelector;

    .line 125
    .line 126
    invoke-virtual {v3, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result v4

    .line 130
    if-nez v4, :cond_1

    .line 131
    .line 132
    iput-object v2, v7, Ld01/g0;->D:Lbu/c;

    .line 133
    .line 134
    :cond_1
    iput-object v3, v7, Ld01/g0;->n:Ljava/net/ProxySelector;

    .line 135
    .line 136
    :cond_2
    if-eqz v0, :cond_3

    .line 137
    .line 138
    new-instance v3, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;

    .line 139
    .line 140
    new-instance v4, Lio/opentelemetry/exporter/sender/okhttp/internal/a;

    .line 141
    .line 142
    invoke-direct {v4, v6}, Lio/opentelemetry/exporter/sender/okhttp/internal/a;-><init>(I)V

    .line 143
    .line 144
    .line 145
    invoke-direct {v3, v0, v4}, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;-><init>(Lio/opentelemetry/sdk/common/export/RetryPolicy;Ljava/util/function/Function;)V

    .line 146
    .line 147
    .line 148
    invoke-virtual {v7, v3}, Ld01/g0;->a(Ld01/c0;)V

    .line 149
    .line 150
    .line 151
    :cond_3
    const-string v0, "http://"

    .line 152
    .line 153
    invoke-virtual {p1, v0}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 154
    .line 155
    .line 156
    move-result v0

    .line 157
    if-eqz v0, :cond_5

    .line 158
    .line 159
    sget-object v0, Ld01/p;->h:Ld01/p;

    .line 160
    .line 161
    invoke-static {v0}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 162
    .line 163
    .line 164
    move-result-object v0

    .line 165
    const-string v1, "connectionSpecs"

    .line 166
    .line 167
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    iget-object v1, v7, Ld01/g0;->s:Ljava/util/List;

    .line 171
    .line 172
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 173
    .line 174
    .line 175
    move-result v1

    .line 176
    if-nez v1, :cond_4

    .line 177
    .line 178
    iput-object v2, v7, Ld01/g0;->D:Lbu/c;

    .line 179
    .line 180
    :cond_4
    invoke-static {v0}, Le01/g;->j(Ljava/util/List;)Ljava/util/List;

    .line 181
    .line 182
    .line 183
    move-result-object v0

    .line 184
    iput-object v0, v7, Ld01/g0;->s:Ljava/util/List;

    .line 185
    .line 186
    goto :goto_1

    .line 187
    :cond_5
    if-eqz p12, :cond_6

    .line 188
    .line 189
    if-eqz v1, :cond_6

    .line 190
    .line 191
    invoke-virtual/range {p12 .. p12}, Ljavax/net/ssl/SSLContext;->getSocketFactory()Ljavax/net/ssl/SSLSocketFactory;

    .line 192
    .line 193
    .line 194
    move-result-object v0

    .line 195
    invoke-virtual {v7, v0, v1}, Ld01/g0;->e(Ljavax/net/ssl/SSLSocketFactory;Ljavax/net/ssl/X509TrustManager;)V

    .line 196
    .line 197
    .line 198
    :cond_6
    :goto_1
    new-instance v0, Ld01/h0;

    .line 199
    .line 200
    invoke-direct {v0, v7}, Ld01/h0;-><init>(Ld01/g0;)V

    .line 201
    .line 202
    .line 203
    iput-object v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;->client:Ld01/h0;

    .line 204
    .line 205
    new-instance v0, Ld01/z;

    .line 206
    .line 207
    invoke-direct {v0, v5}, Ld01/z;-><init>(I)V

    .line 208
    .line 209
    .line 210
    invoke-virtual {v0, v2, p1}, Ld01/z;->h(Ld01/a0;Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    invoke-virtual {v0}, Ld01/z;->c()Ld01/a0;

    .line 214
    .line 215
    .line 216
    move-result-object p1

    .line 217
    iput-object p1, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;->url:Ld01/a0;

    .line 218
    .line 219
    iput-object p2, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;->compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;

    .line 220
    .line 221
    iput-boolean p3, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;->exportAsJson:Z

    .line 222
    .line 223
    sget-object p1, Ld01/d0;->e:Lly0/n;

    .line 224
    .line 225
    invoke-static {p4}, Ljp/ue;->e(Ljava/lang/String;)Ld01/d0;

    .line 226
    .line 227
    .line 228
    move-result-object p1

    .line 229
    iput-object p1, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;->mediaType:Ld01/d0;

    .line 230
    .line 231
    move-object/from16 p1, p9

    .line 232
    .line 233
    iput-object p1, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;->headerSupplier:Ljava/util/function/Supplier;

    .line 234
    .line 235
    return-void
.end method

.method public static synthetic a(Ld01/j0;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;->lambda$send$0(Ld01/j0;Ljava/lang/String;Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic b(Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;Ld01/j0;Ljava/util/function/Consumer;Ljava/util/function/Consumer;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;->lambda$send$2(Ld01/j0;Ljava/util/function/Consumer;Ljava/util/function/Consumer;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic c(Ld01/j0;Ljava/lang/String;Ljava/util/List;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;->lambda$send$1(Ld01/j0;Ljava/lang/String;Ljava/util/List;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static isRetryable(Ld01/t0;)Z
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/exporter/internal/RetryUtil;->retryableHttpResponseCodes()Ljava/util/Set;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget p0, p0, Ld01/t0;->g:I

    .line 6
    .line 7
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-interface {v0, p0}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
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
    const/4 v1, 0x1

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
    iget-object v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;->client:Ld01/h0;

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
    new-instance v0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1;

    .line 16
    .line 17
    invoke-direct {v0, p0, p2, p3}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1;-><init>(Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;Ljava/util/function/Consumer;Ljava/util/function/Consumer;)V

    .line 18
    .line 19
    .line 20
    invoke-static {p1, v0}, Lcom/google/firebase/perf/network/FirebasePerfOkHttpClient;->enqueue(Ld01/j;Ld01/k;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public send(Lio/opentelemetry/exporter/internal/marshal/Marshaler;ILjava/util/function/Consumer;Ljava/util/function/Consumer;)V
    .locals 10
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
            "I",
            "Ljava/util/function/Consumer<",
            "Lio/opentelemetry/exporter/internal/http/HttpSender$Response;",
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
    iget-object v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;->url:Ld01/a0;

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
    iget-object v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;->headerSupplier:Ljava/util/function/Supplier;

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
    const/4 v3, 0x1

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
    new-instance v4, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$RawRequestBody;

    .line 35
    .line 36
    iget-boolean v6, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;->exportAsJson:Z

    .line 37
    .line 38
    iget-object v8, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;->mediaType:Ld01/d0;

    .line 39
    .line 40
    const/4 v9, 0x0

    .line 41
    move-object v5, p1

    .line 42
    move v7, p2

    .line 43
    invoke-direct/range {v4 .. v9}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$RawRequestBody;-><init>(Lio/opentelemetry/exporter/internal/marshal/Marshaler;ZILd01/d0;Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1;)V

    .line 44
    .line 45
    .line 46
    iget-object p1, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;->compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;

    .line 47
    .line 48
    const-string p2, "POST"

    .line 49
    .line 50
    if-eqz p1, :cond_1

    .line 51
    .line 52
    const-string v0, "Content-Encoding"

    .line 53
    .line 54
    invoke-interface {p1}, Lio/opentelemetry/exporter/internal/compression/Compressor;->getEncoding()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    invoke-virtual {v2, v0, p1}, Ld01/j0;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    new-instance p1, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$CompressedRequestBody;

    .line 62
    .line 63
    iget-object v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;->compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;

    .line 64
    .line 65
    const/4 v1, 0x0

    .line 66
    invoke-direct {p1, v0, v4, v1}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$CompressedRequestBody;-><init>(Lio/opentelemetry/exporter/internal/compression/Compressor;Ld01/r0;Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1;)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v2, p2, p1}, Ld01/j0;->e(Ljava/lang/String;Ld01/r0;)V

    .line 70
    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_1
    invoke-virtual {v2, p2, v4}, Ld01/j0;->e(Ljava/lang/String;Ld01/r0;)V

    .line 74
    .line 75
    .line 76
    :goto_0
    new-instance v0, Lc8/r;

    .line 77
    .line 78
    const/4 v5, 0x3

    .line 79
    move-object v1, p0

    .line 80
    move-object v4, p3

    .line 81
    move-object v3, p4

    .line 82
    invoke-direct/range {v0 .. v5}, Lc8/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 83
    .line 84
    .line 85
    invoke-static {v0}, Lio/opentelemetry/api/internal/InstrumentationUtil;->suppressInstrumentation(Ljava/lang/Runnable;)V

    .line 86
    .line 87
    .line 88
    return-void
.end method

.method public shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;->client:Ld01/h0;

    .line 2
    .line 3
    iget-object v0, v0, Ld01/h0;->a:Ld01/t;

    .line 4
    .line 5
    invoke-virtual {v0}, Ld01/t;->a()V

    .line 6
    .line 7
    .line 8
    iget-boolean v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;->managedExecutor:Z

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    iget-object v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;->client:Ld01/h0;

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
    iget-object p0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;->client:Ld01/h0;

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
