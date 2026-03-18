.class public final Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld01/c0;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor$Sleeper;
    }
.end annotation


# static fields
.field private static final logger:Ljava/util/logging/Logger;


# instance fields
.field private final isRetryable:Ljava/util/function/Function;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Function<",
            "Ld01/t0;",
            "Ljava/lang/Boolean;",
            ">;"
        }
    .end annotation
.end field

.field private final randomJitter:Ljava/util/function/Supplier;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Supplier<",
            "Ljava/lang/Double;",
            ">;"
        }
    .end annotation
.end field

.field private final retryExceptionPredicate:Ljava/util/function/Predicate;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Predicate<",
            "Ljava/io/IOException;",
            ">;"
        }
    .end annotation
.end field

.field private final retryPolicy:Lio/opentelemetry/sdk/common/export/RetryPolicy;

.field private final sleeper:Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor$Sleeper;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;->logger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/sdk/common/export/RetryPolicy;Ljava/util/function/Function;)V
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/common/export/RetryPolicy;",
            "Ljava/util/function/Function<",
            "Ld01/t0;",
            "Ljava/lang/Boolean;",
            ">;)V"
        }
    .end annotation

    .line 1
    invoke-virtual {p1}, Lio/opentelemetry/sdk/common/export/RetryPolicy;->getRetryExceptionPredicate()Ljava/util/function/Predicate;

    move-result-object v0

    if-nez v0, :cond_0

    .line 2
    new-instance v0, Lio/opentelemetry/exporter/sender/okhttp/internal/e;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    :goto_0
    move-object v4, v0

    goto :goto_1

    .line 3
    :cond_0
    invoke-virtual {p1}, Lio/opentelemetry/sdk/common/export/RetryPolicy;->getRetryExceptionPredicate()Ljava/util/function/Predicate;

    move-result-object v0

    goto :goto_0

    :goto_1
    sget-object v0, Ljava/util/concurrent/TimeUnit;->NANOSECONDS:Ljava/util/concurrent/TimeUnit;

    .line 4
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    new-instance v5, Lio/opentelemetry/exporter/sender/okhttp/internal/f;

    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    new-instance v6, Lio/opentelemetry/exporter/sender/okhttp/internal/g;

    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    .line 5
    invoke-direct/range {v1 .. v6}, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;-><init>(Lio/opentelemetry/sdk/common/export/RetryPolicy;Ljava/util/function/Function;Ljava/util/function/Predicate;Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor$Sleeper;Ljava/util/function/Supplier;)V

    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/sdk/common/export/RetryPolicy;Ljava/util/function/Function;Ljava/util/function/Predicate;Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor$Sleeper;Ljava/util/function/Supplier;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/common/export/RetryPolicy;",
            "Ljava/util/function/Function<",
            "Ld01/t0;",
            "Ljava/lang/Boolean;",
            ">;",
            "Ljava/util/function/Predicate<",
            "Ljava/io/IOException;",
            ">;",
            "Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor$Sleeper;",
            "Ljava/util/function/Supplier<",
            "Ljava/lang/Double;",
            ">;)V"
        }
    .end annotation

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    iput-object p1, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;->retryPolicy:Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 8
    iput-object p2, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;->isRetryable:Ljava/util/function/Function;

    .line 9
    iput-object p3, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;->retryExceptionPredicate:Ljava/util/function/Predicate;

    .line 10
    iput-object p4, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;->sleeper:Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor$Sleeper;

    .line 11
    iput-object p5, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;->randomJitter:Ljava/util/function/Supplier;

    return-void
.end method

.method public static synthetic a()Ljava/lang/Double;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;->lambda$new$0()Ljava/lang/Double;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic b(Ljava/util/Map$Entry;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;->lambda$responseStringRepresentation$1(Ljava/util/Map$Entry;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static isRetryableException(Ljava/io/IOException;)Z
    .locals 2

    .line 1
    instance-of v0, p0, Ljava/net/SocketTimeoutException;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    return v1

    .line 7
    :cond_0
    instance-of v0, p0, Ljava/net/ConnectException;

    .line 8
    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    return v1

    .line 12
    :cond_1
    instance-of v0, p0, Ljava/net/UnknownHostException;

    .line 13
    .line 14
    if-eqz v0, :cond_2

    .line 15
    .line 16
    return v1

    .line 17
    :cond_2
    instance-of p0, p0, Ljava/net/SocketException;

    .line 18
    .line 19
    if-eqz p0, :cond_3

    .line 20
    .line 21
    return v1

    .line 22
    :cond_3
    const/4 p0, 0x0

    .line 23
    return p0
.end method

.method private static synthetic lambda$new$0()Ljava/lang/Double;
    .locals 5

    .line 1
    invoke-static {}, Ljava/util/concurrent/ThreadLocalRandom;->current()Ljava/util/concurrent/ThreadLocalRandom;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-wide v1, 0x3fe999999999999aL    # 0.8

    .line 6
    .line 7
    .line 8
    .line 9
    .line 10
    const-wide v3, 0x3ff3333333333333L    # 1.2

    .line 11
    .line 12
    .line 13
    .line 14
    .line 15
    invoke-virtual {v0, v1, v2, v3, v4}, Ljava/util/concurrent/ThreadLocalRandom;->nextDouble(DD)D

    .line 16
    .line 17
    .line 18
    move-result-wide v0

    .line 19
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    return-object v0
.end method

.method private static synthetic lambda$responseStringRepresentation$1(Ljava/util/Map$Entry;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    check-cast v1, Ljava/lang/String;

    .line 11
    .line 12
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string v1, "="

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-interface {p0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    check-cast p0, Ljava/lang/Iterable;

    .line 25
    .line 26
    const-string v1, ","

    .line 27
    .line 28
    invoke-static {v1, p0}, Ljava/lang/String;->join(Ljava/lang/CharSequence;Ljava/lang/Iterable;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method

.method private static responseStringRepresentation(Ld01/t0;)Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/util/StringJoiner;

    .line 2
    .line 3
    const-string v1, "Response{"

    .line 4
    .line 5
    const-string v2, "}"

    .line 6
    .line 7
    const-string v3, ","

    .line 8
    .line 9
    invoke-direct {v0, v3, v1, v2}, Ljava/util/StringJoiner;-><init>(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Ljava/lang/CharSequence;)V

    .line 10
    .line 11
    .line 12
    new-instance v1, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    const-string v2, "code="

    .line 15
    .line 16
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    iget v2, p0, Ld01/t0;->g:I

    .line 20
    .line 21
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    invoke-virtual {v0, v1}, Ljava/util/StringJoiner;->add(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;

    .line 29
    .line 30
    .line 31
    new-instance v1, Ljava/lang/StringBuilder;

    .line 32
    .line 33
    const-string v2, "headers="

    .line 34
    .line 35
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Ld01/t0;->i:Ld01/y;

    .line 39
    .line 40
    invoke-virtual {p0}, Ld01/y;->i()Ljava/util/TreeMap;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    invoke-virtual {p0}, Ljava/util/TreeMap;->entrySet()Ljava/util/Set;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    invoke-interface {p0}, Ljava/util/Collection;->stream()Ljava/util/stream/Stream;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    new-instance v2, Lio/opentelemetry/exporter/sender/okhttp/internal/a;

    .line 53
    .line 54
    const/4 v4, 0x2

    .line 55
    invoke-direct {v2, v4}, Lio/opentelemetry/exporter/sender/okhttp/internal/a;-><init>(I)V

    .line 56
    .line 57
    .line 58
    invoke-interface {p0, v2}, Ljava/util/stream/Stream;->map(Ljava/util/function/Function;)Ljava/util/stream/Stream;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    const-string v2, "["

    .line 63
    .line 64
    const-string v4, "]"

    .line 65
    .line 66
    invoke-static {v3, v2, v4}, Ljava/util/stream/Collectors;->joining(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/util/stream/Collector;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    invoke-interface {p0, v2}, Ljava/util/stream/Stream;->collect(Ljava/util/stream/Collector;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    check-cast p0, Ljava/lang/String;

    .line 75
    .line 76
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    invoke-virtual {v0, p0}, Ljava/util/StringJoiner;->add(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;

    .line 84
    .line 85
    .line 86
    invoke-virtual {v0}, Ljava/util/StringJoiner;->toString()Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    return-object p0
.end method


# virtual methods
.method public intercept(Ld01/b0;)Ld01/t0;
    .locals 14

    .line 1
    const-string v0, "non-retryable"

    .line 2
    .line 3
    const-string v1, "retryable"

    .line 4
    .line 5
    const-string v2, "Attempt "

    .line 6
    .line 7
    iget-object v3, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;->retryPolicy:Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 8
    .line 9
    invoke-virtual {v3}, Lio/opentelemetry/sdk/common/export/RetryPolicy;->getInitialBackoff()Ljava/time/Duration;

    .line 10
    .line 11
    .line 12
    move-result-object v3

    .line 13
    invoke-virtual {v3}, Ljava/time/Duration;->toNanos()J

    .line 14
    .line 15
    .line 16
    move-result-wide v3

    .line 17
    const/4 v5, 0x0

    .line 18
    const/4 v6, 0x0

    .line 19
    move-object v7, v5

    .line 20
    move-object v8, v7

    .line 21
    :cond_0
    if-lez v6, :cond_2

    .line 22
    .line 23
    iget-object v9, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;->retryPolicy:Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 24
    .line 25
    invoke-virtual {v9}, Lio/opentelemetry/sdk/common/export/RetryPolicy;->getMaxBackoff()Ljava/time/Duration;

    .line 26
    .line 27
    .line 28
    move-result-object v9

    .line 29
    invoke-virtual {v9}, Ljava/time/Duration;->toNanos()J

    .line 30
    .line 31
    .line 32
    move-result-wide v9

    .line 33
    invoke-static {v3, v4, v9, v10}, Ljava/lang/Math;->min(JJ)J

    .line 34
    .line 35
    .line 36
    move-result-wide v3

    .line 37
    iget-object v9, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;->randomJitter:Ljava/util/function/Supplier;

    .line 38
    .line 39
    invoke-interface {v9}, Ljava/util/function/Supplier;->get()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v9

    .line 43
    check-cast v9, Ljava/lang/Double;

    .line 44
    .line 45
    invoke-virtual {v9}, Ljava/lang/Double;->doubleValue()D

    .line 46
    .line 47
    .line 48
    move-result-wide v9

    .line 49
    long-to-double v3, v3

    .line 50
    mul-double/2addr v9, v3

    .line 51
    double-to-long v9, v9

    .line 52
    iget-object v11, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;->retryPolicy:Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 53
    .line 54
    invoke-virtual {v11}, Lio/opentelemetry/sdk/common/export/RetryPolicy;->getBackoffMultiplier()D

    .line 55
    .line 56
    .line 57
    move-result-wide v11

    .line 58
    mul-double/2addr v11, v3

    .line 59
    double-to-long v3, v11

    .line 60
    :try_start_0
    iget-object v11, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;->sleeper:Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor$Sleeper;

    .line 61
    .line 62
    invoke-interface {v11, v9, v10}, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor$Sleeper;->sleep(J)V
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0

    .line 63
    .line 64
    .line 65
    if-eqz v7, :cond_1

    .line 66
    .line 67
    invoke-virtual {v7}, Ld01/t0;->close()V

    .line 68
    .line 69
    .line 70
    :cond_1
    move-object v8, v5

    .line 71
    goto :goto_0

    .line 72
    :catch_0
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    invoke-virtual {p0}, Ljava/lang/Thread;->interrupt()V

    .line 77
    .line 78
    .line 79
    goto/16 :goto_5

    .line 80
    .line 81
    :cond_2
    :goto_0
    :try_start_1
    move-object v7, p1

    .line 82
    check-cast v7, Li01/f;

    .line 83
    .line 84
    iget-object v7, v7, Li01/f;->e:Ld01/k0;

    .line 85
    .line 86
    move-object v9, p1

    .line 87
    check-cast v9, Li01/f;

    .line 88
    .line 89
    invoke-virtual {v9, v7}, Li01/f;->b(Ld01/k0;)Ld01/t0;

    .line 90
    .line 91
    .line 92
    move-result-object v7

    .line 93
    sget-object v9, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 94
    .line 95
    iget-object v10, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;->isRetryable:Ljava/util/function/Function;

    .line 96
    .line 97
    invoke-interface {v10, v7}, Ljava/util/function/Function;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v10

    .line 101
    invoke-virtual {v9, v10}, Ljava/lang/Boolean;->equals(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result v9

    .line 105
    sget-object v10, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;->logger:Ljava/util/logging/Logger;

    .line 106
    .line 107
    sget-object v11, Ljava/util/logging/Level;->FINER:Ljava/util/logging/Level;

    .line 108
    .line 109
    invoke-virtual {v10, v11}, Ljava/util/logging/Logger;->isLoggable(Ljava/util/logging/Level;)Z

    .line 110
    .line 111
    .line 112
    move-result v12

    .line 113
    if-eqz v12, :cond_4

    .line 114
    .line 115
    new-instance v12, Ljava/lang/StringBuilder;

    .line 116
    .line 117
    invoke-direct {v12}, Ljava/lang/StringBuilder;-><init>()V

    .line 118
    .line 119
    .line 120
    invoke-virtual {v12, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    invoke-virtual {v12, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 124
    .line 125
    .line 126
    const-string v13, " returned "

    .line 127
    .line 128
    invoke-virtual {v12, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 129
    .line 130
    .line 131
    if-eqz v9, :cond_3

    .line 132
    .line 133
    move-object v13, v1

    .line 134
    goto :goto_1

    .line 135
    :cond_3
    move-object v13, v0

    .line 136
    :goto_1
    invoke-virtual {v12, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 137
    .line 138
    .line 139
    const-string v13, " response: "

    .line 140
    .line 141
    invoke-virtual {v12, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 142
    .line 143
    .line 144
    invoke-static {v7}, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;->responseStringRepresentation(Ld01/t0;)Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object v13

    .line 148
    invoke-virtual {v12, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 149
    .line 150
    .line 151
    invoke-virtual {v12}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object v12

    .line 155
    invoke-virtual {v10, v11, v12}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_1

    .line 156
    .line 157
    .line 158
    goto :goto_2

    .line 159
    :catch_1
    move-exception v7

    .line 160
    goto :goto_3

    .line 161
    :cond_4
    :goto_2
    if-nez v9, :cond_7

    .line 162
    .line 163
    return-object v7

    .line 164
    :goto_3
    iget-object v8, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;->retryExceptionPredicate:Ljava/util/function/Predicate;

    .line 165
    .line 166
    invoke-interface {v8, v7}, Ljava/util/function/Predicate;->test(Ljava/lang/Object;)Z

    .line 167
    .line 168
    .line 169
    move-result v8

    .line 170
    sget-object v9, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;->logger:Ljava/util/logging/Logger;

    .line 171
    .line 172
    sget-object v10, Ljava/util/logging/Level;->FINER:Ljava/util/logging/Level;

    .line 173
    .line 174
    invoke-virtual {v9, v10}, Ljava/util/logging/Logger;->isLoggable(Ljava/util/logging/Level;)Z

    .line 175
    .line 176
    .line 177
    move-result v11

    .line 178
    if-eqz v11, :cond_6

    .line 179
    .line 180
    const-string v11, " failed with "

    .line 181
    .line 182
    invoke-static {v2, v6, v11}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 183
    .line 184
    .line 185
    move-result-object v11

    .line 186
    if-eqz v8, :cond_5

    .line 187
    .line 188
    move-object v12, v1

    .line 189
    goto :goto_4

    .line 190
    :cond_5
    move-object v12, v0

    .line 191
    :goto_4
    const-string v13, " exception"

    .line 192
    .line 193
    invoke-static {v11, v12, v13}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 194
    .line 195
    .line 196
    move-result-object v11

    .line 197
    invoke-virtual {v9, v10, v11, v7}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 198
    .line 199
    .line 200
    :cond_6
    if-eqz v8, :cond_9

    .line 201
    .line 202
    move-object v8, v7

    .line 203
    move-object v7, v5

    .line 204
    :cond_7
    add-int/lit8 v6, v6, 0x1

    .line 205
    .line 206
    iget-object v9, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;->retryPolicy:Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 207
    .line 208
    invoke-virtual {v9}, Lio/opentelemetry/sdk/common/export/RetryPolicy;->getMaxAttempts()I

    .line 209
    .line 210
    .line 211
    move-result v9

    .line 212
    if-lt v6, v9, :cond_0

    .line 213
    .line 214
    :goto_5
    if-eqz v7, :cond_8

    .line 215
    .line 216
    return-object v7

    .line 217
    :cond_8
    throw v8

    .line 218
    :cond_9
    throw v7
.end method

.method public shouldRetryOnException(Ljava/io/IOException;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor;->retryExceptionPredicate:Ljava/util/function/Predicate;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Ljava/util/function/Predicate;->test(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
