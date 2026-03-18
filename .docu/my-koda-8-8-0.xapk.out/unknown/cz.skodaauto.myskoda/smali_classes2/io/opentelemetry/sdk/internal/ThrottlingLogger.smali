.class public Lio/opentelemetry/sdk/internal/ThrottlingLogger;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final DEFAULT_RATE_LIMIT:D = 5.0

.field private static final DEFAULT_RATE_TIME_UNIT:Ljava/util/concurrent/TimeUnit;

.field private static final DEFAULT_THROTTLED_RATE_LIMIT:D = 1.0


# instance fields
.field private final delegate:Ljava/util/logging/Logger;

.field private final fastRateLimiter:Lio/opentelemetry/sdk/internal/RateLimiter;

.field private final rateLimit:D

.field private final rateTimeUnit:Ljava/util/concurrent/TimeUnit;

.field private final throttled:Ljava/util/concurrent/atomic/AtomicBoolean;

.field private final throttledRateLimit:D

.field private final throttledRateLimiter:Lio/opentelemetry/sdk/internal/RateLimiter;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Ljava/util/concurrent/TimeUnit;->MINUTES:Ljava/util/concurrent/TimeUnit;

    .line 2
    .line 3
    sput-object v0, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->DEFAULT_RATE_TIME_UNIT:Ljava/util/concurrent/TimeUnit;

    .line 4
    .line 5
    return-void
.end method

.method public constructor <init>(Ljava/util/logging/Logger;)V
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/common/Clock;->getDefault()Lio/opentelemetry/sdk/common/Clock;

    move-result-object v0

    invoke-direct {p0, p1, v0}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;-><init>(Ljava/util/logging/Logger;Lio/opentelemetry/sdk/common/Clock;)V

    return-void
.end method

.method public constructor <init>(Ljava/util/logging/Logger;DDLjava/util/concurrent/TimeUnit;)V
    .locals 8

    .line 2
    invoke-static {}, Lio/opentelemetry/sdk/common/Clock;->getDefault()Lio/opentelemetry/sdk/common/Clock;

    move-result-object v2

    move-object v0, p0

    move-object v1, p1

    move-wide v3, p2

    move-wide v5, p4

    move-object v7, p6

    invoke-direct/range {v0 .. v7}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;-><init>(Ljava/util/logging/Logger;Lio/opentelemetry/sdk/common/Clock;DDLjava/util/concurrent/TimeUnit;)V

    return-void
.end method

.method public constructor <init>(Ljava/util/logging/Logger;Lio/opentelemetry/sdk/common/Clock;)V
    .locals 8

    const-wide/high16 v5, 0x3ff0000000000000L    # 1.0

    .line 3
    sget-object v7, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->DEFAULT_RATE_TIME_UNIT:Ljava/util/concurrent/TimeUnit;

    const-wide/high16 v3, 0x4014000000000000L    # 5.0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    invoke-direct/range {v0 .. v7}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;-><init>(Ljava/util/logging/Logger;Lio/opentelemetry/sdk/common/Clock;DDLjava/util/concurrent/TimeUnit;)V

    return-void
.end method

.method public constructor <init>(Ljava/util/logging/Logger;Lio/opentelemetry/sdk/common/Clock;DDLjava/util/concurrent/TimeUnit;)V
    .locals 8

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    iput-object v0, p0, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->throttled:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->delegate:Ljava/util/logging/Logger;

    .line 7
    iput-wide p3, p0, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->rateLimit:D

    .line 8
    iput-wide p5, p0, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->throttledRateLimit:D

    .line 9
    iput-object p7, p0, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->rateTimeUnit:Ljava/util/concurrent/TimeUnit;

    .line 10
    new-instance v2, Lio/opentelemetry/sdk/internal/RateLimiter;

    const-wide/16 v0, 0x1

    .line 11
    invoke-virtual {p7, v0, v1}, Ljava/util/concurrent/TimeUnit;->toSeconds(J)J

    move-result-wide v3

    long-to-double v3, v3

    div-double v3, p3, v3

    move-object v7, p2

    move-wide v5, p3

    invoke-direct/range {v2 .. v7}, Lio/opentelemetry/sdk/internal/RateLimiter;-><init>(DDLio/opentelemetry/sdk/common/Clock;)V

    iput-object v2, p0, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->fastRateLimiter:Lio/opentelemetry/sdk/internal/RateLimiter;

    .line 12
    new-instance p1, Lio/opentelemetry/sdk/internal/RateLimiter;

    .line 13
    invoke-virtual {p7, v0, v1}, Ljava/util/concurrent/TimeUnit;->toSeconds(J)J

    move-result-wide p2

    long-to-double p2, p2

    div-double p2, p5, p2

    move-wide p4, p5

    move-object p6, v7

    invoke-direct/range {p1 .. p6}, Lio/opentelemetry/sdk/internal/RateLimiter;-><init>(DDLio/opentelemetry/sdk/common/Clock;)V

    iput-object p1, p0, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->throttledRateLimiter:Lio/opentelemetry/sdk/internal/RateLimiter;

    return-void
.end method

.method private doLog(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Throwable;)V
    .locals 0
    .param p3    # Ljava/lang/Throwable;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    if-eqz p3, :cond_0

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->delegate:Ljava/util/logging/Logger;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2, p3}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->delegate:Ljava/util/logging/Logger;

    .line 10
    .line 11
    invoke-virtual {p0, p1, p2}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public isLoggable(Ljava/util/logging/Level;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->delegate:Ljava/util/logging/Logger;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ljava/util/logging/Logger;->isLoggable(Ljava/util/logging/Level;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public log(Ljava/util/logging/Level;Ljava/lang/String;)V
    .locals 1

    const/4 v0, 0x0

    .line 1
    invoke-virtual {p0, p1, p2, v0}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Throwable;)V

    return-void
.end method

.method public log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Throwable;)V
    .locals 6
    .param p3    # Ljava/lang/Throwable;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 2
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->isLoggable(Ljava/util/logging/Level;)Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    .line 3
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->throttled:Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    move-result v0

    const-wide/high16 v1, 0x3ff0000000000000L    # 1.0

    if-eqz v0, :cond_1

    .line 4
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->throttledRateLimiter:Lio/opentelemetry/sdk/internal/RateLimiter;

    invoke-virtual {v0, v1, v2}, Lio/opentelemetry/sdk/internal/RateLimiter;->trySpend(D)Z

    move-result v0

    if-eqz v0, :cond_3

    .line 5
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->doLog(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Throwable;)V

    return-void

    .line 6
    :cond_1
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->fastRateLimiter:Lio/opentelemetry/sdk/internal/RateLimiter;

    invoke-virtual {v0, v1, v2}, Lio/opentelemetry/sdk/internal/RateLimiter;->trySpend(D)Z

    move-result v0

    if-eqz v0, :cond_2

    .line 7
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->doLog(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Throwable;)V

    return-void

    .line 8
    :cond_2
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->throttled:Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 v1, 0x0

    const/4 v2, 0x1

    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    move-result v0

    if-eqz v0, :cond_3

    .line 9
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->throttledRateLimiter:Lio/opentelemetry/sdk/internal/RateLimiter;

    iget-wide v3, p0, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->throttledRateLimit:D

    invoke-virtual {v0, v3, v4}, Lio/opentelemetry/sdk/internal/RateLimiter;->trySpend(D)Z

    .line 10
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->rateTimeUnit:Ljava/util/concurrent/TimeUnit;

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    sget-object v3, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    invoke-virtual {v0, v3}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    move-result-object v0

    .line 11
    iget-wide v4, p0, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->throttledRateLimit:D

    .line 12
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v4

    .line 13
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v5

    sub-int/2addr v5, v2

    invoke-virtual {v0, v1, v5}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v0

    filled-new-array {v4, v0}, [Ljava/lang/Object;

    move-result-object v0

    .line 14
    const-string v1, "Too many log messages detected. Will only log %.0f time(s) per %s from now on."

    invoke-static {v3, v1, v0}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    .line 15
    iget-object v1, p0, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->delegate:Ljava/util/logging/Logger;

    invoke-virtual {v1, p1, v0}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 16
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->doLog(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Throwable;)V

    :cond_3
    :goto_0
    return-void
.end method
