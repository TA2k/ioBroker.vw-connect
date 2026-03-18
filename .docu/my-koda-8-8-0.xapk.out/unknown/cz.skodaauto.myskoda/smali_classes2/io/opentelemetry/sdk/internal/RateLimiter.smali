.class public Lio/opentelemetry/sdk/internal/RateLimiter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final clock:Lio/opentelemetry/sdk/common/Clock;

.field private final creditsPerNanosecond:D

.field private final currentBalance:Ljava/util/concurrent/atomic/AtomicLong;

.field private final maxBalance:J


# direct methods
.method public constructor <init>(DDLio/opentelemetry/sdk/common/Clock;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p5, p0, Lio/opentelemetry/sdk/internal/RateLimiter;->clock:Lio/opentelemetry/sdk/common/Clock;

    .line 5
    .line 6
    const-wide v0, 0x41cdcd6500000000L    # 1.0E9

    .line 7
    .line 8
    .line 9
    .line 10
    .line 11
    div-double/2addr p1, v0

    .line 12
    iput-wide p1, p0, Lio/opentelemetry/sdk/internal/RateLimiter;->creditsPerNanosecond:D

    .line 13
    .line 14
    div-double/2addr p3, p1

    .line 15
    double-to-long p1, p3

    .line 16
    iput-wide p1, p0, Lio/opentelemetry/sdk/internal/RateLimiter;->maxBalance:J

    .line 17
    .line 18
    new-instance p3, Ljava/util/concurrent/atomic/AtomicLong;

    .line 19
    .line 20
    invoke-interface {p5}, Lio/opentelemetry/sdk/common/Clock;->nanoTime()J

    .line 21
    .line 22
    .line 23
    move-result-wide p4

    .line 24
    sub-long/2addr p4, p1

    .line 25
    invoke-direct {p3, p4, p5}, Ljava/util/concurrent/atomic/AtomicLong;-><init>(J)V

    .line 26
    .line 27
    .line 28
    iput-object p3, p0, Lio/opentelemetry/sdk/internal/RateLimiter;->currentBalance:Ljava/util/concurrent/atomic/AtomicLong;

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public trySpend(D)Z
    .locals 9

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/internal/RateLimiter;->creditsPerNanosecond:D

    .line 2
    .line 3
    div-double/2addr p1, v0

    .line 4
    double-to-long p1, p1

    .line 5
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/RateLimiter;->currentBalance:Ljava/util/concurrent/atomic/AtomicLong;

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicLong;->get()J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    iget-object v2, p0, Lio/opentelemetry/sdk/internal/RateLimiter;->clock:Lio/opentelemetry/sdk/common/Clock;

    .line 12
    .line 13
    invoke-interface {v2}, Lio/opentelemetry/sdk/common/Clock;->nanoTime()J

    .line 14
    .line 15
    .line 16
    move-result-wide v2

    .line 17
    sub-long v4, v2, v0

    .line 18
    .line 19
    iget-wide v6, p0, Lio/opentelemetry/sdk/internal/RateLimiter;->maxBalance:J

    .line 20
    .line 21
    cmp-long v8, v4, v6

    .line 22
    .line 23
    if-lez v8, :cond_1

    .line 24
    .line 25
    move-wide v4, v6

    .line 26
    :cond_1
    sub-long/2addr v4, p1

    .line 27
    const-wide/16 v6, 0x0

    .line 28
    .line 29
    cmp-long v6, v4, v6

    .line 30
    .line 31
    if-gez v6, :cond_2

    .line 32
    .line 33
    const/4 p0, 0x0

    .line 34
    return p0

    .line 35
    :cond_2
    iget-object v6, p0, Lio/opentelemetry/sdk/internal/RateLimiter;->currentBalance:Ljava/util/concurrent/atomic/AtomicLong;

    .line 36
    .line 37
    sub-long/2addr v2, v4

    .line 38
    invoke-virtual {v6, v0, v1, v2, v3}, Ljava/util/concurrent/atomic/AtomicLong;->compareAndSet(JJ)Z

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    if-eqz v0, :cond_0

    .line 43
    .line 44
    const/4 p0, 0x1

    .line 45
    return p0
.end method
