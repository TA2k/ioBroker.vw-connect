.class final Lio/opentelemetry/sdk/trace/AnchoredClock;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# instance fields
.field private final clock:Lio/opentelemetry/sdk/common/Clock;

.field private final epochNanos:J

.field private final nanoTime:J


# direct methods
.method private constructor <init>(Lio/opentelemetry/sdk/common/Clock;JJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/AnchoredClock;->clock:Lio/opentelemetry/sdk/common/Clock;

    .line 5
    .line 6
    iput-wide p2, p0, Lio/opentelemetry/sdk/trace/AnchoredClock;->epochNanos:J

    .line 7
    .line 8
    iput-wide p4, p0, Lio/opentelemetry/sdk/trace/AnchoredClock;->nanoTime:J

    .line 9
    .line 10
    return-void
.end method

.method public static create(Lio/opentelemetry/sdk/common/Clock;)Lio/opentelemetry/sdk/trace/AnchoredClock;
    .locals 6

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/trace/AnchoredClock;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/sdk/common/Clock;->now()J

    .line 4
    .line 5
    .line 6
    move-result-wide v2

    .line 7
    invoke-interface {p0}, Lio/opentelemetry/sdk/common/Clock;->nanoTime()J

    .line 8
    .line 9
    .line 10
    move-result-wide v4

    .line 11
    move-object v1, p0

    .line 12
    invoke-direct/range {v0 .. v5}, Lio/opentelemetry/sdk/trace/AnchoredClock;-><init>(Lio/opentelemetry/sdk/common/Clock;JJ)V

    .line 13
    .line 14
    .line 15
    return-object v0
.end method


# virtual methods
.method public now()J
    .locals 4

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/AnchoredClock;->clock:Lio/opentelemetry/sdk/common/Clock;

    .line 2
    .line 3
    invoke-interface {v0}, Lio/opentelemetry/sdk/common/Clock;->nanoTime()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    iget-wide v2, p0, Lio/opentelemetry/sdk/trace/AnchoredClock;->nanoTime:J

    .line 8
    .line 9
    sub-long/2addr v0, v2

    .line 10
    iget-wide v2, p0, Lio/opentelemetry/sdk/trace/AnchoredClock;->epochNanos:J

    .line 11
    .line 12
    add-long/2addr v2, v0

    .line 13
    return-wide v2
.end method

.method public startTime()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/trace/AnchoredClock;->epochNanos:J

    .line 2
    .line 3
    return-wide v0
.end method
