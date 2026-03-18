.class public final Lio/opentelemetry/instrumentation/api/internal/Timer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final startNanoTime:J

.field private final startTime:Ljava/time/Instant;


# direct methods
.method private constructor <init>(Ljava/time/Instant;J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/internal/Timer;->startTime:Ljava/time/Instant;

    .line 5
    .line 6
    iput-wide p2, p0, Lio/opentelemetry/instrumentation/api/internal/Timer;->startNanoTime:J

    .line 7
    .line 8
    return-void
.end method

.method public static start()Lio/opentelemetry/instrumentation/api/internal/Timer;
    .locals 4

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/internal/Timer;

    .line 2
    .line 3
    invoke-static {}, Ljava/time/Instant;->now()Ljava/time/Instant;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 8
    .line 9
    .line 10
    move-result-wide v2

    .line 11
    invoke-direct {v0, v1, v2, v3}, Lio/opentelemetry/instrumentation/api/internal/Timer;-><init>(Ljava/time/Instant;J)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method


# virtual methods
.method public now()Ljava/time/Instant;
    .locals 4

    .line 1
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iget-wide v2, p0, Lio/opentelemetry/instrumentation/api/internal/Timer;->startNanoTime:J

    .line 6
    .line 7
    sub-long/2addr v0, v2

    .line 8
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/internal/Timer;->startTime()Ljava/time/Instant;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-virtual {p0, v0, v1}, Ljava/time/Instant;->plusNanos(J)Ljava/time/Instant;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method public startTime()Ljava/time/Instant;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/internal/Timer;->startTime:Ljava/time/Instant;

    .line 2
    .line 3
    return-object p0
.end method
