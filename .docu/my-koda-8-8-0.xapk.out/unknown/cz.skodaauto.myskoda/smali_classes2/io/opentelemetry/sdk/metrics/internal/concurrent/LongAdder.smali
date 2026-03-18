.class public interface abstract Lio/opentelemetry/sdk/metrics/internal/concurrent/LongAdder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public abstract add(J)V
.end method

.method public decrement()V
    .locals 2

    .line 1
    const-wide/16 v0, -0x1

    .line 2
    .line 3
    invoke-interface {p0, v0, v1}, Lio/opentelemetry/sdk/metrics/internal/concurrent/LongAdder;->add(J)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public doubleValue()D
    .locals 2

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/internal/concurrent/LongAdder;->sum()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    long-to-double v0, v0

    .line 6
    return-wide v0
.end method

.method public floatValue()F
    .locals 2

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/internal/concurrent/LongAdder;->sum()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    long-to-float p0, v0

    .line 6
    return p0
.end method

.method public increment()V
    .locals 2

    .line 1
    const-wide/16 v0, 0x1

    .line 2
    .line 3
    invoke-interface {p0, v0, v1}, Lio/opentelemetry/sdk/metrics/internal/concurrent/LongAdder;->add(J)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public intValue()I
    .locals 2

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/internal/concurrent/LongAdder;->sum()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    long-to-int p0, v0

    .line 6
    return p0
.end method

.method public longValue()J
    .locals 2

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/internal/concurrent/LongAdder;->sum()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public abstract reset()V
.end method

.method public abstract sum()J
.end method

.method public abstract sumThenReset()J
.end method
