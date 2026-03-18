.class Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private attributes:Lio/opentelemetry/api/common/Attributes;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final clock:Lio/opentelemetry/sdk/common/Clock;

.field private doubleValue:D

.field private longValue:J

.field private recordTime:J

.field private spanContext:Lio/opentelemetry/api/trace/SpanContext;


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/common/Clock;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lio/opentelemetry/api/trace/SpanContext;->getInvalid()Lio/opentelemetry/api/trace/SpanContext;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 9
    .line 10
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->clock:Lio/opentelemetry/sdk/common/Clock;

    .line 11
    .line 12
    return-void
.end method

.method private static filtered(Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/common/Attributes;
    .locals 2

    .line 1
    invoke-interface {p1}, Lio/opentelemetry/api/common/Attributes;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    invoke-interface {p1}, Lio/opentelemetry/api/common/Attributes;->asMap()Ljava/util/Map;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-interface {p1}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-interface {p0}, Lio/opentelemetry/api/common/Attributes;->toBuilder()Lio/opentelemetry/api/common/AttributesBuilder;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    new-instance v0, Lac0/s;

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    invoke-direct {v0, p1, v1}, Lac0/s;-><init>(Ljava/lang/Object;I)V

    .line 27
    .line 28
    .line 29
    invoke-interface {p0, v0}, Lio/opentelemetry/api/common/AttributesBuilder;->removeIf(Ljava/util/function/Predicate;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-interface {p0}, Lio/opentelemetry/api/common/AttributesBuilder;->build()Lio/opentelemetry/api/common/Attributes;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0
.end method

.method private offerMeasurement(Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V
    .locals 2

    .line 1
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    iget-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->clock:Lio/opentelemetry/sdk/common/Clock;

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    invoke-interface {p1, v0}, Lio/opentelemetry/sdk/common/Clock;->now(Z)J

    .line 7
    .line 8
    .line 9
    move-result-wide v0

    .line 10
    iput-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->recordTime:J

    .line 11
    .line 12
    invoke-static {p2}, Lio/opentelemetry/api/trace/Span;->fromContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/trace/Span;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-interface {p1}, Lio/opentelemetry/api/trace/Span;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 17
    .line 18
    .line 19
    move-result-object p2

    .line 20
    invoke-interface {p2}, Lio/opentelemetry/api/trace/SpanContext;->isValid()Z

    .line 21
    .line 22
    .line 23
    move-result p2

    .line 24
    if-eqz p2, :cond_0

    .line 25
    .line 26
    invoke-interface {p1}, Lio/opentelemetry/api/trace/Span;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 31
    .line 32
    :cond_0
    return-void
.end method


# virtual methods
.method public declared-synchronized getAndResetDouble(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/metrics/data/DoubleExemplarData;
    .locals 6
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->attributes:Lio/opentelemetry/api/common/Attributes;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 3
    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    monitor-exit p0

    .line 7
    const/4 p0, 0x0

    .line 8
    return-object p0

    .line 9
    :cond_0
    :try_start_1
    invoke-static {v0, p1}, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->filtered(Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/common/Attributes;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->recordTime:J

    .line 14
    .line 15
    iget-object v3, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 16
    .line 17
    iget-wide v4, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->doubleValue:D

    .line 18
    .line 19
    invoke-static/range {v0 .. v5}, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableDoubleExemplarData;->create(Lio/opentelemetry/api/common/Attributes;JLio/opentelemetry/api/trace/SpanContext;D)Lio/opentelemetry/sdk/metrics/data/DoubleExemplarData;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->reset()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 24
    .line 25
    .line 26
    monitor-exit p0

    .line 27
    return-object p1

    .line 28
    :catchall_0
    move-exception v0

    .line 29
    move-object p1, v0

    .line 30
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 31
    throw p1
.end method

.method public declared-synchronized getAndResetLong(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/metrics/data/LongExemplarData;
    .locals 6
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->attributes:Lio/opentelemetry/api/common/Attributes;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 3
    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    monitor-exit p0

    .line 7
    const/4 p0, 0x0

    .line 8
    return-object p0

    .line 9
    :cond_0
    :try_start_1
    invoke-static {v0, p1}, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->filtered(Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/common/Attributes;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->recordTime:J

    .line 14
    .line 15
    iget-object v3, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 16
    .line 17
    iget-wide v4, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->longValue:J

    .line 18
    .line 19
    invoke-static/range {v0 .. v5}, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableLongExemplarData;->create(Lio/opentelemetry/api/common/Attributes;JLio/opentelemetry/api/trace/SpanContext;J)Lio/opentelemetry/sdk/metrics/data/LongExemplarData;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->reset()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 24
    .line 25
    .line 26
    monitor-exit p0

    .line 27
    return-object p1

    .line 28
    :catchall_0
    move-exception v0

    .line 29
    move-object p1, v0

    .line 30
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 31
    throw p1
.end method

.method public declared-synchronized recordDoubleMeasurement(DLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V
    .locals 0

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iput-wide p1, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->doubleValue:D

    .line 3
    .line 4
    invoke-direct {p0, p3, p4}, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->offerMeasurement(Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 5
    .line 6
    .line 7
    monitor-exit p0

    .line 8
    return-void

    .line 9
    :catchall_0
    move-exception p1

    .line 10
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 11
    throw p1
.end method

.method public declared-synchronized recordLongMeasurement(JLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V
    .locals 0

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iput-wide p1, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->longValue:J

    .line 3
    .line 4
    invoke-direct {p0, p3, p4}, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->offerMeasurement(Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 5
    .line 6
    .line 7
    monitor-exit p0

    .line 8
    return-void

    .line 9
    :catchall_0
    move-exception p1

    .line 10
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 11
    throw p1
.end method

.method public declared-synchronized reset()V
    .locals 4

    .line 1
    monitor-enter p0

    .line 2
    const/4 v0, 0x0

    .line 3
    :try_start_0
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 4
    .line 5
    const-wide/16 v0, 0x0

    .line 6
    .line 7
    iput-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->longValue:J

    .line 8
    .line 9
    const-wide/16 v2, 0x0

    .line 10
    .line 11
    iput-wide v2, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->doubleValue:D

    .line 12
    .line 13
    invoke-static {}, Lio/opentelemetry/api/trace/SpanContext;->getInvalid()Lio/opentelemetry/api/trace/SpanContext;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    iput-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 18
    .line 19
    iput-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;->recordTime:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 20
    .line 21
    monitor-exit p0

    .line 22
    return-void

    .line 23
    :catchall_0
    move-exception v0

    .line 24
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 25
    throw v0
.end method
