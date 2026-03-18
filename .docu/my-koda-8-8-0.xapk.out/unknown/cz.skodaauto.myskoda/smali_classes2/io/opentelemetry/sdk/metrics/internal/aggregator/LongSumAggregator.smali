.class public final Lio/opentelemetry/sdk/metrics/internal/aggregator/LongSumAggregator;
.super Lio/opentelemetry/sdk/metrics/internal/aggregator/AbstractSumAggregator;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/sdk/metrics/internal/aggregator/LongSumAggregator$Handle;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lio/opentelemetry/sdk/metrics/internal/aggregator/AbstractSumAggregator<",
        "Lio/opentelemetry/sdk/metrics/data/LongPointData;",
        "Lio/opentelemetry/sdk/metrics/data/LongExemplarData;",
        ">;"
    }
.end annotation


# instance fields
.field private final memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

.field private final reservoirFactory:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;Lio/opentelemetry/sdk/common/export/MemoryMode;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AbstractSumAggregator;-><init>(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;)V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/LongSumAggregator;->reservoirFactory:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;

    .line 5
    .line 6
    iput-object p3, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/LongSumAggregator;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public copyPoint(Lio/opentelemetry/sdk/metrics/data/LongPointData;Lio/opentelemetry/sdk/metrics/data/LongPointData;)V
    .locals 0

    .line 2
    check-cast p2, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;

    invoke-virtual {p2, p1}, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->set(Lio/opentelemetry/sdk/metrics/data/LongPointData;)V

    return-void
.end method

.method public bridge synthetic copyPoint(Lio/opentelemetry/sdk/metrics/data/PointData;Lio/opentelemetry/sdk/metrics/data/PointData;)V
    .locals 0

    .line 1
    check-cast p1, Lio/opentelemetry/sdk/metrics/data/LongPointData;

    check-cast p2, Lio/opentelemetry/sdk/metrics/data/LongPointData;

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/LongSumAggregator;->copyPoint(Lio/opentelemetry/sdk/metrics/data/LongPointData;Lio/opentelemetry/sdk/metrics/data/LongPointData;)V

    return-void
.end method

.method public createHandle()Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle<",
            "Lio/opentelemetry/sdk/metrics/data/LongPointData;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/LongSumAggregator$Handle;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/LongSumAggregator;->reservoirFactory:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;

    .line 4
    .line 5
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/LongSumAggregator;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 6
    .line 7
    invoke-direct {v0, v1, p0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/LongSumAggregator$Handle;-><init>(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;Lio/opentelemetry/sdk/common/export/MemoryMode;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method

.method public createReusablePoint()Lio/opentelemetry/sdk/metrics/data/LongPointData;
    .locals 0

    .line 2
    new-instance p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;

    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;-><init>()V

    return-object p0
.end method

.method public bridge synthetic createReusablePoint()Lio/opentelemetry/sdk/metrics/data/PointData;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/LongSumAggregator;->createReusablePoint()Lio/opentelemetry/sdk/metrics/data/LongPointData;

    move-result-object p0

    return-object p0
.end method

.method public diff(Lio/opentelemetry/sdk/metrics/data/LongPointData;Lio/opentelemetry/sdk/metrics/data/LongPointData;)Lio/opentelemetry/sdk/metrics/data/LongPointData;
    .locals 8

    .line 2
    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/PointData;->getStartEpochNanos()J

    move-result-wide v0

    .line 3
    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/PointData;->getEpochNanos()J

    move-result-wide v2

    .line 4
    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/PointData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    move-result-object v4

    .line 5
    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/LongPointData;->getValue()J

    move-result-wide v5

    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/LongPointData;->getValue()J

    move-result-wide p0

    sub-long/2addr v5, p0

    .line 6
    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/LongPointData;->getExemplars()Ljava/util/List;

    move-result-object v7

    .line 7
    invoke-static/range {v0 .. v7}, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableLongPointData;->create(JJLio/opentelemetry/api/common/Attributes;JLjava/util/List;)Lio/opentelemetry/sdk/metrics/data/LongPointData;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic diff(Lio/opentelemetry/sdk/metrics/data/PointData;Lio/opentelemetry/sdk/metrics/data/PointData;)Lio/opentelemetry/sdk/metrics/data/PointData;
    .locals 0

    .line 1
    check-cast p1, Lio/opentelemetry/sdk/metrics/data/LongPointData;

    check-cast p2, Lio/opentelemetry/sdk/metrics/data/LongPointData;

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/LongSumAggregator;->diff(Lio/opentelemetry/sdk/metrics/data/LongPointData;Lio/opentelemetry/sdk/metrics/data/LongPointData;)Lio/opentelemetry/sdk/metrics/data/LongPointData;

    move-result-object p0

    return-object p0
.end method

.method public diffInPlace(Lio/opentelemetry/sdk/metrics/data/LongPointData;Lio/opentelemetry/sdk/metrics/data/LongPointData;)V
    .locals 9

    .line 2
    move-object v0, p1

    check-cast v0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;

    .line 3
    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/PointData;->getStartEpochNanos()J

    move-result-wide v1

    .line 4
    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/PointData;->getEpochNanos()J

    move-result-wide v3

    .line 5
    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/PointData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    move-result-object v5

    .line 6
    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/LongPointData;->getValue()J

    move-result-wide v6

    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/LongPointData;->getValue()J

    move-result-wide p0

    sub-long/2addr v6, p0

    .line 7
    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/LongPointData;->getExemplars()Ljava/util/List;

    move-result-object v8

    .line 8
    invoke-virtual/range {v0 .. v8}, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->set(JJLio/opentelemetry/api/common/Attributes;JLjava/util/List;)V

    return-void
.end method

.method public bridge synthetic diffInPlace(Lio/opentelemetry/sdk/metrics/data/PointData;Lio/opentelemetry/sdk/metrics/data/PointData;)V
    .locals 0

    .line 1
    check-cast p1, Lio/opentelemetry/sdk/metrics/data/LongPointData;

    check-cast p2, Lio/opentelemetry/sdk/metrics/data/LongPointData;

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/LongSumAggregator;->diffInPlace(Lio/opentelemetry/sdk/metrics/data/LongPointData;Lio/opentelemetry/sdk/metrics/data/LongPointData;)V

    return-void
.end method

.method public toMetricData(Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;Ljava/util/Collection;Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;)Lio/opentelemetry/sdk/metrics/data/MetricData;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/resources/Resource;",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            "Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;",
            "Ljava/util/Collection<",
            "Lio/opentelemetry/sdk/metrics/data/LongPointData;",
            ">;",
            "Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;",
            ")",
            "Lio/opentelemetry/sdk/metrics/data/MetricData;"
        }
    .end annotation

    .line 1
    move-object v0, p0

    .line 2
    move-object p0, p1

    .line 3
    move-object p1, p2

    .line 4
    invoke-virtual {p3}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getName()Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object p2

    .line 8
    move-object v1, p3

    .line 9
    invoke-virtual {v1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getDescription()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p3

    .line 13
    invoke-virtual {v1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getSourceInstrument()Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-virtual {v1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getUnit()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AbstractSumAggregator;->isMonotonic()Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    invoke-static {v0, p5, p4}, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableSumData;->create(ZLio/opentelemetry/sdk/metrics/data/AggregationTemporality;Ljava/util/Collection;)Lio/opentelemetry/sdk/metrics/internal/data/ImmutableSumData;

    .line 26
    .line 27
    .line 28
    move-result-object p5

    .line 29
    move-object p4, v1

    .line 30
    invoke-static/range {p0 .. p5}, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableMetricData;->createLongSum(Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/sdk/metrics/data/SumData;)Lio/opentelemetry/sdk/metrics/data/MetricData;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method
