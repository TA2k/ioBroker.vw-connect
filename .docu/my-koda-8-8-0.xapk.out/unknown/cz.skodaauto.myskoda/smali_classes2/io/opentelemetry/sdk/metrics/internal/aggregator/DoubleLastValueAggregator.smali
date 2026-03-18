.class public final Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator$Handle;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator<",
        "Lio/opentelemetry/sdk/metrics/data/DoublePointData;",
        ">;"
    }
.end annotation

.annotation build Ljavax/annotation/concurrent/ThreadSafe;
.end annotation


# instance fields
.field private final memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

.field private final reservoirFactory:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;Lio/opentelemetry/sdk/common/export/MemoryMode;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator;->reservoirFactory:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public copyPoint(Lio/opentelemetry/sdk/metrics/data/DoublePointData;Lio/opentelemetry/sdk/metrics/data/DoublePointData;)V
    .locals 0

    .line 2
    check-cast p2, Lio/opentelemetry/sdk/metrics/internal/data/MutableDoublePointData;

    invoke-virtual {p2, p1}, Lio/opentelemetry/sdk/metrics/internal/data/MutableDoublePointData;->set(Lio/opentelemetry/sdk/metrics/data/DoublePointData;)V

    return-void
.end method

.method public bridge synthetic copyPoint(Lio/opentelemetry/sdk/metrics/data/PointData;Lio/opentelemetry/sdk/metrics/data/PointData;)V
    .locals 0

    .line 1
    check-cast p1, Lio/opentelemetry/sdk/metrics/data/DoublePointData;

    check-cast p2, Lio/opentelemetry/sdk/metrics/data/DoublePointData;

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator;->copyPoint(Lio/opentelemetry/sdk/metrics/data/DoublePointData;Lio/opentelemetry/sdk/metrics/data/DoublePointData;)V

    return-void
.end method

.method public createHandle()Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle<",
            "Lio/opentelemetry/sdk/metrics/data/DoublePointData;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator$Handle;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator;->reservoirFactory:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;

    .line 4
    .line 5
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    invoke-direct {v0, v1, p0, v2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator$Handle;-><init>(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;Lio/opentelemetry/sdk/common/export/MemoryMode;Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator$1;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method

.method public createReusablePoint()Lio/opentelemetry/sdk/metrics/data/DoublePointData;
    .locals 0

    .line 2
    new-instance p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableDoublePointData;

    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/internal/data/MutableDoublePointData;-><init>()V

    return-object p0
.end method

.method public bridge synthetic createReusablePoint()Lio/opentelemetry/sdk/metrics/data/PointData;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator;->createReusablePoint()Lio/opentelemetry/sdk/metrics/data/DoublePointData;

    move-result-object p0

    return-object p0
.end method

.method public diff(Lio/opentelemetry/sdk/metrics/data/DoublePointData;Lio/opentelemetry/sdk/metrics/data/DoublePointData;)Lio/opentelemetry/sdk/metrics/data/DoublePointData;
    .locals 0

    .line 1
    return-object p2
.end method

.method public bridge synthetic diff(Lio/opentelemetry/sdk/metrics/data/PointData;Lio/opentelemetry/sdk/metrics/data/PointData;)Lio/opentelemetry/sdk/metrics/data/PointData;
    .locals 0

    .line 2
    check-cast p1, Lio/opentelemetry/sdk/metrics/data/DoublePointData;

    check-cast p2, Lio/opentelemetry/sdk/metrics/data/DoublePointData;

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator;->diff(Lio/opentelemetry/sdk/metrics/data/DoublePointData;Lio/opentelemetry/sdk/metrics/data/DoublePointData;)Lio/opentelemetry/sdk/metrics/data/DoublePointData;

    move-result-object p0

    return-object p0
.end method

.method public diffInPlace(Lio/opentelemetry/sdk/metrics/data/DoublePointData;Lio/opentelemetry/sdk/metrics/data/DoublePointData;)V
    .locals 0

    .line 2
    check-cast p1, Lio/opentelemetry/sdk/metrics/internal/data/MutableDoublePointData;

    invoke-virtual {p1, p2}, Lio/opentelemetry/sdk/metrics/internal/data/MutableDoublePointData;->set(Lio/opentelemetry/sdk/metrics/data/DoublePointData;)V

    return-void
.end method

.method public bridge synthetic diffInPlace(Lio/opentelemetry/sdk/metrics/data/PointData;Lio/opentelemetry/sdk/metrics/data/PointData;)V
    .locals 0

    .line 1
    check-cast p1, Lio/opentelemetry/sdk/metrics/data/DoublePointData;

    check-cast p2, Lio/opentelemetry/sdk/metrics/data/DoublePointData;

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleLastValueAggregator;->diffInPlace(Lio/opentelemetry/sdk/metrics/data/DoublePointData;Lio/opentelemetry/sdk/metrics/data/DoublePointData;)V

    return-void
.end method

.method public toMetricData(Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;Ljava/util/Collection;Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;)Lio/opentelemetry/sdk/metrics/data/MetricData;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/resources/Resource;",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            "Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;",
            "Ljava/util/Collection<",
            "Lio/opentelemetry/sdk/metrics/data/DoublePointData;",
            ">;",
            "Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;",
            ")",
            "Lio/opentelemetry/sdk/metrics/data/MetricData;"
        }
    .end annotation

    .line 1
    move-object p0, p1

    .line 2
    move-object p1, p2

    .line 3
    invoke-virtual {p3}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    move-object p5, p3

    .line 8
    invoke-virtual {p5}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getDescription()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p3

    .line 12
    invoke-virtual {p5}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getSourceInstrument()Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;

    .line 13
    .line 14
    .line 15
    move-result-object p5

    .line 16
    invoke-virtual {p5}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getUnit()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p5

    .line 20
    invoke-static {p4}, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableGaugeData;->create(Ljava/util/Collection;)Lio/opentelemetry/sdk/metrics/internal/data/ImmutableGaugeData;

    .line 21
    .line 22
    .line 23
    move-result-object p4

    .line 24
    move-object v0, p5

    .line 25
    move-object p5, p4

    .line 26
    move-object p4, v0

    .line 27
    invoke-static/range {p0 .. p5}, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableMetricData;->createDoubleGauge(Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/sdk/metrics/data/GaugeData;)Lio/opentelemetry/sdk/metrics/data/MetricData;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0
.end method
