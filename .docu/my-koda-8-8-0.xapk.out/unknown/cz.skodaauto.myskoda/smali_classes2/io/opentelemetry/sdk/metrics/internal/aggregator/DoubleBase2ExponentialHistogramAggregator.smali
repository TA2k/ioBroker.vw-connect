.class public final Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator<",
        "Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;",
        ">;"
    }
.end annotation


# instance fields
.field private final maxBuckets:I

.field private final maxScale:I

.field private final memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

.field private final reservoirFactory:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;IILio/opentelemetry/sdk/common/export/MemoryMode;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator;->reservoirFactory:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;

    .line 5
    .line 6
    iput p2, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator;->maxBuckets:I

    .line 7
    .line 8
    iput p3, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator;->maxScale:I

    .line 9
    .line 10
    iput-object p4, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public createHandle()Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle<",
            "Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator;->reservoirFactory:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;

    .line 4
    .line 5
    iget v2, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator;->maxBuckets:I

    .line 6
    .line 7
    iget v3, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator;->maxScale:I

    .line 8
    .line 9
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 10
    .line 11
    invoke-direct {v0, v1, v2, v3, p0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator$Handle;-><init>(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;IILio/opentelemetry/sdk/common/export/MemoryMode;)V

    .line 12
    .line 13
    .line 14
    return-object v0
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
            "Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;",
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
    move-object v0, p3

    .line 8
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getDescription()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p3

    .line 12
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->getSourceInstrument()Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getUnit()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-static {p5, p4}, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableExponentialHistogramData;->create(Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;Ljava/util/Collection;)Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramData;

    .line 21
    .line 22
    .line 23
    move-result-object p5

    .line 24
    move-object p4, v0

    .line 25
    invoke-static/range {p0 .. p5}, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableMetricData;->createExponentialHistogram(Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramData;)Lio/opentelemetry/sdk/metrics/data/MetricData;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method
