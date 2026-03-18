.class Lio/opentelemetry/sdk/metrics/internal/aggregator/DropAggregator$2;
.super Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/sdk/metrics/internal/aggregator/DropAggregator;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle<",
        "Lio/opentelemetry/sdk/metrics/data/PointData;",
        ">;"
    }
.end annotation


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;Z)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;-><init>(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;Z)V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public doAggregateThenMaybeResetDoubles(JJLio/opentelemetry/api/common/Attributes;Ljava/util/List;Z)Lio/opentelemetry/sdk/metrics/data/PointData;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(JJ",
            "Lio/opentelemetry/api/common/Attributes;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/data/DoubleExemplarData;",
            ">;Z)",
            "Lio/opentelemetry/sdk/metrics/data/PointData;"
        }
    .end annotation

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DropAggregator;->access$000()Lio/opentelemetry/sdk/metrics/data/PointData;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public doRecordDouble(D)V
    .locals 0

    .line 1
    return-void
.end method

.method public doRecordLong(J)V
    .locals 0

    .line 1
    return-void
.end method
