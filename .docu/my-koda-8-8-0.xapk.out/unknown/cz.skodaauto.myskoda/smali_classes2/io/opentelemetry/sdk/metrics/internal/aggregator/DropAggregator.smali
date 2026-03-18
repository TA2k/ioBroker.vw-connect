.class public final Lio/opentelemetry/sdk/metrics/internal/aggregator/DropAggregator;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator<",
        "Lio/opentelemetry/sdk/metrics/data/PointData;",
        ">;"
    }
.end annotation


# static fields
.field private static final HANDLE:Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle<",
            "Lio/opentelemetry/sdk/metrics/data/PointData;",
            ">;"
        }
    .end annotation
.end field

.field public static final INSTANCE:Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator<",
            "Lio/opentelemetry/sdk/metrics/data/PointData;",
            ">;"
        }
    .end annotation
.end field

.field private static final POINT_DATA:Lio/opentelemetry/sdk/metrics/data/PointData;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DropAggregator$1;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DropAggregator$1;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DropAggregator;->POINT_DATA:Lio/opentelemetry/sdk/metrics/data/PointData;

    .line 7
    .line 8
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DropAggregator;

    .line 9
    .line 10
    invoke-direct {v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DropAggregator;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DropAggregator;->INSTANCE:Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;

    .line 14
    .line 15
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DropAggregator$2;

    .line 16
    .line 17
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;->noSamples()Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    const/4 v2, 0x1

    .line 22
    invoke-direct {v0, v1, v2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DropAggregator$2;-><init>(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;Z)V

    .line 23
    .line 24
    .line 25
    sput-object v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DropAggregator;->HANDLE:Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;

    .line 26
    .line 27
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic access$000()Lio/opentelemetry/sdk/metrics/data/PointData;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DropAggregator;->POINT_DATA:Lio/opentelemetry/sdk/metrics/data/PointData;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public createHandle()Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle<",
            "Lio/opentelemetry/sdk/metrics/data/PointData;",
            ">;"
        }
    .end annotation

    .line 1
    sget-object p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DropAggregator;->HANDLE:Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle;

    .line 2
    .line 3
    return-object p0
.end method

.method public toMetricData(Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;Ljava/util/Collection;Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;)Lio/opentelemetry/sdk/metrics/data/MetricData;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/resources/Resource;",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            "Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;",
            "Ljava/util/Collection<",
            "Lio/opentelemetry/sdk/metrics/data/PointData;",
            ">;",
            "Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;",
            ")",
            "Lio/opentelemetry/sdk/metrics/data/MetricData;"
        }
    .end annotation

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/aggregator/EmptyMetricData;->getInstance()Lio/opentelemetry/sdk/metrics/data/MetricData;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
