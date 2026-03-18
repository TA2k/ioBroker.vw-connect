.class Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;->histogramBucketReservoir(Lio/opentelemetry/sdk/common/Clock;Ljava/util/List;)Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic val$boundaries:Ljava/util/List;

.field final synthetic val$clock:Lio/opentelemetry/sdk/common/Clock;


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/common/Clock;Ljava/util/List;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$4;->val$clock:Lio/opentelemetry/sdk/common/Clock;

    .line 2
    .line 3
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$4;->val$boundaries:Ljava/util/List;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public createDoubleExemplarReservoir()Lio/opentelemetry/sdk/metrics/internal/exemplar/DoubleExemplarReservoir;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/exemplar/HistogramExemplarReservoir;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$4;->val$clock:Lio/opentelemetry/sdk/common/Clock;

    .line 4
    .line 5
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$4;->val$boundaries:Ljava/util/List;

    .line 6
    .line 7
    invoke-direct {v0, v1, p0}, Lio/opentelemetry/sdk/metrics/internal/exemplar/HistogramExemplarReservoir;-><init>(Lio/opentelemetry/sdk/common/Clock;Ljava/util/List;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method

.method public createLongExemplarReservoir()Lio/opentelemetry/sdk/metrics/internal/exemplar/LongExemplarReservoir;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/exemplar/HistogramExemplarReservoir;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$4;->val$clock:Lio/opentelemetry/sdk/common/Clock;

    .line 4
    .line 5
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$4;->val$boundaries:Ljava/util/List;

    .line 6
    .line 7
    invoke-direct {v0, v1, p0}, Lio/opentelemetry/sdk/metrics/internal/exemplar/HistogramExemplarReservoir;-><init>(Lio/opentelemetry/sdk/common/Clock;Ljava/util/List;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method
