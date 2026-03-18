.class Lio/opentelemetry/sdk/metrics/internal/exemplar/LongFilteredExemplarReservoir;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/internal/exemplar/LongExemplarReservoir;


# instance fields
.field private final filter:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

.field private final reservoir:Lio/opentelemetry/sdk/metrics/internal/exemplar/LongExemplarReservoir;


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;Lio/opentelemetry/sdk/metrics/internal/exemplar/LongExemplarReservoir;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/LongFilteredExemplarReservoir;->filter:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/LongFilteredExemplarReservoir;->reservoir:Lio/opentelemetry/sdk/metrics/internal/exemplar/LongExemplarReservoir;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public collectAndResetLongs(Lio/opentelemetry/api/common/Attributes;)Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/Attributes;",
            ")",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/data/LongExemplarData;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/LongFilteredExemplarReservoir;->reservoir:Lio/opentelemetry/sdk/metrics/internal/exemplar/LongExemplarReservoir;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/exemplar/LongExemplarReservoir;->collectAndResetLongs(Lio/opentelemetry/api/common/Attributes;)Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public offerLongMeasurement(JLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/LongFilteredExemplarReservoir;->filter:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

    .line 2
    .line 3
    invoke-interface {v0, p1, p2, p3, p4}, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;->shouldSampleMeasurement(JLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/LongFilteredExemplarReservoir;->reservoir:Lio/opentelemetry/sdk/metrics/internal/exemplar/LongExemplarReservoir;

    .line 10
    .line 11
    invoke-interface {p0, p1, p2, p3, p4}, Lio/opentelemetry/sdk/metrics/internal/exemplar/LongExemplarReservoir;->offerLongMeasurement(JLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    return-void
.end method
