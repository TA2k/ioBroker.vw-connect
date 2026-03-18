.class public interface abstract Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static filtered(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;)Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$1;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$1;-><init>(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static fixedSizeReservoir(Lio/opentelemetry/sdk/common/Clock;ILjava/util/function/Supplier;)Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/common/Clock;",
            "I",
            "Ljava/util/function/Supplier<",
            "Ljava/util/Random;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$3;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$3;-><init>(Lio/opentelemetry/sdk/common/Clock;ILjava/util/function/Supplier;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static histogramBucketReservoir(Lio/opentelemetry/sdk/common/Clock;Ljava/util/List;)Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/common/Clock;",
            "Ljava/util/List<",
            "Ljava/lang/Double;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$4;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$4;-><init>(Lio/opentelemetry/sdk/common/Clock;Ljava/util/List;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static noSamples()Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$2;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory$2;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public abstract createDoubleExemplarReservoir()Lio/opentelemetry/sdk/metrics/internal/exemplar/DoubleExemplarReservoir;
.end method

.method public abstract createLongExemplarReservoir()Lio/opentelemetry/sdk/metrics/internal/exemplar/LongExemplarReservoir;
.end method
