.class Lio/opentelemetry/sdk/metrics/internal/exemplar/RandomFixedSizeExemplarReservoir;
.super Lio/opentelemetry/sdk/metrics/internal/exemplar/FixedSizeExemplarReservoir;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/sdk/metrics/internal/exemplar/RandomFixedSizeExemplarReservoir$RandomCellSelector;
    }
.end annotation


# direct methods
.method private constructor <init>(Lio/opentelemetry/sdk/common/Clock;ILjava/util/function/Supplier;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/common/Clock;",
            "I",
            "Ljava/util/function/Supplier<",
            "Ljava/util/Random;",
            ">;)V"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/exemplar/RandomFixedSizeExemplarReservoir$RandomCellSelector;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p3, v1}, Lio/opentelemetry/sdk/metrics/internal/exemplar/RandomFixedSizeExemplarReservoir$RandomCellSelector;-><init>(Ljava/util/function/Supplier;Lio/opentelemetry/sdk/metrics/internal/exemplar/RandomFixedSizeExemplarReservoir$1;)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, p1, p2, v0}, Lio/opentelemetry/sdk/metrics/internal/exemplar/FixedSizeExemplarReservoir;-><init>(Lio/opentelemetry/sdk/common/Clock;ILio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCellSelector;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public static create(Lio/opentelemetry/sdk/common/Clock;ILjava/util/function/Supplier;)Lio/opentelemetry/sdk/metrics/internal/exemplar/RandomFixedSizeExemplarReservoir;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/common/Clock;",
            "I",
            "Ljava/util/function/Supplier<",
            "Ljava/util/Random;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/internal/exemplar/RandomFixedSizeExemplarReservoir;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/exemplar/RandomFixedSizeExemplarReservoir;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/exemplar/RandomFixedSizeExemplarReservoir;-><init>(Lio/opentelemetry/sdk/common/Clock;ILjava/util/function/Supplier;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method
