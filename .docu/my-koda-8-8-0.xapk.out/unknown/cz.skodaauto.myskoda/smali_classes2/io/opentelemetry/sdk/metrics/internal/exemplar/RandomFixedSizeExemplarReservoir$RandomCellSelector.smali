.class Lio/opentelemetry/sdk/metrics/internal/exemplar/RandomFixedSizeExemplarReservoir$RandomCellSelector;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCellSelector;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/sdk/metrics/internal/exemplar/RandomFixedSizeExemplarReservoir;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "RandomCellSelector"
.end annotation


# instance fields
.field private final numMeasurements:Lio/opentelemetry/sdk/metrics/internal/concurrent/LongAdder;

.field private final randomSupplier:Ljava/util/function/Supplier;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Supplier<",
            "Ljava/util/Random;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method private constructor <init>(Ljava/util/function/Supplier;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Supplier<",
            "Ljava/util/Random;",
            ">;)V"
        }
    .end annotation

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/concurrent/AdderUtil;->createLongAdder()Lio/opentelemetry/sdk/metrics/internal/concurrent/LongAdder;

    move-result-object v0

    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/RandomFixedSizeExemplarReservoir$RandomCellSelector;->numMeasurements:Lio/opentelemetry/sdk/metrics/internal/concurrent/LongAdder;

    .line 4
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/RandomFixedSizeExemplarReservoir$RandomCellSelector;->randomSupplier:Ljava/util/function/Supplier;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/function/Supplier;Lio/opentelemetry/sdk/metrics/internal/exemplar/RandomFixedSizeExemplarReservoir$1;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/exemplar/RandomFixedSizeExemplarReservoir$RandomCellSelector;-><init>(Ljava/util/function/Supplier;)V

    return-void
.end method

.method private reservoirCellIndex([Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;)I
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/RandomFixedSizeExemplarReservoir$RandomCellSelector;->numMeasurements:Lio/opentelemetry/sdk/metrics/internal/concurrent/LongAdder;

    .line 2
    .line 3
    invoke-interface {v0}, Lio/opentelemetry/sdk/metrics/internal/concurrent/LongAdder;->intValue()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x1

    .line 8
    add-int/2addr v0, v1

    .line 9
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/RandomFixedSizeExemplarReservoir$RandomCellSelector;->randomSupplier:Ljava/util/function/Supplier;

    .line 10
    .line 11
    invoke-interface {v2}, Ljava/util/function/Supplier;->get()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    check-cast v2, Ljava/util/Random;

    .line 16
    .line 17
    if-lez v0, :cond_0

    .line 18
    .line 19
    move v1, v0

    .line 20
    :cond_0
    invoke-virtual {v2, v1}, Ljava/util/Random;->nextInt(I)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/RandomFixedSizeExemplarReservoir$RandomCellSelector;->numMeasurements:Lio/opentelemetry/sdk/metrics/internal/concurrent/LongAdder;

    .line 25
    .line 26
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/internal/concurrent/LongAdder;->increment()V

    .line 27
    .line 28
    .line 29
    array-length p0, p1

    .line 30
    if-ge v0, p0, :cond_1

    .line 31
    .line 32
    return v0

    .line 33
    :cond_1
    const/4 p0, -0x1

    .line 34
    return p0
.end method


# virtual methods
.method public reservoirCellIndexFor([Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;DLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)I
    .locals 0

    .line 2
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/exemplar/RandomFixedSizeExemplarReservoir$RandomCellSelector;->reservoirCellIndex([Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;)I

    move-result p0

    return p0
.end method

.method public reservoirCellIndexFor([Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;JLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)I
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/exemplar/RandomFixedSizeExemplarReservoir$RandomCellSelector;->reservoirCellIndex([Lio/opentelemetry/sdk/metrics/internal/exemplar/ReservoirCell;)I

    move-result p0

    return p0
.end method

.method public reset()V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/RandomFixedSizeExemplarReservoir$RandomCellSelector;->numMeasurements:Lio/opentelemetry/sdk/metrics/internal/concurrent/LongAdder;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/internal/concurrent/LongAdder;->reset()V

    .line 4
    .line 5
    .line 6
    return-void
.end method
