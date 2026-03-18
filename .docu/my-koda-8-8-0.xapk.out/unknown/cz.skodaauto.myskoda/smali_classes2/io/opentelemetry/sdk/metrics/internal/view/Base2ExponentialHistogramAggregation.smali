.class public final Lio/opentelemetry/sdk/metrics/internal/view/Base2ExponentialHistogramAggregation;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/Aggregation;
.implements Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorFactory;


# static fields
.field private static final DEFAULT:Lio/opentelemetry/sdk/metrics/Aggregation;

.field private static final DEFAULT_MAX_BUCKETS:I = 0xa0

.field private static final DEFAULT_MAX_SCALE:I = 0x14


# instance fields
.field private final maxBuckets:I

.field private final maxScale:I


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/view/Base2ExponentialHistogramAggregation;

    .line 2
    .line 3
    const/16 v1, 0xa0

    .line 4
    .line 5
    const/16 v2, 0x14

    .line 6
    .line 7
    invoke-direct {v0, v1, v2}, Lio/opentelemetry/sdk/metrics/internal/view/Base2ExponentialHistogramAggregation;-><init>(II)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lio/opentelemetry/sdk/metrics/internal/view/Base2ExponentialHistogramAggregation;->DEFAULT:Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 11
    .line 12
    return-void
.end method

.method private constructor <init>(II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lio/opentelemetry/sdk/metrics/internal/view/Base2ExponentialHistogramAggregation;->maxBuckets:I

    .line 5
    .line 6
    iput p2, p0, Lio/opentelemetry/sdk/metrics/internal/view/Base2ExponentialHistogramAggregation;->maxScale:I

    .line 7
    .line 8
    return-void
.end method

.method public static create(II)Lio/opentelemetry/sdk/metrics/Aggregation;
    .locals 4

    .line 1
    const/4 v0, 0x2

    .line 2
    const/4 v1, 0x0

    .line 3
    const/4 v2, 0x1

    .line 4
    if-lt p0, v0, :cond_0

    .line 5
    .line 6
    move v0, v2

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    move v0, v1

    .line 9
    :goto_0
    const-string v3, "maxBuckets must be >= 2"

    .line 10
    .line 11
    invoke-static {v0, v3}, Lio/opentelemetry/api/internal/Utils;->checkArgument(ZLjava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const/16 v0, 0x14

    .line 15
    .line 16
    if-gt p1, v0, :cond_1

    .line 17
    .line 18
    const/16 v0, -0xa

    .line 19
    .line 20
    if-lt p1, v0, :cond_1

    .line 21
    .line 22
    move v1, v2

    .line 23
    :cond_1
    const-string v0, "maxScale must be -10 <= x <= 20"

    .line 24
    .line 25
    invoke-static {v1, v0}, Lio/opentelemetry/api/internal/Utils;->checkArgument(ZLjava/lang/String;)V

    .line 26
    .line 27
    .line 28
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/view/Base2ExponentialHistogramAggregation;

    .line 29
    .line 30
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/sdk/metrics/internal/view/Base2ExponentialHistogramAggregation;-><init>(II)V

    .line 31
    .line 32
    .line 33
    return-object v0
.end method

.method public static getDefault()Lio/opentelemetry/sdk/metrics/Aggregation;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/metrics/internal/view/Base2ExponentialHistogramAggregation;->DEFAULT:Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public createAggregator(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;Lio/opentelemetry/sdk/common/export/MemoryMode;)Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T::",
            "Lio/opentelemetry/sdk/metrics/data/PointData;",
            ">(",
            "Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;",
            "Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;",
            "Lio/opentelemetry/sdk/common/export/MemoryMode;",
            ")",
            "Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator<",
            "TT;>;"
        }
    .end annotation

    .line 1
    new-instance p1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator;

    .line 2
    .line 3
    invoke-static {}, Lio/opentelemetry/sdk/common/Clock;->getDefault()Lio/opentelemetry/sdk/common/Clock;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-virtual {v1}, Ljava/lang/Runtime;->availableProcessors()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    invoke-static {}, Lio/opentelemetry/sdk/internal/RandomSupplier;->platformDefault()Ljava/util/function/Supplier;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    invoke-static {v0, v1, v2}, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;->fixedSizeReservoir(Lio/opentelemetry/sdk/common/Clock;ILjava/util/function/Supplier;)Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    invoke-static {p2, v0}, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;->filtered(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;)Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;

    .line 24
    .line 25
    .line 26
    move-result-object p2

    .line 27
    iget v0, p0, Lio/opentelemetry/sdk/metrics/internal/view/Base2ExponentialHistogramAggregation;->maxBuckets:I

    .line 28
    .line 29
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/view/Base2ExponentialHistogramAggregation;->maxScale:I

    .line 30
    .line 31
    invoke-direct {p1, p2, v0, p0, p3}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramAggregator;-><init>(Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarReservoirFactory;IILio/opentelemetry/sdk/common/export/MemoryMode;)V

    .line 32
    .line 33
    .line 34
    return-object p1
.end method

.method public isCompatibleWithInstrument(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;)Z
    .locals 1

    .line 1
    sget-object p0, Lio/opentelemetry/sdk/metrics/internal/view/Base2ExponentialHistogramAggregation$1;->$SwitchMap$io$opentelemetry$sdk$metrics$InstrumentType:[I

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getType()Lio/opentelemetry/sdk/metrics/InstrumentType;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 8
    .line 9
    .line 10
    move-result p1

    .line 11
    aget p0, p0, p1

    .line 12
    .line 13
    const/4 p1, 0x1

    .line 14
    if-eq p0, p1, :cond_0

    .line 15
    .line 16
    const/4 v0, 0x2

    .line 17
    if-eq p0, v0, :cond_0

    .line 18
    .line 19
    const/4 p0, 0x0

    .line 20
    return p0

    .line 21
    :cond_0
    return p1
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "Base2ExponentialHistogramAggregation{maxBuckets="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lio/opentelemetry/sdk/metrics/internal/view/Base2ExponentialHistogramAggregation;->maxBuckets:I

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ",maxScale="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/view/Base2ExponentialHistogramAggregation;->maxScale:I

    .line 19
    .line 20
    const-string v1, "}"

    .line 21
    .line 22
    invoke-static {p0, v1, v0}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method
