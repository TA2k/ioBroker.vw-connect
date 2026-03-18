.class final Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final EXPONENT_BIAS:I = 0x3ff

.field private static final EXPONENT_BIT_MASK:J = 0x7ff0000000000000L

.field private static final EXPONENT_WIDTH:I = 0xb

.field private static final LOG_BASE2_E:D

.field private static final SIGNIFICAND_BIT_MASK:J = 0xfffffffffffffL

.field private static final SIGNIFICAND_WIDTH:I = 0x34

.field private static final cache:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/Integer;",
            "Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private final scale:I

.field private final scaleFactor:D


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;->cache:Ljava/util/Map;

    .line 7
    .line 8
    const-wide/high16 v0, 0x4000000000000000L    # 2.0

    .line 9
    .line 10
    invoke-static {v0, v1}, Ljava/lang/Math;->log(D)D

    .line 11
    .line 12
    .line 13
    move-result-wide v0

    .line 14
    const-wide/high16 v2, 0x3ff0000000000000L    # 1.0

    .line 15
    .line 16
    div-double/2addr v2, v0

    .line 17
    sput-wide v2, Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;->LOG_BASE2_E:D

    .line 18
    .line 19
    return-void
.end method

.method private constructor <init>(I)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;->scale:I

    .line 5
    .line 6
    invoke-static {p1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;->computeScaleFactor(I)D

    .line 7
    .line 8
    .line 9
    move-result-wide v0

    .line 10
    iput-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;->scaleFactor:D

    .line 11
    .line 12
    return-void
.end method

.method public static synthetic a(I)Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method private static computeScaleFactor(I)D
    .locals 2

    .line 1
    sget-wide v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;->LOG_BASE2_E:D

    .line 2
    .line 3
    invoke-static {v0, v1, p0}, Ljava/lang/Math;->scalb(DI)D

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    return-wide v0
.end method

.method public static get(I)Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;
    .locals 2

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;->cache:Ljava/util/Map;

    .line 2
    .line 3
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    new-instance v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/a;

    .line 8
    .line 9
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    invoke-interface {v0, p0, v1}, Ljava/util/Map;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    check-cast p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;

    .line 17
    .line 18
    return-object p0
.end method

.method private getIndexByLogarithm(D)I
    .locals 2

    .line 1
    invoke-static {p1, p2}, Ljava/lang/Math;->log(D)D

    .line 2
    .line 3
    .line 4
    move-result-wide p1

    .line 5
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;->scaleFactor:D

    .line 6
    .line 7
    mul-double/2addr p1, v0

    .line 8
    invoke-static {p1, p2}, Ljava/lang/Math;->ceil(D)D

    .line 9
    .line 10
    .line 11
    move-result-wide p0

    .line 12
    double-to-int p0, p0

    .line 13
    add-int/lit8 p0, p0, -0x1

    .line 14
    .line 15
    return p0
.end method

.method private static mapToIndexScaleZero(D)I
    .locals 6

    .line 1
    invoke-static {p0, p1}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    const-wide/high16 v0, 0x7ff0000000000000L    # Double.POSITIVE_INFINITY

    .line 6
    .line 7
    and-long/2addr v0, p0

    .line 8
    const/16 v2, 0x34

    .line 9
    .line 10
    shr-long/2addr v0, v2

    .line 11
    const-wide v2, 0xfffffffffffffL

    .line 12
    .line 13
    .line 14
    .line 15
    .line 16
    and-long/2addr p0, v2

    .line 17
    const-wide/16 v2, 0x0

    .line 18
    .line 19
    cmp-long v4, v0, v2

    .line 20
    .line 21
    if-nez v4, :cond_0

    .line 22
    .line 23
    const-wide/16 v4, 0x1

    .line 24
    .line 25
    sub-long v4, p0, v4

    .line 26
    .line 27
    invoke-static {v4, v5}, Ljava/lang/Long;->numberOfLeadingZeros(J)I

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    add-int/lit8 v4, v4, -0xc

    .line 32
    .line 33
    int-to-long v4, v4

    .line 34
    sub-long/2addr v0, v4

    .line 35
    :cond_0
    const-wide/16 v4, 0x3ff

    .line 36
    .line 37
    sub-long/2addr v0, v4

    .line 38
    long-to-int v0, v0

    .line 39
    cmp-long p0, p0, v2

    .line 40
    .line 41
    if-nez p0, :cond_1

    .line 42
    .line 43
    add-int/lit8 v0, v0, -0x1

    .line 44
    .line 45
    :cond_1
    return v0
.end method


# virtual methods
.method public computeIndex(D)I
    .locals 1

    .line 1
    invoke-static {p1, p2}, Ljava/lang/Math;->abs(D)D

    .line 2
    .line 3
    .line 4
    move-result-wide p1

    .line 5
    iget v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;->scale:I

    .line 6
    .line 7
    if-lez v0, :cond_0

    .line 8
    .line 9
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;->getIndexByLogarithm(D)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0

    .line 14
    :cond_0
    if-nez v0, :cond_1

    .line 15
    .line 16
    invoke-static {p1, p2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;->mapToIndexScaleZero(D)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    return p0

    .line 21
    :cond_1
    invoke-static {p1, p2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;->mapToIndexScaleZero(D)I

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;->scale:I

    .line 26
    .line 27
    neg-int p0, p0

    .line 28
    shr-int p0, p1, p0

    .line 29
    .line 30
    return p0
.end method
