.class final Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;


# instance fields
.field private base2ExponentialHistogramIndexer:Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;

.field private counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

.field private final memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

.field private reusableCounts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private scale:I

.field private totalCount:J


# direct methods
.method public constructor <init>(IILio/opentelemetry/sdk/common/export/MemoryMode;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p3, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 3
    new-instance p3, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    invoke-direct {p3, p2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;-><init>(I)V

    iput-object p3, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 4
    iput p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->scale:I

    .line 5
    invoke-static {p1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;->get(I)Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;

    move-result-object p1

    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->base2ExponentialHistogramIndexer:Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;

    const-wide/16 p1, 0x0

    .line 6
    iput-wide p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->totalCount:J

    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;)V
    .locals 2

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    iget-object v1, p1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    invoke-direct {v0, v1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;-><init>(Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;)V

    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 9
    iget v0, p1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->scale:I

    iput v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->scale:I

    .line 10
    iget-object v0, p1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->base2ExponentialHistogramIndexer:Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;

    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->base2ExponentialHistogramIndexer:Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;

    .line 11
    iget-wide v0, p1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->totalCount:J

    iput-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->totalCount:J

    .line 12
    iget-object v0, p1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 13
    iget-object p1, p1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->reusableCounts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->reusableCounts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    return-void
.end method

.method private sameBucketCounts(Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;)Z
    .locals 7

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->totalCount:J

    .line 2
    .line 3
    iget-wide v2, p1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->totalCount:J

    .line 4
    .line 5
    cmp-long v0, v0, v2

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    return v1

    .line 11
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 12
    .line 13
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->getIndexStart()I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    iget-object v2, p1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 18
    .line 19
    invoke-virtual {v2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->getIndexStart()I

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    invoke-static {v0, v2}, Ljava/lang/Math;->min(II)I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    const/high16 v2, -0x80000000

    .line 28
    .line 29
    if-ne v0, v2, :cond_1

    .line 30
    .line 31
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 32
    .line 33
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->getIndexStart()I

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    iget-object v2, p1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 38
    .line 39
    invoke-virtual {v2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->getIndexStart()I

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    invoke-static {v0, v2}, Ljava/lang/Math;->max(II)I

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    :cond_1
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 48
    .line 49
    invoke-virtual {v2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->getIndexEnd()I

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    iget-object v3, p1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 54
    .line 55
    invoke-virtual {v3}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->getIndexEnd()I

    .line 56
    .line 57
    .line 58
    move-result v3

    .line 59
    invoke-static {v2, v3}, Ljava/lang/Math;->max(II)I

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    :goto_0
    if-gt v0, v2, :cond_3

    .line 64
    .line 65
    iget-object v3, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 66
    .line 67
    invoke-virtual {v3, v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->get(I)J

    .line 68
    .line 69
    .line 70
    move-result-wide v3

    .line 71
    iget-object v5, p1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 72
    .line 73
    invoke-virtual {v5, v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->get(I)J

    .line 74
    .line 75
    .line 76
    move-result-wide v5

    .line 77
    cmp-long v3, v3, v5

    .line 78
    .line 79
    if-eqz v3, :cond_2

    .line 80
    .line 81
    return v1

    .line 82
    :cond_2
    add-int/lit8 v0, v0, 0x1

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_3
    const/4 p0, 0x1

    .line 86
    return p0
.end method


# virtual methods
.method public clear(I)V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->totalCount:J

    .line 4
    .line 5
    iput p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->scale:I

    .line 6
    .line 7
    invoke-static {p1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;->get(I)Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->base2ExponentialHistogramIndexer:Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;

    .line 12
    .line 13
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 14
    .line 15
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->clear()V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public copy()Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;-><init>(Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public downscale(I)V
    .locals 6

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    if-ltz p1, :cond_8

    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 7
    .line 8
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->isEmpty()Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-nez v0, :cond_7

    .line 13
    .line 14
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 15
    .line 16
    sget-object v1, Lio/opentelemetry/sdk/common/export/MemoryMode;->IMMUTABLE_DATA:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 17
    .line 18
    if-ne v0, v1, :cond_1

    .line 19
    .line 20
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 21
    .line 22
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 23
    .line 24
    invoke-direct {v0, v1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;-><init>(Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;)V

    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->reusableCounts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 29
    .line 30
    if-nez v0, :cond_2

    .line 31
    .line 32
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 33
    .line 34
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 35
    .line 36
    invoke-direct {v0, v1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;-><init>(Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;)V

    .line 37
    .line 38
    .line 39
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->reusableCounts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 40
    .line 41
    :cond_2
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->reusableCounts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 42
    .line 43
    :goto_0
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->clear()V

    .line 44
    .line 45
    .line 46
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 47
    .line 48
    invoke-virtual {v1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->getIndexStart()I

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    :goto_1
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 53
    .line 54
    invoke-virtual {v2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->getIndexEnd()I

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    if-gt v1, v2, :cond_5

    .line 59
    .line 60
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 61
    .line 62
    invoke-virtual {v2, v1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->get(I)J

    .line 63
    .line 64
    .line 65
    move-result-wide v2

    .line 66
    const-wide/16 v4, 0x0

    .line 67
    .line 68
    cmp-long v4, v2, v4

    .line 69
    .line 70
    if-lez v4, :cond_4

    .line 71
    .line 72
    shr-int v4, v1, p1

    .line 73
    .line 74
    invoke-virtual {v0, v4, v2, v3}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->increment(IJ)Z

    .line 75
    .line 76
    .line 77
    move-result v2

    .line 78
    if-eqz v2, :cond_3

    .line 79
    .line 80
    goto :goto_2

    .line 81
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 82
    .line 83
    const-string p1, "Failed to create new downscaled buckets."

    .line 84
    .line 85
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    throw p0

    .line 89
    :cond_4
    :goto_2
    add-int/lit8 v1, v1, 0x1

    .line 90
    .line 91
    goto :goto_1

    .line 92
    :cond_5
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->memoryMode:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 93
    .line 94
    sget-object v2, Lio/opentelemetry/sdk/common/export/MemoryMode;->REUSABLE_DATA:Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 95
    .line 96
    if-ne v1, v2, :cond_6

    .line 97
    .line 98
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 99
    .line 100
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 101
    .line 102
    iput-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->reusableCounts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 103
    .line 104
    goto :goto_3

    .line 105
    :cond_6
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 106
    .line 107
    :cond_7
    :goto_3
    iget v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->scale:I

    .line 108
    .line 109
    sub-int/2addr v0, p1

    .line 110
    iput v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->scale:I

    .line 111
    .line 112
    invoke-static {v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;->get(I)Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;

    .line 113
    .line 114
    .line 115
    move-result-object p1

    .line 116
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->base2ExponentialHistogramIndexer:Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;

    .line 117
    .line 118
    return-void

    .line 119
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 120
    .line 121
    const-string v0, "Cannot downscale by negative amount. Was given "

    .line 122
    .line 123
    const-string v1, "."

    .line 124
    .line 125
    invoke-static {v0, p1, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object p1

    .line 129
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    throw p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 3
    .param p1    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    instance-of v0, p1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    return v1

    .line 7
    :cond_0
    check-cast p1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;

    .line 8
    .line 9
    iget v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->scale:I

    .line 10
    .line 11
    iget v2, p1, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->scale:I

    .line 12
    .line 13
    if-ne v0, v2, :cond_1

    .line 14
    .line 15
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->sameBucketCounts(Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;)Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    if-eqz p0, :cond_1

    .line 20
    .line 21
    const/4 p0, 0x1

    .line 22
    return p0

    .line 23
    :cond_1
    return v1
.end method

.method public getBucketCounts()Ljava/util/List;
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 2
    .line 3
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    sget-object p0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 13
    .line 14
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->getIndexEnd()I

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 19
    .line 20
    invoke-virtual {v1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->getIndexStart()I

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    sub-int/2addr v0, v1

    .line 25
    add-int/lit8 v0, v0, 0x1

    .line 26
    .line 27
    new-array v1, v0, [J

    .line 28
    .line 29
    const/4 v2, 0x0

    .line 30
    :goto_0
    if-ge v2, v0, :cond_1

    .line 31
    .line 32
    iget-object v3, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 33
    .line 34
    invoke-virtual {v3}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->getIndexStart()I

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    add-int/2addr v4, v2

    .line 39
    invoke-virtual {v3, v4}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->get(I)J

    .line 40
    .line 41
    .line 42
    move-result-wide v3

    .line 43
    aput-wide v3, v1, v2

    .line 44
    .line 45
    add-int/lit8 v2, v2, 0x1

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_1
    invoke-static {v1}, Lio/opentelemetry/sdk/internal/PrimitiveLongList;->wrap([J)Ljava/util/List;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0
.end method

.method public getBucketCountsIntoReusableList(Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 2
    .line 3
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    invoke-virtual {p1, v1}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->resizeAndClear(I)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 15
    .line 16
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->getIndexEnd()I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 21
    .line 22
    invoke-virtual {v2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->getIndexStart()I

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    sub-int/2addr v0, v2

    .line 27
    add-int/lit8 v0, v0, 0x1

    .line 28
    .line 29
    invoke-virtual {p1}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->size()I

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    if-eq v2, v0, :cond_1

    .line 34
    .line 35
    invoke-virtual {p1, v0}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->resizeAndClear(I)V

    .line 36
    .line 37
    .line 38
    :cond_1
    :goto_0
    if-ge v1, v0, :cond_2

    .line 39
    .line 40
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 41
    .line 42
    invoke-virtual {v2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->getIndexStart()I

    .line 43
    .line 44
    .line 45
    move-result v3

    .line 46
    add-int/2addr v3, v1

    .line 47
    invoke-virtual {v2, v3}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->get(I)J

    .line 48
    .line 49
    .line 50
    move-result-wide v2

    .line 51
    invoke-virtual {p1, v1, v2, v3}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->setLong(IJ)J

    .line 52
    .line 53
    .line 54
    add-int/lit8 v1, v1, 0x1

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_2
    return-void
.end method

.method public getOffset()I
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 2
    .line 3
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return p0

    .line 11
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 12
    .line 13
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->getIndexStart()I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0
.end method

.method public getScale()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->scale:I

    .line 2
    .line 3
    return p0
.end method

.method public getScaleReduction(D)I
    .locals 4

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->base2ExponentialHistogramIndexer:Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;

    invoke-virtual {v0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;->computeIndex(D)I

    move-result p1

    int-to-long p1, p1

    .line 2
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->getIndexStart()I

    move-result v0

    int-to-long v0, v0

    invoke-static {p1, p2, v0, v1}, Ljava/lang/Math;->min(JJ)J

    move-result-wide v0

    .line 3
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    invoke-virtual {v2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->getIndexEnd()I

    move-result v2

    int-to-long v2, v2

    invoke-static {p1, p2, v2, v3}, Ljava/lang/Math;->max(JJ)J

    move-result-wide p1

    .line 4
    invoke-virtual {p0, v0, v1, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->getScaleReduction(JJ)I

    move-result p0

    return p0
.end method

.method public getScaleReduction(JJ)I
    .locals 5

    const/4 v0, 0x0

    :goto_0
    sub-long v1, p3, p1

    const-wide/16 v3, 0x1

    add-long/2addr v1, v3

    .line 5
    iget-object v3, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    invoke-virtual {v3}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->getMaxSize()I

    move-result v3

    int-to-long v3, v3

    cmp-long v1, v1, v3

    if-lez v1, :cond_0

    const/4 v1, 0x1

    shr-long/2addr p1, v1

    shr-long/2addr p3, v1

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_0
    return v0
.end method

.method public getTotalCount()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->totalCount:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public hashCode()I
    .locals 7

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 2
    .line 3
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->getIndexStart()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const v1, 0xf4243

    .line 8
    .line 9
    .line 10
    move v2, v1

    .line 11
    :goto_0
    iget-object v3, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 12
    .line 13
    invoke-virtual {v3}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->getIndexEnd()I

    .line 14
    .line 15
    .line 16
    move-result v3

    .line 17
    if-gt v0, v3, :cond_1

    .line 18
    .line 19
    iget-object v3, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 20
    .line 21
    invoke-virtual {v3, v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->get(I)J

    .line 22
    .line 23
    .line 24
    move-result-wide v3

    .line 25
    const-wide/16 v5, 0x0

    .line 26
    .line 27
    cmp-long v5, v3, v5

    .line 28
    .line 29
    if-eqz v5, :cond_0

    .line 30
    .line 31
    xor-int/2addr v2, v0

    .line 32
    mul-int/2addr v2, v1

    .line 33
    int-to-long v5, v2

    .line 34
    xor-long v2, v5, v3

    .line 35
    .line 36
    long-to-int v2, v2

    .line 37
    mul-int/2addr v2, v1

    .line 38
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_1
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->scale:I

    .line 42
    .line 43
    xor-int/2addr p0, v2

    .line 44
    return p0
.end method

.method public record(D)Z
    .locals 4

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmpl-double v0, p1, v0

    .line 4
    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->base2ExponentialHistogramIndexer:Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;

    .line 8
    .line 9
    invoke-virtual {v0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/Base2ExponentialHistogramIndexer;->computeIndex(D)I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    iget-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 14
    .line 15
    const-wide/16 v0, 0x1

    .line 16
    .line 17
    invoke-virtual {p2, p1, v0, v1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->increment(IJ)Z

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    if-eqz p1, :cond_0

    .line 22
    .line 23
    iget-wide v2, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->totalCount:J

    .line 24
    .line 25
    add-long/2addr v2, v0

    .line 26
    iput-wide v2, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->totalCount:J

    .line 27
    .line 28
    :cond_0
    return p1

    .line 29
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 30
    .line 31
    const-string p1, "Illegal attempted recording of zero at bucket level."

    .line 32
    .line 33
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "DoubleExponentialHistogramBuckets{scale: "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->scale:I

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", offset: "

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->getOffset()I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v1, ", counts: "

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/DoubleBase2ExponentialHistogramBuckets;->counts:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;

    .line 31
    .line 32
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string p0, " }"

    .line 36
    .line 37
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0
.end method
