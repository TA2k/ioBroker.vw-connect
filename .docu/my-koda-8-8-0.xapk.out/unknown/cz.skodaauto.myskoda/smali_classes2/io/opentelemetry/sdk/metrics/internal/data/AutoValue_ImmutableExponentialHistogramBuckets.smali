.class final Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableExponentialHistogramBuckets;
.super Lio/opentelemetry/sdk/metrics/internal/data/ImmutableExponentialHistogramBuckets;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final bucketCounts:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation
.end field

.field private final offset:I

.field private final scale:I

.field private final totalCount:J


# direct methods
.method public constructor <init>(IILjava/util/List;J)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(II",
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;J)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableExponentialHistogramBuckets;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableExponentialHistogramBuckets;->scale:I

    .line 5
    .line 6
    iput p2, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableExponentialHistogramBuckets;->offset:I

    .line 7
    .line 8
    if-eqz p3, :cond_0

    .line 9
    .line 10
    iput-object p3, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableExponentialHistogramBuckets;->bucketCounts:Ljava/util/List;

    .line 11
    .line 12
    iput-wide p4, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableExponentialHistogramBuckets;->totalCount:J

    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 16
    .line 17
    const-string p1, "Null bucketCounts"

    .line 18
    .line 19
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    throw p0
.end method


# virtual methods
.method public equals(Ljava/lang/Object;)Z
    .locals 5

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p1, p0, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableExponentialHistogramBuckets;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p1, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableExponentialHistogramBuckets;

    .line 11
    .line 12
    iget v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableExponentialHistogramBuckets;->scale:I

    .line 13
    .line 14
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;->getScale()I

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    if-ne v1, v3, :cond_1

    .line 19
    .line 20
    iget v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableExponentialHistogramBuckets;->offset:I

    .line 21
    .line 22
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;->getOffset()I

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    if-ne v1, v3, :cond_1

    .line 27
    .line 28
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableExponentialHistogramBuckets;->bucketCounts:Ljava/util/List;

    .line 29
    .line 30
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;->getBucketCounts()Ljava/util/List;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    invoke-interface {v1, v3}, Ljava/util/List;->equals(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-eqz v1, :cond_1

    .line 39
    .line 40
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableExponentialHistogramBuckets;->totalCount:J

    .line 41
    .line 42
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;->getTotalCount()J

    .line 43
    .line 44
    .line 45
    move-result-wide p0

    .line 46
    cmp-long p0, v3, p0

    .line 47
    .line 48
    if-nez p0, :cond_1

    .line 49
    .line 50
    return v0

    .line 51
    :cond_1
    return v2
.end method

.method public getBucketCounts()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableExponentialHistogramBuckets;->bucketCounts:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public getOffset()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableExponentialHistogramBuckets;->offset:I

    .line 2
    .line 3
    return p0
.end method

.method public getScale()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableExponentialHistogramBuckets;->scale:I

    .line 2
    .line 3
    return p0
.end method

.method public getTotalCount()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableExponentialHistogramBuckets;->totalCount:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public hashCode()I
    .locals 5

    .line 1
    iget v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableExponentialHistogramBuckets;->scale:I

    .line 2
    .line 3
    const v1, 0xf4243

    .line 4
    .line 5
    .line 6
    xor-int/2addr v0, v1

    .line 7
    mul-int/2addr v0, v1

    .line 8
    iget v2, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableExponentialHistogramBuckets;->offset:I

    .line 9
    .line 10
    xor-int/2addr v0, v2

    .line 11
    mul-int/2addr v0, v1

    .line 12
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableExponentialHistogramBuckets;->bucketCounts:Ljava/util/List;

    .line 13
    .line 14
    invoke-interface {v2}, Ljava/util/List;->hashCode()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    xor-int/2addr v0, v2

    .line 19
    mul-int/2addr v0, v1

    .line 20
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableExponentialHistogramBuckets;->totalCount:J

    .line 21
    .line 22
    const/16 p0, 0x20

    .line 23
    .line 24
    ushr-long v3, v1, p0

    .line 25
    .line 26
    xor-long/2addr v1, v3

    .line 27
    long-to-int p0, v1

    .line 28
    xor-int/2addr p0, v0

    .line 29
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "ImmutableExponentialHistogramBuckets{scale="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableExponentialHistogramBuckets;->scale:I

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", offset="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableExponentialHistogramBuckets;->offset:I

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", bucketCounts="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableExponentialHistogramBuckets;->bucketCounts:Ljava/util/List;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", totalCount="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableExponentialHistogramBuckets;->totalCount:J

    .line 39
    .line 40
    const-string p0, "}"

    .line 41
    .line 42
    invoke-static {v1, v2, p0, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->k(JLjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0
.end method
