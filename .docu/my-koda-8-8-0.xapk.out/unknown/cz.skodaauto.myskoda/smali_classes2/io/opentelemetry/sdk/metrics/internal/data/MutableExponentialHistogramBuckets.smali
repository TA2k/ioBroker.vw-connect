.class public final Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;


# instance fields
.field private bucketCounts:Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

.field private offset:I

.field private scale:I

.field private totalCount:J


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->empty()Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;->bucketCounts:Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public equals(Ljava/lang/Object;)Z
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p1, p0, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p1, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    .line 11
    .line 12
    iget v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;->scale:I

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
    iget v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;->offset:I

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
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;->totalCount:J

    .line 29
    .line 30
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;->getTotalCount()J

    .line 31
    .line 32
    .line 33
    move-result-wide v5

    .line 34
    cmp-long v1, v3, v5

    .line 35
    .line 36
    if-nez v1, :cond_1

    .line 37
    .line 38
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;->bucketCounts:Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 39
    .line 40
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;->getBucketCounts()Ljava/util/List;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    invoke-static {p0, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    if-eqz p0, :cond_1

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
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;->bucketCounts:Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 2
    .line 3
    return-object p0
.end method

.method public getOffset()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;->offset:I

    .line 2
    .line 3
    return p0
.end method

.method public getReusableBucketCountsList()Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;->bucketCounts:Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 2
    .line 3
    return-object p0
.end method

.method public getScale()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;->scale:I

    .line 2
    .line 3
    return p0
.end method

.method public getTotalCount()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;->totalCount:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public hashCode()I
    .locals 5

    .line 1
    iget v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;->scale:I

    .line 2
    .line 3
    mul-int/lit8 v0, v0, 0x1f

    .line 4
    .line 5
    iget v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;->offset:I

    .line 6
    .line 7
    add-int/2addr v0, v1

    .line 8
    mul-int/lit8 v0, v0, 0x1f

    .line 9
    .line 10
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;->totalCount:J

    .line 11
    .line 12
    const/16 v3, 0x20

    .line 13
    .line 14
    ushr-long v3, v1, v3

    .line 15
    .line 16
    xor-long/2addr v1, v3

    .line 17
    long-to-int v1, v1

    .line 18
    add-int/2addr v0, v1

    .line 19
    mul-int/lit8 v0, v0, 0x1f

    .line 20
    .line 21
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;->bucketCounts:Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 22
    .line 23
    if-eqz p0, :cond_0

    .line 24
    .line 25
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 p0, 0x0

    .line 31
    :goto_0
    add-int/2addr v0, p0

    .line 32
    return v0
.end method

.method public set(IIJLio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;)Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;
    .locals 0

    .line 1
    iput p1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;->scale:I

    .line 2
    .line 3
    iput p2, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;->offset:I

    .line 4
    .line 5
    iput-wide p3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;->totalCount:J

    .line 6
    .line 7
    iput-object p5, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;->bucketCounts:Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 8
    .line 9
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "MutableExponentialHistogramBuckets{scale="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;->scale:I

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
    iget v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;->offset:I

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
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;->bucketCounts:Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

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
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramBuckets;->totalCount:J

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
