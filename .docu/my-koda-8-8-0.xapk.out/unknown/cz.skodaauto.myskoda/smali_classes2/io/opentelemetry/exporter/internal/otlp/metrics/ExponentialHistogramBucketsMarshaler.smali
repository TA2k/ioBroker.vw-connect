.class public Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final counts:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation
.end field

.field private final offset:I


# direct methods
.method private constructor <init>(ILjava/util/List;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I",
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;)V"
        }
    .end annotation

    .line 1
    invoke-static {p1, p2}, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;->calculateSize(ILjava/util/List;)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iput p1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;->offset:I

    .line 9
    .line 10
    iput-object p2, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;->counts:Ljava/util/List;

    .line 11
    .line 12
    return-void
.end method

.method public static calculateSize(ILjava/util/List;)I
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I",
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;)I"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint$Buckets;->OFFSET:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    invoke-static {v0, p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeSInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    instance-of v0, p1, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint$Buckets;->BUCKET_COUNTS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 12
    .line 13
    check-cast p1, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 14
    .line 15
    invoke-static {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedUInt64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;)I

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    :goto_0
    add-int/2addr p1, p0

    .line 20
    return p1

    .line 21
    :cond_0
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint$Buckets;->BUCKET_COUNTS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 22
    .line 23
    invoke-static {p1}, Lio/opentelemetry/sdk/internal/PrimitiveLongList;->toArray(Ljava/util/List;)[J

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    invoke-static {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedUInt64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[J)I

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    goto :goto_0
.end method

.method public static create(Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;)Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;->getOffset()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;->getBucketCounts()Ljava/util/List;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-direct {v0, v1, p0}, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;-><init>(ILjava/util/List;)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method


# virtual methods
.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 2

    .line 1
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint$Buckets;->OFFSET:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iget v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;->offset:I

    .line 4
    .line 5
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeSInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;->counts:Ljava/util/List;

    .line 9
    .line 10
    instance-of v0, p0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint$Buckets;->BUCKET_COUNTS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 15
    .line 16
    check-cast p0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 17
    .line 18
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedUInt64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :cond_0
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint$Buckets;->BUCKET_COUNTS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 23
    .line 24
    invoke-static {p0}, Lio/opentelemetry/sdk/internal/PrimitiveLongList;->toArray(Ljava/util/List;)[J

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedUInt64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[J)V

    .line 29
    .line 30
    .line 31
    return-void
.end method
