.class final Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsStatelessMarshaler;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler<",
        "Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;",
        ">;"
    }
.end annotation


# static fields
.field static final INSTANCE:Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsStatelessMarshaler;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsStatelessMarshaler;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsStatelessMarshaler;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsStatelessMarshaler;

    .line 7
    .line 8
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public getBinarySerializedSize(Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 0

    .line 2
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;->getOffset()I

    move-result p0

    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;->getBucketCounts()Ljava/util/List;

    move-result-object p1

    .line 3
    invoke-static {p0, p1}, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;->calculateSize(ILjava/util/List;)I

    move-result p0

    return p0
.end method

.method public bridge synthetic getBinarySerializedSize(Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 0

    .line 1
    check-cast p1, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsStatelessMarshaler;->getBinarySerializedSize(Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0
.end method

.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 0

    .line 2
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint$Buckets;->OFFSET:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;->getOffset()I

    move-result p3

    invoke-virtual {p1, p0, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeSInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V

    .line 3
    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;->getBucketCounts()Ljava/util/List;

    move-result-object p0

    .line 4
    instance-of p2, p0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    if-eqz p2, :cond_0

    .line 5
    sget-object p2, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint$Buckets;->BUCKET_COUNTS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    check-cast p0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    invoke-virtual {p1, p2, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedUInt64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;)V

    return-void

    .line 6
    :cond_0
    sget-object p2, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint$Buckets;->BUCKET_COUNTS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 7
    invoke-static {p0}, Lio/opentelemetry/sdk/internal/PrimitiveLongList;->toArray(Ljava/util/List;)[J

    move-result-object p0

    .line 8
    invoke-virtual {p1, p2, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedUInt64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[J)V

    return-void
.end method

.method public bridge synthetic writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 0

    .line 1
    check-cast p2, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsStatelessMarshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void
.end method
