.class final Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointStatelessMarshaler;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler<",
        "Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;",
        ">;"
    }
.end annotation


# static fields
.field static final INSTANCE:Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointStatelessMarshaler;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointStatelessMarshaler;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointStatelessMarshaler;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointStatelessMarshaler;

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
.method public getBinarySerializedSize(Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 3

    .line 2
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->START_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 3
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/PointData;->getStartEpochNanos()J

    move-result-wide v0

    .line 4
    invoke-static {p0, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    move-result p0

    .line 5
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 6
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/PointData;->getEpochNanos()J

    move-result-wide v1

    .line 7
    invoke-static {v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    move-result v0

    add-int/2addr v0, p0

    .line 8
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getCount()J

    move-result-wide v1

    invoke-static {p0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    move-result p0

    add-int/2addr p0, v0

    .line 9
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->SUM:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getSum()D

    move-result-wide v1

    invoke-static {v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeDouble(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)I

    move-result v0

    add-int/2addr v0, p0

    .line 10
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->hasMin()Z

    move-result p0

    if-eqz p0, :cond_0

    .line 11
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->MIN:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getMin()D

    move-result-wide v1

    invoke-static {p0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeDoubleOptional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)I

    move-result p0

    add-int/2addr v0, p0

    .line 12
    :cond_0
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->hasMax()Z

    move-result p0

    if-eqz p0, :cond_1

    .line 13
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->MAX:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getMax()D

    move-result-wide v1

    invoke-static {p0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeDoubleOptional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)I

    move-result p0

    add-int/2addr v0, p0

    .line 14
    :cond_1
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->SCALE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getScale()I

    move-result v1

    invoke-static {p0, v1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeSInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    move-result p0

    add-int/2addr p0, v0

    .line 15
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->ZERO_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 16
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getZeroCount()J

    move-result-wide v1

    invoke-static {v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    move-result v0

    add-int/2addr v0, p0

    .line 17
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->POSITIVE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 18
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getPositiveBuckets()Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    move-result-object v1

    sget-object v2, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsStatelessMarshaler;

    .line 19
    invoke-static {p0, v1, v2, p2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    add-int/2addr p0, v0

    .line 20
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->NEGATIVE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 21
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getNegativeBuckets()Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    move-result-object v1

    .line 22
    invoke-static {v0, v1, v2, p2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result v0

    add-int/2addr v0, p0

    .line 23
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->EXEMPLARS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 24
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getExemplars()Ljava/util/List;

    move-result-object v1

    sget-object v2, Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarStatelessMarshaler;

    .line 25
    invoke-static {p0, v1, v2, p2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    add-int/2addr p0, v0

    .line 26
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 27
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/PointData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    move-result-object p1

    sget-object v1, Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler;

    .line 28
    invoke-static {v0, p1, v1, p2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p1

    add-int/2addr p1, p0

    return p1
.end method

.method public bridge synthetic getBinarySerializedSize(Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 0

    .line 1
    check-cast p1, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointStatelessMarshaler;->getBinarySerializedSize(Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0
.end method

.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 2

    .line 2
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->START_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 3
    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/PointData;->getStartEpochNanos()J

    move-result-wide v0

    .line 4
    invoke-virtual {p1, p0, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 5
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/PointData;->getEpochNanos()J

    move-result-wide v0

    invoke-virtual {p1, p0, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 6
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getCount()J

    move-result-wide v0

    invoke-virtual {p1, p0, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 7
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->SUM:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getSum()D

    move-result-wide v0

    invoke-virtual {p1, p0, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeDouble(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)V

    .line 8
    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->hasMin()Z

    move-result p0

    if-eqz p0, :cond_0

    .line 9
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->MIN:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getMin()D

    move-result-wide v0

    invoke-virtual {p1, p0, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeDoubleOptional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)V

    .line 10
    :cond_0
    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->hasMax()Z

    move-result p0

    if-eqz p0, :cond_1

    .line 11
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->MAX:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getMax()D

    move-result-wide v0

    invoke-virtual {p1, p0, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeDoubleOptional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)V

    .line 12
    :cond_1
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->SCALE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getScale()I

    move-result v0

    invoke-virtual {p1, p0, v0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeSInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V

    .line 13
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->ZERO_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getZeroCount()J

    move-result-wide v0

    invoke-virtual {p1, p0, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 14
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->POSITIVE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 15
    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getPositiveBuckets()Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    move-result-object v0

    sget-object v1, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsStatelessMarshaler;

    .line 16
    invoke-virtual {p1, p0, v0, v1, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 17
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->NEGATIVE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 18
    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getNegativeBuckets()Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    move-result-object v0

    .line 19
    invoke-virtual {p1, p0, v0, v1, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 20
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->EXEMPLARS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 21
    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getExemplars()Ljava/util/List;

    move-result-object v0

    sget-object v1, Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarStatelessMarshaler;

    .line 22
    invoke-virtual {p1, p0, v0, v1, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 23
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 24
    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/PointData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    move-result-object p2

    sget-object v0, Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler;

    .line 25
    invoke-virtual {p1, p0, p2, v0, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void
.end method

.method public bridge synthetic writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 0

    .line 1
    check-cast p2, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;

    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointStatelessMarshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void
.end method
