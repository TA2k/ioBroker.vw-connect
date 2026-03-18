.class final Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field static final synthetic $assertionsDisabled:Z


# instance fields
.field private final attributes:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

.field private final exemplars:[Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;

.field private final startTimeUnixNano:J

.field private final timeUnixNano:J

.field private final value:Lio/opentelemetry/sdk/metrics/data/PointData;

.field private final valueField:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;


# direct methods
.method private constructor <init>(JJLio/opentelemetry/sdk/metrics/data/PointData;Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)V
    .locals 2

    .line 1
    move-object v1, p6

    .line 2
    move-object p6, p5

    .line 3
    move-object p5, v1

    .line 4
    invoke-static/range {p1 .. p8}, Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointMarshaler;->calculateSize(JJLio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/sdk/metrics/data/PointData;[Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)I

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 9
    .line 10
    .line 11
    iput-wide p1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointMarshaler;->startTimeUnixNano:J

    .line 12
    .line 13
    iput-wide p3, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointMarshaler;->timeUnixNano:J

    .line 14
    .line 15
    iput-object p6, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointMarshaler;->value:Lio/opentelemetry/sdk/metrics/data/PointData;

    .line 16
    .line 17
    iput-object p5, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointMarshaler;->valueField:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 18
    .line 19
    iput-object p7, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointMarshaler;->exemplars:[Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;

    .line 20
    .line 21
    iput-object p8, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointMarshaler;->attributes:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 22
    .line 23
    return-void
.end method

.method private static calculateSize(JJLio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/sdk/metrics/data/PointData;[Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)I
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/NumberDataPoint;->START_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    invoke-static {v0, p0, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    sget-object p1, Lio/opentelemetry/proto/metrics/v1/internal/NumberDataPoint;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 8
    .line 9
    invoke-static {p1, p2, p3}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    add-int/2addr p1, p0

    .line 14
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/NumberDataPoint;->AS_INT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 15
    .line 16
    if-ne p4, p0, :cond_0

    .line 17
    .line 18
    check-cast p5, Lio/opentelemetry/sdk/metrics/data/LongPointData;

    .line 19
    .line 20
    invoke-interface {p5}, Lio/opentelemetry/sdk/metrics/data/LongPointData;->getValue()J

    .line 21
    .line 22
    .line 23
    move-result-wide p2

    .line 24
    invoke-static {p4, p2, p3}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64Optional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    :goto_0
    add-int/2addr p0, p1

    .line 29
    goto :goto_1

    .line 30
    :cond_0
    check-cast p5, Lio/opentelemetry/sdk/metrics/data/DoublePointData;

    .line 31
    .line 32
    invoke-interface {p5}, Lio/opentelemetry/sdk/metrics/data/DoublePointData;->getValue()D

    .line 33
    .line 34
    .line 35
    move-result-wide p2

    .line 36
    invoke-static {p4, p2, p3}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeDoubleOptional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    goto :goto_0

    .line 41
    :goto_1
    sget-object p1, Lio/opentelemetry/proto/metrics/v1/internal/NumberDataPoint;->EXEMPLARS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 42
    .line 43
    invoke-static {p1, p6}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 44
    .line 45
    .line 46
    move-result p1

    .line 47
    add-int/2addr p1, p0

    .line 48
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/NumberDataPoint;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 49
    .line 50
    invoke-static {p0, p7}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    add-int/2addr p0, p1

    .line 55
    return p0
.end method

.method public static create(Lio/opentelemetry/sdk/metrics/data/PointData;)Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointMarshaler;
    .locals 10

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/data/PointData;->getExemplars()Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;->createRepeated(Ljava/util/List;)[Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;

    .line 6
    .line 7
    .line 8
    move-result-object v8

    .line 9
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/data/PointData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;->createForAttributes(Lio/opentelemetry/api/common/Attributes;)[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 14
    .line 15
    .line 16
    move-result-object v9

    .line 17
    new-instance v1, Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointMarshaler;

    .line 18
    .line 19
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/data/PointData;->getStartEpochNanos()J

    .line 20
    .line 21
    .line 22
    move-result-wide v2

    .line 23
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/data/PointData;->getEpochNanos()J

    .line 24
    .line 25
    .line 26
    move-result-wide v4

    .line 27
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointMarshaler;->toProtoPointValueType(Lio/opentelemetry/sdk/metrics/data/PointData;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 28
    .line 29
    .line 30
    move-result-object v7

    .line 31
    move-object v6, p0

    .line 32
    invoke-direct/range {v1 .. v9}, Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointMarshaler;-><init>(JJLio/opentelemetry/sdk/metrics/data/PointData;Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)V

    .line 33
    .line 34
    .line 35
    return-object v1
.end method

.method public static createRepeated(Ljava/util/Collection;)[Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointMarshaler;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "+",
            "Lio/opentelemetry/sdk/metrics/data/PointData;",
            ">;)[",
            "Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointMarshaler;"
        }
    .end annotation

    .line 1
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    new-array v0, v0, [Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointMarshaler;

    .line 6
    .line 7
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    const/4 v1, 0x0

    .line 12
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    if-eqz v2, :cond_0

    .line 17
    .line 18
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    check-cast v2, Lio/opentelemetry/sdk/metrics/data/PointData;

    .line 23
    .line 24
    add-int/lit8 v3, v1, 0x1

    .line 25
    .line 26
    invoke-static {v2}, Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointMarshaler;->create(Lio/opentelemetry/sdk/metrics/data/PointData;)Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointMarshaler;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    aput-object v2, v0, v1

    .line 31
    .line 32
    move v1, v3

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    return-object v0
.end method

.method public static toProtoPointValueType(Lio/opentelemetry/sdk/metrics/data/PointData;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;
    .locals 0

    .line 1
    instance-of p0, p0, Lio/opentelemetry/sdk/metrics/data/LongPointData;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/NumberDataPoint;->AS_INT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/NumberDataPoint;->AS_DOUBLE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 9
    .line 10
    return-object p0
.end method


# virtual methods
.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 3

    .line 1
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/NumberDataPoint;->START_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointMarshaler;->startTimeUnixNano:J

    .line 4
    .line 5
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 6
    .line 7
    .line 8
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/NumberDataPoint;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 9
    .line 10
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointMarshaler;->timeUnixNano:J

    .line 11
    .line 12
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 13
    .line 14
    .line 15
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointMarshaler;->valueField:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 16
    .line 17
    sget-object v1, Lio/opentelemetry/proto/metrics/v1/internal/NumberDataPoint;->AS_INT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 18
    .line 19
    if-ne v0, v1, :cond_0

    .line 20
    .line 21
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointMarshaler;->value:Lio/opentelemetry/sdk/metrics/data/PointData;

    .line 22
    .line 23
    check-cast v1, Lio/opentelemetry/sdk/metrics/data/LongPointData;

    .line 24
    .line 25
    invoke-interface {v1}, Lio/opentelemetry/sdk/metrics/data/LongPointData;->getValue()J

    .line 26
    .line 27
    .line 28
    move-result-wide v1

    .line 29
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64Optional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointMarshaler;->value:Lio/opentelemetry/sdk/metrics/data/PointData;

    .line 34
    .line 35
    check-cast v1, Lio/opentelemetry/sdk/metrics/data/DoublePointData;

    .line 36
    .line 37
    invoke-interface {v1}, Lio/opentelemetry/sdk/metrics/data/DoublePointData;->getValue()D

    .line 38
    .line 39
    .line 40
    move-result-wide v1

    .line 41
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeDoubleOptional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)V

    .line 42
    .line 43
    .line 44
    :goto_0
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/NumberDataPoint;->EXEMPLARS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 45
    .line 46
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointMarshaler;->exemplars:[Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;

    .line 47
    .line 48
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 49
    .line 50
    .line 51
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/NumberDataPoint;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 52
    .line 53
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/NumberDataPointMarshaler;->attributes:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 54
    .line 55
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 56
    .line 57
    .line 58
    return-void
.end method
