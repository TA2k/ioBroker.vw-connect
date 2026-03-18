.class final Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final attributes:[Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;

.field private final count:J

.field private final quantileValues:[Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileMarshaler;

.field private final startTimeUnixNano:J

.field private final sum:D

.field private final timeUnixNano:J


# direct methods
.method private constructor <init>(JJJD[Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileMarshaler;[Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;)V
    .locals 1

    .line 1
    invoke-static/range {p1 .. p10}, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;->calculateSize(JJJD[Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileMarshaler;[Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iput-wide p1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;->startTimeUnixNano:J

    .line 9
    .line 10
    iput-wide p3, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;->timeUnixNano:J

    .line 11
    .line 12
    iput-wide p5, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;->count:J

    .line 13
    .line 14
    iput-wide p7, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;->sum:D

    .line 15
    .line 16
    iput-object p9, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;->quantileValues:[Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileMarshaler;

    .line 17
    .line 18
    iput-object p10, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;->attributes:[Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;

    .line 19
    .line 20
    return-void
.end method

.method private static calculateSize(JJJD[Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileMarshaler;[Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;)I
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint;->START_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    invoke-static {v0, p0, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    sget-object p1, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

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
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint;->COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 15
    .line 16
    invoke-static {p0, p4, p5}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    add-int/2addr p0, p1

    .line 21
    sget-object p1, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint;->SUM:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 22
    .line 23
    invoke-static {p1, p6, p7}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeDouble(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)I

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    add-int/2addr p1, p0

    .line 28
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint;->QUANTILE_VALUES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 29
    .line 30
    invoke-static {p0, p8}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    add-int/2addr p0, p1

    .line 35
    sget-object p1, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 36
    .line 37
    invoke-static {p1, p9}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    add-int/2addr p1, p0

    .line 42
    return p1
.end method

.method public static create(Lio/opentelemetry/sdk/metrics/data/SummaryPointData;)Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;
    .locals 12

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/data/SummaryPointData;->getValues()Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileMarshaler;->createRepeated(Ljava/util/List;)[Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileMarshaler;

    .line 6
    .line 7
    .line 8
    move-result-object v10

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
    move-result-object v11

    .line 17
    new-instance v1, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;

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
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/data/SummaryPointData;->getCount()J

    .line 28
    .line 29
    .line 30
    move-result-wide v6

    .line 31
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/data/SummaryPointData;->getSum()D

    .line 32
    .line 33
    .line 34
    move-result-wide v8

    .line 35
    invoke-direct/range {v1 .. v11}, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;-><init>(JJJD[Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileMarshaler;[Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;)V

    .line 36
    .line 37
    .line 38
    return-object v1
.end method

.method public static createRepeated(Ljava/util/Collection;)[Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Lio/opentelemetry/sdk/metrics/data/SummaryPointData;",
            ">;)[",
            "Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;"
        }
    .end annotation

    .line 1
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    new-array v0, v0, [Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;

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
    check-cast v2, Lio/opentelemetry/sdk/metrics/data/SummaryPointData;

    .line 23
    .line 24
    add-int/lit8 v3, v1, 0x1

    .line 25
    .line 26
    invoke-static {v2}, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;->create(Lio/opentelemetry/sdk/metrics/data/SummaryPointData;)Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;

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


# virtual methods
.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 3

    .line 1
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint;->START_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;->startTimeUnixNano:J

    .line 4
    .line 5
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 6
    .line 7
    .line 8
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 9
    .line 10
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;->timeUnixNano:J

    .line 11
    .line 12
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 13
    .line 14
    .line 15
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint;->COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 16
    .line 17
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;->count:J

    .line 18
    .line 19
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 20
    .line 21
    .line 22
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint;->SUM:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 23
    .line 24
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;->sum:D

    .line 25
    .line 26
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeDouble(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)V

    .line 27
    .line 28
    .line 29
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint;->QUANTILE_VALUES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 30
    .line 31
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;->quantileValues:[Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileMarshaler;

    .line 32
    .line 33
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 34
    .line 35
    .line 36
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 37
    .line 38
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;->attributes:[Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;

    .line 39
    .line 40
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 41
    .line 42
    .line 43
    return-void
.end method
