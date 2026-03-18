.class final Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final attributes:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

.field private final bucketCounts:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation
.end field

.field private final count:J

.field private final exemplars:[Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;

.field private final explicitBounds:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Double;",
            ">;"
        }
    .end annotation
.end field

.field private final hasMax:Z

.field private final hasMin:Z

.field private final max:D

.field private final min:D

.field private final startTimeUnixNano:J

.field private final sum:D

.field private final timeUnixNano:J


# direct methods
.method private constructor <init>(JJJDZDZDLjava/util/List;Ljava/util/List;[Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(JJJDZDZD",
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;",
            "Ljava/util/List<",
            "Ljava/lang/Double;",
            ">;[",
            "Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;",
            "[",
            "Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-static/range {p1 .. p18}, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->calculateSize(JJJDZDZDLjava/util/List;Ljava/util/List;[Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iput-wide p1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->startTimeUnixNano:J

    .line 9
    .line 10
    iput-wide p3, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->timeUnixNano:J

    .line 11
    .line 12
    iput-wide p5, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->count:J

    .line 13
    .line 14
    iput-wide p7, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->sum:D

    .line 15
    .line 16
    iput-boolean p9, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->hasMin:Z

    .line 17
    .line 18
    iput-wide p10, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->min:D

    .line 19
    .line 20
    iput-boolean p12, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->hasMax:Z

    .line 21
    .line 22
    iput-wide p13, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->max:D

    .line 23
    .line 24
    move-object/from16 p1, p15

    .line 25
    .line 26
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->bucketCounts:Ljava/util/List;

    .line 27
    .line 28
    move-object/from16 p1, p16

    .line 29
    .line 30
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->explicitBounds:Ljava/util/List;

    .line 31
    .line 32
    move-object/from16 p1, p17

    .line 33
    .line 34
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->exemplars:[Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;

    .line 35
    .line 36
    move-object/from16 p1, p18

    .line 37
    .line 38
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->attributes:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 39
    .line 40
    return-void
.end method

.method private static calculateSize(JJJDZDZDLjava/util/List;Ljava/util/List;[Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)I
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(JJJDZDZD",
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;",
            "Ljava/util/List<",
            "Ljava/lang/Double;",
            ">;[",
            "Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;",
            "[",
            "Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;",
            ")I"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->START_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    invoke-static {v0, p0, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    sget-object p1, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

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
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

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
    sget-object p1, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->SUM:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 22
    .line 23
    invoke-static {p1, p6, p7}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeDoubleOptional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)I

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    add-int/2addr p1, p0

    .line 28
    if-eqz p8, :cond_0

    .line 29
    .line 30
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->MIN:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 31
    .line 32
    invoke-static {p0, p9, p10}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeDoubleOptional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)I

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    add-int/2addr p1, p0

    .line 37
    :cond_0
    if-eqz p11, :cond_1

    .line 38
    .line 39
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->MAX:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 40
    .line 41
    invoke-static {p0, p12, p13}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeDoubleOptional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)I

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    add-int/2addr p1, p0

    .line 46
    :cond_1
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->BUCKET_COUNTS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 47
    .line 48
    invoke-static {p0, p14}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;)I

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    add-int/2addr p0, p1

    .line 53
    sget-object p1, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->EXPLICIT_BOUNDS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 54
    .line 55
    move-object/from16 p2, p15

    .line 56
    .line 57
    invoke-static {p1, p2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedDouble(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;)I

    .line 58
    .line 59
    .line 60
    move-result p1

    .line 61
    add-int/2addr p1, p0

    .line 62
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->EXEMPLARS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 63
    .line 64
    move-object/from16 p2, p16

    .line 65
    .line 66
    invoke-static {p0, p2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 67
    .line 68
    .line 69
    move-result p0

    .line 70
    add-int/2addr p0, p1

    .line 71
    sget-object p1, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 72
    .line 73
    move-object/from16 p2, p17

    .line 74
    .line 75
    invoke-static {p1, p2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 76
    .line 77
    .line 78
    move-result p1

    .line 79
    add-int/2addr p1, p0

    .line 80
    return p1
.end method

.method public static create(Lio/opentelemetry/sdk/metrics/data/HistogramPointData;)Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;
    .locals 20

    .line 1
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/metrics/data/PointData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;->createForAttributes(Lio/opentelemetry/api/common/Attributes;)[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 6
    .line 7
    .line 8
    move-result-object v19

    .line 9
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/metrics/data/HistogramPointData;->getExemplars()Ljava/util/List;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;->createRepeated(Ljava/util/List;)[Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;

    .line 14
    .line 15
    .line 16
    move-result-object v18

    .line 17
    new-instance v1, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;

    .line 18
    .line 19
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/metrics/data/PointData;->getStartEpochNanos()J

    .line 20
    .line 21
    .line 22
    move-result-wide v2

    .line 23
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/metrics/data/PointData;->getEpochNanos()J

    .line 24
    .line 25
    .line 26
    move-result-wide v4

    .line 27
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/metrics/data/HistogramPointData;->getCount()J

    .line 28
    .line 29
    .line 30
    move-result-wide v6

    .line 31
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/metrics/data/HistogramPointData;->getSum()D

    .line 32
    .line 33
    .line 34
    move-result-wide v8

    .line 35
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/metrics/data/HistogramPointData;->hasMin()Z

    .line 36
    .line 37
    .line 38
    move-result v10

    .line 39
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/metrics/data/HistogramPointData;->getMin()D

    .line 40
    .line 41
    .line 42
    move-result-wide v11

    .line 43
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/metrics/data/HistogramPointData;->hasMax()Z

    .line 44
    .line 45
    .line 46
    move-result v13

    .line 47
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/metrics/data/HistogramPointData;->getMax()D

    .line 48
    .line 49
    .line 50
    move-result-wide v14

    .line 51
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/metrics/data/HistogramPointData;->getCounts()Ljava/util/List;

    .line 52
    .line 53
    .line 54
    move-result-object v16

    .line 55
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/metrics/data/HistogramPointData;->getBoundaries()Ljava/util/List;

    .line 56
    .line 57
    .line 58
    move-result-object v17

    .line 59
    invoke-direct/range {v1 .. v19}, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;-><init>(JJJDZDZDLjava/util/List;Ljava/util/List;[Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)V

    .line 60
    .line 61
    .line 62
    return-object v1
.end method

.method public static createRepeated(Ljava/util/Collection;)[Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Lio/opentelemetry/sdk/metrics/data/HistogramPointData;",
            ">;)[",
            "Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;"
        }
    .end annotation

    .line 1
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    new-array v0, v0, [Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;

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
    check-cast v2, Lio/opentelemetry/sdk/metrics/data/HistogramPointData;

    .line 23
    .line 24
    add-int/lit8 v3, v1, 0x1

    .line 25
    .line 26
    invoke-static {v2}, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->create(Lio/opentelemetry/sdk/metrics/data/HistogramPointData;)Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;

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
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->START_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->startTimeUnixNano:J

    .line 4
    .line 5
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 6
    .line 7
    .line 8
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 9
    .line 10
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->timeUnixNano:J

    .line 11
    .line 12
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 13
    .line 14
    .line 15
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 16
    .line 17
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->count:J

    .line 18
    .line 19
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 20
    .line 21
    .line 22
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->SUM:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 23
    .line 24
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->sum:D

    .line 25
    .line 26
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeDoubleOptional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)V

    .line 27
    .line 28
    .line 29
    iget-boolean v0, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->hasMin:Z

    .line 30
    .line 31
    if-eqz v0, :cond_0

    .line 32
    .line 33
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->MIN:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 34
    .line 35
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->min:D

    .line 36
    .line 37
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeDoubleOptional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)V

    .line 38
    .line 39
    .line 40
    :cond_0
    iget-boolean v0, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->hasMax:Z

    .line 41
    .line 42
    if-eqz v0, :cond_1

    .line 43
    .line 44
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->MAX:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 45
    .line 46
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->max:D

    .line 47
    .line 48
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeDoubleOptional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)V

    .line 49
    .line 50
    .line 51
    :cond_1
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->BUCKET_COUNTS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 52
    .line 53
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->bucketCounts:Ljava/util/List;

    .line 54
    .line 55
    invoke-static {v1}, Lio/opentelemetry/sdk/internal/PrimitiveLongList;->toArray(Ljava/util/List;)[J

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[J)V

    .line 60
    .line 61
    .line 62
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->EXPLICIT_BOUNDS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 63
    .line 64
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->explicitBounds:Ljava/util/List;

    .line 65
    .line 66
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedDouble(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;)V

    .line 67
    .line 68
    .line 69
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->EXEMPLARS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 70
    .line 71
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->exemplars:[Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;

    .line 72
    .line 73
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 74
    .line 75
    .line 76
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/HistogramDataPoint;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 77
    .line 78
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->attributes:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 79
    .line 80
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 81
    .line 82
    .line 83
    return-void
.end method
