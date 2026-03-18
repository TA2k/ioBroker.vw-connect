.class public Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final attributes:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

.field private final count:J

.field private final exemplars:[Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;

.field private final hasMax:Z

.field private final hasMin:Z

.field private final max:D

.field private final min:D

.field private final negativeBuckets:Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;

.field private final positiveBuckets:Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;

.field private final scale:I

.field private final startTimeUnixNano:J

.field private final sum:D

.field private final timeUnixNano:J

.field private final zeroCount:J


# direct methods
.method private constructor <init>(JJIJDZDZDJLio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;[Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;)V
    .locals 22

    .line 1
    move-wide/from16 v1, p1

    .line 2
    .line 3
    move-wide/from16 v3, p3

    .line 4
    .line 5
    move/from16 v5, p5

    .line 6
    .line 7
    move-wide/from16 v6, p6

    .line 8
    .line 9
    move-wide/from16 v8, p8

    .line 10
    .line 11
    move/from16 v10, p10

    .line 12
    .line 13
    move-wide/from16 v11, p11

    .line 14
    .line 15
    move/from16 v13, p13

    .line 16
    .line 17
    move-wide/from16 v14, p14

    .line 18
    .line 19
    move-wide/from16 v16, p16

    .line 20
    .line 21
    move-object/from16 v18, p18

    .line 22
    .line 23
    move-object/from16 v19, p19

    .line 24
    .line 25
    move-object/from16 v21, p20

    .line 26
    .line 27
    move-object/from16 v20, p21

    .line 28
    .line 29
    invoke-static/range {v1 .. v21}, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->calculateSize(JJIJDZDZDJLio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;[Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)I

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    move-object/from16 v1, p0

    .line 34
    .line 35
    invoke-direct {v1, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 36
    .line 37
    .line 38
    move-wide/from16 v2, p1

    .line 39
    .line 40
    iput-wide v2, v1, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->startTimeUnixNano:J

    .line 41
    .line 42
    move-wide/from16 v3, p3

    .line 43
    .line 44
    iput-wide v3, v1, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->timeUnixNano:J

    .line 45
    .line 46
    iput v5, v1, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->scale:I

    .line 47
    .line 48
    iput-wide v8, v1, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->sum:D

    .line 49
    .line 50
    iput-boolean v10, v1, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->hasMin:Z

    .line 51
    .line 52
    iput-wide v11, v1, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->min:D

    .line 53
    .line 54
    iput-boolean v13, v1, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->hasMax:Z

    .line 55
    .line 56
    iput-wide v14, v1, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->max:D

    .line 57
    .line 58
    iput-wide v6, v1, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->count:J

    .line 59
    .line 60
    move-wide/from16 v2, p16

    .line 61
    .line 62
    iput-wide v2, v1, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->zeroCount:J

    .line 63
    .line 64
    move-object/from16 v0, p18

    .line 65
    .line 66
    iput-object v0, v1, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->positiveBuckets:Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;

    .line 67
    .line 68
    move-object/from16 v0, p19

    .line 69
    .line 70
    iput-object v0, v1, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->negativeBuckets:Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;

    .line 71
    .line 72
    move-object/from16 v0, p20

    .line 73
    .line 74
    iput-object v0, v1, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->attributes:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 75
    .line 76
    move-object/from16 v0, p21

    .line 77
    .line 78
    iput-object v0, v1, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->exemplars:[Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;

    .line 79
    .line 80
    return-void
.end method

.method private static calculateSize(JJIJDZDZDJLio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;[Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)I
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->START_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    invoke-static {v0, p0, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    sget-object p1, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

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
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->SCALE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 15
    .line 16
    invoke-static {p0, p4}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeSInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    add-int/2addr p0, p1

    .line 21
    sget-object p1, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 22
    .line 23
    invoke-static {p1, p5, p6}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    add-int/2addr p1, p0

    .line 28
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->SUM:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 29
    .line 30
    invoke-static {p0, p7, p8}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeDouble(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    add-int/2addr p0, p1

    .line 35
    if-eqz p9, :cond_0

    .line 36
    .line 37
    sget-object p1, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->MIN:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 38
    .line 39
    invoke-static {p1, p10, p11}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeDoubleOptional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)I

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    add-int/2addr p0, p1

    .line 44
    :cond_0
    if-eqz p12, :cond_1

    .line 45
    .line 46
    sget-object p1, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->MAX:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 47
    .line 48
    invoke-static {p1, p13, p14}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeDoubleOptional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)I

    .line 49
    .line 50
    .line 51
    move-result p1

    .line 52
    add-int/2addr p0, p1

    .line 53
    :cond_1
    sget-object p1, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->ZERO_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 54
    .line 55
    move-wide/from16 p2, p15

    .line 56
    .line 57
    invoke-static {p1, p2, p3}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    .line 58
    .line 59
    .line 60
    move-result p1

    .line 61
    add-int/2addr p1, p0

    .line 62
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->POSITIVE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 63
    .line 64
    move-object/from16 p2, p17

    .line 65
    .line 66
    invoke-static {p0, p2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 67
    .line 68
    .line 69
    move-result p0

    .line 70
    add-int/2addr p0, p1

    .line 71
    sget-object p1, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->NEGATIVE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 72
    .line 73
    move-object/from16 p2, p18

    .line 74
    .line 75
    invoke-static {p1, p2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 76
    .line 77
    .line 78
    move-result p1

    .line 79
    add-int/2addr p1, p0

    .line 80
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->EXEMPLARS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 81
    .line 82
    move-object/from16 p2, p19

    .line 83
    .line 84
    invoke-static {p0, p2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 85
    .line 86
    .line 87
    move-result p0

    .line 88
    add-int/2addr p0, p1

    .line 89
    sget-object p1, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 90
    .line 91
    move-object/from16 p2, p20

    .line 92
    .line 93
    invoke-static {p1, p2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 94
    .line 95
    .line 96
    move-result p1

    .line 97
    add-int/2addr p1, p0

    .line 98
    return p1
.end method

.method public static create(Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;)Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;
    .locals 23

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
    move-result-object v21

    .line 9
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getExemplars()Ljava/util/List;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;->createRepeated(Ljava/util/List;)[Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;

    .line 14
    .line 15
    .line 16
    move-result-object v22

    .line 17
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getPositiveBuckets()Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;->create(Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;)Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;

    .line 22
    .line 23
    .line 24
    move-result-object v19

    .line 25
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getNegativeBuckets()Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;->create(Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;)Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;

    .line 30
    .line 31
    .line 32
    move-result-object v20

    .line 33
    new-instance v1, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;

    .line 34
    .line 35
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/metrics/data/PointData;->getStartEpochNanos()J

    .line 36
    .line 37
    .line 38
    move-result-wide v2

    .line 39
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/metrics/data/PointData;->getEpochNanos()J

    .line 40
    .line 41
    .line 42
    move-result-wide v4

    .line 43
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getScale()I

    .line 44
    .line 45
    .line 46
    move-result v6

    .line 47
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getCount()J

    .line 48
    .line 49
    .line 50
    move-result-wide v7

    .line 51
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getSum()D

    .line 52
    .line 53
    .line 54
    move-result-wide v9

    .line 55
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->hasMin()Z

    .line 56
    .line 57
    .line 58
    move-result v11

    .line 59
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getMin()D

    .line 60
    .line 61
    .line 62
    move-result-wide v12

    .line 63
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->hasMax()Z

    .line 64
    .line 65
    .line 66
    move-result v14

    .line 67
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getMax()D

    .line 68
    .line 69
    .line 70
    move-result-wide v15

    .line 71
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getZeroCount()J

    .line 72
    .line 73
    .line 74
    move-result-wide v17

    .line 75
    invoke-direct/range {v1 .. v22}, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;-><init>(JJIJDZDZDJLio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;[Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;)V

    .line 76
    .line 77
    .line 78
    return-object v1
.end method

.method public static createRepeated(Ljava/util/Collection;)[Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;",
            ">;)[",
            "Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;"
        }
    .end annotation

    .line 1
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    new-array v0, v0, [Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;

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
    check-cast v2, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;

    .line 23
    .line 24
    add-int/lit8 v3, v1, 0x1

    .line 25
    .line 26
    invoke-static {v2}, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->create(Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;)Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;

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
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->START_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->startTimeUnixNano:J

    .line 4
    .line 5
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 6
    .line 7
    .line 8
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 9
    .line 10
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->timeUnixNano:J

    .line 11
    .line 12
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 13
    .line 14
    .line 15
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 16
    .line 17
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->count:J

    .line 18
    .line 19
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 20
    .line 21
    .line 22
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->SUM:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 23
    .line 24
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->sum:D

    .line 25
    .line 26
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeDouble(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)V

    .line 27
    .line 28
    .line 29
    iget-boolean v0, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->hasMin:Z

    .line 30
    .line 31
    if-eqz v0, :cond_0

    .line 32
    .line 33
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->MIN:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 34
    .line 35
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->min:D

    .line 36
    .line 37
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeDoubleOptional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)V

    .line 38
    .line 39
    .line 40
    :cond_0
    iget-boolean v0, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->hasMax:Z

    .line 41
    .line 42
    if-eqz v0, :cond_1

    .line 43
    .line 44
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->MAX:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 45
    .line 46
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->max:D

    .line 47
    .line 48
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeDoubleOptional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)V

    .line 49
    .line 50
    .line 51
    :cond_1
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->SCALE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 52
    .line 53
    iget v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->scale:I

    .line 54
    .line 55
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeSInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V

    .line 56
    .line 57
    .line 58
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->ZERO_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 59
    .line 60
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->zeroCount:J

    .line 61
    .line 62
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 63
    .line 64
    .line 65
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->POSITIVE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 66
    .line 67
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->positiveBuckets:Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;

    .line 68
    .line 69
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 70
    .line 71
    .line 72
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->NEGATIVE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 73
    .line 74
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->negativeBuckets:Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramBucketsMarshaler;

    .line 75
    .line 76
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 77
    .line 78
    .line 79
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->EXEMPLARS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 80
    .line 81
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->exemplars:[Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;

    .line 82
    .line 83
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 84
    .line 85
    .line 86
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/ExponentialHistogramDataPoint;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 87
    .line 88
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramDataPointMarshaler;->attributes:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 89
    .line 90
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 91
    .line 92
    .line 93
    return-void
.end method
