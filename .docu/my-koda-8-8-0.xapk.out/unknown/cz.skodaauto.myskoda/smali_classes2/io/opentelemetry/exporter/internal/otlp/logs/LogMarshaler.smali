.class final Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final INVALID_SPAN_ID:Ljava/lang/String;

.field private static final INVALID_TRACE_ID:Ljava/lang/String;


# instance fields
.field private final anyValueMarshaler:Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final attributeMarshalers:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

.field private final droppedAttributesCount:I

.field private final eventName:[B

.field private final observedTimeUnixNano:J

.field private final severityNumber:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

.field private final severityText:[B

.field private final spanId:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final timeUnixNano:J

.field private final traceFlags:Lio/opentelemetry/api/trace/TraceFlags;

.field private final traceId:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/api/trace/TraceId;->getInvalid()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->INVALID_TRACE_ID:Ljava/lang/String;

    .line 6
    .line 7
    invoke-static {}, Lio/opentelemetry/api/trace/SpanId;->getInvalid()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->INVALID_SPAN_ID:Ljava/lang/String;

    .line 12
    .line 13
    return-void
.end method

.method private constructor <init>(JJLio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;[BLio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;ILio/opentelemetry/api/trace/TraceFlags;Ljava/lang/String;Ljava/lang/String;[B)V
    .locals 1
    .param p7    # Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p11    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p12    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    invoke-static/range {p1 .. p13}, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->calculateSize(JJLio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;[BLio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;ILio/opentelemetry/api/trace/TraceFlags;Ljava/lang/String;Ljava/lang/String;[B)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iput-wide p1, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->timeUnixNano:J

    .line 9
    .line 10
    iput-wide p3, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->observedTimeUnixNano:J

    .line 11
    .line 12
    iput-object p11, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->traceId:Ljava/lang/String;

    .line 13
    .line 14
    iput-object p12, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->spanId:Ljava/lang/String;

    .line 15
    .line 16
    iput-object p10, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->traceFlags:Lio/opentelemetry/api/trace/TraceFlags;

    .line 17
    .line 18
    iput-object p5, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->severityNumber:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 19
    .line 20
    iput-object p6, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->severityText:[B

    .line 21
    .line 22
    iput-object p7, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->anyValueMarshaler:Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;

    .line 23
    .line 24
    iput-object p8, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->attributeMarshalers:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 25
    .line 26
    iput p9, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->droppedAttributesCount:I

    .line 27
    .line 28
    iput-object p13, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->eventName:[B

    .line 29
    .line 30
    return-void
.end method

.method private static calculateSize(JJLio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;[BLio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;ILio/opentelemetry/api/trace/TraceFlags;Ljava/lang/String;Ljava/lang/String;[B)I
    .locals 1
    .param p6    # Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p10    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p11    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    sget-object v0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    invoke-static {v0, p0, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    sget-object p1, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->OBSERVED_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

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
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->SEVERITY_NUMBER:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 15
    .line 16
    invoke-static {p0, p4}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeEnum(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    add-int/2addr p0, p1

    .line 21
    sget-object p1, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->SEVERITY_TEXT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 22
    .line 23
    invoke-static {p1, p5}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)I

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    add-int/2addr p1, p0

    .line 28
    if-eqz p6, :cond_0

    .line 29
    .line 30
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->BODY:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 31
    .line 32
    invoke-static {p0, p6}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    add-int/2addr p1, p0

    .line 37
    :cond_0
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 38
    .line 39
    invoke-static {p0, p7}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    add-int/2addr p0, p1

    .line 44
    sget-object p1, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->DROPPED_ATTRIBUTES_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 45
    .line 46
    invoke-static {p1, p8}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeUInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    .line 47
    .line 48
    .line 49
    move-result p1

    .line 50
    add-int/2addr p1, p0

    .line 51
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->FLAGS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 52
    .line 53
    invoke-interface {p9}, Lio/opentelemetry/api/trace/TraceFlags;->asByte()B

    .line 54
    .line 55
    .line 56
    move-result p2

    .line 57
    invoke-static {p0, p2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeByteAsFixed32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;B)I

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    add-int/2addr p0, p1

    .line 62
    sget-object p1, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->TRACE_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 63
    .line 64
    invoke-static {p1, p10}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeTraceId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)I

    .line 65
    .line 66
    .line 67
    move-result p1

    .line 68
    add-int/2addr p1, p0

    .line 69
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->SPAN_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 70
    .line 71
    invoke-static {p0, p11}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeSpanId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)I

    .line 72
    .line 73
    .line 74
    move-result p0

    .line 75
    add-int/2addr p0, p1

    .line 76
    sget-object p1, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->EVENT_NAME:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 77
    .line 78
    invoke-static {p1, p12}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)I

    .line 79
    .line 80
    .line 81
    move-result p1

    .line 82
    add-int/2addr p1, p0

    .line 83
    return p1
.end method

.method public static create(Lio/opentelemetry/sdk/logs/data/LogRecordData;)Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;
    .locals 16

    .line 1
    invoke-static/range {p0 .. p0}, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;->isExtendedLogRecordData(Lio/opentelemetry/sdk/logs/data/LogRecordData;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-static/range {p0 .. p0}, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;->createdExtendedAttributesMarhsalers(Lio/opentelemetry/sdk/logs/data/LogRecordData;)[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    :goto_0
    move-object v9, v0

    .line 12
    goto :goto_1

    .line 13
    :cond_0
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;->createForAttributes(Lio/opentelemetry/api/common/Attributes;)[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    goto :goto_0

    .line 22
    :goto_1
    invoke-static/range {p0 .. p0}, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;->isExtendedLogRecordData(Lio/opentelemetry/sdk/logs/data/LogRecordData;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    invoke-static/range {p0 .. p0}, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;->extendedAttributesSize(Lio/opentelemetry/sdk/logs/data/LogRecordData;)I

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    goto :goto_2

    .line 33
    :cond_1
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    invoke-interface {v0}, Lio/opentelemetry/api/common/Attributes;->size()I

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    :goto_2
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getBodyValue()Lio/opentelemetry/api/common/Value;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    const/4 v2, 0x0

    .line 46
    if-nez v1, :cond_2

    .line 47
    .line 48
    move-object v8, v2

    .line 49
    goto :goto_3

    .line 50
    :cond_2
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getBodyValue()Lio/opentelemetry/api/common/Value;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    invoke-static {v1}, Lio/opentelemetry/exporter/internal/otlp/AnyValueMarshaler;->create(Lio/opentelemetry/api/common/Value;)Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    move-object v8, v1

    .line 59
    :goto_3
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    move-object v3, v1

    .line 64
    new-instance v1, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;

    .line 65
    .line 66
    move-object v5, v2

    .line 67
    move-object v4, v3

    .line 68
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getTimestampEpochNanos()J

    .line 69
    .line 70
    .line 71
    move-result-wide v2

    .line 72
    move-object v6, v4

    .line 73
    move-object v7, v5

    .line 74
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getObservedTimestampEpochNanos()J

    .line 75
    .line 76
    .line 77
    move-result-wide v4

    .line 78
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getSeverity()Lio/opentelemetry/api/logs/Severity;

    .line 79
    .line 80
    .line 81
    move-result-object v10

    .line 82
    invoke-static {v10}, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->toProtoSeverityNumber(Lio/opentelemetry/api/logs/Severity;)Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 83
    .line 84
    .line 85
    move-result-object v10

    .line 86
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getSeverityText()Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object v11

    .line 90
    invoke-static {v11}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->toBytes(Ljava/lang/String;)[B

    .line 91
    .line 92
    .line 93
    move-result-object v11

    .line 94
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getTotalAttributeCount()I

    .line 95
    .line 96
    .line 97
    move-result v12

    .line 98
    sub-int/2addr v12, v0

    .line 99
    move-object v0, v7

    .line 100
    move-object v7, v11

    .line 101
    invoke-interface {v6}, Lio/opentelemetry/api/trace/SpanContext;->getTraceFlags()Lio/opentelemetry/api/trace/TraceFlags;

    .line 102
    .line 103
    .line 104
    move-result-object v11

    .line 105
    invoke-interface {v6}, Lio/opentelemetry/api/trace/SpanContext;->getTraceId()Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object v13

    .line 109
    sget-object v14, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->INVALID_TRACE_ID:Ljava/lang/String;

    .line 110
    .line 111
    invoke-virtual {v13, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result v13

    .line 115
    if-eqz v13, :cond_3

    .line 116
    .line 117
    move-object v13, v0

    .line 118
    goto :goto_4

    .line 119
    :cond_3
    invoke-interface {v6}, Lio/opentelemetry/api/trace/SpanContext;->getTraceId()Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object v13

    .line 123
    :goto_4
    invoke-interface {v6}, Lio/opentelemetry/api/trace/SpanContext;->getSpanId()Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object v14

    .line 127
    sget-object v15, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->INVALID_SPAN_ID:Ljava/lang/String;

    .line 128
    .line 129
    invoke-virtual {v14, v15}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    move-result v14

    .line 133
    if-eqz v14, :cond_4

    .line 134
    .line 135
    goto :goto_5

    .line 136
    :cond_4
    invoke-interface {v6}, Lio/opentelemetry/api/trace/SpanContext;->getSpanId()Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object v0

    .line 140
    :goto_5
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getEventName()Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object v6

    .line 144
    invoke-static {v6}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->toBytes(Ljava/lang/String;)[B

    .line 145
    .line 146
    .line 147
    move-result-object v14

    .line 148
    move-object v6, v10

    .line 149
    move v10, v12

    .line 150
    move-object v12, v13

    .line 151
    move-object v13, v0

    .line 152
    invoke-direct/range {v1 .. v14}, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;-><init>(JJLio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;[BLio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;ILio/opentelemetry/api/trace/TraceFlags;Ljava/lang/String;Ljava/lang/String;[B)V

    .line 153
    .line 154
    .line 155
    return-object v1
.end method

.method public static toProtoSeverityNumber(Lio/opentelemetry/api/logs/Severity;)Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler$1;->$SwitchMap$io$opentelemetry$api$logs$Severity:[I

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    aget p0, v0, p0

    .line 8
    .line 9
    packed-switch p0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_UNSPECIFIED:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_0
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_UNSPECIFIED:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_1
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_FATAL4:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 19
    .line 20
    return-object p0

    .line 21
    :pswitch_2
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_FATAL3:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_3
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_FATAL2:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_4
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_FATAL:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_5
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_ERROR4:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_6
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_ERROR3:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_7
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_ERROR2:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_8
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_ERROR:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 40
    .line 41
    return-object p0

    .line 42
    :pswitch_9
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_WARN4:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 43
    .line 44
    return-object p0

    .line 45
    :pswitch_a
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_WARN3:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 46
    .line 47
    return-object p0

    .line 48
    :pswitch_b
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_WARN2:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_c
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_WARN:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 52
    .line 53
    return-object p0

    .line 54
    :pswitch_d
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_INFO4:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 55
    .line 56
    return-object p0

    .line 57
    :pswitch_e
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_INFO3:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 58
    .line 59
    return-object p0

    .line 60
    :pswitch_f
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_INFO2:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 61
    .line 62
    return-object p0

    .line 63
    :pswitch_10
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_INFO:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 64
    .line 65
    return-object p0

    .line 66
    :pswitch_11
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_DEBUG4:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 67
    .line 68
    return-object p0

    .line 69
    :pswitch_12
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_DEBUG3:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 70
    .line 71
    return-object p0

    .line 72
    :pswitch_13
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_DEBUG2:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 73
    .line 74
    return-object p0

    .line 75
    :pswitch_14
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_DEBUG:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 76
    .line 77
    return-object p0

    .line 78
    :pswitch_15
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_TRACE4:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 79
    .line 80
    return-object p0

    .line 81
    :pswitch_16
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_TRACE3:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 82
    .line 83
    return-object p0

    .line 84
    :pswitch_17
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_TRACE2:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 85
    .line 86
    return-object p0

    .line 87
    :pswitch_18
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/SeverityNumber;->SEVERITY_NUMBER_TRACE:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 88
    .line 89
    return-object p0

    .line 90
    nop

    .line 91
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 3

    .line 1
    sget-object v0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->timeUnixNano:J

    .line 4
    .line 5
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 6
    .line 7
    .line 8
    sget-object v0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->OBSERVED_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 9
    .line 10
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->observedTimeUnixNano:J

    .line 11
    .line 12
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 13
    .line 14
    .line 15
    sget-object v0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->SEVERITY_NUMBER:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 16
    .line 17
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->severityNumber:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 18
    .line 19
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeEnum(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;)V

    .line 20
    .line 21
    .line 22
    sget-object v0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->SEVERITY_TEXT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 23
    .line 24
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->severityText:[B

    .line 25
    .line 26
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeString(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)V

    .line 27
    .line 28
    .line 29
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->anyValueMarshaler:Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;

    .line 30
    .line 31
    if-eqz v0, :cond_0

    .line 32
    .line 33
    sget-object v1, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->BODY:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 34
    .line 35
    invoke-virtual {p1, v1, v0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 36
    .line 37
    .line 38
    :cond_0
    sget-object v0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 39
    .line 40
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->attributeMarshalers:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 41
    .line 42
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 43
    .line 44
    .line 45
    sget-object v0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->DROPPED_ATTRIBUTES_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 46
    .line 47
    iget v1, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->droppedAttributesCount:I

    .line 48
    .line 49
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeUInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V

    .line 50
    .line 51
    .line 52
    sget-object v0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->FLAGS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 53
    .line 54
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->traceFlags:Lio/opentelemetry/api/trace/TraceFlags;

    .line 55
    .line 56
    invoke-interface {v1}, Lio/opentelemetry/api/trace/TraceFlags;->asByte()B

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeByteAsFixed32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;B)V

    .line 61
    .line 62
    .line 63
    sget-object v0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->TRACE_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 64
    .line 65
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->traceId:Ljava/lang/String;

    .line 66
    .line 67
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeTraceId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    sget-object v0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->SPAN_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 71
    .line 72
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->spanId:Ljava/lang/String;

    .line 73
    .line 74
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeSpanId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    sget-object v0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->EVENT_NAME:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 78
    .line 79
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->eventName:[B

    .line 80
    .line 81
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeString(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)V

    .line 82
    .line 83
    .line 84
    return-void
.end method
