.class final Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final EMPTY_BYTES:[B


# instance fields
.field private final attributeMarshalers:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

.field private final droppedAttributesCount:I

.field private final droppedEventsCount:I

.field private final droppedLinksCount:I

.field private final endEpochNanos:J

.field private final flags:Lio/opentelemetry/api/trace/TraceFlags;

.field private final isParentContextRemote:Z

.field private final nameUtf8:[B

.field private final parentSpanId:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final spanEventMarshalers:[Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;

.field private final spanId:Ljava/lang/String;

.field private final spanKind:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

.field private final spanLinkMarshalers:[Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;

.field private final spanStatusMarshaler:Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatusMarshaler;

.field private final startEpochNanos:J

.field private final traceId:Ljava/lang/String;

.field private final traceStateUtf8:[B


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [B

    .line 3
    .line 4
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->EMPTY_BYTES:[B

    .line 5
    .line 6
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;Ljava/lang/String;[BLjava/lang/String;[BLio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;JJ[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;I[Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;I[Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;ILio/opentelemetry/exporter/internal/otlp/traces/SpanStatusMarshaler;Lio/opentelemetry/api/trace/TraceFlags;Z)V
    .locals 1
    .param p4    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    invoke-static/range {p1 .. p19}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->calculateSize(Ljava/lang/String;Ljava/lang/String;[BLjava/lang/String;[BLio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;JJ[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;I[Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;I[Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;ILio/opentelemetry/exporter/internal/otlp/traces/SpanStatusMarshaler;Lio/opentelemetry/api/trace/TraceFlags;Z)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->traceId:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p2, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->spanId:Ljava/lang/String;

    .line 11
    .line 12
    iput-object p3, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->traceStateUtf8:[B

    .line 13
    .line 14
    iput-object p4, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->parentSpanId:Ljava/lang/String;

    .line 15
    .line 16
    iput-object p5, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->nameUtf8:[B

    .line 17
    .line 18
    iput-object p6, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->spanKind:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 19
    .line 20
    iput-wide p7, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->startEpochNanos:J

    .line 21
    .line 22
    iput-wide p9, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->endEpochNanos:J

    .line 23
    .line 24
    iput-object p11, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->attributeMarshalers:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 25
    .line 26
    iput p12, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->droppedAttributesCount:I

    .line 27
    .line 28
    iput-object p13, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->spanEventMarshalers:[Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;

    .line 29
    .line 30
    iput p14, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->droppedEventsCount:I

    .line 31
    .line 32
    move-object/from16 p1, p15

    .line 33
    .line 34
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->spanLinkMarshalers:[Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;

    .line 35
    .line 36
    move/from16 p1, p16

    .line 37
    .line 38
    iput p1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->droppedLinksCount:I

    .line 39
    .line 40
    move-object/from16 p1, p17

    .line 41
    .line 42
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->spanStatusMarshaler:Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatusMarshaler;

    .line 43
    .line 44
    move-object/from16 p1, p18

    .line 45
    .line 46
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->flags:Lio/opentelemetry/api/trace/TraceFlags;

    .line 47
    .line 48
    move/from16 p1, p19

    .line 49
    .line 50
    iput-boolean p1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->isParentContextRemote:Z

    .line 51
    .line 52
    return-void
.end method

.method private static calculateSize(Ljava/lang/String;Ljava/lang/String;[BLjava/lang/String;[BLio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;JJ[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;I[Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;I[Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;ILio/opentelemetry/exporter/internal/otlp/traces/SpanStatusMarshaler;Lio/opentelemetry/api/trace/TraceFlags;Z)I
    .locals 1
    .param p3    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->TRACE_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    invoke-static {v0, p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeTraceId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->SPAN_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 8
    .line 9
    invoke-static {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeSpanId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    add-int/2addr p1, p0

    .line 14
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span;->TRACE_STATE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 15
    .line 16
    invoke-static {p0, p2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    add-int/2addr p0, p1

    .line 21
    sget-object p1, Lio/opentelemetry/proto/trace/v1/internal/Span;->PARENT_SPAN_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 22
    .line 23
    invoke-static {p1, p3}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeSpanId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)I

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    add-int/2addr p1, p0

    .line 28
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span;->NAME:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 29
    .line 30
    invoke-static {p0, p4}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    add-int/2addr p0, p1

    .line 35
    sget-object p1, Lio/opentelemetry/proto/trace/v1/internal/Span;->KIND:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 36
    .line 37
    invoke-static {p1, p5}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeEnum(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;)I

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    add-int/2addr p1, p0

    .line 42
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span;->START_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 43
    .line 44
    invoke-static {p0, p6, p7}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    add-int/2addr p0, p1

    .line 49
    sget-object p1, Lio/opentelemetry/proto/trace/v1/internal/Span;->END_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 50
    .line 51
    invoke-static {p1, p8, p9}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    .line 52
    .line 53
    .line 54
    move-result p1

    .line 55
    add-int/2addr p1, p0

    .line 56
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 57
    .line 58
    invoke-static {p0, p10}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 59
    .line 60
    .line 61
    move-result p0

    .line 62
    add-int/2addr p0, p1

    .line 63
    sget-object p1, Lio/opentelemetry/proto/trace/v1/internal/Span;->DROPPED_ATTRIBUTES_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 64
    .line 65
    invoke-static {p1, p11}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeUInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    .line 66
    .line 67
    .line 68
    move-result p1

    .line 69
    add-int/2addr p1, p0

    .line 70
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span;->EVENTS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 71
    .line 72
    invoke-static {p0, p12}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 73
    .line 74
    .line 75
    move-result p0

    .line 76
    add-int/2addr p0, p1

    .line 77
    sget-object p1, Lio/opentelemetry/proto/trace/v1/internal/Span;->DROPPED_EVENTS_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 78
    .line 79
    invoke-static {p1, p13}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeUInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    .line 80
    .line 81
    .line 82
    move-result p1

    .line 83
    add-int/2addr p1, p0

    .line 84
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span;->LINKS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 85
    .line 86
    invoke-static {p0, p14}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 87
    .line 88
    .line 89
    move-result p0

    .line 90
    add-int/2addr p0, p1

    .line 91
    sget-object p1, Lio/opentelemetry/proto/trace/v1/internal/Span;->DROPPED_LINKS_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 92
    .line 93
    move/from16 p2, p15

    .line 94
    .line 95
    invoke-static {p1, p2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeUInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    .line 96
    .line 97
    .line 98
    move-result p1

    .line 99
    add-int/2addr p1, p0

    .line 100
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span;->STATUS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 101
    .line 102
    move-object/from16 p2, p16

    .line 103
    .line 104
    invoke-static {p0, p2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 105
    .line 106
    .line 107
    move-result p0

    .line 108
    add-int/2addr p0, p1

    .line 109
    sget-object p1, Lio/opentelemetry/proto/trace/v1/internal/Span;->FLAGS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 110
    .line 111
    invoke-static/range {p17 .. p18}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanFlags;->withParentIsRemoteFlags(Lio/opentelemetry/api/trace/TraceFlags;Z)I

    .line 112
    .line 113
    .line 114
    move-result p2

    .line 115
    invoke-static {p1, p2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    .line 116
    .line 117
    .line 118
    move-result p1

    .line 119
    add-int/2addr p1, p0

    .line 120
    return p1
.end method

.method public static create(Lio/opentelemetry/sdk/trace/data/SpanData;)Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;
    .locals 21

    .line 1
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;->createForAttributes(Lio/opentelemetry/api/common/Attributes;)[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 6
    .line 7
    .line 8
    move-result-object v12

    .line 9
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getEvents()Ljava/util/List;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;->createRepeated(Ljava/util/List;)[Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;

    .line 14
    .line 15
    .line 16
    move-result-object v14

    .line 17
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getLinks()Ljava/util/List;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;->createRepeated(Ljava/util/List;)[Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;

    .line 22
    .line 23
    .line 24
    move-result-object v16

    .line 25
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getParentSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    invoke-interface {v0}, Lio/opentelemetry/api/trace/SpanContext;->isValid()Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-eqz v0, :cond_0

    .line 34
    .line 35
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getParentSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    invoke-interface {v0}, Lio/opentelemetry/api/trace/SpanContext;->getSpanId()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    :goto_0
    move-object v5, v0

    .line 44
    goto :goto_1

    .line 45
    :cond_0
    const/4 v0, 0x0

    .line 46
    goto :goto_0

    .line 47
    :goto_1
    invoke-static/range {p0 .. p0}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->encodeSpanTraceState(Lio/opentelemetry/sdk/trace/data/SpanData;)[B

    .line 48
    .line 49
    .line 50
    move-result-object v4

    .line 51
    new-instance v1, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;

    .line 52
    .line 53
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    invoke-interface {v0}, Lio/opentelemetry/api/trace/SpanContext;->getTraceId()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    invoke-interface {v0}, Lio/opentelemetry/api/trace/SpanContext;->getSpanId()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v3

    .line 69
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getName()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->toBytes(Ljava/lang/String;)[B

    .line 74
    .line 75
    .line 76
    move-result-object v6

    .line 77
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getKind()Lio/opentelemetry/api/trace/SpanKind;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->toProtoSpanKind(Lio/opentelemetry/api/trace/SpanKind;)Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 82
    .line 83
    .line 84
    move-result-object v7

    .line 85
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getStartEpochNanos()J

    .line 86
    .line 87
    .line 88
    move-result-wide v8

    .line 89
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getEndEpochNanos()J

    .line 90
    .line 91
    .line 92
    move-result-wide v10

    .line 93
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getTotalAttributeCount()I

    .line 94
    .line 95
    .line 96
    move-result v0

    .line 97
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 98
    .line 99
    .line 100
    move-result-object v13

    .line 101
    invoke-interface {v13}, Lio/opentelemetry/api/common/Attributes;->size()I

    .line 102
    .line 103
    .line 104
    move-result v13

    .line 105
    sub-int v13, v0, v13

    .line 106
    .line 107
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getTotalRecordedEvents()I

    .line 108
    .line 109
    .line 110
    move-result v0

    .line 111
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getEvents()Ljava/util/List;

    .line 112
    .line 113
    .line 114
    move-result-object v15

    .line 115
    invoke-interface {v15}, Ljava/util/List;->size()I

    .line 116
    .line 117
    .line 118
    move-result v15

    .line 119
    sub-int v15, v0, v15

    .line 120
    .line 121
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getTotalRecordedLinks()I

    .line 122
    .line 123
    .line 124
    move-result v0

    .line 125
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getLinks()Ljava/util/List;

    .line 126
    .line 127
    .line 128
    move-result-object v17

    .line 129
    invoke-interface/range {v17 .. v17}, Ljava/util/List;->size()I

    .line 130
    .line 131
    .line 132
    move-result v17

    .line 133
    sub-int v17, v0, v17

    .line 134
    .line 135
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getStatus()Lio/opentelemetry/sdk/trace/data/StatusData;

    .line 136
    .line 137
    .line 138
    move-result-object v0

    .line 139
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatusMarshaler;->create(Lio/opentelemetry/sdk/trace/data/StatusData;)Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatusMarshaler;

    .line 140
    .line 141
    .line 142
    move-result-object v18

    .line 143
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 144
    .line 145
    .line 146
    move-result-object v0

    .line 147
    invoke-interface {v0}, Lio/opentelemetry/api/trace/SpanContext;->getTraceFlags()Lio/opentelemetry/api/trace/TraceFlags;

    .line 148
    .line 149
    .line 150
    move-result-object v19

    .line 151
    invoke-interface/range {p0 .. p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getParentSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 152
    .line 153
    .line 154
    move-result-object v0

    .line 155
    invoke-interface {v0}, Lio/opentelemetry/api/trace/SpanContext;->isRemote()Z

    .line 156
    .line 157
    .line 158
    move-result v20

    .line 159
    invoke-direct/range {v1 .. v20}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;-><init>(Ljava/lang/String;Ljava/lang/String;[BLjava/lang/String;[BLio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;JJ[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;I[Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;I[Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;ILio/opentelemetry/exporter/internal/otlp/traces/SpanStatusMarshaler;Lio/opentelemetry/api/trace/TraceFlags;Z)V

    .line 160
    .line 161
    .line 162
    return-object v1
.end method

.method public static encodeSpanTraceState(Lio/opentelemetry/sdk/trace/data/SpanData;)[B
    .locals 0

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0}, Lio/opentelemetry/api/trace/SpanContext;->getTraceState()Lio/opentelemetry/api/trace/TraceState;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->encodeTraceState(Lio/opentelemetry/api/trace/TraceState;)[B

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public static encodeTraceState(Lio/opentelemetry/api/trace/TraceState;)[B
    .locals 1

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/api/trace/TraceState;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->EMPTY_BYTES:[B

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    invoke-static {p0}, Lio/opentelemetry/api/trace/propagation/internal/W3CTraceContextEncoding;->encodeTraceState(Lio/opentelemetry/api/trace/TraceState;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    sget-object v0, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public static toProtoSpanKind(Lio/opentelemetry/api/trace/SpanKind;)Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler$1;->$SwitchMap$io$opentelemetry$api$trace$SpanKind:[I

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
    const/4 v0, 0x1

    .line 10
    if-eq p0, v0, :cond_4

    .line 11
    .line 12
    const/4 v0, 0x2

    .line 13
    if-eq p0, v0, :cond_3

    .line 14
    .line 15
    const/4 v0, 0x3

    .line 16
    if-eq p0, v0, :cond_2

    .line 17
    .line 18
    const/4 v0, 0x4

    .line 19
    if-eq p0, v0, :cond_1

    .line 20
    .line 21
    const/4 v0, 0x5

    .line 22
    if-eq p0, v0, :cond_0

    .line 23
    .line 24
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span$SpanKind;->SPAN_KIND_UNSPECIFIED:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 25
    .line 26
    return-object p0

    .line 27
    :cond_0
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span$SpanKind;->SPAN_KIND_CONSUMER:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_1
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span$SpanKind;->SPAN_KIND_PRODUCER:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 31
    .line 32
    return-object p0

    .line 33
    :cond_2
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span$SpanKind;->SPAN_KIND_CLIENT:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_3
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span$SpanKind;->SPAN_KIND_SERVER:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 37
    .line 38
    return-object p0

    .line 39
    :cond_4
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span$SpanKind;->SPAN_KIND_INTERNAL:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 40
    .line 41
    return-object p0
.end method


# virtual methods
.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 3

    .line 1
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->TRACE_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->traceId:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeTraceId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->SPAN_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 9
    .line 10
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->spanId:Ljava/lang/String;

    .line 11
    .line 12
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeSpanId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->TRACE_STATE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 16
    .line 17
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->traceStateUtf8:[B

    .line 18
    .line 19
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeString(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)V

    .line 20
    .line 21
    .line 22
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->PARENT_SPAN_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 23
    .line 24
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->parentSpanId:Ljava/lang/String;

    .line 25
    .line 26
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeSpanId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->NAME:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 30
    .line 31
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->nameUtf8:[B

    .line 32
    .line 33
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeString(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)V

    .line 34
    .line 35
    .line 36
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->KIND:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 37
    .line 38
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->spanKind:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 39
    .line 40
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeEnum(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;)V

    .line 41
    .line 42
    .line 43
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->START_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 44
    .line 45
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->startEpochNanos:J

    .line 46
    .line 47
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 48
    .line 49
    .line 50
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->END_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 51
    .line 52
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->endEpochNanos:J

    .line 53
    .line 54
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 55
    .line 56
    .line 57
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 58
    .line 59
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->attributeMarshalers:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 60
    .line 61
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 62
    .line 63
    .line 64
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->DROPPED_ATTRIBUTES_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 65
    .line 66
    iget v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->droppedAttributesCount:I

    .line 67
    .line 68
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeUInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V

    .line 69
    .line 70
    .line 71
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->EVENTS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 72
    .line 73
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->spanEventMarshalers:[Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventMarshaler;

    .line 74
    .line 75
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 76
    .line 77
    .line 78
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->DROPPED_EVENTS_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 79
    .line 80
    iget v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->droppedEventsCount:I

    .line 81
    .line 82
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeUInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V

    .line 83
    .line 84
    .line 85
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->LINKS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 86
    .line 87
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->spanLinkMarshalers:[Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;

    .line 88
    .line 89
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 90
    .line 91
    .line 92
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->DROPPED_LINKS_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 93
    .line 94
    iget v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->droppedLinksCount:I

    .line 95
    .line 96
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeUInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V

    .line 97
    .line 98
    .line 99
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->STATUS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 100
    .line 101
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->spanStatusMarshaler:Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatusMarshaler;

    .line 102
    .line 103
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 104
    .line 105
    .line 106
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->FLAGS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 107
    .line 108
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->flags:Lio/opentelemetry/api/trace/TraceFlags;

    .line 109
    .line 110
    iget-boolean p0, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->isParentContextRemote:Z

    .line 111
    .line 112
    invoke-static {v1, p0}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanFlags;->withParentIsRemoteFlags(Lio/opentelemetry/api/trace/TraceFlags;Z)I

    .line 113
    .line 114
    .line 115
    move-result p0

    .line 116
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V

    .line 117
    .line 118
    .line 119
    return-void
.end method
