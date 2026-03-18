.class final Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final EMPTY:[Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;


# instance fields
.field private final attributeMarshalers:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

.field private final droppedAttributesCount:I

.field private final isLinkContextRemote:Z

.field private final spanId:Ljava/lang/String;

.field private final traceFlags:Lio/opentelemetry/api/trace/TraceFlags;

.field private final traceId:Ljava/lang/String;

.field private final traceStateUtf8:[B


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;

    .line 3
    .line 4
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;->EMPTY:[Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;

    .line 5
    .line 6
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/trace/TraceFlags;[B[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;IZ)V
    .locals 1

    .line 1
    invoke-static/range {p1 .. p7}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;->calculateSize(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/trace/TraceFlags;[B[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;IZ)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;->traceId:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p2, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;->spanId:Ljava/lang/String;

    .line 11
    .line 12
    iput-object p3, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;->traceFlags:Lio/opentelemetry/api/trace/TraceFlags;

    .line 13
    .line 14
    iput-object p4, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;->traceStateUtf8:[B

    .line 15
    .line 16
    iput-object p5, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;->attributeMarshalers:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 17
    .line 18
    iput p6, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;->droppedAttributesCount:I

    .line 19
    .line 20
    iput-boolean p7, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;->isLinkContextRemote:Z

    .line 21
    .line 22
    return-void
.end method

.method private static calculateSize(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/trace/TraceFlags;[B[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;IZ)I
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$Link;->TRACE_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    invoke-static {v0, p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeTraceId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$Link;->SPAN_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

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
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span$Link;->TRACE_STATE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 15
    .line 16
    invoke-static {p0, p3}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    add-int/2addr p0, p1

    .line 21
    sget-object p1, Lio/opentelemetry/proto/trace/v1/internal/Span$Link;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 22
    .line 23
    invoke-static {p1, p4}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    add-int/2addr p1, p0

    .line 28
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span$Link;->DROPPED_ATTRIBUTES_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 29
    .line 30
    invoke-static {p0, p5}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeUInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    add-int/2addr p0, p1

    .line 35
    sget-object p1, Lio/opentelemetry/proto/trace/v1/internal/Span$Link;->FLAGS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 36
    .line 37
    invoke-static {p2, p6}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanFlags;->withParentIsRemoteFlags(Lio/opentelemetry/api/trace/TraceFlags;Z)I

    .line 38
    .line 39
    .line 40
    move-result p2

    .line 41
    invoke-static {p1, p2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    .line 42
    .line 43
    .line 44
    move-result p1

    .line 45
    add-int/2addr p1, p0

    .line 46
    return p1
.end method

.method public static create(Lio/opentelemetry/sdk/trace/data/LinkData;)Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;
    .locals 8

    .line 1
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;->encodeSpanLinkTraceState(Lio/opentelemetry/sdk/trace/data/LinkData;)[B

    .line 2
    .line 3
    .line 4
    move-result-object v4

    .line 5
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;

    .line 6
    .line 7
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/LinkData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-interface {v1}, Lio/opentelemetry/api/trace/SpanContext;->getTraceId()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/LinkData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    invoke-interface {v2}, Lio/opentelemetry/api/trace/SpanContext;->getSpanId()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/LinkData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    invoke-interface {v3}, Lio/opentelemetry/api/trace/SpanContext;->getTraceFlags()Lio/opentelemetry/api/trace/TraceFlags;

    .line 28
    .line 29
    .line 30
    move-result-object v3

    .line 31
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/LinkData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 32
    .line 33
    .line 34
    move-result-object v5

    .line 35
    invoke-static {v5}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;->createForAttributes(Lio/opentelemetry/api/common/Attributes;)[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 36
    .line 37
    .line 38
    move-result-object v5

    .line 39
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/LinkData;->getTotalAttributeCount()I

    .line 40
    .line 41
    .line 42
    move-result v6

    .line 43
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/LinkData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 44
    .line 45
    .line 46
    move-result-object v7

    .line 47
    invoke-interface {v7}, Lio/opentelemetry/api/common/Attributes;->size()I

    .line 48
    .line 49
    .line 50
    move-result v7

    .line 51
    sub-int/2addr v6, v7

    .line 52
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/LinkData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-interface {p0}, Lio/opentelemetry/api/trace/SpanContext;->isRemote()Z

    .line 57
    .line 58
    .line 59
    move-result v7

    .line 60
    invoke-direct/range {v0 .. v7}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;-><init>(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/trace/TraceFlags;[B[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;IZ)V

    .line 61
    .line 62
    .line 63
    return-object v0
.end method

.method public static createRepeated(Ljava/util/List;)[Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/trace/data/LinkData;",
            ">;)[",
            "Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;"
        }
    .end annotation

    .line 1
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;->EMPTY:[Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    new-array v0, v0, [Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;

    .line 15
    .line 16
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    const/4 v1, 0x0

    .line 21
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-eqz v2, :cond_1

    .line 26
    .line 27
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    check-cast v2, Lio/opentelemetry/sdk/trace/data/LinkData;

    .line 32
    .line 33
    add-int/lit8 v3, v1, 0x1

    .line 34
    .line 35
    invoke-static {v2}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;->create(Lio/opentelemetry/sdk/trace/data/LinkData;)Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    aput-object v2, v0, v1

    .line 40
    .line 41
    move v1, v3

    .line 42
    goto :goto_0

    .line 43
    :cond_1
    return-object v0
.end method

.method public static encodeSpanLinkTraceState(Lio/opentelemetry/sdk/trace/data/LinkData;)[B
    .locals 0

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/LinkData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

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


# virtual methods
.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 2

    .line 1
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$Link;->TRACE_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;->traceId:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeTraceId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$Link;->SPAN_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 9
    .line 10
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;->spanId:Ljava/lang/String;

    .line 11
    .line 12
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeSpanId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$Link;->TRACE_STATE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 16
    .line 17
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;->traceStateUtf8:[B

    .line 18
    .line 19
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeString(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)V

    .line 20
    .line 21
    .line 22
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$Link;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 23
    .line 24
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;->attributeMarshalers:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 25
    .line 26
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 27
    .line 28
    .line 29
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$Link;->DROPPED_ATTRIBUTES_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 30
    .line 31
    iget v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;->droppedAttributesCount:I

    .line 32
    .line 33
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeUInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V

    .line 34
    .line 35
    .line 36
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$Link;->FLAGS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 37
    .line 38
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;->traceFlags:Lio/opentelemetry/api/trace/TraceFlags;

    .line 39
    .line 40
    iget-boolean p0, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;->isLinkContextRemote:Z

    .line 41
    .line 42
    invoke-static {v1, p0}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanFlags;->withParentIsRemoteFlags(Lio/opentelemetry/api/trace/TraceFlags;Z)I

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V

    .line 47
    .line 48
    .line 49
    return-void
.end method
