.class final Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field static final synthetic $assertionsDisabled:Z


# instance fields
.field private final filteredAttributeMarshalers:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

.field private final spanContext:Lio/opentelemetry/api/trace/SpanContext;

.field private final timeUnixNano:J

.field private final value:Lio/opentelemetry/sdk/metrics/data/ExemplarData;

.field private final valueField:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;


# direct methods
.method private constructor <init>(JLio/opentelemetry/sdk/metrics/data/ExemplarData;Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/api/trace/SpanContext;[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)V
    .locals 2

    .line 1
    move-object v1, p4

    .line 2
    move-object p4, p3

    .line 3
    move-object p3, v1

    .line 4
    invoke-static/range {p1 .. p6}, Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;->calculateSize(JLio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/sdk/metrics/data/ExemplarData;Lio/opentelemetry/api/trace/SpanContext;[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)I

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 9
    .line 10
    .line 11
    iput-wide p1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;->timeUnixNano:J

    .line 12
    .line 13
    iput-object p4, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;->value:Lio/opentelemetry/sdk/metrics/data/ExemplarData;

    .line 14
    .line 15
    iput-object p3, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;->valueField:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 16
    .line 17
    iput-object p5, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 18
    .line 19
    iput-object p6, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;->filteredAttributeMarshalers:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 20
    .line 21
    return-void
.end method

.method private static calculateSize(JLio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/sdk/metrics/data/ExemplarData;Lio/opentelemetry/api/trace/SpanContext;[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)I
    .locals 2

    .line 1
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Exemplar;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    invoke-static {v0, p0, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    sget-object p1, Lio/opentelemetry/proto/metrics/v1/internal/Exemplar;->AS_INT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 8
    .line 9
    if-ne p2, p1, :cond_0

    .line 10
    .line 11
    check-cast p3, Lio/opentelemetry/sdk/metrics/data/LongExemplarData;

    .line 12
    .line 13
    invoke-interface {p3}, Lio/opentelemetry/sdk/metrics/data/LongExemplarData;->getValue()J

    .line 14
    .line 15
    .line 16
    move-result-wide v0

    .line 17
    invoke-static {p2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64Optional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    :goto_0
    add-int/2addr p1, p0

    .line 22
    goto :goto_1

    .line 23
    :cond_0
    check-cast p3, Lio/opentelemetry/sdk/metrics/data/DoubleExemplarData;

    .line 24
    .line 25
    invoke-interface {p3}, Lio/opentelemetry/sdk/metrics/data/DoubleExemplarData;->getValue()D

    .line 26
    .line 27
    .line 28
    move-result-wide v0

    .line 29
    invoke-static {p2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeDoubleOptional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)I

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    goto :goto_0

    .line 34
    :goto_1
    invoke-interface {p4}, Lio/opentelemetry/api/trace/SpanContext;->isValid()Z

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    if-eqz p0, :cond_1

    .line 39
    .line 40
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/Exemplar;->SPAN_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 41
    .line 42
    invoke-interface {p4}, Lio/opentelemetry/api/trace/SpanContext;->getSpanId()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p2

    .line 46
    invoke-static {p0, p2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeSpanId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)I

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    add-int/2addr p0, p1

    .line 51
    sget-object p1, Lio/opentelemetry/proto/metrics/v1/internal/Exemplar;->TRACE_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 52
    .line 53
    invoke-interface {p4}, Lio/opentelemetry/api/trace/SpanContext;->getTraceId()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p2

    .line 57
    invoke-static {p1, p2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeTraceId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)I

    .line 58
    .line 59
    .line 60
    move-result p1

    .line 61
    add-int/2addr p1, p0

    .line 62
    :cond_1
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/Exemplar;->FILTERED_ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 63
    .line 64
    invoke-static {p0, p5}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    add-int/2addr p0, p1

    .line 69
    return p0
.end method

.method public static create(Lio/opentelemetry/sdk/metrics/data/ExemplarData;)Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;
    .locals 8

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/data/ExemplarData;->getFilteredAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;->createForAttributes(Lio/opentelemetry/api/common/Attributes;)[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 6
    .line 7
    .line 8
    move-result-object v7

    .line 9
    new-instance v1, Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;

    .line 10
    .line 11
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/data/ExemplarData;->getEpochNanos()J

    .line 12
    .line 13
    .line 14
    move-result-wide v2

    .line 15
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;->toProtoExemplarValueType(Lio/opentelemetry/sdk/metrics/data/ExemplarData;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 16
    .line 17
    .line 18
    move-result-object v5

    .line 19
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/data/ExemplarData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 20
    .line 21
    .line 22
    move-result-object v6

    .line 23
    move-object v4, p0

    .line 24
    invoke-direct/range {v1 .. v7}, Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;-><init>(JLio/opentelemetry/sdk/metrics/data/ExemplarData;Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/api/trace/SpanContext;[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)V

    .line 25
    .line 26
    .line 27
    return-object v1
.end method

.method public static createRepeated(Ljava/util/List;)[Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "+",
            "Lio/opentelemetry/sdk/metrics/data/ExemplarData;",
            ">;)[",
            "Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;"
        }
    .end annotation

    .line 1
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    new-array v1, v0, [Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    :goto_0
    if-ge v2, v0, :cond_0

    .line 9
    .line 10
    invoke-interface {p0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v3

    .line 14
    check-cast v3, Lio/opentelemetry/sdk/metrics/data/ExemplarData;

    .line 15
    .line 16
    invoke-static {v3}, Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;->create(Lio/opentelemetry/sdk/metrics/data/ExemplarData;)Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    aput-object v3, v1, v2

    .line 21
    .line 22
    add-int/lit8 v2, v2, 0x1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    return-object v1
.end method

.method public static toProtoExemplarValueType(Lio/opentelemetry/sdk/metrics/data/ExemplarData;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;
    .locals 0

    .line 1
    instance-of p0, p0, Lio/opentelemetry/sdk/metrics/data/LongExemplarData;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/Exemplar;->AS_INT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/Exemplar;->AS_DOUBLE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 9
    .line 10
    return-object p0
.end method


# virtual methods
.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 3

    .line 1
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Exemplar;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;->timeUnixNano:J

    .line 4
    .line 5
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;->valueField:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 9
    .line 10
    sget-object v1, Lio/opentelemetry/proto/metrics/v1/internal/Exemplar;->AS_INT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 11
    .line 12
    if-ne v0, v1, :cond_0

    .line 13
    .line 14
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;->value:Lio/opentelemetry/sdk/metrics/data/ExemplarData;

    .line 15
    .line 16
    check-cast v1, Lio/opentelemetry/sdk/metrics/data/LongExemplarData;

    .line 17
    .line 18
    invoke-interface {v1}, Lio/opentelemetry/sdk/metrics/data/LongExemplarData;->getValue()J

    .line 19
    .line 20
    .line 21
    move-result-wide v1

    .line 22
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64Optional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;->value:Lio/opentelemetry/sdk/metrics/data/ExemplarData;

    .line 27
    .line 28
    check-cast v1, Lio/opentelemetry/sdk/metrics/data/DoubleExemplarData;

    .line 29
    .line 30
    invoke-interface {v1}, Lio/opentelemetry/sdk/metrics/data/DoubleExemplarData;->getValue()D

    .line 31
    .line 32
    .line 33
    move-result-wide v1

    .line 34
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeDoubleOptional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)V

    .line 35
    .line 36
    .line 37
    :goto_0
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 38
    .line 39
    invoke-interface {v0}, Lio/opentelemetry/api/trace/SpanContext;->isValid()Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-eqz v0, :cond_1

    .line 44
    .line 45
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Exemplar;->SPAN_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 46
    .line 47
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 48
    .line 49
    invoke-interface {v1}, Lio/opentelemetry/api/trace/SpanContext;->getSpanId()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeSpanId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Exemplar;->TRACE_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 57
    .line 58
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 59
    .line 60
    invoke-interface {v1}, Lio/opentelemetry/api/trace/SpanContext;->getTraceId()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeTraceId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    :cond_1
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Exemplar;->FILTERED_ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 68
    .line 69
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExemplarMarshaler;->filteredAttributeMarshalers:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 70
    .line 71
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 72
    .line 73
    .line 74
    return-void
.end method
