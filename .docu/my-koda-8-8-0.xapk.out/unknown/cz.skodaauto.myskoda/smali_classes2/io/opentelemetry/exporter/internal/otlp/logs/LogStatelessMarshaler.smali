.class final Lio/opentelemetry/exporter/internal/otlp/logs/LogStatelessMarshaler;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler<",
        "Lio/opentelemetry/sdk/logs/data/LogRecordData;",
        ">;"
    }
.end annotation


# static fields
.field static final INSTANCE:Lio/opentelemetry/exporter/internal/otlp/logs/LogStatelessMarshaler;

.field private static final INVALID_SPAN_ID:Ljava/lang/String;

.field private static final INVALID_TRACE_ID:Ljava/lang/String;


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
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/logs/LogStatelessMarshaler;->INVALID_TRACE_ID:Ljava/lang/String;

    .line 6
    .line 7
    invoke-static {}, Lio/opentelemetry/api/trace/SpanId;->getInvalid()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/logs/LogStatelessMarshaler;->INVALID_SPAN_ID:Ljava/lang/String;

    .line 12
    .line 13
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/logs/LogStatelessMarshaler;

    .line 14
    .line 15
    invoke-direct {v0}, Lio/opentelemetry/exporter/internal/otlp/logs/LogStatelessMarshaler;-><init>()V

    .line 16
    .line 17
    .line 18
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/logs/LogStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/logs/LogStatelessMarshaler;

    .line 19
    .line 20
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public getBinarySerializedSize(Lio/opentelemetry/sdk/logs/data/LogRecordData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 3

    .line 2
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p1}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getTimestampEpochNanos()J

    move-result-wide v0

    invoke-static {p0, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    move-result p0

    .line 3
    sget-object v0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->OBSERVED_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 4
    invoke-interface {p1}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getObservedTimestampEpochNanos()J

    move-result-wide v1

    .line 5
    invoke-static {v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    move-result v0

    add-int/2addr v0, p0

    .line 6
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->SEVERITY_NUMBER:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 7
    invoke-interface {p1}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getSeverity()Lio/opentelemetry/api/logs/Severity;

    move-result-object v1

    invoke-static {v1}, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->toProtoSeverityNumber(Lio/opentelemetry/api/logs/Severity;)Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    move-result-object v1

    invoke-static {p0, v1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeEnum(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;)I

    move-result p0

    add-int/2addr p0, v0

    .line 8
    sget-object v0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->SEVERITY_TEXT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 9
    invoke-interface {p1}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getSeverityText()Ljava/lang/String;

    move-result-object v1

    .line 10
    invoke-static {v0, v1, p2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeStringWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result v0

    add-int/2addr v0, p0

    .line 11
    invoke-interface {p1}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getBodyValue()Lio/opentelemetry/api/common/Value;

    move-result-object p0

    if-eqz p0, :cond_0

    .line 12
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->BODY:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 13
    invoke-interface {p1}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getBodyValue()Lio/opentelemetry/api/common/Value;

    move-result-object v1

    sget-object v2, Lio/opentelemetry/exporter/internal/otlp/AnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/AnyValueStatelessMarshaler;

    .line 14
    invoke-static {p0, v1, v2, p2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    add-int/2addr v0, p0

    .line 15
    :cond_0
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;->isExtendedLogRecordData(Lio/opentelemetry/sdk/logs/data/LogRecordData;)Z

    move-result p0

    if-eqz p0, :cond_1

    .line 16
    invoke-static {p1, p2}, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;->sizeExtendedAttributes(Lio/opentelemetry/sdk/logs/data/LogRecordData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    add-int/2addr p0, v0

    .line 17
    invoke-interface {p1}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getTotalAttributeCount()I

    move-result v0

    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;->extendedAttributesSize(Lio/opentelemetry/sdk/logs/data/LogRecordData;)I

    move-result v1

    sub-int/2addr v0, v1

    .line 18
    sget-object v1, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->DROPPED_ATTRIBUTES_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-static {v1, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeUInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    move-result v0

    :goto_0
    add-int/2addr v0, p0

    goto :goto_1

    .line 19
    :cond_1
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 20
    invoke-interface {p1}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    move-result-object v1

    sget-object v2, Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler;

    .line 21
    invoke-static {p0, v1, v2, p2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    add-int/2addr p0, v0

    .line 22
    invoke-interface {p1}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getTotalAttributeCount()I

    move-result v0

    invoke-interface {p1}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    move-result-object v1

    invoke-interface {v1}, Lio/opentelemetry/api/common/Attributes;->size()I

    move-result v1

    sub-int/2addr v0, v1

    .line 23
    sget-object v1, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->DROPPED_ATTRIBUTES_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-static {v1, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeUInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    move-result v0

    goto :goto_0

    .line 24
    :goto_1
    invoke-interface {p1}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    move-result-object p0

    .line 25
    sget-object v1, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->FLAGS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p0}, Lio/opentelemetry/api/trace/SpanContext;->getTraceFlags()Lio/opentelemetry/api/trace/TraceFlags;

    move-result-object v2

    invoke-interface {v2}, Lio/opentelemetry/api/trace/TraceFlags;->asByte()B

    move-result v2

    invoke-static {v1, v2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    move-result v1

    add-int/2addr v1, v0

    .line 26
    invoke-interface {p0}, Lio/opentelemetry/api/trace/SpanContext;->getTraceId()Ljava/lang/String;

    move-result-object v0

    sget-object v2, Lio/opentelemetry/exporter/internal/otlp/logs/LogStatelessMarshaler;->INVALID_TRACE_ID:Ljava/lang/String;

    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_2

    .line 27
    sget-object v0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->TRACE_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p0}, Lio/opentelemetry/api/trace/SpanContext;->getTraceId()Ljava/lang/String;

    move-result-object v2

    invoke-static {v0, v2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeTraceId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)I

    move-result v0

    add-int/2addr v1, v0

    .line 28
    :cond_2
    invoke-interface {p0}, Lio/opentelemetry/api/trace/SpanContext;->getSpanId()Ljava/lang/String;

    move-result-object v0

    sget-object v2, Lio/opentelemetry/exporter/internal/otlp/logs/LogStatelessMarshaler;->INVALID_SPAN_ID:Ljava/lang/String;

    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_3

    .line 29
    sget-object v0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->SPAN_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p0}, Lio/opentelemetry/api/trace/SpanContext;->getSpanId()Ljava/lang/String;

    move-result-object p0

    invoke-static {v0, p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeSpanId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)I

    move-result p0

    add-int/2addr v1, p0

    .line 30
    :cond_3
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->EVENT_NAME:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 31
    invoke-interface {p1}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getEventName()Ljava/lang/String;

    move-result-object p1

    .line 32
    invoke-static {p0, p1, p2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeStringWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    add-int/2addr p0, v1

    return p0
.end method

.method public bridge synthetic getBinarySerializedSize(Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 0

    .line 1
    check-cast p1, Lio/opentelemetry/sdk/logs/data/LogRecordData;

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/otlp/logs/LogStatelessMarshaler;->getBinarySerializedSize(Lio/opentelemetry/sdk/logs/data/LogRecordData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0
.end method

.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/sdk/logs/data/LogRecordData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 2

    .line 2
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getTimestampEpochNanos()J

    move-result-wide v0

    invoke-virtual {p1, p0, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 3
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->OBSERVED_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 4
    invoke-interface {p2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getObservedTimestampEpochNanos()J

    move-result-wide v0

    .line 5
    invoke-virtual {p1, p0, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 6
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->SEVERITY_NUMBER:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getSeverity()Lio/opentelemetry/api/logs/Severity;

    move-result-object v0

    invoke-static {v0}, Lio/opentelemetry/exporter/internal/otlp/logs/LogMarshaler;->toProtoSeverityNumber(Lio/opentelemetry/api/logs/Severity;)Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    move-result-object v0

    invoke-virtual {p1, p0, v0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeEnum(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;)V

    .line 7
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->SEVERITY_TEXT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getSeverityText()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, p0, v0, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeStringWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 8
    invoke-interface {p2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getBodyValue()Lio/opentelemetry/api/common/Value;

    move-result-object p0

    if-eqz p0, :cond_0

    .line 9
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->BODY:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 10
    invoke-interface {p2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getBodyValue()Lio/opentelemetry/api/common/Value;

    move-result-object v0

    sget-object v1, Lio/opentelemetry/exporter/internal/otlp/AnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/AnyValueStatelessMarshaler;

    .line 11
    invoke-virtual {p1, p0, v0, v1, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 12
    :cond_0
    invoke-static {p2}, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;->isExtendedLogRecordData(Lio/opentelemetry/sdk/logs/data/LogRecordData;)Z

    move-result p0

    if-eqz p0, :cond_1

    .line 13
    invoke-static {p1, p2, p3}, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;->serializeExtendedAttributes(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/sdk/logs/data/LogRecordData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 14
    invoke-interface {p2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getTotalAttributeCount()I

    move-result p0

    invoke-static {p2}, Lio/opentelemetry/exporter/internal/otlp/IncubatingUtil;->extendedAttributesSize(Lio/opentelemetry/sdk/logs/data/LogRecordData;)I

    move-result v0

    :goto_0
    sub-int/2addr p0, v0

    goto :goto_1

    .line 15
    :cond_1
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 16
    invoke-interface {p2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    move-result-object v0

    sget-object v1, Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler;

    .line 17
    invoke-virtual {p1, p0, v0, v1, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 18
    invoke-interface {p2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getTotalAttributeCount()I

    move-result p0

    invoke-interface {p2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    move-result-object v0

    invoke-interface {v0}, Lio/opentelemetry/api/common/Attributes;->size()I

    move-result v0

    goto :goto_0

    .line 19
    :goto_1
    sget-object v0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->DROPPED_ATTRIBUTES_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeUInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V

    .line 20
    invoke-interface {p2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    move-result-object p0

    .line 21
    sget-object v0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->FLAGS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p0}, Lio/opentelemetry/api/trace/SpanContext;->getTraceFlags()Lio/opentelemetry/api/trace/TraceFlags;

    move-result-object v1

    invoke-interface {v1}, Lio/opentelemetry/api/trace/TraceFlags;->asByte()B

    move-result v1

    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V

    .line 22
    invoke-interface {p0}, Lio/opentelemetry/api/trace/SpanContext;->getTraceId()Ljava/lang/String;

    move-result-object v0

    sget-object v1, Lio/opentelemetry/exporter/internal/otlp/logs/LogStatelessMarshaler;->INVALID_TRACE_ID:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_2

    .line 23
    sget-object v0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->TRACE_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p0}, Lio/opentelemetry/api/trace/SpanContext;->getTraceId()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v0, v1, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeTraceId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 24
    :cond_2
    invoke-interface {p0}, Lio/opentelemetry/api/trace/SpanContext;->getSpanId()Ljava/lang/String;

    move-result-object v0

    sget-object v1, Lio/opentelemetry/exporter/internal/otlp/logs/LogStatelessMarshaler;->INVALID_SPAN_ID:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_3

    .line 25
    sget-object v0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->SPAN_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p0}, Lio/opentelemetry/api/trace/SpanContext;->getSpanId()Ljava/lang/String;

    move-result-object p0

    invoke-virtual {p1, v0, p0, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeSpanId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 26
    :cond_3
    sget-object p0, Lio/opentelemetry/proto/logs/v1/internal/LogRecord;->EVENT_NAME:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getEventName()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p1, p0, p2, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeStringWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void
.end method

.method public bridge synthetic writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 0

    .line 1
    check-cast p2, Lio/opentelemetry/sdk/logs/data/LogRecordData;

    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/otlp/logs/LogStatelessMarshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/sdk/logs/data/LogRecordData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void
.end method
