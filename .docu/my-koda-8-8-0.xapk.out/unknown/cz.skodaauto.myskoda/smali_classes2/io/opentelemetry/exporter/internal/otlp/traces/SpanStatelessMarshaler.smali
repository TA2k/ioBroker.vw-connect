.class final Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatelessMarshaler;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler<",
        "Lio/opentelemetry/sdk/trace/data/SpanData;",
        ">;"
    }
.end annotation


# static fields
.field static final INSTANCE:Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatelessMarshaler;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatelessMarshaler;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatelessMarshaler;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatelessMarshaler;

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
.method public getBinarySerializedSize(Lio/opentelemetry/sdk/trace/data/SpanData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 3

    .line 2
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span;->TRACE_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getTraceId()Ljava/lang/String;

    move-result-object v0

    invoke-static {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeTraceId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)I

    move-result p0

    .line 3
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->SPAN_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getSpanId()Ljava/lang/String;

    move-result-object v1

    invoke-static {v0, v1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeSpanId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)I

    move-result v0

    add-int/2addr v0, p0

    .line 4
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->encodeSpanTraceState(Lio/opentelemetry/sdk/trace/data/SpanData;)[B

    move-result-object p0

    .line 5
    invoke-virtual {p2, p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->addData(Ljava/lang/Object;)V

    .line 6
    sget-object v1, Lio/opentelemetry/proto/trace/v1/internal/Span;->TRACE_STATE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-static {v1, p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)I

    move-result p0

    add-int/2addr p0, v0

    .line 7
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getParentSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    move-result-object v0

    invoke-interface {v0}, Lio/opentelemetry/api/trace/SpanContext;->isValid()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getParentSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    move-result-object v0

    invoke-interface {v0}, Lio/opentelemetry/api/trace/SpanContext;->getSpanId()Ljava/lang/String;

    move-result-object v0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    .line 8
    :goto_0
    sget-object v1, Lio/opentelemetry/proto/trace/v1/internal/Span;->PARENT_SPAN_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-static {v1, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeSpanId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)I

    move-result v0

    add-int/2addr v0, p0

    .line 9
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span;->NAME:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-static {p0, v1, p2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeStringWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    add-int/2addr p0, v0

    .line 10
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->KIND:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getKind()Lio/opentelemetry/api/trace/SpanKind;

    move-result-object v1

    invoke-static {v1}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->toProtoSpanKind(Lio/opentelemetry/api/trace/SpanKind;)Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    move-result-object v1

    invoke-static {v0, v1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeEnum(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;)I

    move-result v0

    add-int/2addr v0, p0

    .line 11
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span;->START_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getStartEpochNanos()J

    move-result-wide v1

    invoke-static {p0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    move-result p0

    add-int/2addr p0, v0

    .line 12
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->END_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getEndEpochNanos()J

    move-result-wide v1

    invoke-static {v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    move-result v0

    add-int/2addr v0, p0

    .line 13
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 14
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    move-result-object v1

    sget-object v2, Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler;

    .line 15
    invoke-static {p0, v1, v2, p2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    add-int/2addr p0, v0

    .line 16
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getTotalAttributeCount()I

    move-result v0

    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    move-result-object v1

    invoke-interface {v1}, Lio/opentelemetry/api/common/Attributes;->size()I

    move-result v1

    sub-int/2addr v0, v1

    .line 17
    sget-object v1, Lio/opentelemetry/proto/trace/v1/internal/Span;->DROPPED_ATTRIBUTES_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-static {v1, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeUInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    move-result v0

    add-int/2addr v0, p0

    .line 18
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span;->EVENTS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 19
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getEvents()Ljava/util/List;

    move-result-object v1

    sget-object v2, Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventStatelessMarshaler;

    .line 20
    invoke-static {p0, v1, v2, p2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    add-int/2addr p0, v0

    .line 21
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getTotalRecordedEvents()I

    move-result v0

    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getEvents()Ljava/util/List;

    move-result-object v1

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    sub-int/2addr v0, v1

    .line 22
    sget-object v1, Lio/opentelemetry/proto/trace/v1/internal/Span;->DROPPED_EVENTS_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-static {v1, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeUInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    move-result v0

    add-int/2addr v0, p0

    .line 23
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span;->LINKS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 24
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getLinks()Ljava/util/List;

    move-result-object v1

    sget-object v2, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkStatelessMarshaler;

    .line 25
    invoke-static {p0, v1, v2, p2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    add-int/2addr p0, v0

    .line 26
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getTotalRecordedLinks()I

    move-result v0

    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getLinks()Ljava/util/List;

    move-result-object v1

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    sub-int/2addr v0, v1

    .line 27
    sget-object v1, Lio/opentelemetry/proto/trace/v1/internal/Span;->DROPPED_LINKS_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-static {v1, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeUInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    move-result v0

    add-int/2addr v0, p0

    .line 28
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span;->STATUS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 29
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getStatus()Lio/opentelemetry/sdk/trace/data/StatusData;

    move-result-object v1

    sget-object v2, Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatusStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatusStatelessMarshaler;

    .line 30
    invoke-static {p0, v1, v2, p2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    add-int/2addr p0, v0

    .line 31
    sget-object p2, Lio/opentelemetry/proto/trace/v1/internal/Span;->FLAGS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 32
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    move-result-object v0

    invoke-interface {v0}, Lio/opentelemetry/api/trace/SpanContext;->getTraceFlags()Lio/opentelemetry/api/trace/TraceFlags;

    move-result-object v0

    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getParentSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    move-result-object p1

    invoke-interface {p1}, Lio/opentelemetry/api/trace/SpanContext;->isRemote()Z

    move-result p1

    .line 33
    invoke-static {v0, p1}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanFlags;->withParentIsRemoteFlags(Lio/opentelemetry/api/trace/TraceFlags;Z)I

    move-result p1

    .line 34
    invoke-static {p2, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    move-result p1

    add-int/2addr p1, p0

    return p1
.end method

.method public bridge synthetic getBinarySerializedSize(Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 0

    .line 1
    check-cast p1, Lio/opentelemetry/sdk/trace/data/SpanData;

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatelessMarshaler;->getBinarySerializedSize(Lio/opentelemetry/sdk/trace/data/SpanData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0
.end method

.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/sdk/trace/data/SpanData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 2

    .line 2
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span;->TRACE_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getTraceId()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, p0, v0, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeTraceId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 3
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span;->SPAN_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getSpanId()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, p0, v0, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeSpanId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 4
    const-class p0, [B

    invoke-virtual {p3, p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->getData(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, [B

    .line 5
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->TRACE_STATE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeString(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)V

    .line 6
    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getParentSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    move-result-object p0

    invoke-interface {p0}, Lio/opentelemetry/api/trace/SpanContext;->isValid()Z

    move-result p0

    if-eqz p0, :cond_0

    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getParentSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    move-result-object p0

    invoke-interface {p0}, Lio/opentelemetry/api/trace/SpanContext;->getSpanId()Ljava/lang/String;

    move-result-object p0

    goto :goto_0

    :cond_0
    const/4 p0, 0x0

    .line 7
    :goto_0
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->PARENT_SPAN_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-virtual {p1, v0, p0, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeSpanId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 8
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span;->NAME:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, p0, v0, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeStringWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 9
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span;->KIND:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getKind()Lio/opentelemetry/api/trace/SpanKind;

    move-result-object v0

    invoke-static {v0}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanMarshaler;->toProtoSpanKind(Lio/opentelemetry/api/trace/SpanKind;)Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    move-result-object v0

    invoke-virtual {p1, p0, v0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeEnum(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;)V

    .line 10
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span;->START_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getStartEpochNanos()J

    move-result-wide v0

    invoke-virtual {p1, p0, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 11
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span;->END_TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getEndEpochNanos()J

    move-result-wide v0

    invoke-virtual {p1, p0, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 12
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 13
    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    move-result-object v0

    sget-object v1, Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler;

    .line 14
    invoke-virtual {p1, p0, v0, v1, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 15
    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getTotalAttributeCount()I

    move-result p0

    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    move-result-object v0

    invoke-interface {v0}, Lio/opentelemetry/api/common/Attributes;->size()I

    move-result v0

    sub-int/2addr p0, v0

    .line 16
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->DROPPED_ATTRIBUTES_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeUInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V

    .line 17
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span;->EVENTS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 18
    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getEvents()Ljava/util/List;

    move-result-object v0

    sget-object v1, Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/traces/SpanEventStatelessMarshaler;

    .line 19
    invoke-virtual {p1, p0, v0, v1, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 20
    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getTotalRecordedEvents()I

    move-result p0

    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getEvents()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v0

    sub-int/2addr p0, v0

    .line 21
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->DROPPED_EVENTS_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeUInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V

    .line 22
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span;->LINKS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 23
    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getLinks()Ljava/util/List;

    move-result-object v0

    sget-object v1, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkStatelessMarshaler;

    .line 24
    invoke-virtual {p1, p0, v0, v1, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 25
    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getTotalRecordedLinks()I

    move-result p0

    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getLinks()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v0

    sub-int/2addr p0, v0

    .line 26
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span;->DROPPED_LINKS_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeUInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V

    .line 27
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span;->STATUS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 28
    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getStatus()Lio/opentelemetry/sdk/trace/data/StatusData;

    move-result-object v0

    sget-object v1, Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatusStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatusStatelessMarshaler;

    .line 29
    invoke-virtual {p1, p0, v0, v1, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 30
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span;->FLAGS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 31
    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    move-result-object p3

    invoke-interface {p3}, Lio/opentelemetry/api/trace/SpanContext;->getTraceFlags()Lio/opentelemetry/api/trace/TraceFlags;

    move-result-object p3

    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/SpanData;->getParentSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    move-result-object p2

    invoke-interface {p2}, Lio/opentelemetry/api/trace/SpanContext;->isRemote()Z

    move-result p2

    .line 32
    invoke-static {p3, p2}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanFlags;->withParentIsRemoteFlags(Lio/opentelemetry/api/trace/TraceFlags;Z)I

    move-result p2

    .line 33
    invoke-virtual {p1, p0, p2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V

    return-void
.end method

.method public bridge synthetic writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 0

    .line 1
    check-cast p2, Lio/opentelemetry/sdk/trace/data/SpanData;

    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatelessMarshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/sdk/trace/data/SpanData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void
.end method
