.class final Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkStatelessMarshaler;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler<",
        "Lio/opentelemetry/sdk/trace/data/LinkData;",
        ">;"
    }
.end annotation


# static fields
.field static final INSTANCE:Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkStatelessMarshaler;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkStatelessMarshaler;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkStatelessMarshaler;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkStatelessMarshaler;

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
.method public getBinarySerializedSize(Lio/opentelemetry/sdk/trace/data/LinkData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 3

    .line 2
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkMarshaler;->encodeSpanLinkTraceState(Lio/opentelemetry/sdk/trace/data/LinkData;)[B

    move-result-object p0

    .line 3
    invoke-virtual {p2, p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->addData(Ljava/lang/Object;)V

    .line 4
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$Link;->TRACE_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/LinkData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    move-result-object v1

    invoke-interface {v1}, Lio/opentelemetry/api/trace/SpanContext;->getTraceId()Ljava/lang/String;

    move-result-object v1

    invoke-static {v0, v1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeTraceId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)I

    move-result v0

    .line 5
    sget-object v1, Lio/opentelemetry/proto/trace/v1/internal/Span$Link;->SPAN_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/LinkData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    move-result-object v2

    invoke-interface {v2}, Lio/opentelemetry/api/trace/SpanContext;->getSpanId()Ljava/lang/String;

    move-result-object v2

    invoke-static {v1, v2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeSpanId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)I

    move-result v1

    add-int/2addr v1, v0

    .line 6
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$Link;->TRACE_STATE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-static {v0, p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)I

    move-result p0

    add-int/2addr p0, v1

    .line 7
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$Link;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 8
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/LinkData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    move-result-object v1

    sget-object v2, Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler;

    .line 9
    invoke-static {v0, v1, v2, p2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p2

    add-int/2addr p2, p0

    .line 10
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/LinkData;->getTotalAttributeCount()I

    move-result p0

    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/LinkData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    move-result-object v0

    invoke-interface {v0}, Lio/opentelemetry/api/common/Attributes;->size()I

    move-result v0

    sub-int/2addr p0, v0

    .line 11
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$Link;->DROPPED_ATTRIBUTES_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-static {v0, p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeUInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    move-result p0

    add-int/2addr p0, p2

    .line 12
    sget-object p2, Lio/opentelemetry/proto/trace/v1/internal/Span$Link;->FLAGS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 13
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/LinkData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    move-result-object v0

    invoke-interface {v0}, Lio/opentelemetry/api/trace/SpanContext;->getTraceFlags()Lio/opentelemetry/api/trace/TraceFlags;

    move-result-object v0

    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/LinkData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    move-result-object p1

    invoke-interface {p1}, Lio/opentelemetry/api/trace/SpanContext;->isRemote()Z

    move-result p1

    .line 14
    invoke-static {v0, p1}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanFlags;->withParentIsRemoteFlags(Lio/opentelemetry/api/trace/TraceFlags;Z)I

    move-result p1

    .line 15
    invoke-static {p2, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    move-result p1

    add-int/2addr p1, p0

    return p1
.end method

.method public bridge synthetic getBinarySerializedSize(Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 0

    .line 1
    check-cast p1, Lio/opentelemetry/sdk/trace/data/LinkData;

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkStatelessMarshaler;->getBinarySerializedSize(Lio/opentelemetry/sdk/trace/data/LinkData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0
.end method

.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/sdk/trace/data/LinkData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 2

    .line 2
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span$Link;->TRACE_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/LinkData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    move-result-object v0

    invoke-interface {v0}, Lio/opentelemetry/api/trace/SpanContext;->getTraceId()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, p0, v0, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeTraceId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 3
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span$Link;->SPAN_ID:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/LinkData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    move-result-object v0

    invoke-interface {v0}, Lio/opentelemetry/api/trace/SpanContext;->getSpanId()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, p0, v0, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeSpanId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 4
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span$Link;->TRACE_STATE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    const-class v0, [B

    invoke-virtual {p3, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->getData(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [B

    invoke-virtual {p1, p0, v0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeString(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)V

    .line 5
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span$Link;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 6
    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/LinkData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    move-result-object v0

    sget-object v1, Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler;

    .line 7
    invoke-virtual {p1, p0, v0, v1, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 8
    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/LinkData;->getTotalAttributeCount()I

    move-result p0

    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/LinkData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    move-result-object p3

    invoke-interface {p3}, Lio/opentelemetry/api/common/Attributes;->size()I

    move-result p3

    sub-int/2addr p0, p3

    .line 9
    sget-object p3, Lio/opentelemetry/proto/trace/v1/internal/Span$Link;->DROPPED_ATTRIBUTES_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    invoke-virtual {p1, p3, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeUInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V

    .line 10
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Span$Link;->FLAGS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 11
    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/LinkData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    move-result-object p3

    invoke-interface {p3}, Lio/opentelemetry/api/trace/SpanContext;->getTraceFlags()Lio/opentelemetry/api/trace/TraceFlags;

    move-result-object p3

    invoke-interface {p2}, Lio/opentelemetry/sdk/trace/data/LinkData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    move-result-object p2

    invoke-interface {p2}, Lio/opentelemetry/api/trace/SpanContext;->isRemote()Z

    move-result p2

    .line 12
    invoke-static {p3, p2}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanFlags;->withParentIsRemoteFlags(Lio/opentelemetry/api/trace/TraceFlags;Z)I

    move-result p2

    .line 13
    invoke-virtual {p1, p0, p2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeFixed32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V

    return-void
.end method

.method public bridge synthetic writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 0

    .line 1
    check-cast p2, Lio/opentelemetry/sdk/trace/data/LinkData;

    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanLinkStatelessMarshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/sdk/trace/data/LinkData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void
.end method
