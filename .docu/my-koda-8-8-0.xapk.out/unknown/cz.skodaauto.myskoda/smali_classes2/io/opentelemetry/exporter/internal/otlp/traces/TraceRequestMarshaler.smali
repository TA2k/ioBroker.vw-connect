.class public final Lio/opentelemetry/exporter/internal/otlp/traces/TraceRequestMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final resourceSpansMarshalers:[Lio/opentelemetry/exporter/internal/otlp/traces/ResourceSpansMarshaler;


# direct methods
.method private constructor <init>([Lio/opentelemetry/exporter/internal/otlp/traces/ResourceSpansMarshaler;)V
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/collector/trace/v1/internal/ExportTraceServiceRequest;->RESOURCE_SPANS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    invoke-static {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/TraceRequestMarshaler;->resourceSpansMarshalers:[Lio/opentelemetry/exporter/internal/otlp/traces/ResourceSpansMarshaler;

    .line 11
    .line 12
    return-void
.end method

.method public static create(Ljava/util/Collection;)Lio/opentelemetry/exporter/internal/otlp/traces/TraceRequestMarshaler;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Lio/opentelemetry/sdk/trace/data/SpanData;",
            ">;)",
            "Lio/opentelemetry/exporter/internal/otlp/traces/TraceRequestMarshaler;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/traces/TraceRequestMarshaler;

    .line 2
    .line 3
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/otlp/traces/ResourceSpansMarshaler;->create(Ljava/util/Collection;)[Lio/opentelemetry/exporter/internal/otlp/traces/ResourceSpansMarshaler;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-direct {v0, p0}, Lio/opentelemetry/exporter/internal/otlp/traces/TraceRequestMarshaler;-><init>([Lio/opentelemetry/exporter/internal/otlp/traces/ResourceSpansMarshaler;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method


# virtual methods
.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/collector/trace/v1/internal/ExportTraceServiceRequest;->RESOURCE_SPANS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/traces/TraceRequestMarshaler;->resourceSpansMarshalers:[Lio/opentelemetry/exporter/internal/otlp/traces/ResourceSpansMarshaler;

    .line 4
    .line 5
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
