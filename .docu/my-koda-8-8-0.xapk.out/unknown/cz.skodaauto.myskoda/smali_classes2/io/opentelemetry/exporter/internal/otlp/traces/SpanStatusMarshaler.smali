.class final Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatusMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final descriptionUtf8:[B

.field private final protoStatusCode:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;


# direct methods
.method private constructor <init>(Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;[B)V
    .locals 1

    .line 1
    invoke-static {p1, p2}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatusMarshaler;->computeSize(Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;[B)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatusMarshaler;->protoStatusCode:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 9
    .line 10
    iput-object p2, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatusMarshaler;->descriptionUtf8:[B

    .line 11
    .line 12
    return-void
.end method

.method private static computeSize(Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;[B)I
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Status;->MESSAGE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    invoke-static {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Status;->CODE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 8
    .line 9
    invoke-static {v0, p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeEnum(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    add-int/2addr p0, p1

    .line 14
    return p0
.end method

.method public static create(Lio/opentelemetry/sdk/trace/data/StatusData;)Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatusMarshaler;
    .locals 2

    .line 1
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatusMarshaler;->toProtoSpanStatus(Lio/opentelemetry/sdk/trace/data/StatusData;)Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/StatusData;->getDescription()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->toBytes(Ljava/lang/String;)[B

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    new-instance v1, Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatusMarshaler;

    .line 14
    .line 15
    invoke-direct {v1, v0, p0}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatusMarshaler;-><init>(Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;[B)V

    .line 16
    .line 17
    .line 18
    return-object v1
.end method

.method public static toProtoSpanStatus(Lio/opentelemetry/sdk/trace/data/StatusData;)Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;
    .locals 3

    .line 1
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Status$StatusCode;->STATUS_CODE_UNSET:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/StatusData;->getStatusCode()Lio/opentelemetry/api/trace/StatusCode;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    sget-object v2, Lio/opentelemetry/api/trace/StatusCode;->OK:Lio/opentelemetry/api/trace/StatusCode;

    .line 8
    .line 9
    if-ne v1, v2, :cond_0

    .line 10
    .line 11
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Status$StatusCode;->STATUS_CODE_OK:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 12
    .line 13
    return-object p0

    .line 14
    :cond_0
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/StatusData;->getStatusCode()Lio/opentelemetry/api/trace/StatusCode;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    sget-object v1, Lio/opentelemetry/api/trace/StatusCode;->ERROR:Lio/opentelemetry/api/trace/StatusCode;

    .line 19
    .line 20
    if-ne p0, v1, :cond_1

    .line 21
    .line 22
    sget-object p0, Lio/opentelemetry/proto/trace/v1/internal/Status$StatusCode;->STATUS_CODE_ERROR:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_1
    return-object v0
.end method


# virtual methods
.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 2

    .line 1
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Status;->MESSAGE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatusMarshaler;->descriptionUtf8:[B

    .line 4
    .line 5
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeString(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)V

    .line 6
    .line 7
    .line 8
    sget-object v0, Lio/opentelemetry/proto/trace/v1/internal/Status;->CODE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 9
    .line 10
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanStatusMarshaler;->protoStatusCode:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 11
    .line 12
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeEnum(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method
