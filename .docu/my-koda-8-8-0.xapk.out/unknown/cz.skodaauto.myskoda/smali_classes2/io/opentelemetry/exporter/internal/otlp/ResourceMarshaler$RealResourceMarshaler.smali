.class final Lio/opentelemetry/exporter/internal/otlp/ResourceMarshaler$RealResourceMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/exporter/internal/otlp/ResourceMarshaler;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "RealResourceMarshaler"
.end annotation


# instance fields
.field private final attributes:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;


# direct methods
.method private constructor <init>([Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)V
    .locals 1

    .line 2
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/ResourceMarshaler$RealResourceMarshaler;->calculateSize([Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)I

    move-result v0

    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 3
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/ResourceMarshaler$RealResourceMarshaler;->attributes:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    return-void
.end method

.method public synthetic constructor <init>([Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;Lio/opentelemetry/exporter/internal/otlp/ResourceMarshaler$1;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/exporter/internal/otlp/ResourceMarshaler$RealResourceMarshaler;-><init>([Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)V

    return-void
.end method

.method private static calculateSize([Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)I
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/resource/v1/internal/Resource;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    invoke-static {v0, p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method


# virtual methods
.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/resource/v1/internal/Resource;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/ResourceMarshaler$RealResourceMarshaler;->attributes:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 4
    .line 5
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
