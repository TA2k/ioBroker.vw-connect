.class final Lio/opentelemetry/exporter/internal/otlp/InstrumentationScopeMarshaler$RealInstrumentationScopeMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/exporter/internal/otlp/InstrumentationScopeMarshaler;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "RealInstrumentationScopeMarshaler"
.end annotation


# instance fields
.field private final attributes:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

.field private final name:[B

.field private final version:[B


# direct methods
.method public constructor <init>([B[B[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)V
    .locals 1

    .line 1
    invoke-static {p1, p2, p3}, Lio/opentelemetry/exporter/internal/otlp/InstrumentationScopeMarshaler$RealInstrumentationScopeMarshaler;->computeSize([B[B[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/InstrumentationScopeMarshaler$RealInstrumentationScopeMarshaler;->name:[B

    .line 9
    .line 10
    iput-object p2, p0, Lio/opentelemetry/exporter/internal/otlp/InstrumentationScopeMarshaler$RealInstrumentationScopeMarshaler;->version:[B

    .line 11
    .line 12
    iput-object p3, p0, Lio/opentelemetry/exporter/internal/otlp/InstrumentationScopeMarshaler$RealInstrumentationScopeMarshaler;->attributes:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 13
    .line 14
    return-void
.end method

.method private static computeSize([B[B[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;)I
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/common/v1/internal/InstrumentationScope;->NAME:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    invoke-static {v0, p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    sget-object v0, Lio/opentelemetry/proto/common/v1/internal/InstrumentationScope;->VERSION:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 8
    .line 9
    invoke-static {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    add-int/2addr p1, p0

    .line 14
    sget-object p0, Lio/opentelemetry/proto/common/v1/internal/InstrumentationScope;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 15
    .line 16
    invoke-static {p0, p2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    add-int/2addr p0, p1

    .line 21
    return p0
.end method


# virtual methods
.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 2

    .line 1
    sget-object v0, Lio/opentelemetry/proto/common/v1/internal/InstrumentationScope;->NAME:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/InstrumentationScopeMarshaler$RealInstrumentationScopeMarshaler;->name:[B

    .line 4
    .line 5
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeString(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)V

    .line 6
    .line 7
    .line 8
    sget-object v0, Lio/opentelemetry/proto/common/v1/internal/InstrumentationScope;->VERSION:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 9
    .line 10
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/InstrumentationScopeMarshaler$RealInstrumentationScopeMarshaler;->version:[B

    .line 11
    .line 12
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeString(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)V

    .line 13
    .line 14
    .line 15
    sget-object v0, Lio/opentelemetry/proto/common/v1/internal/InstrumentationScope;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 16
    .line 17
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/InstrumentationScopeMarshaler$RealInstrumentationScopeMarshaler;->attributes:[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 18
    .line 19
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 20
    .line 21
    .line 22
    return-void
.end method
