.class final Lio/opentelemetry/exporter/internal/otlp/DoubleAnyValueMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final value:D


# direct methods
.method private constructor <init>(D)V
    .locals 1

    .line 1
    invoke-static {p1, p2}, Lio/opentelemetry/exporter/internal/otlp/DoubleAnyValueMarshaler;->calculateSize(D)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iput-wide p1, p0, Lio/opentelemetry/exporter/internal/otlp/DoubleAnyValueMarshaler;->value:D

    .line 9
    .line 10
    return-void
.end method

.method private static calculateSize(D)I
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/common/v1/internal/AnyValue;->DOUBLE_VALUE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    invoke-virtual {v0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    invoke-static {p0, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeDoubleSizeNoTag(D)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    add-int/2addr p0, v0

    .line 12
    return p0
.end method

.method public static create(D)Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/DoubleAnyValueMarshaler;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/exporter/internal/otlp/DoubleAnyValueMarshaler;-><init>(D)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 3

    .line 1
    sget-object v0, Lio/opentelemetry/proto/common/v1/internal/AnyValue;->DOUBLE_VALUE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/DoubleAnyValueMarshaler;->value:D

    .line 4
    .line 5
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->writeDouble(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
