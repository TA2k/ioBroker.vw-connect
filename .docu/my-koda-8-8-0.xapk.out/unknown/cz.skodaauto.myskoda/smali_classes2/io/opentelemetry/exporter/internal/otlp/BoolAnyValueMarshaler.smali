.class final Lio/opentelemetry/exporter/internal/otlp/BoolAnyValueMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final value:Z


# direct methods
.method private constructor <init>(Z)V
    .locals 1

    .line 1
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/BoolAnyValueMarshaler;->calculateSize(Z)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iput-boolean p1, p0, Lio/opentelemetry/exporter/internal/otlp/BoolAnyValueMarshaler;->value:Z

    .line 9
    .line 10
    return-void
.end method

.method private static calculateSize(Z)I
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/common/v1/internal/AnyValue;->BOOL_VALUE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    invoke-virtual {v0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeBoolSizeNoTag(Z)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    add-int/2addr p0, v0

    .line 12
    return p0
.end method

.method public static create(Z)Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/BoolAnyValueMarshaler;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/exporter/internal/otlp/BoolAnyValueMarshaler;-><init>(Z)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/common/v1/internal/AnyValue;->BOOL_VALUE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iget-boolean p0, p0, Lio/opentelemetry/exporter/internal/otlp/BoolAnyValueMarshaler;->value:Z

    .line 4
    .line 5
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->writeBool(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Z)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
