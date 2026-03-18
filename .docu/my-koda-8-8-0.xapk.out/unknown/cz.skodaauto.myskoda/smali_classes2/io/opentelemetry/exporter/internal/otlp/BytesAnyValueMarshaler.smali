.class final Lio/opentelemetry/exporter/internal/otlp/BytesAnyValueMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final value:[B


# direct methods
.method private constructor <init>([B)V
    .locals 1

    .line 1
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/BytesAnyValueMarshaler;->calculateSize([B)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/BytesAnyValueMarshaler;->value:[B

    .line 9
    .line 10
    return-void
.end method

.method private static calculateSize([B)I
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/common/v1/internal/AnyValue;->BYTES_VALUE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    invoke-virtual {v0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeByteArraySizeNoTag([B)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    add-int/2addr p0, v0

    .line 12
    return p0
.end method

.method public static create(Ljava/nio/ByteBuffer;)Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/nio/Buffer;->remaining()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    new-array v0, v0, [B

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Ljava/nio/ByteBuffer;->get([B)Ljava/nio/ByteBuffer;

    .line 8
    .line 9
    .line 10
    new-instance p0, Lio/opentelemetry/exporter/internal/otlp/BytesAnyValueMarshaler;

    .line 11
    .line 12
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/otlp/BytesAnyValueMarshaler;-><init>([B)V

    .line 13
    .line 14
    .line 15
    return-object p0
.end method


# virtual methods
.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/common/v1/internal/AnyValue;->BYTES_VALUE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/BytesAnyValueMarshaler;->value:[B

    .line 4
    .line 5
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->writeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
