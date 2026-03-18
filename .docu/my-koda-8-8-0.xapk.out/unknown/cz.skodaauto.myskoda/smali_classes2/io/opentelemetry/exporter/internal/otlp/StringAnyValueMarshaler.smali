.class final Lio/opentelemetry/exporter/internal/otlp/StringAnyValueMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final valueUtf8:[B


# direct methods
.method private constructor <init>([B)V
    .locals 1

    .line 1
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/StringAnyValueMarshaler;->calculateSize([B)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/StringAnyValueMarshaler;->valueUtf8:[B

    .line 9
    .line 10
    return-void
.end method

.method private static calculateSize([B)I
    .locals 1

    .line 1
    array-length v0, p0

    .line 2
    if-nez v0, :cond_0

    .line 3
    .line 4
    const/4 p0, 0x0

    .line 5
    return p0

    .line 6
    :cond_0
    sget-object v0, Lio/opentelemetry/proto/common/v1/internal/AnyValue;->STRING_VALUE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 7
    .line 8
    invoke-virtual {v0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeByteArraySizeNoTag([B)I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    add-int/2addr p0, v0

    .line 17
    return p0
.end method

.method public static create(Ljava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/StringAnyValueMarshaler;

    .line 2
    .line 3
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->toBytes(Ljava/lang/String;)[B

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-direct {v0, p0}, Lio/opentelemetry/exporter/internal/otlp/StringAnyValueMarshaler;-><init>([B)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method


# virtual methods
.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/StringAnyValueMarshaler;->valueUtf8:[B

    .line 2
    .line 3
    array-length v0, p0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    return-void

    .line 7
    :cond_0
    sget-object v0, Lio/opentelemetry/proto/common/v1/internal/AnyValue;->STRING_VALUE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 8
    .line 9
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->writeString(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)V

    .line 10
    .line 11
    .line 12
    return-void
.end method
