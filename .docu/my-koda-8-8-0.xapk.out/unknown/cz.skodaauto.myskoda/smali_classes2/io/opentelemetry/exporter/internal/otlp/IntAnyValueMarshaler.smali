.class final Lio/opentelemetry/exporter/internal/otlp/IntAnyValueMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final value:J


# direct methods
.method private constructor <init>(J)V
    .locals 1

    .line 1
    invoke-static {p1, p2}, Lio/opentelemetry/exporter/internal/otlp/IntAnyValueMarshaler;->calculateSize(J)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iput-wide p1, p0, Lio/opentelemetry/exporter/internal/otlp/IntAnyValueMarshaler;->value:J

    .line 9
    .line 10
    return-void
.end method

.method private static calculateSize(J)I
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/common/v1/internal/AnyValue;->INT_VALUE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    invoke-virtual {v0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    invoke-static {p0, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeInt64SizeNoTag(J)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    add-int/2addr p0, v0

    .line 12
    return p0
.end method

.method public static create(J)Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/IntAnyValueMarshaler;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/exporter/internal/otlp/IntAnyValueMarshaler;-><init>(J)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 3

    .line 1
    sget-object v0, Lio/opentelemetry/proto/common/v1/internal/AnyValue;->INT_VALUE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/IntAnyValueMarshaler;->value:J

    .line 4
    .line 5
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->writeInt64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
