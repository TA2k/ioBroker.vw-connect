.class final Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final quantile:D

.field private final value:D


# direct methods
.method private constructor <init>(DD)V
    .locals 1

    .line 1
    invoke-static {p1, p2, p3, p4}, Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileMarshaler;->calculateSize(DD)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iput-wide p1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileMarshaler;->quantile:D

    .line 9
    .line 10
    iput-wide p3, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileMarshaler;->value:D

    .line 11
    .line 12
    return-void
.end method

.method public static calculateSize(DD)I
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint$ValueAtQuantile;->QUANTILE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    invoke-static {v0, p0, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeDouble(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    sget-object p1, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint$ValueAtQuantile;->VALUE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 8
    .line 9
    invoke-static {p1, p2, p3}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeDouble(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    add-int/2addr p1, p0

    .line 14
    return p1
.end method

.method private static create(Lio/opentelemetry/sdk/metrics/data/ValueAtQuantile;)Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileMarshaler;
    .locals 5

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileMarshaler;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/data/ValueAtQuantile;->getQuantile()D

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/data/ValueAtQuantile;->getValue()D

    .line 8
    .line 9
    .line 10
    move-result-wide v3

    .line 11
    invoke-direct {v0, v1, v2, v3, v4}, Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileMarshaler;-><init>(DD)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method public static createRepeated(Ljava/util/List;)[Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileMarshaler;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/data/ValueAtQuantile;",
            ">;)[",
            "Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileMarshaler;"
        }
    .end annotation

    .line 1
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    new-array v1, v0, [Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileMarshaler;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    :goto_0
    if-ge v2, v0, :cond_0

    .line 9
    .line 10
    invoke-interface {p0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v3

    .line 14
    check-cast v3, Lio/opentelemetry/sdk/metrics/data/ValueAtQuantile;

    .line 15
    .line 16
    invoke-static {v3}, Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileMarshaler;->create(Lio/opentelemetry/sdk/metrics/data/ValueAtQuantile;)Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileMarshaler;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    aput-object v3, v1, v2

    .line 21
    .line 22
    add-int/lit8 v2, v2, 0x1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    return-object v1
.end method


# virtual methods
.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 3

    .line 1
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint$ValueAtQuantile;->QUANTILE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileMarshaler;->quantile:D

    .line 4
    .line 5
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeDouble(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)V

    .line 6
    .line 7
    .line 8
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/SummaryDataPoint$ValueAtQuantile;->VALUE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 9
    .line 10
    iget-wide v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/ValueAtQuantileMarshaler;->value:D

    .line 11
    .line 12
    invoke-virtual {p1, v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeDouble(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)V

    .line 13
    .line 14
    .line 15
    return-void
.end method
