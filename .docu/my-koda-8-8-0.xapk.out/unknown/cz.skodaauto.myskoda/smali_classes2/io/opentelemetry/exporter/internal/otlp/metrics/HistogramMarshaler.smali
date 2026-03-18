.class final Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final aggregationTemporality:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

.field private final dataPoints:[Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;


# direct methods
.method private constructor <init>([Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;)V
    .locals 1

    .line 1
    invoke-static {p1, p2}, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramMarshaler;->calculateSize([Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramMarshaler;->dataPoints:[Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;

    .line 9
    .line 10
    iput-object p2, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramMarshaler;->aggregationTemporality:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 11
    .line 12
    return-void
.end method

.method private static calculateSize([Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;)I
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Histogram;->DATA_POINTS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    invoke-static {v0, p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Histogram;->AGGREGATION_TEMPORALITY:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 8
    .line 9
    invoke-static {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeEnum(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;)I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    add-int/2addr p1, p0

    .line 14
    return p1
.end method

.method public static create(Lio/opentelemetry/sdk/metrics/data/HistogramData;)Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramMarshaler;
    .locals 2

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/data/HistogramData;->getPoints()Ljava/util/Collection;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;->createRepeated(Ljava/util/Collection;)[Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    new-instance v1, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramMarshaler;

    .line 10
    .line 11
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/data/HistogramData;->getAggregationTemporality()Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricsMarshalerUtil;->mapToTemporality(Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;)Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-direct {v1, v0, p0}, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramMarshaler;-><init>([Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;)V

    .line 20
    .line 21
    .line 22
    return-object v1
.end method


# virtual methods
.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 2

    .line 1
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Histogram;->DATA_POINTS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramMarshaler;->dataPoints:[Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramDataPointMarshaler;

    .line 4
    .line 5
    invoke-virtual {p1, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 6
    .line 7
    .line 8
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Histogram;->AGGREGATION_TEMPORALITY:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 9
    .line 10
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/HistogramMarshaler;->aggregationTemporality:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 11
    .line 12
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeEnum(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method
