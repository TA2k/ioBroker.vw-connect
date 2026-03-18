.class final Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final dataPoints:[Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;


# direct methods
.method private constructor <init>([Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;)V
    .locals 1

    .line 1
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryMarshaler;->calculateSize([Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryMarshaler;->dataPoints:[Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;

    .line 9
    .line 10
    return-void
.end method

.method private static calculateSize([Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;)I
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Summary;->DATA_POINTS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

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

.method public static create(Lio/opentelemetry/sdk/metrics/data/SummaryData;)Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryMarshaler;
    .locals 1

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/sdk/metrics/data/Data;->getPoints()Ljava/util/Collection;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;->createRepeated(Ljava/util/Collection;)[Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryMarshaler;

    .line 10
    .line 11
    invoke-direct {v0, p0}, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryMarshaler;-><init>([Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method


# virtual methods
.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/metrics/v1/internal/Summary;->DATA_POINTS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryMarshaler;->dataPoints:[Lio/opentelemetry/exporter/internal/otlp/metrics/SummaryDataPointMarshaler;

    .line 4
    .line 5
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
