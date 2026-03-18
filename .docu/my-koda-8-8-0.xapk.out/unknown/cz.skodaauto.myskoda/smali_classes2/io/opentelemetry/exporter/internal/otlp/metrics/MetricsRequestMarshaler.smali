.class public final Lio/opentelemetry/exporter/internal/otlp/metrics/MetricsRequestMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final resourceMetricsMarshalers:[Lio/opentelemetry/exporter/internal/otlp/metrics/ResourceMetricsMarshaler;


# direct methods
.method private constructor <init>([Lio/opentelemetry/exporter/internal/otlp/metrics/ResourceMetricsMarshaler;)V
    .locals 1

    .line 1
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricsRequestMarshaler;->calculateSize([Lio/opentelemetry/exporter/internal/otlp/metrics/ResourceMetricsMarshaler;)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricsRequestMarshaler;->resourceMetricsMarshalers:[Lio/opentelemetry/exporter/internal/otlp/metrics/ResourceMetricsMarshaler;

    .line 9
    .line 10
    return-void
.end method

.method private static calculateSize([Lio/opentelemetry/exporter/internal/otlp/metrics/ResourceMetricsMarshaler;)I
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/collector/metrics/v1/internal/ExportMetricsServiceRequest;->RESOURCE_METRICS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

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

.method public static create(Ljava/util/Collection;)Lio/opentelemetry/exporter/internal/otlp/metrics/MetricsRequestMarshaler;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Lio/opentelemetry/sdk/metrics/data/MetricData;",
            ">;)",
            "Lio/opentelemetry/exporter/internal/otlp/metrics/MetricsRequestMarshaler;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricsRequestMarshaler;

    .line 2
    .line 3
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/otlp/metrics/ResourceMetricsMarshaler;->create(Ljava/util/Collection;)[Lio/opentelemetry/exporter/internal/otlp/metrics/ResourceMetricsMarshaler;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-direct {v0, p0}, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricsRequestMarshaler;-><init>([Lio/opentelemetry/exporter/internal/otlp/metrics/ResourceMetricsMarshaler;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method


# virtual methods
.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/proto/collector/metrics/v1/internal/ExportMetricsServiceRequest;->RESOURCE_METRICS:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricsRequestMarshaler;->resourceMetricsMarshalers:[Lio/opentelemetry/exporter/internal/otlp/metrics/ResourceMetricsMarshaler;

    .line 4
    .line 5
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
