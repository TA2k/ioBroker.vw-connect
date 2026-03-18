.class Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler$7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler<",
        "Lio/opentelemetry/sdk/metrics/data/MetricData;",
        ">;"
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public getBinarySerializedSize(Lio/opentelemetry/sdk/metrics/data/MetricData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 1

    .line 2
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/Metric;->EXPONENTIAL_HISTOGRAM:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 3
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/MetricData;->getExponentialHistogramData()Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramData;

    move-result-object p1

    sget-object v0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramStatelessMarshaler;

    .line 4
    invoke-static {p0, p1, v0, p2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0
.end method

.method public bridge synthetic getBinarySerializedSize(Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 0

    .line 1
    check-cast p1, Lio/opentelemetry/sdk/metrics/data/MetricData;

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler$7;->getBinarySerializedSize(Lio/opentelemetry/sdk/metrics/data/MetricData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0
.end method

.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/sdk/metrics/data/MetricData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 1

    .line 2
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/Metric;->EXPONENTIAL_HISTOGRAM:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 3
    invoke-interface {p2}, Lio/opentelemetry/sdk/metrics/data/MetricData;->getExponentialHistogramData()Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramData;

    move-result-object p2

    sget-object v0, Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/metrics/ExponentialHistogramStatelessMarshaler;

    .line 4
    invoke-virtual {p1, p0, p2, v0, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void
.end method

.method public bridge synthetic writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 0

    .line 1
    check-cast p2, Lio/opentelemetry/sdk/metrics/data/MetricData;

    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricStatelessMarshaler$7;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/sdk/metrics/data/MetricData;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void
.end method
