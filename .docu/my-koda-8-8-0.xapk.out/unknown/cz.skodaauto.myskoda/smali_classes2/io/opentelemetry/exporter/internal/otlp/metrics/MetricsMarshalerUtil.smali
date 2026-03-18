.class final Lio/opentelemetry/exporter/internal/otlp/metrics/MetricsMarshalerUtil;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static mapToTemporality(Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;)Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricsMarshalerUtil$1;->$SwitchMap$io$opentelemetry$sdk$metrics$data$AggregationTemporality:[I

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    aget p0, v0, p0

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    if-eq p0, v0, :cond_1

    .line 11
    .line 12
    const/4 v0, 0x2

    .line 13
    if-eq p0, v0, :cond_0

    .line 14
    .line 15
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/AggregationTemporality;->AGGREGATION_TEMPORALITY_UNSPECIFIED:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/AggregationTemporality;->AGGREGATION_TEMPORALITY_DELTA:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 19
    .line 20
    return-object p0

    .line 21
    :cond_1
    sget-object p0, Lio/opentelemetry/proto/metrics/v1/internal/AggregationTemporality;->AGGREGATION_TEMPORALITY_CUMULATIVE:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 22
    .line 23
    return-object p0
.end method
