.class final Lio/opentelemetry/sdk/metrics/IncubatingUtil;
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

.method public static createExtendedDoubleGaugeBuilder(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleGaugeBuilder;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/ExtendedSdkDoubleGauge$ExtendedSdkDoubleGaugeBuilder;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/sdk/metrics/ExtendedSdkDoubleGauge$ExtendedSdkDoubleGaugeBuilder;-><init>(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static createExtendedDoubleHistogramBuilder(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/ExtendedSdkDoubleHistogram$ExtendedSdkDoubleHistogramBuilder;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/sdk/metrics/ExtendedSdkDoubleHistogram$ExtendedSdkDoubleHistogramBuilder;-><init>(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static createExtendedLongCounterBuilder(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongCounterBuilder;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/ExtendedSdkLongCounter$ExtendedSdkLongCounterBuilder;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/sdk/metrics/ExtendedSdkLongCounter$ExtendedSdkLongCounterBuilder;-><init>(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static createExtendedLongUpDownCounterBuilder(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/ExtendedSdkLongUpDownCounter$ExtendedSdkLongUpDownCounterBuilder;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/sdk/metrics/ExtendedSdkLongUpDownCounter$ExtendedSdkLongUpDownCounterBuilder;-><init>(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method
