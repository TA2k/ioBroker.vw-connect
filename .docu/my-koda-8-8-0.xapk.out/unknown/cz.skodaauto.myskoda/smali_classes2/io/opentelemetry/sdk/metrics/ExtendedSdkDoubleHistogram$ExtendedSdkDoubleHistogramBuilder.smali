.class final Lio/opentelemetry/sdk/metrics/ExtendedSdkDoubleHistogram$ExtendedSdkDoubleHistogramBuilder;
.super Lio/opentelemetry/sdk/metrics/SdkDoubleHistogram$SdkDoubleHistogramBuilder;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/incubator/metrics/ExtendedDoubleHistogramBuilder;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/sdk/metrics/ExtendedSdkDoubleHistogram;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "ExtendedSdkDoubleHistogramBuilder"
.end annotation


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/sdk/metrics/SdkDoubleHistogram$SdkDoubleHistogramBuilder;-><init>(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public bridge synthetic build()Lio/opentelemetry/api/metrics/DoubleHistogram;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/ExtendedSdkDoubleHistogram$ExtendedSdkDoubleHistogramBuilder;->build()Lio/opentelemetry/sdk/metrics/ExtendedSdkDoubleHistogram;

    move-result-object p0

    return-object p0
.end method

.method public build()Lio/opentelemetry/sdk/metrics/ExtendedSdkDoubleHistogram;
    .locals 2

    .line 3
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/SdkDoubleHistogram$SdkDoubleHistogramBuilder;->builder:Lio/opentelemetry/sdk/metrics/InstrumentBuilder;

    new-instance v0, Lio/opentelemetry/sdk/metrics/a;

    const/4 v1, 0x4

    invoke-direct {v0, v1}, Lio/opentelemetry/sdk/metrics/a;-><init>(I)V

    invoke-virtual {p0, v0}, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->buildSynchronousInstrument(Lio/opentelemetry/sdk/metrics/InstrumentBuilder$SynchronousInstrumentConstructor;)Lio/opentelemetry/sdk/metrics/AbstractInstrument;

    move-result-object p0

    check-cast p0, Lio/opentelemetry/sdk/metrics/ExtendedSdkDoubleHistogram;

    return-object p0
.end method

.method public bridge synthetic build()Lio/opentelemetry/sdk/metrics/SdkDoubleHistogram;
    .locals 0

    .line 2
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/ExtendedSdkDoubleHistogram$ExtendedSdkDoubleHistogramBuilder;->build()Lio/opentelemetry/sdk/metrics/ExtendedSdkDoubleHistogram;

    move-result-object p0

    return-object p0
.end method

.method public ofLongs()Lio/opentelemetry/api/incubator/metrics/ExtendedLongHistogramBuilder;
    .locals 2

    .line 2
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/SdkDoubleHistogram$SdkDoubleHistogramBuilder;->builder:Lio/opentelemetry/sdk/metrics/InstrumentBuilder;

    new-instance v0, Lio/opentelemetry/sdk/metrics/a;

    const/4 v1, 0x3

    invoke-direct {v0, v1}, Lio/opentelemetry/sdk/metrics/a;-><init>(I)V

    invoke-virtual {p0, v0}, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->swapBuilder(Lio/opentelemetry/sdk/metrics/InstrumentBuilder$SwapBuilder;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lio/opentelemetry/api/incubator/metrics/ExtendedLongHistogramBuilder;

    return-object p0
.end method

.method public bridge synthetic ofLongs()Lio/opentelemetry/api/metrics/LongHistogramBuilder;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/ExtendedSdkDoubleHistogram$ExtendedSdkDoubleHistogramBuilder;->ofLongs()Lio/opentelemetry/api/incubator/metrics/ExtendedLongHistogramBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setAttributesAdvice(Ljava/util/List;)Lio/opentelemetry/api/incubator/metrics/ExtendedDoubleHistogramBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "*>;>;)",
            "Lio/opentelemetry/api/incubator/metrics/ExtendedDoubleHistogramBuilder;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkDoubleHistogram$SdkDoubleHistogramBuilder;->builder:Lio/opentelemetry/sdk/metrics/InstrumentBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->setAdviceAttributes(Ljava/util/List;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method
