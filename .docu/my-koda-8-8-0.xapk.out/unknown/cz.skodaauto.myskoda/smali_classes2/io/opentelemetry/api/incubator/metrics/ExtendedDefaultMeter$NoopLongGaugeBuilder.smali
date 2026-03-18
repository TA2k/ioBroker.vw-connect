.class Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongGaugeBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/incubator/metrics/ExtendedLongGaugeBuilder;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "NoopLongGaugeBuilder"
.end annotation


# static fields
.field private static final NOOP_GAUGE:Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongGauge;

.field private static final NOOP_OBSERVABLE_GAUGE:Lio/opentelemetry/api/metrics/ObservableLongGauge;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongGaugeBuilder$1;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongGaugeBuilder$1;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongGaugeBuilder;->NOOP_OBSERVABLE_GAUGE:Lio/opentelemetry/api/metrics/ObservableLongGauge;

    .line 7
    .line 8
    new-instance v0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongGauge;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    invoke-direct {v0, v1}, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongGauge;-><init>(Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$1;)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongGaugeBuilder;->NOOP_GAUGE:Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongGauge;

    .line 15
    .line 16
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$1;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongGaugeBuilder;-><init>()V

    return-void
.end method


# virtual methods
.method public build()Lio/opentelemetry/api/metrics/LongGauge;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongGaugeBuilder;->NOOP_GAUGE:Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongGauge;

    .line 2
    .line 3
    return-object p0
.end method

.method public buildObserver()Lio/opentelemetry/api/metrics/ObservableLongMeasurement;
    .locals 0

    .line 1
    invoke-static {}, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter;->access$800()Lio/opentelemetry/api/metrics/ObservableLongMeasurement;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public buildWithCallback(Ljava/util/function/Consumer;)Lio/opentelemetry/api/metrics/ObservableLongGauge;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Consumer<",
            "Lio/opentelemetry/api/metrics/ObservableLongMeasurement;",
            ">;)",
            "Lio/opentelemetry/api/metrics/ObservableLongGauge;"
        }
    .end annotation

    .line 1
    sget-object p0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongGaugeBuilder;->NOOP_OBSERVABLE_GAUGE:Lio/opentelemetry/api/metrics/ObservableLongGauge;

    .line 2
    .line 3
    return-object p0
.end method

.method public setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongGaugeBuilder;
    .locals 0

    .line 1
    return-object p0
.end method

.method public setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongGaugeBuilder;
    .locals 0

    .line 1
    return-object p0
.end method
