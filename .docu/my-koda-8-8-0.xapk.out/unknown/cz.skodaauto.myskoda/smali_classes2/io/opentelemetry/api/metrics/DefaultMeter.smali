.class Lio/opentelemetry/api/metrics/DefaultMeter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/metrics/Meter;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongCounterBuilder;,
        Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongUpDownCounterBuilder;,
        Lio/opentelemetry/api/metrics/DefaultMeter$NoopDoubleHistogramBuilder;,
        Lio/opentelemetry/api/metrics/DefaultMeter$NoopDoubleGaugeBuilder;,
        Lio/opentelemetry/api/metrics/DefaultMeter$NoopObservableDoubleMeasurement;,
        Lio/opentelemetry/api/metrics/DefaultMeter$NoopObservableLongMeasurement;,
        Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongGauge;,
        Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongGaugeBuilder;,
        Lio/opentelemetry/api/metrics/DefaultMeter$NoopDoubleGauge;,
        Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongHistogramBuilder;,
        Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongHistogram;,
        Lio/opentelemetry/api/metrics/DefaultMeter$NoopDoubleHistogram;,
        Lio/opentelemetry/api/metrics/DefaultMeter$NoopDoubleUpDownCounterBuilder;,
        Lio/opentelemetry/api/metrics/DefaultMeter$NoopDoubleUpDownCounter;,
        Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongUpDownCounter;,
        Lio/opentelemetry/api/metrics/DefaultMeter$NoopDoubleCounterBuilder;,
        Lio/opentelemetry/api/metrics/DefaultMeter$NoopDoubleCounter;,
        Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongCounter;
    }
.end annotation

.annotation build Ljavax/annotation/concurrent/ThreadSafe;
.end annotation


# static fields
.field private static final INSTANCE:Lio/opentelemetry/api/metrics/Meter;

.field private static final NOOP_BATCH_CALLBACK:Lio/opentelemetry/api/metrics/BatchCallback;

.field private static final NOOP_DOUBLE_GAUGE_BUILDER:Lio/opentelemetry/api/metrics/DoubleGaugeBuilder;

.field private static final NOOP_DOUBLE_HISTOGRAM_BUILDER:Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

.field private static final NOOP_LONG_COUNTER_BUILDER:Lio/opentelemetry/api/metrics/LongCounterBuilder;

.field private static final NOOP_LONG_UP_DOWN_COUNTER_BUILDER:Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

.field private static final NOOP_OBSERVABLE_DOUBLE_MEASUREMENT:Lio/opentelemetry/api/metrics/ObservableDoubleMeasurement;

.field private static final NOOP_OBSERVABLE_LONG_MEASUREMENT:Lio/opentelemetry/api/metrics/ObservableLongMeasurement;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/api/metrics/DefaultMeter;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/api/metrics/DefaultMeter;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/api/metrics/DefaultMeter;->INSTANCE:Lio/opentelemetry/api/metrics/Meter;

    .line 7
    .line 8
    new-instance v0, Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongCounterBuilder;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    invoke-direct {v0, v1}, Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongCounterBuilder;-><init>(Lio/opentelemetry/api/metrics/DefaultMeter$1;)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lio/opentelemetry/api/metrics/DefaultMeter;->NOOP_LONG_COUNTER_BUILDER:Lio/opentelemetry/api/metrics/LongCounterBuilder;

    .line 15
    .line 16
    new-instance v0, Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongUpDownCounterBuilder;

    .line 17
    .line 18
    invoke-direct {v0, v1}, Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongUpDownCounterBuilder;-><init>(Lio/opentelemetry/api/metrics/DefaultMeter$1;)V

    .line 19
    .line 20
    .line 21
    sput-object v0, Lio/opentelemetry/api/metrics/DefaultMeter;->NOOP_LONG_UP_DOWN_COUNTER_BUILDER:Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

    .line 22
    .line 23
    new-instance v0, Lio/opentelemetry/api/metrics/DefaultMeter$NoopDoubleHistogramBuilder;

    .line 24
    .line 25
    invoke-direct {v0, v1}, Lio/opentelemetry/api/metrics/DefaultMeter$NoopDoubleHistogramBuilder;-><init>(Lio/opentelemetry/api/metrics/DefaultMeter$1;)V

    .line 26
    .line 27
    .line 28
    sput-object v0, Lio/opentelemetry/api/metrics/DefaultMeter;->NOOP_DOUBLE_HISTOGRAM_BUILDER:Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 29
    .line 30
    new-instance v0, Lio/opentelemetry/api/metrics/DefaultMeter$NoopDoubleGaugeBuilder;

    .line 31
    .line 32
    invoke-direct {v0, v1}, Lio/opentelemetry/api/metrics/DefaultMeter$NoopDoubleGaugeBuilder;-><init>(Lio/opentelemetry/api/metrics/DefaultMeter$1;)V

    .line 33
    .line 34
    .line 35
    sput-object v0, Lio/opentelemetry/api/metrics/DefaultMeter;->NOOP_DOUBLE_GAUGE_BUILDER:Lio/opentelemetry/api/metrics/DoubleGaugeBuilder;

    .line 36
    .line 37
    new-instance v0, Lio/opentelemetry/api/metrics/DefaultMeter$1;

    .line 38
    .line 39
    invoke-direct {v0}, Lio/opentelemetry/api/metrics/DefaultMeter$1;-><init>()V

    .line 40
    .line 41
    .line 42
    sput-object v0, Lio/opentelemetry/api/metrics/DefaultMeter;->NOOP_BATCH_CALLBACK:Lio/opentelemetry/api/metrics/BatchCallback;

    .line 43
    .line 44
    new-instance v0, Lio/opentelemetry/api/metrics/DefaultMeter$NoopObservableDoubleMeasurement;

    .line 45
    .line 46
    invoke-direct {v0, v1}, Lio/opentelemetry/api/metrics/DefaultMeter$NoopObservableDoubleMeasurement;-><init>(Lio/opentelemetry/api/metrics/DefaultMeter$1;)V

    .line 47
    .line 48
    .line 49
    sput-object v0, Lio/opentelemetry/api/metrics/DefaultMeter;->NOOP_OBSERVABLE_DOUBLE_MEASUREMENT:Lio/opentelemetry/api/metrics/ObservableDoubleMeasurement;

    .line 50
    .line 51
    new-instance v0, Lio/opentelemetry/api/metrics/DefaultMeter$NoopObservableLongMeasurement;

    .line 52
    .line 53
    invoke-direct {v0, v1}, Lio/opentelemetry/api/metrics/DefaultMeter$NoopObservableLongMeasurement;-><init>(Lio/opentelemetry/api/metrics/DefaultMeter$1;)V

    .line 54
    .line 55
    .line 56
    sput-object v0, Lio/opentelemetry/api/metrics/DefaultMeter;->NOOP_OBSERVABLE_LONG_MEASUREMENT:Lio/opentelemetry/api/metrics/ObservableLongMeasurement;

    .line 57
    .line 58
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic access$1000()Lio/opentelemetry/api/metrics/ObservableDoubleMeasurement;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/api/metrics/DefaultMeter;->NOOP_OBSERVABLE_DOUBLE_MEASUREMENT:Lio/opentelemetry/api/metrics/ObservableDoubleMeasurement;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic access$800()Lio/opentelemetry/api/metrics/ObservableLongMeasurement;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/api/metrics/DefaultMeter;->NOOP_OBSERVABLE_LONG_MEASUREMENT:Lio/opentelemetry/api/metrics/ObservableLongMeasurement;

    .line 2
    .line 3
    return-object v0
.end method

.method public static getInstance()Lio/opentelemetry/api/metrics/Meter;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/api/metrics/DefaultMeter;->INSTANCE:Lio/opentelemetry/api/metrics/Meter;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public varargs batchCallback(Ljava/lang/Runnable;Lio/opentelemetry/api/metrics/ObservableMeasurement;[Lio/opentelemetry/api/metrics/ObservableMeasurement;)Lio/opentelemetry/api/metrics/BatchCallback;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/api/metrics/DefaultMeter;->NOOP_BATCH_CALLBACK:Lio/opentelemetry/api/metrics/BatchCallback;

    .line 2
    .line 3
    return-object p0
.end method

.method public counterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongCounterBuilder;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/api/metrics/DefaultMeter;->NOOP_LONG_COUNTER_BUILDER:Lio/opentelemetry/api/metrics/LongCounterBuilder;

    .line 2
    .line 3
    return-object p0
.end method

.method public gaugeBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleGaugeBuilder;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/api/metrics/DefaultMeter;->NOOP_DOUBLE_GAUGE_BUILDER:Lio/opentelemetry/api/metrics/DoubleGaugeBuilder;

    .line 2
    .line 3
    return-object p0
.end method

.method public histogramBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/api/metrics/DefaultMeter;->NOOP_DOUBLE_HISTOGRAM_BUILDER:Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 2
    .line 3
    return-object p0
.end method

.method public upDownCounterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/api/metrics/DefaultMeter;->NOOP_LONG_UP_DOWN_COUNTER_BUILDER:Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

    .line 2
    .line 3
    return-object p0
.end method
