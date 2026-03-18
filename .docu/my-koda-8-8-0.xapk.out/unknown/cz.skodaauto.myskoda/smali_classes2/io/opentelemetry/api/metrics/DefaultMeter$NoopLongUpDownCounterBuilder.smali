.class Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongUpDownCounterBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/api/metrics/DefaultMeter;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "NoopLongUpDownCounterBuilder"
.end annotation


# static fields
.field private static final NOOP_DOUBLE_UP_DOWN_COUNTER_BUILDER:Lio/opentelemetry/api/metrics/DoubleUpDownCounterBuilder;

.field private static final NOOP_OBSERVABLE_UP_DOWN_COUNTER:Lio/opentelemetry/api/metrics/ObservableLongUpDownCounter;

.field private static final NOOP_UP_DOWN_COUNTER:Lio/opentelemetry/api/metrics/LongUpDownCounter;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongUpDownCounterBuilder$1;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongUpDownCounterBuilder$1;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongUpDownCounterBuilder;->NOOP_UP_DOWN_COUNTER:Lio/opentelemetry/api/metrics/LongUpDownCounter;

    .line 7
    .line 8
    new-instance v0, Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongUpDownCounterBuilder$2;

    .line 9
    .line 10
    invoke-direct {v0}, Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongUpDownCounterBuilder$2;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongUpDownCounterBuilder;->NOOP_OBSERVABLE_UP_DOWN_COUNTER:Lio/opentelemetry/api/metrics/ObservableLongUpDownCounter;

    .line 14
    .line 15
    new-instance v0, Lio/opentelemetry/api/metrics/DefaultMeter$NoopDoubleUpDownCounterBuilder;

    .line 16
    .line 17
    const/4 v1, 0x0

    .line 18
    invoke-direct {v0, v1}, Lio/opentelemetry/api/metrics/DefaultMeter$NoopDoubleUpDownCounterBuilder;-><init>(Lio/opentelemetry/api/metrics/DefaultMeter$1;)V

    .line 19
    .line 20
    .line 21
    sput-object v0, Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongUpDownCounterBuilder;->NOOP_DOUBLE_UP_DOWN_COUNTER_BUILDER:Lio/opentelemetry/api/metrics/DoubleUpDownCounterBuilder;

    .line 22
    .line 23
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/api/metrics/DefaultMeter$1;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongUpDownCounterBuilder;-><init>()V

    return-void
.end method


# virtual methods
.method public build()Lio/opentelemetry/api/metrics/LongUpDownCounter;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongUpDownCounterBuilder;->NOOP_UP_DOWN_COUNTER:Lio/opentelemetry/api/metrics/LongUpDownCounter;

    .line 2
    .line 3
    return-object p0
.end method

.method public buildObserver()Lio/opentelemetry/api/metrics/ObservableLongMeasurement;
    .locals 0

    .line 1
    invoke-static {}, Lio/opentelemetry/api/metrics/DefaultMeter;->access$800()Lio/opentelemetry/api/metrics/ObservableLongMeasurement;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public buildWithCallback(Ljava/util/function/Consumer;)Lio/opentelemetry/api/metrics/ObservableLongUpDownCounter;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Consumer<",
            "Lio/opentelemetry/api/metrics/ObservableLongMeasurement;",
            ">;)",
            "Lio/opentelemetry/api/metrics/ObservableLongUpDownCounter;"
        }
    .end annotation

    .line 1
    sget-object p0, Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongUpDownCounterBuilder;->NOOP_OBSERVABLE_UP_DOWN_COUNTER:Lio/opentelemetry/api/metrics/ObservableLongUpDownCounter;

    .line 2
    .line 3
    return-object p0
.end method

.method public ofDoubles()Lio/opentelemetry/api/metrics/DoubleUpDownCounterBuilder;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongUpDownCounterBuilder;->NOOP_DOUBLE_UP_DOWN_COUNTER_BUILDER:Lio/opentelemetry/api/metrics/DoubleUpDownCounterBuilder;

    .line 2
    .line 3
    return-object p0
.end method

.method public setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;
    .locals 0

    .line 1
    return-object p0
.end method

.method public setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;
    .locals 0

    .line 1
    return-object p0
.end method
