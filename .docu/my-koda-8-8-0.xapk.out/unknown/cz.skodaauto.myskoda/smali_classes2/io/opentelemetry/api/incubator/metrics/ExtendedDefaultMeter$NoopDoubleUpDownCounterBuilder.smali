.class Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopDoubleUpDownCounterBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/incubator/metrics/ExtendedDoubleUpDownCounterBuilder;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "NoopDoubleUpDownCounterBuilder"
.end annotation


# static fields
.field private static final NOOP_OBSERVABLE_UP_DOWN_COUNTER:Lio/opentelemetry/api/metrics/ObservableDoubleUpDownCounter;

.field private static final NOOP_UP_DOWN_COUNTER:Lio/opentelemetry/api/metrics/DoubleUpDownCounter;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopDoubleUpDownCounterBuilder$1;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopDoubleUpDownCounterBuilder$1;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopDoubleUpDownCounterBuilder;->NOOP_UP_DOWN_COUNTER:Lio/opentelemetry/api/metrics/DoubleUpDownCounter;

    .line 7
    .line 8
    new-instance v0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopDoubleUpDownCounterBuilder$2;

    .line 9
    .line 10
    invoke-direct {v0}, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopDoubleUpDownCounterBuilder$2;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopDoubleUpDownCounterBuilder;->NOOP_OBSERVABLE_UP_DOWN_COUNTER:Lio/opentelemetry/api/metrics/ObservableDoubleUpDownCounter;

    .line 14
    .line 15
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
    invoke-direct {p0}, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopDoubleUpDownCounterBuilder;-><init>()V

    return-void
.end method


# virtual methods
.method public build()Lio/opentelemetry/api/metrics/DoubleUpDownCounter;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopDoubleUpDownCounterBuilder;->NOOP_UP_DOWN_COUNTER:Lio/opentelemetry/api/metrics/DoubleUpDownCounter;

    .line 2
    .line 3
    return-object p0
.end method

.method public buildObserver()Lio/opentelemetry/api/metrics/ObservableDoubleMeasurement;
    .locals 0

    .line 1
    invoke-static {}, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter;->access$1000()Lio/opentelemetry/api/metrics/ObservableDoubleMeasurement;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public buildWithCallback(Ljava/util/function/Consumer;)Lio/opentelemetry/api/metrics/ObservableDoubleUpDownCounter;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Consumer<",
            "Lio/opentelemetry/api/metrics/ObservableDoubleMeasurement;",
            ">;)",
            "Lio/opentelemetry/api/metrics/ObservableDoubleUpDownCounter;"
        }
    .end annotation

    .line 1
    sget-object p0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopDoubleUpDownCounterBuilder;->NOOP_OBSERVABLE_UP_DOWN_COUNTER:Lio/opentelemetry/api/metrics/ObservableDoubleUpDownCounter;

    .line 2
    .line 3
    return-object p0
.end method

.method public setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleUpDownCounterBuilder;
    .locals 0

    .line 1
    return-object p0
.end method

.method public setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleUpDownCounterBuilder;
    .locals 0

    .line 1
    return-object p0
.end method
