.class Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongCounterBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/incubator/metrics/ExtendedLongCounterBuilder;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "NoopLongCounterBuilder"
.end annotation


# static fields
.field private static final NOOP_COUNTER:Lio/opentelemetry/api/metrics/LongCounter;

.field private static final NOOP_DOUBLE_COUNTER_BUILDER:Lio/opentelemetry/api/metrics/DoubleCounterBuilder;

.field private static final NOOP_OBSERVABLE_COUNTER:Lio/opentelemetry/api/metrics/ObservableLongCounter;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongCounter;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongCounter;-><init>(Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$1;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongCounterBuilder;->NOOP_COUNTER:Lio/opentelemetry/api/metrics/LongCounter;

    .line 8
    .line 9
    new-instance v0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongCounterBuilder$1;

    .line 10
    .line 11
    invoke-direct {v0}, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongCounterBuilder$1;-><init>()V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongCounterBuilder;->NOOP_OBSERVABLE_COUNTER:Lio/opentelemetry/api/metrics/ObservableLongCounter;

    .line 15
    .line 16
    new-instance v0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopDoubleCounterBuilder;

    .line 17
    .line 18
    invoke-direct {v0, v1}, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopDoubleCounterBuilder;-><init>(Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$1;)V

    .line 19
    .line 20
    .line 21
    sput-object v0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongCounterBuilder;->NOOP_DOUBLE_COUNTER_BUILDER:Lio/opentelemetry/api/metrics/DoubleCounterBuilder;

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

.method public synthetic constructor <init>(Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$1;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongCounterBuilder;-><init>()V

    return-void
.end method


# virtual methods
.method public build()Lio/opentelemetry/api/metrics/LongCounter;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongCounterBuilder;->NOOP_COUNTER:Lio/opentelemetry/api/metrics/LongCounter;

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

.method public buildWithCallback(Ljava/util/function/Consumer;)Lio/opentelemetry/api/metrics/ObservableLongCounter;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Consumer<",
            "Lio/opentelemetry/api/metrics/ObservableLongMeasurement;",
            ">;)",
            "Lio/opentelemetry/api/metrics/ObservableLongCounter;"
        }
    .end annotation

    .line 1
    sget-object p0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongCounterBuilder;->NOOP_OBSERVABLE_COUNTER:Lio/opentelemetry/api/metrics/ObservableLongCounter;

    .line 2
    .line 3
    return-object p0
.end method

.method public ofDoubles()Lio/opentelemetry/api/metrics/DoubleCounterBuilder;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeter$NoopLongCounterBuilder;->NOOP_DOUBLE_COUNTER_BUILDER:Lio/opentelemetry/api/metrics/DoubleCounterBuilder;

    .line 2
    .line 3
    return-object p0
.end method

.method public setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongCounterBuilder;
    .locals 0

    .line 1
    return-object p0
.end method

.method public setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongCounterBuilder;
    .locals 0

    .line 1
    return-object p0
.end method
