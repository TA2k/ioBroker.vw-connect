.class Lio/opentelemetry/api/metrics/DefaultMeter$NoopDoubleCounterBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/metrics/DoubleCounterBuilder;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/api/metrics/DefaultMeter;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "NoopDoubleCounterBuilder"
.end annotation


# static fields
.field private static final NOOP_COUNTER:Lio/opentelemetry/api/metrics/DoubleCounter;

.field private static final NOOP_OBSERVABLE_COUNTER:Lio/opentelemetry/api/metrics/ObservableDoubleCounter;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/api/metrics/DefaultMeter$NoopDoubleCounter;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/api/metrics/DefaultMeter$NoopDoubleCounter;-><init>(Lio/opentelemetry/api/metrics/DefaultMeter$1;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lio/opentelemetry/api/metrics/DefaultMeter$NoopDoubleCounterBuilder;->NOOP_COUNTER:Lio/opentelemetry/api/metrics/DoubleCounter;

    .line 8
    .line 9
    new-instance v0, Lio/opentelemetry/api/metrics/DefaultMeter$NoopDoubleCounterBuilder$1;

    .line 10
    .line 11
    invoke-direct {v0}, Lio/opentelemetry/api/metrics/DefaultMeter$NoopDoubleCounterBuilder$1;-><init>()V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lio/opentelemetry/api/metrics/DefaultMeter$NoopDoubleCounterBuilder;->NOOP_OBSERVABLE_COUNTER:Lio/opentelemetry/api/metrics/ObservableDoubleCounter;

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

.method public synthetic constructor <init>(Lio/opentelemetry/api/metrics/DefaultMeter$1;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Lio/opentelemetry/api/metrics/DefaultMeter$NoopDoubleCounterBuilder;-><init>()V

    return-void
.end method


# virtual methods
.method public build()Lio/opentelemetry/api/metrics/DoubleCounter;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/api/metrics/DefaultMeter$NoopDoubleCounterBuilder;->NOOP_COUNTER:Lio/opentelemetry/api/metrics/DoubleCounter;

    .line 2
    .line 3
    return-object p0
.end method

.method public buildObserver()Lio/opentelemetry/api/metrics/ObservableDoubleMeasurement;
    .locals 0

    .line 1
    invoke-static {}, Lio/opentelemetry/api/metrics/DefaultMeter;->access$1000()Lio/opentelemetry/api/metrics/ObservableDoubleMeasurement;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public buildWithCallback(Ljava/util/function/Consumer;)Lio/opentelemetry/api/metrics/ObservableDoubleCounter;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Consumer<",
            "Lio/opentelemetry/api/metrics/ObservableDoubleMeasurement;",
            ">;)",
            "Lio/opentelemetry/api/metrics/ObservableDoubleCounter;"
        }
    .end annotation

    .line 1
    sget-object p0, Lio/opentelemetry/api/metrics/DefaultMeter$NoopDoubleCounterBuilder;->NOOP_OBSERVABLE_COUNTER:Lio/opentelemetry/api/metrics/ObservableDoubleCounter;

    .line 2
    .line 3
    return-object p0
.end method

.method public setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleCounterBuilder;
    .locals 0

    .line 1
    return-object p0
.end method

.method public setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleCounterBuilder;
    .locals 0

    .line 1
    return-object p0
.end method
