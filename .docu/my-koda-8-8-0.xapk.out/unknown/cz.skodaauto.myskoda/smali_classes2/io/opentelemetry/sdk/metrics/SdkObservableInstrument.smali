.class Lio/opentelemetry/sdk/metrics/SdkObservableInstrument;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/metrics/ObservableDoubleCounter;
.implements Lio/opentelemetry/api/metrics/ObservableLongCounter;
.implements Lio/opentelemetry/api/metrics/ObservableDoubleGauge;
.implements Lio/opentelemetry/api/metrics/ObservableLongGauge;
.implements Lio/opentelemetry/api/metrics/ObservableDoubleUpDownCounter;
.implements Lio/opentelemetry/api/metrics/ObservableLongUpDownCounter;
.implements Lio/opentelemetry/api/metrics/BatchCallback;


# static fields
.field private static final logger:Ljava/util/logging/Logger;


# instance fields
.field private final callbackRegistration:Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;

.field private final removed:Ljava/util/concurrent/atomic/AtomicBoolean;

.field private final sdkMeter:Lio/opentelemetry/sdk/metrics/SdkMeter;

.field private final throttlingLogger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/sdk/metrics/SdkObservableInstrument;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lio/opentelemetry/sdk/metrics/SdkObservableInstrument;->logger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/sdk/metrics/SdkMeter;Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 5
    .line 6
    sget-object v1, Lio/opentelemetry/sdk/metrics/SdkObservableInstrument;->logger:Ljava/util/logging/Logger;

    .line 7
    .line 8
    invoke-direct {v0, v1}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;-><init>(Ljava/util/logging/Logger;)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkObservableInstrument;->throttlingLogger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 12
    .line 13
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 17
    .line 18
    .line 19
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkObservableInstrument;->removed:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 20
    .line 21
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/SdkObservableInstrument;->sdkMeter:Lio/opentelemetry/sdk/metrics/SdkMeter;

    .line 22
    .line 23
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/SdkObservableInstrument;->callbackRegistration:Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;

    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public close()V
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkObservableInstrument;->removed:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkObservableInstrument;->throttlingLogger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 12
    .line 13
    sget-object v1, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 14
    .line 15
    new-instance v2, Ljava/lang/StringBuilder;

    .line 16
    .line 17
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 18
    .line 19
    .line 20
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/SdkObservableInstrument;->callbackRegistration:Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;

    .line 21
    .line 22
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string p0, " has called close() multiple times."

    .line 26
    .line 27
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-virtual {v0, v1, p0}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkObservableInstrument;->sdkMeter:Lio/opentelemetry/sdk/metrics/SdkMeter;

    .line 39
    .line 40
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/SdkObservableInstrument;->callbackRegistration:Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;

    .line 41
    .line 42
    invoke-virtual {v0, p0}, Lio/opentelemetry/sdk/metrics/SdkMeter;->removeCallback(Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;)V

    .line 43
    .line 44
    .line 45
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "SdkObservableInstrument{callback="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/SdkObservableInstrument;->callbackRegistration:Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string p0, "}"

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method
