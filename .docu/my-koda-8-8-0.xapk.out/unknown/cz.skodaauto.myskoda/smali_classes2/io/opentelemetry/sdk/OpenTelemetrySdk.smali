.class public Lio/opentelemetry/sdk/OpenTelemetrySdk;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/OpenTelemetry;
.implements Ljava/io/Closeable;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedTracerProvider;,
        Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedMeterProvider;,
        Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedLoggerProvider;
    }
.end annotation

.annotation build Ljavax/annotation/concurrent/ThreadSafe;
.end annotation


# static fields
.field private static final LOGGER:Ljava/util/logging/Logger;


# instance fields
.field private final isShutdown:Ljava/util/concurrent/atomic/AtomicBoolean;

.field private final loggerProvider:Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedLoggerProvider;

.field private final meterProvider:Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedMeterProvider;

.field private final propagators:Lio/opentelemetry/context/propagation/ContextPropagators;

.field private final tracerProvider:Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedTracerProvider;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/sdk/OpenTelemetrySdk;

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
    sput-object v0, Lio/opentelemetry/sdk/OpenTelemetrySdk;->LOGGER:Ljava/util/logging/Logger;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/sdk/trace/SdkTracerProvider;Lio/opentelemetry/sdk/metrics/SdkMeterProvider;Lio/opentelemetry/sdk/logs/SdkLoggerProvider;Lio/opentelemetry/context/propagation/ContextPropagators;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lio/opentelemetry/sdk/OpenTelemetrySdk;->isShutdown:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 11
    .line 12
    new-instance v0, Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedTracerProvider;

    .line 13
    .line 14
    invoke-direct {v0, p1}, Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedTracerProvider;-><init>(Lio/opentelemetry/sdk/trace/SdkTracerProvider;)V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lio/opentelemetry/sdk/OpenTelemetrySdk;->tracerProvider:Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedTracerProvider;

    .line 18
    .line 19
    new-instance p1, Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedMeterProvider;

    .line 20
    .line 21
    invoke-direct {p1, p2}, Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedMeterProvider;-><init>(Lio/opentelemetry/sdk/metrics/SdkMeterProvider;)V

    .line 22
    .line 23
    .line 24
    iput-object p1, p0, Lio/opentelemetry/sdk/OpenTelemetrySdk;->meterProvider:Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedMeterProvider;

    .line 25
    .line 26
    new-instance p1, Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedLoggerProvider;

    .line 27
    .line 28
    invoke-direct {p1, p3}, Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedLoggerProvider;-><init>(Lio/opentelemetry/sdk/logs/SdkLoggerProvider;)V

    .line 29
    .line 30
    .line 31
    iput-object p1, p0, Lio/opentelemetry/sdk/OpenTelemetrySdk;->loggerProvider:Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedLoggerProvider;

    .line 32
    .line 33
    iput-object p4, p0, Lio/opentelemetry/sdk/OpenTelemetrySdk;->propagators:Lio/opentelemetry/context/propagation/ContextPropagators;

    .line 34
    .line 35
    return-void
.end method

.method public static builder()Lio/opentelemetry/sdk/OpenTelemetrySdkBuilder;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/OpenTelemetrySdkBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/sdk/OpenTelemetrySdkBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public close()V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/OpenTelemetrySdk;->shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-wide/16 v0, 0xa

    .line 6
    .line 7
    sget-object v2, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 8
    .line 9
    invoke-virtual {p0, v0, v1, v2}, Lio/opentelemetry/sdk/common/CompletableResultCode;->join(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public final getLogsBridge()Lio/opentelemetry/api/logs/LoggerProvider;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/OpenTelemetrySdk;->loggerProvider:Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedLoggerProvider;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getMeterProvider()Lio/opentelemetry/api/metrics/MeterProvider;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/OpenTelemetrySdk;->meterProvider:Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedMeterProvider;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPropagators()Lio/opentelemetry/context/propagation/ContextPropagators;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/OpenTelemetrySdk;->propagators:Lio/opentelemetry/context/propagation/ContextPropagators;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getSdkLoggerProvider()Lio/opentelemetry/sdk/logs/SdkLoggerProvider;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/OpenTelemetrySdk;->loggerProvider:Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedLoggerProvider;

    .line 2
    .line 3
    invoke-virtual {p0}, Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedLoggerProvider;->unobfuscate()Lio/opentelemetry/sdk/logs/SdkLoggerProvider;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final getSdkMeterProvider()Lio/opentelemetry/sdk/metrics/SdkMeterProvider;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/OpenTelemetrySdk;->meterProvider:Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedMeterProvider;

    .line 2
    .line 3
    invoke-virtual {p0}, Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedMeterProvider;->unobfuscate()Lio/opentelemetry/sdk/metrics/SdkMeterProvider;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final getSdkTracerProvider()Lio/opentelemetry/sdk/trace/SdkTracerProvider;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/OpenTelemetrySdk;->tracerProvider:Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedTracerProvider;

    .line 2
    .line 3
    invoke-virtual {p0}, Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedTracerProvider;->unobfuscate()Lio/opentelemetry/sdk/trace/SdkTracerProvider;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final getTracerProvider()Lio/opentelemetry/api/trace/TracerProvider;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/OpenTelemetrySdk;->tracerProvider:Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedTracerProvider;

    .line 2
    .line 3
    return-object p0
.end method

.method public shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/OpenTelemetrySdk;->isShutdown:Ljava/util/concurrent/atomic/AtomicBoolean;

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
    sget-object p0, Lio/opentelemetry/sdk/OpenTelemetrySdk;->LOGGER:Ljava/util/logging/Logger;

    .line 12
    .line 13
    const-string v0, "Multiple shutdown calls"

    .line 14
    .line 15
    invoke-virtual {p0, v0}, Ljava/util/logging/Logger;->info(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-static {}, Lio/opentelemetry/sdk/common/CompletableResultCode;->ofSuccess()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :cond_0
    new-instance v0, Ljava/util/ArrayList;

    .line 24
    .line 25
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lio/opentelemetry/sdk/OpenTelemetrySdk;->tracerProvider:Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedTracerProvider;

    .line 29
    .line 30
    invoke-virtual {v1}, Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedTracerProvider;->unobfuscate()Lio/opentelemetry/sdk/trace/SdkTracerProvider;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    invoke-virtual {v1}, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    iget-object v1, p0, Lio/opentelemetry/sdk/OpenTelemetrySdk;->meterProvider:Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedMeterProvider;

    .line 42
    .line 43
    invoke-virtual {v1}, Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedMeterProvider;->unobfuscate()Lio/opentelemetry/sdk/metrics/SdkMeterProvider;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    invoke-virtual {v1}, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    iget-object p0, p0, Lio/opentelemetry/sdk/OpenTelemetrySdk;->loggerProvider:Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedLoggerProvider;

    .line 55
    .line 56
    invoke-virtual {p0}, Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedLoggerProvider;->unobfuscate()Lio/opentelemetry/sdk/logs/SdkLoggerProvider;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    invoke-virtual {p0}, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;->shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    invoke-static {v0}, Lio/opentelemetry/sdk/common/CompletableResultCode;->ofAll(Ljava/util/Collection;)Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "OpenTelemetrySdk{tracerProvider="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lio/opentelemetry/sdk/OpenTelemetrySdk;->tracerProvider:Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedTracerProvider;

    .line 9
    .line 10
    invoke-virtual {v1}, Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedTracerProvider;->unobfuscate()Lio/opentelemetry/sdk/trace/SdkTracerProvider;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string v1, ", meterProvider="

    .line 18
    .line 19
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    iget-object v1, p0, Lio/opentelemetry/sdk/OpenTelemetrySdk;->meterProvider:Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedMeterProvider;

    .line 23
    .line 24
    invoke-virtual {v1}, Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedMeterProvider;->unobfuscate()Lio/opentelemetry/sdk/metrics/SdkMeterProvider;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v1, ", loggerProvider="

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget-object v1, p0, Lio/opentelemetry/sdk/OpenTelemetrySdk;->loggerProvider:Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedLoggerProvider;

    .line 37
    .line 38
    invoke-virtual {v1}, Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedLoggerProvider;->unobfuscate()Lio/opentelemetry/sdk/logs/SdkLoggerProvider;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const-string v1, ", propagators="

    .line 46
    .line 47
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    iget-object p0, p0, Lio/opentelemetry/sdk/OpenTelemetrySdk;->propagators:Lio/opentelemetry/context/propagation/ContextPropagators;

    .line 51
    .line 52
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    const-string p0, "}"

    .line 56
    .line 57
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    return-object p0
.end method
