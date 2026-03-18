.class Lio/opentelemetry/api/GlobalOpenTelemetry$ObfuscatedOpenTelemetry;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/OpenTelemetry;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/api/GlobalOpenTelemetry;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "ObfuscatedOpenTelemetry"
.end annotation

.annotation build Ljavax/annotation/concurrent/ThreadSafe;
.end annotation


# instance fields
.field private final delegate:Lio/opentelemetry/api/OpenTelemetry;


# direct methods
.method public constructor <init>(Lio/opentelemetry/api/OpenTelemetry;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/api/GlobalOpenTelemetry$ObfuscatedOpenTelemetry;->delegate:Lio/opentelemetry/api/OpenTelemetry;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public getLogsBridge()Lio/opentelemetry/api/logs/LoggerProvider;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/api/GlobalOpenTelemetry$ObfuscatedOpenTelemetry;->delegate:Lio/opentelemetry/api/OpenTelemetry;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/api/OpenTelemetry;->getLogsBridge()Lio/opentelemetry/api/logs/LoggerProvider;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getMeterProvider()Lio/opentelemetry/api/metrics/MeterProvider;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/api/GlobalOpenTelemetry$ObfuscatedOpenTelemetry;->delegate:Lio/opentelemetry/api/OpenTelemetry;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/api/OpenTelemetry;->getMeterProvider()Lio/opentelemetry/api/metrics/MeterProvider;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getPropagators()Lio/opentelemetry/context/propagation/ContextPropagators;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/api/GlobalOpenTelemetry$ObfuscatedOpenTelemetry;->delegate:Lio/opentelemetry/api/OpenTelemetry;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/api/OpenTelemetry;->getPropagators()Lio/opentelemetry/context/propagation/ContextPropagators;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getTracerProvider()Lio/opentelemetry/api/trace/TracerProvider;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/api/GlobalOpenTelemetry$ObfuscatedOpenTelemetry;->delegate:Lio/opentelemetry/api/OpenTelemetry;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/api/OpenTelemetry;->getTracerProvider()Lio/opentelemetry/api/trace/TracerProvider;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public tracerBuilder(Ljava/lang/String;)Lio/opentelemetry/api/trace/TracerBuilder;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/api/GlobalOpenTelemetry$ObfuscatedOpenTelemetry;->delegate:Lio/opentelemetry/api/OpenTelemetry;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lio/opentelemetry/api/OpenTelemetry;->tracerBuilder(Ljava/lang/String;)Lio/opentelemetry/api/trace/TracerBuilder;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
