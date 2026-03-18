.class final Lio/opentelemetry/api/DefaultOpenTelemetry;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/OpenTelemetry;


# annotations
.annotation build Ljavax/annotation/concurrent/ThreadSafe;
.end annotation


# static fields
.field private static final NO_OP:Lio/opentelemetry/api/OpenTelemetry;


# instance fields
.field private final propagators:Lio/opentelemetry/context/propagation/ContextPropagators;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/api/DefaultOpenTelemetry;

    .line 2
    .line 3
    invoke-static {}, Lio/opentelemetry/context/propagation/ContextPropagators;->noop()Lio/opentelemetry/context/propagation/ContextPropagators;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-direct {v0, v1}, Lio/opentelemetry/api/DefaultOpenTelemetry;-><init>(Lio/opentelemetry/context/propagation/ContextPropagators;)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lio/opentelemetry/api/DefaultOpenTelemetry;->NO_OP:Lio/opentelemetry/api/OpenTelemetry;

    .line 11
    .line 12
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/context/propagation/ContextPropagators;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/api/DefaultOpenTelemetry;->propagators:Lio/opentelemetry/context/propagation/ContextPropagators;

    .line 5
    .line 6
    return-void
.end method

.method public static getNoop()Lio/opentelemetry/api/OpenTelemetry;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/api/DefaultOpenTelemetry;->NO_OP:Lio/opentelemetry/api/OpenTelemetry;

    .line 2
    .line 3
    return-object v0
.end method

.method public static getPropagating(Lio/opentelemetry/context/propagation/ContextPropagators;)Lio/opentelemetry/api/OpenTelemetry;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/api/DefaultOpenTelemetry;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/api/DefaultOpenTelemetry;-><init>(Lio/opentelemetry/context/propagation/ContextPropagators;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public getMeterProvider()Lio/opentelemetry/api/metrics/MeterProvider;
    .locals 0

    .line 1
    invoke-static {}, Lio/opentelemetry/api/metrics/MeterProvider;->noop()Lio/opentelemetry/api/metrics/MeterProvider;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public getPropagators()Lio/opentelemetry/context/propagation/ContextPropagators;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/api/DefaultOpenTelemetry;->propagators:Lio/opentelemetry/context/propagation/ContextPropagators;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTracerProvider()Lio/opentelemetry/api/trace/TracerProvider;
    .locals 0

    .line 1
    invoke-static {}, Lio/opentelemetry/api/trace/TracerProvider;->noop()Lio/opentelemetry/api/trace/TracerProvider;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "DefaultOpenTelemetry{propagators="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lio/opentelemetry/api/DefaultOpenTelemetry;->propagators:Lio/opentelemetry/context/propagation/ContextPropagators;

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
