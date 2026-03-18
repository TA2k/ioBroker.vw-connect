.class public final Lio/opentelemetry/sdk/trace/SdkTracerProvider;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/trace/TracerProvider;
.implements Ljava/io/Closeable;


# static fields
.field static final DEFAULT_TRACER_NAME:Ljava/lang/String; = ""

.field private static final logger:Ljava/util/logging/Logger;


# instance fields
.field private final sharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

.field private tracerConfigurator:Lio/opentelemetry/sdk/internal/ScopeConfigurator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/sdk/internal/ScopeConfigurator<",
            "Lio/opentelemetry/sdk/trace/internal/TracerConfig;",
            ">;"
        }
    .end annotation
.end field

.field private final tracerSdkComponentRegistry:Lio/opentelemetry/sdk/internal/ComponentRegistry;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/sdk/internal/ComponentRegistry<",
            "Lio/opentelemetry/sdk/trace/SdkTracer;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/sdk/trace/SdkTracerProvider;

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
    sput-object v0, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->logger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/sdk/common/Clock;Lio/opentelemetry/sdk/trace/IdGenerator;Lio/opentelemetry/sdk/resources/Resource;Ljava/util/function/Supplier;Lio/opentelemetry/sdk/trace/samplers/Sampler;Ljava/util/List;Lio/opentelemetry/sdk/internal/ScopeConfigurator;Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;)V
    .locals 8
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/common/Clock;",
            "Lio/opentelemetry/sdk/trace/IdGenerator;",
            "Lio/opentelemetry/sdk/resources/Resource;",
            "Ljava/util/function/Supplier<",
            "Lio/opentelemetry/sdk/trace/SpanLimits;",
            ">;",
            "Lio/opentelemetry/sdk/trace/samplers/Sampler;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/trace/SpanProcessor;",
            ">;",
            "Lio/opentelemetry/sdk/internal/ScopeConfigurator<",
            "Lio/opentelemetry/sdk/trace/internal/TracerConfig;",
            ">;",
            "Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 5
    .line 6
    move-object v1, p1

    .line 7
    move-object v2, p2

    .line 8
    move-object v3, p3

    .line 9
    move-object v4, p4

    .line 10
    move-object v5, p5

    .line 11
    move-object v6, p6

    .line 12
    move-object/from16 v7, p8

    .line 13
    .line 14
    invoke-direct/range {v0 .. v7}, Lio/opentelemetry/sdk/trace/TracerSharedState;-><init>(Lio/opentelemetry/sdk/common/Clock;Lio/opentelemetry/sdk/trace/IdGenerator;Lio/opentelemetry/sdk/resources/Resource;Ljava/util/function/Supplier;Lio/opentelemetry/sdk/trace/samplers/Sampler;Ljava/util/List;Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;)V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->sharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 18
    .line 19
    new-instance p1, Lio/opentelemetry/sdk/internal/ComponentRegistry;

    .line 20
    .line 21
    new-instance p2, Lio/opentelemetry/sdk/trace/e;

    .line 22
    .line 23
    invoke-direct {p2, p0}, Lio/opentelemetry/sdk/trace/e;-><init>(Lio/opentelemetry/sdk/trace/SdkTracerProvider;)V

    .line 24
    .line 25
    .line 26
    invoke-direct {p1, p2}, Lio/opentelemetry/sdk/internal/ComponentRegistry;-><init>(Ljava/util/function/Function;)V

    .line 27
    .line 28
    .line 29
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->tracerSdkComponentRegistry:Lio/opentelemetry/sdk/internal/ComponentRegistry;

    .line 30
    .line 31
    iput-object p7, p0, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->tracerConfigurator:Lio/opentelemetry/sdk/internal/ScopeConfigurator;

    .line 32
    .line 33
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/sdk/trace/SdkTracerProvider;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Lio/opentelemetry/sdk/trace/SdkTracer;
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->lambda$new$0(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Lio/opentelemetry/sdk/trace/SdkTracer;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b(Lio/opentelemetry/sdk/trace/SdkTracerProvider;Lio/opentelemetry/sdk/trace/SdkTracer;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->lambda$setTracerConfigurator$1(Lio/opentelemetry/sdk/trace/SdkTracer;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static builder()Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method private getTracerConfig(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Lio/opentelemetry/sdk/trace/internal/TracerConfig;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->tracerConfigurator:Lio/opentelemetry/sdk/internal/ScopeConfigurator;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Ljava/util/function/Function;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/sdk/trace/internal/TracerConfig;

    .line 8
    .line 9
    if-nez p0, :cond_0

    .line 10
    .line 11
    invoke-static {}, Lio/opentelemetry/sdk/trace/internal/TracerConfig;->defaultConfig()Lio/opentelemetry/sdk/trace/internal/TracerConfig;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    :cond_0
    return-object p0
.end method

.method private synthetic lambda$new$0(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Lio/opentelemetry/sdk/trace/SdkTracer;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->sharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->getTracerConfig(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Lio/opentelemetry/sdk/trace/internal/TracerConfig;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-static {v0, p1, p0}, Lio/opentelemetry/sdk/trace/SdkTracer;->create(Lio/opentelemetry/sdk/trace/TracerSharedState;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/trace/internal/TracerConfig;)Lio/opentelemetry/sdk/trace/SdkTracer;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method private synthetic lambda$setTracerConfigurator$1(Lio/opentelemetry/sdk/trace/SdkTracer;)V
    .locals 1

    .line 1
    invoke-virtual {p1}, Lio/opentelemetry/sdk/trace/SdkTracer;->getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->getTracerConfig(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Lio/opentelemetry/sdk/trace/internal/TracerConfig;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {p1, p0}, Lio/opentelemetry/sdk/trace/SdkTracer;->updateTracerConfig(Lio/opentelemetry/sdk/trace/internal/TracerConfig;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public close()V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;

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

.method public forceFlush()Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->sharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 2
    .line 3
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/TracerSharedState;->getActiveSpanProcessor()Lio/opentelemetry/sdk/trace/SpanProcessor;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/SpanProcessor;->forceFlush()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public get(Ljava/lang/String;)Lio/opentelemetry/api/trace/Tracer;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->tracerBuilder(Ljava/lang/String;)Lio/opentelemetry/api/trace/TracerBuilder;

    move-result-object p0

    invoke-interface {p0}, Lio/opentelemetry/api/trace/TracerBuilder;->build()Lio/opentelemetry/api/trace/Tracer;

    move-result-object p0

    return-object p0
.end method

.method public get(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/api/trace/Tracer;
    .locals 0

    .line 2
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->tracerBuilder(Ljava/lang/String;)Lio/opentelemetry/api/trace/TracerBuilder;

    move-result-object p0

    .line 3
    invoke-interface {p0, p2}, Lio/opentelemetry/api/trace/TracerBuilder;->setInstrumentationVersion(Ljava/lang/String;)Lio/opentelemetry/api/trace/TracerBuilder;

    move-result-object p0

    .line 4
    invoke-interface {p0}, Lio/opentelemetry/api/trace/TracerBuilder;->build()Lio/opentelemetry/api/trace/Tracer;

    move-result-object p0

    return-object p0
.end method

.method public getSampler()Lio/opentelemetry/sdk/trace/samplers/Sampler;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->sharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 2
    .line 3
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/TracerSharedState;->getSampler()Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getSpanLimits()Lio/opentelemetry/sdk/trace/SpanLimits;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->sharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 2
    .line 3
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/TracerSharedState;->getSpanLimits()Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public setTracerConfigurator(Lio/opentelemetry/sdk/internal/ScopeConfigurator;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/internal/ScopeConfigurator<",
            "Lio/opentelemetry/sdk/trace/internal/TracerConfig;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->tracerConfigurator:Lio/opentelemetry/sdk/internal/ScopeConfigurator;

    .line 2
    .line 3
    iget-object p1, p0, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->tracerSdkComponentRegistry:Lio/opentelemetry/sdk/internal/ComponentRegistry;

    .line 4
    .line 5
    invoke-virtual {p1}, Lio/opentelemetry/sdk/internal/ComponentRegistry;->getComponents()Ljava/util/Collection;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    new-instance v0, Lio/opentelemetry/sdk/trace/d;

    .line 10
    .line 11
    invoke-direct {v0, p0}, Lio/opentelemetry/sdk/trace/d;-><init>(Lio/opentelemetry/sdk/trace/SdkTracerProvider;)V

    .line 12
    .line 13
    .line 14
    invoke-interface {p1, v0}, Ljava/lang/Iterable;->forEach(Ljava/util/function/Consumer;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->sharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 2
    .line 3
    invoke-virtual {v0}, Lio/opentelemetry/sdk/trace/TracerSharedState;->hasBeenShutdown()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    sget-object p0, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->logger:Ljava/util/logging/Logger;

    .line 10
    .line 11
    sget-object v0, Ljava/util/logging/Level;->INFO:Ljava/util/logging/Level;

    .line 12
    .line 13
    const-string v1, "Calling shutdown() multiple times."

    .line 14
    .line 15
    invoke-virtual {p0, v0, v1}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

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
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->sharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 24
    .line 25
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/TracerSharedState;->shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "SdkTracerProvider{clock="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->sharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 9
    .line 10
    invoke-virtual {v1}, Lio/opentelemetry/sdk/trace/TracerSharedState;->getClock()Lio/opentelemetry/sdk/common/Clock;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string v1, ", idGenerator="

    .line 18
    .line 19
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->sharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 23
    .line 24
    invoke-virtual {v1}, Lio/opentelemetry/sdk/trace/TracerSharedState;->getIdGenerator()Lio/opentelemetry/sdk/trace/IdGenerator;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v1, ", resource="

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->sharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 37
    .line 38
    invoke-virtual {v1}, Lio/opentelemetry/sdk/trace/TracerSharedState;->getResource()Lio/opentelemetry/sdk/resources/Resource;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const-string v1, ", spanLimitsSupplier="

    .line 46
    .line 47
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->sharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 51
    .line 52
    invoke-virtual {v1}, Lio/opentelemetry/sdk/trace/TracerSharedState;->getSpanLimits()Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    const-string v1, ", sampler="

    .line 60
    .line 61
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->sharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 65
    .line 66
    invoke-virtual {v1}, Lio/opentelemetry/sdk/trace/TracerSharedState;->getSampler()Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v1, ", spanProcessor="

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->sharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 79
    .line 80
    invoke-virtual {v1}, Lio/opentelemetry/sdk/trace/TracerSharedState;->getActiveSpanProcessor()Lio/opentelemetry/sdk/trace/SpanProcessor;

    .line 81
    .line 82
    .line 83
    move-result-object v1

    .line 84
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    const-string v1, ", tracerConfigurator="

    .line 88
    .line 89
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->tracerConfigurator:Lio/opentelemetry/sdk/internal/ScopeConfigurator;

    .line 93
    .line 94
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    const/16 p0, 0x7d

    .line 98
    .line 99
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    return-object p0
.end method

.method public tracerBuilder(Ljava/lang/String;)Lio/opentelemetry/api/trace/TracerBuilder;
    .locals 1
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/String;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    :cond_0
    sget-object p1, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->logger:Ljava/util/logging/Logger;

    .line 10
    .line 11
    const-string v0, "Tracer requested without instrumentation scope name."

    .line 12
    .line 13
    invoke-virtual {p1, v0}, Ljava/util/logging/Logger;->fine(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string p1, ""

    .line 17
    .line 18
    :cond_1
    new-instance v0, Lio/opentelemetry/sdk/trace/SdkTracerBuilder;

    .line 19
    .line 20
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkTracerProvider;->tracerSdkComponentRegistry:Lio/opentelemetry/sdk/internal/ComponentRegistry;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/sdk/trace/SdkTracerBuilder;-><init>(Lio/opentelemetry/sdk/internal/ComponentRegistry;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    return-object v0
.end method
