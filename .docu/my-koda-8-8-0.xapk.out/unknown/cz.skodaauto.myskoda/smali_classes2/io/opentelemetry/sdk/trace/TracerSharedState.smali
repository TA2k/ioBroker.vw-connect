.class final Lio/opentelemetry/sdk/trace/TracerSharedState;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final activeSpanProcessor:Lio/opentelemetry/sdk/trace/SpanProcessor;

.field private final clock:Lio/opentelemetry/sdk/common/Clock;

.field private final exceptionAttributeResolver:Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;

.field private final idGenerator:Lio/opentelemetry/sdk/trace/IdGenerator;

.field private final idGeneratorSafeToSkipIdValidation:Z

.field private final lock:Ljava/lang/Object;

.field private final resource:Lio/opentelemetry/sdk/resources/Resource;

.field private final sampler:Lio/opentelemetry/sdk/trace/samplers/Sampler;

.field private volatile shutdownResult:Lio/opentelemetry/sdk/common/CompletableResultCode;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final spanLimitsSupplier:Ljava/util/function/Supplier;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Supplier<",
            "Lio/opentelemetry/sdk/trace/SpanLimits;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/common/Clock;Lio/opentelemetry/sdk/trace/IdGenerator;Lio/opentelemetry/sdk/resources/Resource;Ljava/util/function/Supplier;Lio/opentelemetry/sdk/trace/samplers/Sampler;Ljava/util/List;Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;)V
    .locals 1
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
            "Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/Object;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lio/opentelemetry/sdk/trace/TracerSharedState;->lock:Ljava/lang/Object;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    iput-object v0, p0, Lio/opentelemetry/sdk/trace/TracerSharedState;->shutdownResult:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 13
    .line 14
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/TracerSharedState;->clock:Lio/opentelemetry/sdk/common/Clock;

    .line 15
    .line 16
    iput-object p2, p0, Lio/opentelemetry/sdk/trace/TracerSharedState;->idGenerator:Lio/opentelemetry/sdk/trace/IdGenerator;

    .line 17
    .line 18
    instance-of p1, p2, Lio/opentelemetry/sdk/trace/RandomIdGenerator;

    .line 19
    .line 20
    iput-boolean p1, p0, Lio/opentelemetry/sdk/trace/TracerSharedState;->idGeneratorSafeToSkipIdValidation:Z

    .line 21
    .line 22
    iput-object p3, p0, Lio/opentelemetry/sdk/trace/TracerSharedState;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 23
    .line 24
    iput-object p4, p0, Lio/opentelemetry/sdk/trace/TracerSharedState;->spanLimitsSupplier:Ljava/util/function/Supplier;

    .line 25
    .line 26
    iput-object p5, p0, Lio/opentelemetry/sdk/trace/TracerSharedState;->sampler:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 27
    .line 28
    invoke-static {p6}, Lio/opentelemetry/sdk/trace/SpanProcessor;->composite(Ljava/lang/Iterable;)Lio/opentelemetry/sdk/trace/SpanProcessor;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/TracerSharedState;->activeSpanProcessor:Lio/opentelemetry/sdk/trace/SpanProcessor;

    .line 33
    .line 34
    iput-object p7, p0, Lio/opentelemetry/sdk/trace/TracerSharedState;->exceptionAttributeResolver:Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;

    .line 35
    .line 36
    return-void
.end method


# virtual methods
.method public getActiveSpanProcessor()Lio/opentelemetry/sdk/trace/SpanProcessor;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/TracerSharedState;->activeSpanProcessor:Lio/opentelemetry/sdk/trace/SpanProcessor;

    .line 2
    .line 3
    return-object p0
.end method

.method public getClock()Lio/opentelemetry/sdk/common/Clock;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/TracerSharedState;->clock:Lio/opentelemetry/sdk/common/Clock;

    .line 2
    .line 3
    return-object p0
.end method

.method public getExceptionAttributesResolver()Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/TracerSharedState;->exceptionAttributeResolver:Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;

    .line 2
    .line 3
    return-object p0
.end method

.method public getIdGenerator()Lio/opentelemetry/sdk/trace/IdGenerator;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/TracerSharedState;->idGenerator:Lio/opentelemetry/sdk/trace/IdGenerator;

    .line 2
    .line 3
    return-object p0
.end method

.method public getResource()Lio/opentelemetry/sdk/resources/Resource;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/TracerSharedState;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSampler()Lio/opentelemetry/sdk/trace/samplers/Sampler;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/TracerSharedState;->sampler:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSpanLimits()Lio/opentelemetry/sdk/trace/SpanLimits;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/TracerSharedState;->spanLimitsSupplier:Ljava/util/function/Supplier;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/function/Supplier;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 8
    .line 9
    return-object p0
.end method

.method public hasBeenShutdown()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/TracerSharedState;->shutdownResult:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public isIdGeneratorSafeToSkipIdValidation()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/sdk/trace/TracerSharedState;->idGeneratorSafeToSkipIdValidation:Z

    .line 2
    .line 3
    return p0
.end method

.method public shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/TracerSharedState;->lock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/TracerSharedState;->shutdownResult:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/TracerSharedState;->shutdownResult:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 9
    .line 10
    monitor-exit v0

    .line 11
    return-object p0

    .line 12
    :catchall_0
    move-exception p0

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/TracerSharedState;->activeSpanProcessor:Lio/opentelemetry/sdk/trace/SpanProcessor;

    .line 15
    .line 16
    invoke-interface {v1}, Lio/opentelemetry/sdk/trace/SpanProcessor;->shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    iput-object v1, p0, Lio/opentelemetry/sdk/trace/TracerSharedState;->shutdownResult:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 21
    .line 22
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/TracerSharedState;->shutdownResult:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 23
    .line 24
    monitor-exit v0

    .line 25
    return-object p0

    .line 26
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 27
    throw p0
.end method
