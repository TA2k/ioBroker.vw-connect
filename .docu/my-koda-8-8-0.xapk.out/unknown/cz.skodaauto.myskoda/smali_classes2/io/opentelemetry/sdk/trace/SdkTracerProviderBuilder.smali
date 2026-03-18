.class public final Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final DEFAULT_SAMPLER:Lio/opentelemetry/sdk/trace/samplers/Sampler;


# instance fields
.field private clock:Lio/opentelemetry/sdk/common/Clock;

.field private exceptionAttributeResolver:Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;

.field private idsGenerator:Lio/opentelemetry/sdk/trace/IdGenerator;

.field private resource:Lio/opentelemetry/sdk/resources/Resource;

.field private sampler:Lio/opentelemetry/sdk/trace/samplers/Sampler;

.field private spanLimitsSupplier:Ljava/util/function/Supplier;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Supplier<",
            "Lio/opentelemetry/sdk/trace/SpanLimits;",
            ">;"
        }
    .end annotation
.end field

.field private final spanProcessors:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/trace/SpanProcessor;",
            ">;"
        }
    .end annotation
.end field

.field private tracerConfiguratorBuilder:Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder<",
            "Lio/opentelemetry/sdk/trace/internal/TracerConfig;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/trace/samplers/Sampler;->alwaysOn()Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Lio/opentelemetry/sdk/trace/samplers/Sampler;->parentBased(Lio/opentelemetry/sdk/trace/samplers/Sampler;)Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sput-object v0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->DEFAULT_SAMPLER:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->spanProcessors:Ljava/util/List;

    .line 10
    .line 11
    invoke-static {}, Lio/opentelemetry/sdk/common/Clock;->getDefault()Lio/opentelemetry/sdk/common/Clock;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iput-object v0, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->clock:Lio/opentelemetry/sdk/common/Clock;

    .line 16
    .line 17
    invoke-static {}, Lio/opentelemetry/sdk/trace/IdGenerator;->random()Lio/opentelemetry/sdk/trace/IdGenerator;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    iput-object v0, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->idsGenerator:Lio/opentelemetry/sdk/trace/IdGenerator;

    .line 22
    .line 23
    invoke-static {}, Lio/opentelemetry/sdk/resources/Resource;->getDefault()Lio/opentelemetry/sdk/resources/Resource;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    iput-object v0, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 28
    .line 29
    new-instance v0, Lio/opentelemetry/sdk/trace/f;

    .line 30
    .line 31
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 32
    .line 33
    .line 34
    iput-object v0, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->spanLimitsSupplier:Ljava/util/function/Supplier;

    .line 35
    .line 36
    sget-object v0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->DEFAULT_SAMPLER:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 37
    .line 38
    iput-object v0, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->sampler:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 39
    .line 40
    invoke-static {}, Lio/opentelemetry/sdk/trace/internal/TracerConfig;->configuratorBuilder()Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    iput-object v0, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->tracerConfiguratorBuilder:Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;

    .line 45
    .line 46
    invoke-static {}, Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;->getDefault()Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    iput-object v0, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->exceptionAttributeResolver:Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;

    .line 51
    .line 52
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/sdk/trace/SpanLimits;)Lio/opentelemetry/sdk/trace/SpanLimits;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->lambda$setSpanLimits$0(Lio/opentelemetry/sdk/trace/SpanLimits;)Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static synthetic lambda$setSpanLimits$0(Lio/opentelemetry/sdk/trace/SpanLimits;)Lio/opentelemetry/sdk/trace/SpanLimits;
    .locals 0

    .line 1
    return-object p0
.end method


# virtual methods
.method public addResource(Lio/opentelemetry/sdk/resources/Resource;)Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;
    .locals 1

    .line 1
    const-string v0, "resource"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Lio/opentelemetry/sdk/resources/Resource;->merge(Lio/opentelemetry/sdk/resources/Resource;)Lio/opentelemetry/sdk/resources/Resource;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 13
    .line 14
    return-object p0
.end method

.method public addSpanProcessor(Lio/opentelemetry/sdk/trace/SpanProcessor;)Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;
    .locals 1

    .line 1
    const-string v0, "spanProcessor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->spanProcessors:Ljava/util/List;

    .line 7
    .line 8
    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public addSpanProcessorFirst(Lio/opentelemetry/sdk/trace/SpanProcessor;)Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;
    .locals 2

    .line 1
    const-string v0, "spanProcessor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->spanProcessors:Ljava/util/List;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-interface {v0, v1, p1}, Ljava/util/List;->add(ILjava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    return-object p0
.end method

.method public addTracerConfiguratorCondition(Ljava/util/function/Predicate;Lio/opentelemetry/sdk/trace/internal/TracerConfig;)Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Predicate<",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            ">;",
            "Lio/opentelemetry/sdk/trace/internal/TracerConfig;",
            ")",
            "Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->tracerConfiguratorBuilder:Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2}, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;->addCondition(Ljava/util/function/Predicate;Ljava/lang/Object;)Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public build()Lio/opentelemetry/sdk/trace/SdkTracerProvider;
    .locals 9

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/trace/SdkTracerProvider;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->clock:Lio/opentelemetry/sdk/common/Clock;

    .line 4
    .line 5
    iget-object v2, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->idsGenerator:Lio/opentelemetry/sdk/trace/IdGenerator;

    .line 6
    .line 7
    iget-object v3, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 8
    .line 9
    iget-object v4, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->spanLimitsSupplier:Ljava/util/function/Supplier;

    .line 10
    .line 11
    iget-object v5, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->sampler:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 12
    .line 13
    iget-object v6, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->spanProcessors:Ljava/util/List;

    .line 14
    .line 15
    iget-object v7, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->tracerConfiguratorBuilder:Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;

    .line 16
    .line 17
    invoke-virtual {v7}, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;->build()Lio/opentelemetry/sdk/internal/ScopeConfigurator;

    .line 18
    .line 19
    .line 20
    move-result-object v7

    .line 21
    iget-object v8, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->exceptionAttributeResolver:Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;

    .line 22
    .line 23
    invoke-direct/range {v0 .. v8}, Lio/opentelemetry/sdk/trace/SdkTracerProvider;-><init>(Lio/opentelemetry/sdk/common/Clock;Lio/opentelemetry/sdk/trace/IdGenerator;Lio/opentelemetry/sdk/resources/Resource;Ljava/util/function/Supplier;Lio/opentelemetry/sdk/trace/samplers/Sampler;Ljava/util/List;Lio/opentelemetry/sdk/internal/ScopeConfigurator;Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;)V

    .line 24
    .line 25
    .line 26
    return-object v0
.end method

.method public setClock(Lio/opentelemetry/sdk/common/Clock;)Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;
    .locals 1

    .line 1
    const-string v0, "clock"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->clock:Lio/opentelemetry/sdk/common/Clock;

    .line 7
    .line 8
    return-object p0
.end method

.method public setExceptionAttributeResolver(Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;)Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;
    .locals 1

    .line 1
    const-string v0, "exceptionAttributeResolver"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->exceptionAttributeResolver:Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;

    .line 7
    .line 8
    return-object p0
.end method

.method public setIdGenerator(Lio/opentelemetry/sdk/trace/IdGenerator;)Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;
    .locals 1

    .line 1
    const-string v0, "idGenerator"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->idsGenerator:Lio/opentelemetry/sdk/trace/IdGenerator;

    .line 7
    .line 8
    return-object p0
.end method

.method public setResource(Lio/opentelemetry/sdk/resources/Resource;)Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;
    .locals 1

    .line 1
    const-string v0, "resource"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 7
    .line 8
    return-object p0
.end method

.method public setSampler(Lio/opentelemetry/sdk/trace/samplers/Sampler;)Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;
    .locals 1

    .line 1
    const-string v0, "sampler"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->sampler:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 7
    .line 8
    return-object p0
.end method

.method public setSpanLimits(Lio/opentelemetry/sdk/trace/SpanLimits;)Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;
    .locals 1

    .line 1
    const-string v0, "spanLimits"

    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 2
    new-instance v0, Lio/opentelemetry/sdk/trace/g;

    invoke-direct {v0, p1}, Lio/opentelemetry/sdk/trace/g;-><init>(Lio/opentelemetry/sdk/trace/SpanLimits;)V

    iput-object v0, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->spanLimitsSupplier:Ljava/util/function/Supplier;

    return-object p0
.end method

.method public setSpanLimits(Ljava/util/function/Supplier;)Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Supplier<",
            "Lio/opentelemetry/sdk/trace/SpanLimits;",
            ">;)",
            "Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;"
        }
    .end annotation

    .line 3
    const-string v0, "spanLimitsSupplier"

    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->spanLimitsSupplier:Ljava/util/function/Supplier;

    return-object p0
.end method

.method public setTracerConfigurator(Lio/opentelemetry/sdk/internal/ScopeConfigurator;)Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/internal/ScopeConfigurator<",
            "Lio/opentelemetry/sdk/trace/internal/TracerConfig;",
            ">;)",
            "Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;"
        }
    .end annotation

    .line 1
    invoke-interface {p1}, Lio/opentelemetry/sdk/internal/ScopeConfigurator;->toBuilder()Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;->tracerConfiguratorBuilder:Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;

    .line 6
    .line 7
    return-object p0
.end method
