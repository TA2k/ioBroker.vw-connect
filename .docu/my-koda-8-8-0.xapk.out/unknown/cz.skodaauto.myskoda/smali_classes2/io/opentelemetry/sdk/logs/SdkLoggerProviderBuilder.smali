.class public final Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private clock:Lio/opentelemetry/sdk/common/Clock;

.field private exceptionAttributeResolver:Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;

.field private logLimitsSupplier:Ljava/util/function/Supplier;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Supplier<",
            "Lio/opentelemetry/sdk/logs/LogLimits;",
            ">;"
        }
    .end annotation
.end field

.field private final logRecordProcessors:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/logs/LogRecordProcessor;",
            ">;"
        }
    .end annotation
.end field

.field private loggerConfiguratorBuilder:Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder<",
            "Lio/opentelemetry/sdk/logs/internal/LoggerConfig;",
            ">;"
        }
    .end annotation
.end field

.field private resource:Lio/opentelemetry/sdk/resources/Resource;


# direct methods
.method public constructor <init>()V
    .locals 2

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
    iput-object v0, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;->logRecordProcessors:Ljava/util/List;

    .line 10
    .line 11
    invoke-static {}, Lio/opentelemetry/sdk/resources/Resource;->getDefault()Lio/opentelemetry/sdk/resources/Resource;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iput-object v0, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 16
    .line 17
    new-instance v0, Lio/opentelemetry/exporter/internal/grpc/b;

    .line 18
    .line 19
    const/4 v1, 0x2

    .line 20
    invoke-direct {v0, v1}, Lio/opentelemetry/exporter/internal/grpc/b;-><init>(I)V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;->logLimitsSupplier:Ljava/util/function/Supplier;

    .line 24
    .line 25
    invoke-static {}, Lio/opentelemetry/sdk/common/Clock;->getDefault()Lio/opentelemetry/sdk/common/Clock;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    iput-object v0, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;->clock:Lio/opentelemetry/sdk/common/Clock;

    .line 30
    .line 31
    invoke-static {}, Lio/opentelemetry/sdk/logs/internal/LoggerConfig;->configuratorBuilder()Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    iput-object v0, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;->loggerConfiguratorBuilder:Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;

    .line 36
    .line 37
    invoke-static {}, Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;->getDefault()Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    iput-object v0, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;->exceptionAttributeResolver:Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;

    .line 42
    .line 43
    return-void
.end method


# virtual methods
.method public addLogRecordProcessor(Lio/opentelemetry/sdk/logs/LogRecordProcessor;)Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;
    .locals 1

    .line 1
    const-string v0, "processor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;->logRecordProcessors:Ljava/util/List;

    .line 7
    .line 8
    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public addLogRecordProcessorFirst(Lio/opentelemetry/sdk/logs/LogRecordProcessor;)Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;
    .locals 2

    .line 1
    const-string v0, "processor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;->logRecordProcessors:Ljava/util/List;

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

.method public addLoggerConfiguratorCondition(Ljava/util/function/Predicate;Lio/opentelemetry/sdk/logs/internal/LoggerConfig;)Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Predicate<",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            ">;",
            "Lio/opentelemetry/sdk/logs/internal/LoggerConfig;",
            ")",
            "Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;->loggerConfiguratorBuilder:Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2}, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;->addCondition(Ljava/util/function/Predicate;Ljava/lang/Object;)Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public addResource(Lio/opentelemetry/sdk/resources/Resource;)Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;
    .locals 1

    .line 1
    const-string v0, "resource"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Lio/opentelemetry/sdk/resources/Resource;->merge(Lio/opentelemetry/sdk/resources/Resource;)Lio/opentelemetry/sdk/resources/Resource;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 13
    .line 14
    return-object p0
.end method

.method public build()Lio/opentelemetry/sdk/logs/SdkLoggerProvider;
    .locals 7

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 4
    .line 5
    iget-object v2, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;->logLimitsSupplier:Ljava/util/function/Supplier;

    .line 6
    .line 7
    iget-object v3, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;->logRecordProcessors:Ljava/util/List;

    .line 8
    .line 9
    iget-object v4, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;->clock:Lio/opentelemetry/sdk/common/Clock;

    .line 10
    .line 11
    iget-object v5, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;->loggerConfiguratorBuilder:Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;

    .line 12
    .line 13
    invoke-virtual {v5}, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;->build()Lio/opentelemetry/sdk/internal/ScopeConfigurator;

    .line 14
    .line 15
    .line 16
    move-result-object v5

    .line 17
    iget-object v6, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;->exceptionAttributeResolver:Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;

    .line 18
    .line 19
    invoke-direct/range {v0 .. v6}, Lio/opentelemetry/sdk/logs/SdkLoggerProvider;-><init>(Lio/opentelemetry/sdk/resources/Resource;Ljava/util/function/Supplier;Ljava/util/List;Lio/opentelemetry/sdk/common/Clock;Lio/opentelemetry/sdk/internal/ScopeConfigurator;Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;)V

    .line 20
    .line 21
    .line 22
    return-object v0
.end method

.method public setClock(Lio/opentelemetry/sdk/common/Clock;)Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;
    .locals 1

    .line 1
    const-string v0, "clock"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;->clock:Lio/opentelemetry/sdk/common/Clock;

    .line 7
    .line 8
    return-object p0
.end method

.method public setExceptionAttributeResolver(Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;)Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;
    .locals 1

    .line 1
    const-string v0, "exceptionAttributeResolver"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;->exceptionAttributeResolver:Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;

    .line 7
    .line 8
    return-object p0
.end method

.method public setLogLimits(Ljava/util/function/Supplier;)Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Supplier<",
            "Lio/opentelemetry/sdk/logs/LogLimits;",
            ">;)",
            "Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;"
        }
    .end annotation

    .line 1
    const-string v0, "logLimitsSupplier"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;->logLimitsSupplier:Ljava/util/function/Supplier;

    .line 7
    .line 8
    return-object p0
.end method

.method public setLoggerConfigurator(Lio/opentelemetry/sdk/internal/ScopeConfigurator;)Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/internal/ScopeConfigurator<",
            "Lio/opentelemetry/sdk/logs/internal/LoggerConfig;",
            ">;)",
            "Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;"
        }
    .end annotation

    .line 1
    invoke-interface {p1}, Lio/opentelemetry/sdk/internal/ScopeConfigurator;->toBuilder()Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;->loggerConfiguratorBuilder:Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;

    .line 6
    .line 7
    return-object p0
.end method

.method public setResource(Lio/opentelemetry/sdk/resources/Resource;)Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;
    .locals 1

    .line 1
    const-string v0, "resource"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 7
    .line 8
    return-object p0
.end method
