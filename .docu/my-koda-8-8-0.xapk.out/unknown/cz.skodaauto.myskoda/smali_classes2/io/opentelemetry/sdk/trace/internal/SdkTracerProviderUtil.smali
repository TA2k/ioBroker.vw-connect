.class public final Lio/opentelemetry/sdk/trace/internal/SdkTracerProviderUtil;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static addTracerConfiguratorCondition(Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;Ljava/util/function/Predicate;Lio/opentelemetry/sdk/trace/internal/TracerConfig;)V
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;",
            "Ljava/util/function/Predicate<",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            ">;",
            "Lio/opentelemetry/sdk/trace/internal/TracerConfig;",
            ")V"
        }
    .end annotation

    .line 1
    :try_start_0
    const-class v0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;

    .line 2
    .line 3
    const-string v1, "addTracerConfiguratorCondition"

    .line 4
    .line 5
    const-class v2, Ljava/util/function/Predicate;

    .line 6
    .line 7
    const-class v3, Lio/opentelemetry/sdk/trace/internal/TracerConfig;

    .line 8
    .line 9
    filled-new-array {v2, v3}, [Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    invoke-virtual {v0, v1, v2}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    const/4 v1, 0x1

    .line 18
    invoke-virtual {v0, v1}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 19
    .line 20
    .line 21
    filled-new-array {p1, p2}, [Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    invoke-virtual {v0, p0, p1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/IllegalAccessException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/reflect/InvocationTargetException; {:try_start_0 .. :try_end_0} :catch_0

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :catch_0
    move-exception p0

    .line 30
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 31
    .line 32
    const-string p2, "Error calling addTracerConfiguratorCondition on SdkTracerProviderBuilder"

    .line 33
    .line 34
    invoke-direct {p1, p2, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 35
    .line 36
    .line 37
    throw p1
.end method

.method public static setExceptionAttributeResolver(Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;)V
    .locals 3

    .line 1
    :try_start_0
    const-class v0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;

    .line 2
    .line 3
    const-string v1, "setExceptionAttributeResolver"

    .line 4
    .line 5
    const-class v2, Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;

    .line 6
    .line 7
    filled-new-array {v2}, [Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    invoke-virtual {v0, v1, v2}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const/4 v1, 0x1

    .line 16
    invoke-virtual {v0, v1}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 17
    .line 18
    .line 19
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    invoke-virtual {v0, p0, p1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/IllegalAccessException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/reflect/InvocationTargetException; {:try_start_0 .. :try_end_0} :catch_0

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :catch_0
    move-exception p0

    .line 28
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 29
    .line 30
    const-string v0, "Error calling setExceptionAttributeResolver on SdkTracerProviderBuilder"

    .line 31
    .line 32
    invoke-direct {p1, v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 33
    .line 34
    .line 35
    throw p1
.end method

.method public static setTracerConfigurator(Lio/opentelemetry/sdk/trace/SdkTracerProvider;Lio/opentelemetry/sdk/internal/ScopeConfigurator;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/trace/SdkTracerProvider;",
            "Lio/opentelemetry/sdk/internal/ScopeConfigurator<",
            "Lio/opentelemetry/sdk/trace/internal/TracerConfig;",
            ">;)V"
        }
    .end annotation

    .line 1
    :try_start_0
    const-class v0, Lio/opentelemetry/sdk/trace/SdkTracerProvider;

    const-string v1, "setTracerConfigurator"

    const-class v2, Lio/opentelemetry/sdk/internal/ScopeConfigurator;

    filled-new-array {v2}, [Ljava/lang/Class;

    move-result-object v2

    .line 2
    invoke-virtual {v0, v1, v2}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v0

    const/4 v1, 0x1

    .line 3
    invoke-virtual {v0, v1}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 4
    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {v0, p0, p1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/IllegalAccessException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/reflect/InvocationTargetException; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p0

    .line 5
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "Error calling setTracerConfigurator on SdkTracerProvider"

    invoke-direct {p1, v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw p1
.end method

.method public static setTracerConfigurator(Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;Lio/opentelemetry/sdk/internal/ScopeConfigurator;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;",
            "Lio/opentelemetry/sdk/internal/ScopeConfigurator<",
            "Lio/opentelemetry/sdk/trace/internal/TracerConfig;",
            ">;)V"
        }
    .end annotation

    .line 6
    :try_start_0
    const-class v0, Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;

    const-string v1, "setTracerConfigurator"

    const-class v2, Lio/opentelemetry/sdk/internal/ScopeConfigurator;

    filled-new-array {v2}, [Ljava/lang/Class;

    move-result-object v2

    .line 7
    invoke-virtual {v0, v1, v2}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v0

    const/4 v1, 0x1

    .line 8
    invoke-virtual {v0, v1}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 9
    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {v0, p0, p1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/IllegalAccessException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/reflect/InvocationTargetException; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p0

    .line 10
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "Error calling setTracerConfigurator on SdkTracerProviderBuilder"

    invoke-direct {p1, v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw p1
.end method
