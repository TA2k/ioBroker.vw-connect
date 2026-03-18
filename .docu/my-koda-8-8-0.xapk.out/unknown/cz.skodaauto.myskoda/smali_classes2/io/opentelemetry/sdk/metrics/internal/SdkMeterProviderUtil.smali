.class public final Lio/opentelemetry/sdk/metrics/internal/SdkMeterProviderUtil;
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

.method private static addAttributesProcessor(Lio/opentelemetry/sdk/metrics/ViewBuilder;Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;)V
    .locals 3

    .line 1
    :try_start_0
    const-class v0, Lio/opentelemetry/sdk/metrics/ViewBuilder;

    .line 2
    .line 3
    const-string v1, "addAttributesProcessor"

    .line 4
    .line 5
    const-class v2, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

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
    .catch Ljava/lang/reflect/InvocationTargetException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/IllegalAccessException; {:try_start_0 .. :try_end_0} :catch_0

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
    const-string v0, "Error adding AttributesProcessor to ViewBuilder"

    .line 31
    .line 32
    invoke-direct {p1, v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 33
    .line 34
    .line 35
    throw p1
.end method

.method public static addMeterConfiguratorCondition(Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;Ljava/util/function/Predicate;Lio/opentelemetry/sdk/metrics/internal/MeterConfig;)Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;",
            "Ljava/util/function/Predicate<",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            ">;",
            "Lio/opentelemetry/sdk/metrics/internal/MeterConfig;",
            ")",
            "Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;"
        }
    .end annotation

    .line 1
    :try_start_0
    const-class v0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;

    .line 2
    .line 3
    const-string v1, "addMeterConfiguratorCondition"

    .line 4
    .line 5
    const-class v2, Ljava/util/function/Predicate;

    .line 6
    .line 7
    const-class v3, Lio/opentelemetry/sdk/metrics/internal/MeterConfig;

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
    return-object p0

    .line 29
    :catch_0
    move-exception p0

    .line 30
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 31
    .line 32
    const-string p2, "Error calling addMeterConfiguratorCondition on SdkMeterProviderBuilder"

    .line 33
    .line 34
    invoke-direct {p1, p2, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 35
    .line 36
    .line 37
    throw p1
.end method

.method public static appendAllBaggageAttributes(Lio/opentelemetry/sdk/metrics/ViewBuilder;)V
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/metrics/internal/view/StringPredicates;->ALL:Ljava/util/function/Predicate;

    .line 2
    .line 3
    invoke-static {p0, v0}, Lio/opentelemetry/sdk/metrics/internal/SdkMeterProviderUtil;->appendFilteredBaggageAttributes(Lio/opentelemetry/sdk/metrics/ViewBuilder;Ljava/util/function/Predicate;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static appendFilteredBaggageAttributes(Lio/opentelemetry/sdk/metrics/ViewBuilder;Ljava/util/function/Predicate;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/metrics/ViewBuilder;",
            "Ljava/util/function/Predicate<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 1
    invoke-static {p1}, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;->appendBaggageByKeyName(Ljava/util/function/Predicate;)Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/SdkMeterProviderUtil;->addAttributesProcessor(Lio/opentelemetry/sdk/metrics/ViewBuilder;Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public static resetForTest(Lio/opentelemetry/sdk/metrics/SdkMeterProvider;)V
    .locals 3

    .line 1
    :try_start_0
    const-class v0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;

    .line 2
    .line 3
    const-string v1, "resetForTest"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-virtual {v0, v1, v2}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-virtual {v0, v1}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0, p0, v2}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/reflect/InvocationTargetException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/IllegalAccessException; {:try_start_0 .. :try_end_0} :catch_0

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :catch_0
    move-exception p0

    .line 19
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 20
    .line 21
    const-string v1, "Error calling resetForTest on SdkMeterProvider"

    .line 22
    .line 23
    invoke-direct {v0, v1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 24
    .line 25
    .line 26
    throw v0
.end method

.method public static setMeterConfigurator(Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;Lio/opentelemetry/sdk/internal/ScopeConfigurator;)Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;",
            "Lio/opentelemetry/sdk/internal/ScopeConfigurator<",
            "Lio/opentelemetry/sdk/metrics/internal/MeterConfig;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;"
        }
    .end annotation

    .line 6
    :try_start_0
    const-class v0, Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;

    const-string v1, "setMeterConfigurator"

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

    return-object p0

    :catch_0
    move-exception p0

    .line 10
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "Error calling setMeterConfigurator on SdkMeterProviderBuilder"

    invoke-direct {p1, v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw p1
.end method

.method public static setMeterConfigurator(Lio/opentelemetry/sdk/metrics/SdkMeterProvider;Lio/opentelemetry/sdk/internal/ScopeConfigurator;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/metrics/SdkMeterProvider;",
            "Lio/opentelemetry/sdk/internal/ScopeConfigurator<",
            "Lio/opentelemetry/sdk/metrics/internal/MeterConfig;",
            ">;)V"
        }
    .end annotation

    .line 1
    :try_start_0
    const-class v0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;

    const-string v1, "setMeterConfigurator"

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

    const-string v0, "Error calling setMeterConfigurator on SdkMeterProvider"

    invoke-direct {p1, v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw p1
.end method
