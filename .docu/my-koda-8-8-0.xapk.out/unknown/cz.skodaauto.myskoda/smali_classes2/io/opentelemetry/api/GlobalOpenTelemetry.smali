.class public final Lio/opentelemetry/api/GlobalOpenTelemetry;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/api/GlobalOpenTelemetry$ObfuscatedOpenTelemetry;
    }
.end annotation


# static fields
.field private static final GLOBAL_AUTOCONFIGURE_ENABLED_PROPERTY:Ljava/lang/String; = "otel.java.global-autoconfigure.enabled"

.field private static volatile globalOpenTelemetry:Lio/opentelemetry/api/OpenTelemetry;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private static final logger:Ljava/util/logging/Logger;

.field private static final mutex:Ljava/lang/Object;

.field private static setGlobalCaller:Ljava/lang/Throwable;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/api/GlobalOpenTelemetry;

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
    sput-object v0, Lio/opentelemetry/api/GlobalOpenTelemetry;->logger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    new-instance v0, Ljava/lang/Object;

    .line 14
    .line 15
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 16
    .line 17
    .line 18
    sput-object v0, Lio/opentelemetry/api/GlobalOpenTelemetry;->mutex:Ljava/lang/Object;

    .line 19
    .line 20
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static get()Lio/opentelemetry/api/OpenTelemetry;
    .locals 2

    .line 1
    sget-object v0, Lio/opentelemetry/api/GlobalOpenTelemetry;->globalOpenTelemetry:Lio/opentelemetry/api/OpenTelemetry;

    .line 2
    .line 3
    if-nez v0, :cond_2

    .line 4
    .line 5
    sget-object v1, Lio/opentelemetry/api/GlobalOpenTelemetry;->mutex:Ljava/lang/Object;

    .line 6
    .line 7
    monitor-enter v1

    .line 8
    :try_start_0
    sget-object v0, Lio/opentelemetry/api/GlobalOpenTelemetry;->globalOpenTelemetry:Lio/opentelemetry/api/OpenTelemetry;

    .line 9
    .line 10
    if-nez v0, :cond_1

    .line 11
    .line 12
    invoke-static {}, Lio/opentelemetry/api/GlobalOpenTelemetry;->maybeAutoConfigureAndSetGlobal()Lio/opentelemetry/api/OpenTelemetry;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    monitor-exit v1

    .line 19
    return-object v0

    .line 20
    :catchall_0
    move-exception v0

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    invoke-static {}, Lio/opentelemetry/api/OpenTelemetry;->noop()Lio/opentelemetry/api/OpenTelemetry;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-static {v0}, Lio/opentelemetry/api/GlobalOpenTelemetry;->set(Lio/opentelemetry/api/OpenTelemetry;)V

    .line 27
    .line 28
    .line 29
    invoke-static {}, Lio/opentelemetry/api/OpenTelemetry;->noop()Lio/opentelemetry/api/OpenTelemetry;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    monitor-exit v1

    .line 34
    return-object v0

    .line 35
    :cond_1
    monitor-exit v1

    .line 36
    return-object v0

    .line 37
    :goto_0
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 38
    throw v0

    .line 39
    :cond_2
    return-object v0
.end method

.method public static getMeter(Ljava/lang/String;)Lio/opentelemetry/api/metrics/Meter;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/api/GlobalOpenTelemetry;->get()Lio/opentelemetry/api/OpenTelemetry;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {v0, p0}, Lio/opentelemetry/api/OpenTelemetry;->getMeter(Ljava/lang/String;)Lio/opentelemetry/api/metrics/Meter;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public static getMeterProvider()Lio/opentelemetry/api/metrics/MeterProvider;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/api/GlobalOpenTelemetry;->get()Lio/opentelemetry/api/OpenTelemetry;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {v0}, Lio/opentelemetry/api/OpenTelemetry;->getMeterProvider()Lio/opentelemetry/api/metrics/MeterProvider;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    return-object v0
.end method

.method public static getPropagators()Lio/opentelemetry/context/propagation/ContextPropagators;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/api/GlobalOpenTelemetry;->get()Lio/opentelemetry/api/OpenTelemetry;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {v0}, Lio/opentelemetry/api/OpenTelemetry;->getPropagators()Lio/opentelemetry/context/propagation/ContextPropagators;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    return-object v0
.end method

.method public static getTracer(Ljava/lang/String;)Lio/opentelemetry/api/trace/Tracer;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/api/GlobalOpenTelemetry;->get()Lio/opentelemetry/api/OpenTelemetry;

    move-result-object v0

    invoke-interface {v0, p0}, Lio/opentelemetry/api/OpenTelemetry;->getTracer(Ljava/lang/String;)Lio/opentelemetry/api/trace/Tracer;

    move-result-object p0

    return-object p0
.end method

.method public static getTracer(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/api/trace/Tracer;
    .locals 1

    .line 2
    invoke-static {}, Lio/opentelemetry/api/GlobalOpenTelemetry;->get()Lio/opentelemetry/api/OpenTelemetry;

    move-result-object v0

    invoke-interface {v0, p0, p1}, Lio/opentelemetry/api/OpenTelemetry;->getTracer(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/api/trace/Tracer;

    move-result-object p0

    return-object p0
.end method

.method public static getTracerProvider()Lio/opentelemetry/api/trace/TracerProvider;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/api/GlobalOpenTelemetry;->get()Lio/opentelemetry/api/OpenTelemetry;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {v0}, Lio/opentelemetry/api/OpenTelemetry;->getTracerProvider()Lio/opentelemetry/api/trace/TracerProvider;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    return-object v0
.end method

.method private static maybeAutoConfigureAndSetGlobal()Lio/opentelemetry/api/OpenTelemetry;
    .locals 5
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    const/4 v0, 0x0

    .line 2
    :try_start_0
    const-string v1, "io.opentelemetry.sdk.autoconfigure.AutoConfiguredOpenTelemetrySdk"

    .line 3
    .line 4
    invoke-static {v1}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 5
    .line 6
    .line 7
    move-result-object v1
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_2

    .line 8
    const-string v2, "otel.java.global-autoconfigure.enabled"

    .line 9
    .line 10
    const-string v3, "false"

    .line 11
    .line 12
    invoke-static {v2, v3}, Lio/opentelemetry/api/internal/ConfigUtil;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    invoke-static {v2}, Ljava/lang/Boolean;->parseBoolean(Ljava/lang/String;)Z

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    if-nez v2, :cond_0

    .line 21
    .line 22
    sget-object v1, Lio/opentelemetry/api/GlobalOpenTelemetry;->logger:Ljava/util/logging/Logger;

    .line 23
    .line 24
    sget-object v2, Ljava/util/logging/Level;->INFO:Ljava/util/logging/Level;

    .line 25
    .line 26
    const-string v3, "AutoConfiguredOpenTelemetrySdk found on classpath but automatic configuration is disabled. To enable, run your JVM with -Dotel.java.global-autoconfigure.enabled=true"

    .line 27
    .line 28
    invoke-virtual {v1, v2, v3}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    return-object v0

    .line 32
    :cond_0
    :try_start_1
    const-string v2, "initialize"

    .line 33
    .line 34
    invoke-virtual {v1, v2, v0}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    invoke-virtual {v2, v0, v0}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v2

    .line 42
    const-string v3, "getOpenTelemetrySdk"

    .line 43
    .line 44
    invoke-virtual {v1, v3, v0}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    invoke-virtual {v1, v2, v0}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    check-cast v1, Lio/opentelemetry/api/OpenTelemetry;

    .line 53
    .line 54
    invoke-static {v1}, Lio/opentelemetry/api/GlobalOpenTelemetry;->obfuscatedOpenTelemetry(Lio/opentelemetry/api/OpenTelemetry;)Lio/opentelemetry/api/OpenTelemetry;

    .line 55
    .line 56
    .line 57
    move-result-object v0
    :try_end_1
    .catch Ljava/lang/NoSuchMethodException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/lang/IllegalAccessException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/lang/reflect/InvocationTargetException; {:try_start_1 .. :try_end_1} :catch_0

    .line 58
    return-object v0

    .line 59
    :catch_0
    move-exception v1

    .line 60
    sget-object v2, Lio/opentelemetry/api/GlobalOpenTelemetry;->logger:Ljava/util/logging/Logger;

    .line 61
    .line 62
    sget-object v3, Ljava/util/logging/Level;->SEVERE:Ljava/util/logging/Level;

    .line 63
    .line 64
    const-string v4, "Error automatically configuring OpenTelemetry SDK. OpenTelemetry will not be enabled."

    .line 65
    .line 66
    invoke-virtual {v1}, Ljava/lang/reflect/InvocationTargetException;->getTargetException()Ljava/lang/Throwable;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    invoke-virtual {v2, v3, v4, v1}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 71
    .line 72
    .line 73
    return-object v0

    .line 74
    :catch_1
    move-exception v0

    .line 75
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 76
    .line 77
    const-string v2, "AutoConfiguredOpenTelemetrySdk detected on classpath but could not invoke initialize method. This is a bug in OpenTelemetry."

    .line 78
    .line 79
    invoke-direct {v1, v2, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 80
    .line 81
    .line 82
    throw v1

    .line 83
    :catch_2
    return-object v0
.end method

.method public static meterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/MeterBuilder;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/api/GlobalOpenTelemetry;->get()Lio/opentelemetry/api/OpenTelemetry;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {v0, p0}, Lio/opentelemetry/api/OpenTelemetry;->meterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/MeterBuilder;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private static obfuscatedOpenTelemetry(Lio/opentelemetry/api/OpenTelemetry;)Lio/opentelemetry/api/OpenTelemetry;
    .locals 1

    .line 1
    invoke-static {p0}, Lio/opentelemetry/api/internal/IncubatingUtil;->obfuscatedOpenTelemetryIfIncubating(Lio/opentelemetry/api/OpenTelemetry;)Lio/opentelemetry/api/OpenTelemetry;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    return-object v0

    .line 8
    :cond_0
    new-instance v0, Lio/opentelemetry/api/GlobalOpenTelemetry$ObfuscatedOpenTelemetry;

    .line 9
    .line 10
    invoke-direct {v0, p0}, Lio/opentelemetry/api/GlobalOpenTelemetry$ObfuscatedOpenTelemetry;-><init>(Lio/opentelemetry/api/OpenTelemetry;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public static resetForTest()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    sput-object v0, Lio/opentelemetry/api/GlobalOpenTelemetry;->globalOpenTelemetry:Lio/opentelemetry/api/OpenTelemetry;

    .line 3
    .line 4
    return-void
.end method

.method public static set(Lio/opentelemetry/api/OpenTelemetry;)V
    .locals 3

    .line 1
    sget-object v0, Lio/opentelemetry/api/GlobalOpenTelemetry;->mutex:Ljava/lang/Object;

    monitor-enter v0

    .line 2
    :try_start_0
    sget-object v1, Lio/opentelemetry/api/GlobalOpenTelemetry;->globalOpenTelemetry:Lio/opentelemetry/api/OpenTelemetry;

    if-nez v1, :cond_0

    .line 3
    invoke-static {p0}, Lio/opentelemetry/api/GlobalOpenTelemetry;->obfuscatedOpenTelemetry(Lio/opentelemetry/api/OpenTelemetry;)Lio/opentelemetry/api/OpenTelemetry;

    move-result-object p0

    sput-object p0, Lio/opentelemetry/api/GlobalOpenTelemetry;->globalOpenTelemetry:Lio/opentelemetry/api/OpenTelemetry;

    .line 4
    new-instance p0, Ljava/lang/Throwable;

    invoke-direct {p0}, Ljava/lang/Throwable;-><init>()V

    sput-object p0, Lio/opentelemetry/api/GlobalOpenTelemetry;->setGlobalCaller:Ljava/lang/Throwable;

    .line 5
    monitor-exit v0

    return-void

    :catchall_0
    move-exception p0

    goto :goto_0

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string v1, "GlobalOpenTelemetry.set has already been called. GlobalOpenTelemetry.set must be called only once before any calls to GlobalOpenTelemetry.get. If you are using the OpenTelemetrySdk, use OpenTelemetrySdkBuilder.buildAndRegisterGlobal instead. Previous invocation set to cause of this exception."

    sget-object v2, Lio/opentelemetry/api/GlobalOpenTelemetry;->setGlobalCaller:Ljava/lang/Throwable;

    invoke-direct {p0, v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw p0

    .line 7
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public static set(Ljava/util/function/Supplier;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Supplier<",
            "Lio/opentelemetry/api/OpenTelemetry;",
            ">;)V"
        }
    .end annotation

    .line 8
    sget-object v0, Lio/opentelemetry/api/GlobalOpenTelemetry;->mutex:Ljava/lang/Object;

    monitor-enter v0

    .line 9
    :try_start_0
    invoke-interface {p0}, Ljava/util/function/Supplier;->get()Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lio/opentelemetry/api/OpenTelemetry;

    .line 10
    invoke-static {p0}, Lio/opentelemetry/api/GlobalOpenTelemetry;->set(Lio/opentelemetry/api/OpenTelemetry;)V

    .line 11
    monitor-exit v0

    return-void

    :catchall_0
    move-exception p0

    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public static tracerBuilder(Ljava/lang/String;)Lio/opentelemetry/api/trace/TracerBuilder;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/api/GlobalOpenTelemetry;->get()Lio/opentelemetry/api/OpenTelemetry;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {v0, p0}, Lio/opentelemetry/api/OpenTelemetry;->tracerBuilder(Ljava/lang/String;)Lio/opentelemetry/api/trace/TracerBuilder;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
