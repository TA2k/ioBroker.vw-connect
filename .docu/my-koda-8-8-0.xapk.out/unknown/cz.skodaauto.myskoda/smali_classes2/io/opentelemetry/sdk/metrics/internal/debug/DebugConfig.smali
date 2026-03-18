.class public final Lio/opentelemetry/sdk/metrics/internal/debug/DebugConfig;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final ENABLE_METRICS_DEBUG_PROPERTY:Ljava/lang/String; = "otel.experimental.sdk.metrics.debug"

.field private static enabled:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-string v0, "otel.experimental.sdk.metrics.debug"

    .line 2
    .line 3
    const-string v1, "false"

    .line 4
    .line 5
    invoke-static {v0, v1}, Lio/opentelemetry/api/internal/ConfigUtil;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-static {v0}, Ljava/lang/Boolean;->parseBoolean(Ljava/lang/String;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    sput-boolean v0, Lio/opentelemetry/sdk/metrics/internal/debug/DebugConfig;->enabled:Z

    .line 14
    .line 15
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

.method public static enableForTesting(Z)V
    .locals 0

    .line 1
    sput-boolean p0, Lio/opentelemetry/sdk/metrics/internal/debug/DebugConfig;->enabled:Z

    .line 2
    .line 3
    return-void
.end method

.method public static getHowToEnableMessage()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "To enable better debugging, run your JVM with -Dotel.experimental.sdk.metrics.debug=true"

    .line 2
    .line 3
    return-object v0
.end method

.method public static isMetricsDebugEnabled()Z
    .locals 1

    .line 1
    sget-boolean v0, Lio/opentelemetry/sdk/metrics/internal/debug/DebugConfig;->enabled:Z

    .line 2
    .line 3
    return v0
.end method
