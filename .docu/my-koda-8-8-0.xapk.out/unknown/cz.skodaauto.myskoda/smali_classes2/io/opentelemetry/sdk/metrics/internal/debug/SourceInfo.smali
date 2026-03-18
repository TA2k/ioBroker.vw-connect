.class public interface abstract Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static fromCurrentStack()Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;
    .locals 2

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/debug/DebugConfig;->isMetricsDebugEnabled()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;->noSourceInfo()Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    return-object v0

    .line 12
    :cond_0
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/debug/StackTraceSourceInfo;

    .line 13
    .line 14
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    invoke-virtual {v1}, Ljava/lang/Thread;->getStackTrace()[Ljava/lang/StackTraceElement;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-direct {v0, v1}, Lio/opentelemetry/sdk/metrics/internal/debug/StackTraceSourceInfo;-><init>([Ljava/lang/StackTraceElement;)V

    .line 23
    .line 24
    .line 25
    return-object v0
.end method

.method public static noSourceInfo()Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;->INSTANCE:Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public abstract multiLineDebugString()Ljava/lang/String;
.end method

.method public abstract shortDebugString()Ljava/lang/String;
.end method
