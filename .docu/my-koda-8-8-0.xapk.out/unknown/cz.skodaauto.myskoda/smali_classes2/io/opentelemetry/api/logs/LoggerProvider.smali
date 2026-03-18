.class public interface abstract Lio/opentelemetry/api/logs/LoggerProvider;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Ljavax/annotation/concurrent/ThreadSafe;
.end annotation


# direct methods
.method public static noop()Lio/opentelemetry/api/logs/LoggerProvider;
    .locals 2

    .line 1
    invoke-static {}, Lio/opentelemetry/api/logs/DefaultLoggerProvider;->getInstance()Lio/opentelemetry/api/logs/LoggerProvider;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-string v1, "io.opentelemetry.api.incubator.logs.ExtendedDefaultLoggerProvider"

    .line 6
    .line 7
    invoke-static {v0, v1}, Lio/opentelemetry/api/internal/IncubatingUtil;->incubatingApiIfAvailable(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    check-cast v0, Lio/opentelemetry/api/logs/LoggerProvider;

    .line 12
    .line 13
    return-object v0
.end method


# virtual methods
.method public get(Ljava/lang/String;)Lio/opentelemetry/api/logs/Logger;
    .locals 0

    .line 1
    invoke-interface {p0, p1}, Lio/opentelemetry/api/logs/LoggerProvider;->loggerBuilder(Ljava/lang/String;)Lio/opentelemetry/api/logs/LoggerBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0}, Lio/opentelemetry/api/logs/LoggerBuilder;->build()Lio/opentelemetry/api/logs/Logger;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public abstract loggerBuilder(Ljava/lang/String;)Lio/opentelemetry/api/logs/LoggerBuilder;
.end method
