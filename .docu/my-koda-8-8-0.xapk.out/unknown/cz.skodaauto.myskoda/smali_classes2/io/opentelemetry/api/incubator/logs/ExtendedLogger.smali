.class public interface abstract Lio/opentelemetry/api/incubator/logs/ExtendedLogger;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/logs/Logger;


# virtual methods
.method public isEnabled()Z
    .locals 1
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 3
    sget-object v0, Lio/opentelemetry/api/logs/Severity;->UNDEFINED_SEVERITY_NUMBER:Lio/opentelemetry/api/logs/Severity;

    invoke-interface {p0, v0}, Lio/opentelemetry/api/incubator/logs/ExtendedLogger;->isEnabled(Lio/opentelemetry/api/logs/Severity;)Z

    move-result p0

    return p0
.end method

.method public isEnabled(Lio/opentelemetry/api/logs/Severity;)Z
    .locals 1

    .line 2
    invoke-static {}, Lio/opentelemetry/context/Context;->current()Lio/opentelemetry/context/Context;

    move-result-object v0

    invoke-interface {p0, p1, v0}, Lio/opentelemetry/api/incubator/logs/ExtendedLogger;->isEnabled(Lio/opentelemetry/api/logs/Severity;Lio/opentelemetry/context/Context;)Z

    move-result p0

    return p0
.end method

.method public isEnabled(Lio/opentelemetry/api/logs/Severity;Lio/opentelemetry/context/Context;)Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    return p0
.end method

.method public abstract logRecordBuilder()Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
.end method

.method public bridge synthetic logRecordBuilder()Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/api/incubator/logs/ExtendedLogger;->logRecordBuilder()Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method
