.class public interface abstract Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public setStatus(Lio/opentelemetry/api/trace/StatusCode;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusBuilder;
    .locals 1

    .line 1
    const-string v0, ""

    invoke-interface {p0, p1, v0}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusBuilder;->setStatus(Lio/opentelemetry/api/trace/StatusCode;Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusBuilder;

    move-result-object p0

    return-object p0
.end method

.method public abstract setStatus(Lio/opentelemetry/api/trace/StatusCode;Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusBuilder;
.end method
