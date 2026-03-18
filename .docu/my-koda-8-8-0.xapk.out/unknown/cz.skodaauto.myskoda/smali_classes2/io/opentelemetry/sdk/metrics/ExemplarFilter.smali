.class public interface abstract Lio/opentelemetry/sdk/metrics/ExemplarFilter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static alwaysOff()Lio/opentelemetry/sdk/metrics/ExemplarFilter;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/exemplar/AlwaysOffExemplarFilter;->getInstance()Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static alwaysOn()Lio/opentelemetry/sdk/metrics/ExemplarFilter;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/exemplar/AlwaysOnExemplarFilter;->getInstance()Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static traceBased()Lio/opentelemetry/sdk/metrics/ExemplarFilter;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/exemplar/TraceBasedExemplarFilter;->getInstance()Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method
