.class public interface abstract Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/ExemplarFilter;


# direct methods
.method public static asExemplarFilterInternal(Lio/opentelemetry/sdk/metrics/ExemplarFilter;)Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;
    .locals 1

    .line 1
    instance-of v0, p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p0, Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 9
    .line 10
    const-string v0, "Custom ExemplarFilter implementations are currently not supported. Use one of the standard implementations returned by the static factories in the ExemplarFilter class."

    .line 11
    .line 12
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    throw p0
.end method


# virtual methods
.method public abstract shouldSampleMeasurement(DLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)Z
.end method

.method public abstract shouldSampleMeasurement(JLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)Z
.end method
