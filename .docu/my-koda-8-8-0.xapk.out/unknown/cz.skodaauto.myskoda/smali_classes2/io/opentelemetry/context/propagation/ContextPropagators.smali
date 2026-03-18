.class public interface abstract Lio/opentelemetry/context/propagation/ContextPropagators;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Ljavax/annotation/concurrent/ThreadSafe;
.end annotation


# direct methods
.method public static create(Lio/opentelemetry/context/propagation/TextMapPropagator;)Lio/opentelemetry/context/propagation/ContextPropagators;
    .locals 1

    .line 1
    const-string v0, "textPropagator"

    .line 2
    .line 3
    invoke-static {p0, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    new-instance v0, Lio/opentelemetry/context/propagation/DefaultContextPropagators;

    .line 7
    .line 8
    invoke-direct {v0, p0}, Lio/opentelemetry/context/propagation/DefaultContextPropagators;-><init>(Lio/opentelemetry/context/propagation/TextMapPropagator;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method

.method public static noop()Lio/opentelemetry/context/propagation/ContextPropagators;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/context/propagation/DefaultContextPropagators;->noop()Lio/opentelemetry/context/propagation/ContextPropagators;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method


# virtual methods
.method public abstract getTextMapPropagator()Lio/opentelemetry/context/propagation/TextMapPropagator;
.end method
