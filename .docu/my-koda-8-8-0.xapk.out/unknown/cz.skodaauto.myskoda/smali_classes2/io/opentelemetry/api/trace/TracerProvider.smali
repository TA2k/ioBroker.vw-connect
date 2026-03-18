.class public interface abstract Lio/opentelemetry/api/trace/TracerProvider;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Ljavax/annotation/concurrent/ThreadSafe;
.end annotation


# direct methods
.method public static noop()Lio/opentelemetry/api/trace/TracerProvider;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/api/trace/DefaultTracerProvider;->getInstance()Lio/opentelemetry/api/trace/TracerProvider;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method


# virtual methods
.method public abstract get(Ljava/lang/String;)Lio/opentelemetry/api/trace/Tracer;
.end method

.method public abstract get(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/api/trace/Tracer;
.end method

.method public tracerBuilder(Ljava/lang/String;)Lio/opentelemetry/api/trace/TracerBuilder;
    .locals 0

    .line 1
    invoke-static {}, Lio/opentelemetry/api/trace/DefaultTracerBuilder;->getInstance()Lio/opentelemetry/api/trace/TracerBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
