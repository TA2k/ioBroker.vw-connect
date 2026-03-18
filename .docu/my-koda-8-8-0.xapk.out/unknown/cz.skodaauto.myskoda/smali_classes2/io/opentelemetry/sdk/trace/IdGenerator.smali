.class public interface abstract Lio/opentelemetry/sdk/trace/IdGenerator;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Ljavax/annotation/concurrent/ThreadSafe;
.end annotation


# direct methods
.method public static random()Lio/opentelemetry/sdk/trace/IdGenerator;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/trace/RandomIdGenerator;->INSTANCE:Lio/opentelemetry/sdk/trace/RandomIdGenerator;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public abstract generateSpanId()Ljava/lang/String;
.end method

.method public abstract generateTraceId()Ljava/lang/String;
.end method
