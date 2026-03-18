.class public interface abstract Lio/opentelemetry/sdk/common/Clock;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Ljavax/annotation/concurrent/ThreadSafe;
.end annotation


# direct methods
.method public static getDefault()Lio/opentelemetry/sdk/common/Clock;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/common/SystemClock;->getInstance()Lio/opentelemetry/sdk/common/Clock;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method


# virtual methods
.method public abstract nanoTime()J
.end method

.method public abstract now()J
.end method

.method public now(Z)J
    .locals 0

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/sdk/common/Clock;->now()J

    move-result-wide p0

    return-wide p0
.end method
