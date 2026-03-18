.class public interface abstract Lio/opentelemetry/instrumentation/api/instrumenter/ErrorCauseExtractor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Ljava/lang/FunctionalInterface;
.end annotation


# direct methods
.method public static getDefault()Lio/opentelemetry/instrumentation/api/instrumenter/ErrorCauseExtractor;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/instrumenter/DefaultErrorCauseExtractor;->INSTANCE:Lio/opentelemetry/instrumentation/api/instrumenter/ErrorCauseExtractor;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public abstract extract(Ljava/lang/Throwable;)Ljava/lang/Throwable;
.end method
