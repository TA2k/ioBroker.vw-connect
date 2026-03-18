.class public interface abstract Lio/opentelemetry/sdk/trace/data/ExceptionEventData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/trace/data/EventData;


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# direct methods
.method public static create(JLjava/lang/Throwable;Lio/opentelemetry/api/common/Attributes;I)Lio/opentelemetry/sdk/trace/data/ExceptionEventData;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3, p4}, Lio/opentelemetry/sdk/trace/data/ImmutableExceptionEventData;->create(JLjava/lang/Throwable;Lio/opentelemetry/api/common/Attributes;I)Lio/opentelemetry/sdk/trace/data/ExceptionEventData;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method


# virtual methods
.method public abstract getException()Ljava/lang/Throwable;
.end method
