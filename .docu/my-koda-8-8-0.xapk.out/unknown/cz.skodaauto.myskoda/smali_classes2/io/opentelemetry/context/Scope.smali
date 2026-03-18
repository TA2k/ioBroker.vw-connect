.class public interface abstract Lio/opentelemetry/context/Scope;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/AutoCloseable;


# direct methods
.method public static noop()Lio/opentelemetry/context/Scope;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;->INSTANCE:Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public abstract close()V
.end method
