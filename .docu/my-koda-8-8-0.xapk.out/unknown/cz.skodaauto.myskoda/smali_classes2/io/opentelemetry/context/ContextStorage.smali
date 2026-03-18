.class public interface abstract Lio/opentelemetry/context/ContextStorage;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static addWrapper(Ljava/util/function/Function;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Function<",
            "-",
            "Lio/opentelemetry/context/ContextStorage;",
            "+",
            "Lio/opentelemetry/context/ContextStorage;",
            ">;)V"
        }
    .end annotation

    .line 1
    invoke-static {p0}, Lio/opentelemetry/context/ContextStorageWrappers;->addWrapper(Ljava/util/function/Function;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static defaultStorage()Lio/opentelemetry/context/ContextStorage;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/context/ThreadLocalContextStorage;->INSTANCE:Lio/opentelemetry/context/ThreadLocalContextStorage;

    .line 2
    .line 3
    return-object v0
.end method

.method public static get()Lio/opentelemetry/context/ContextStorage;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/context/LazyStorage;->get()Lio/opentelemetry/context/ContextStorage;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method


# virtual methods
.method public abstract attach(Lio/opentelemetry/context/Context;)Lio/opentelemetry/context/Scope;
.end method

.method public abstract current()Lio/opentelemetry/context/Context;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public root()Lio/opentelemetry/context/Context;
    .locals 0

    .line 1
    invoke-static {}, Lio/opentelemetry/context/ArrayBasedContext;->root()Lio/opentelemetry/context/Context;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
