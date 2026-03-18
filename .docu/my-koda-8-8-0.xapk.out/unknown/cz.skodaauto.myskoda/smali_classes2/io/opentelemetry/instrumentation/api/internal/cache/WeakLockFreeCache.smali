.class final Lio/opentelemetry/instrumentation/api/internal/cache/WeakLockFreeCache;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/internal/cache/Cache;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<K:",
        "Ljava/lang/Object;",
        "V:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Lio/opentelemetry/instrumentation/api/internal/cache/Cache<",
        "TK;TV;>;"
    }
.end annotation


# instance fields
.field private final delegate:Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/WeakConcurrentMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/WeakConcurrentMap<",
            "TK;TV;>;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/WeakConcurrentMap$WithInlinedExpunction;

    .line 5
    .line 6
    invoke-direct {v0}, Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/WeakConcurrentMap$WithInlinedExpunction;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/internal/cache/WeakLockFreeCache;->delegate:Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/WeakConcurrentMap;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TK;",
            "Ljava/util/function/Function<",
            "-TK;+TV;>;)TV;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/internal/cache/WeakLockFreeCache;->delegate:Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/WeakConcurrentMap;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/WeakConcurrentMap;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public get(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TK;)TV;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/internal/cache/WeakLockFreeCache;->delegate:Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/WeakConcurrentMap;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/WeakConcurrentMap;->getIfPresent(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public put(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TK;TV;)V"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/internal/cache/WeakLockFreeCache;->delegate:Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/WeakConcurrentMap;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/WeakConcurrentMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public remove(Ljava/lang/Object;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TK;)V"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/internal/cache/WeakLockFreeCache;->delegate:Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/WeakConcurrentMap;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/WeakConcurrentMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public size()I
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/internal/cache/WeakLockFreeCache;->delegate:Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/WeakConcurrentMap;

    .line 2
    .line 3
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/WeakConcurrentMap;->approximateSize()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
