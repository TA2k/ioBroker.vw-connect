.class public final Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# instance fields
.field private final objectCreator:Ljava/util/function/Supplier;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Supplier<",
            "TT;>;"
        }
    .end annotation
.end field

.field private final pool:Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack<",
            "TT;>;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ljava/util/function/Supplier;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Supplier<",
            "TT;>;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;

    .line 5
    .line 6
    invoke-direct {v0}, Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;->pool:Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;

    .line 10
    .line 11
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;->objectCreator:Ljava/util/function/Supplier;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public borrowObject()Ljava/lang/Object;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()TT;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;->pool:Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;

    .line 2
    .line 3
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;->pop()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;->objectCreator:Ljava/util/function/Supplier;

    .line 10
    .line 11
    invoke-interface {p0}, Ljava/util/function/Supplier;->get()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :cond_0
    return-object v0
.end method

.method public returnObject(Ljava/lang/Object;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TT;)V"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;->pool:Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;->push(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
