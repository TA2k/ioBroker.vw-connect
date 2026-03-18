.class public abstract Lrx0/c;
.super Lrx0/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final _context:Lpx0/g;

.field private transient intercepted:Lkotlin/coroutines/Continuation;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lkotlin/coroutines/Continuation<",
            "Ljava/lang/Object;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lkotlin/coroutines/Continuation;)V
    .locals 1

    if-eqz p1, :cond_0

    .line 3
    invoke-interface {p1}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    move-result-object v0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    invoke-direct {p0, p1, v0}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;Lpx0/g;)V

    return-void
.end method

.method public constructor <init>(Lkotlin/coroutines/Continuation;Lpx0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lrx0/a;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 2
    iput-object p2, p0, Lrx0/c;->_context:Lpx0/g;

    return-void
.end method


# virtual methods
.method public getContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lrx0/c;->_context:Lpx0/g;

    .line 2
    .line 3
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public final intercepted()Lkotlin/coroutines/Continuation;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lkotlin/coroutines/Continuation<",
            "Ljava/lang/Object;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lrx0/c;->intercepted:Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    invoke-virtual {p0}, Lrx0/c;->getContext()Lpx0/g;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sget-object v1, Lpx0/c;->d:Lpx0/c;

    .line 10
    .line 11
    invoke-interface {v0, v1}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    check-cast v0, Lpx0/d;

    .line 16
    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    check-cast v0, Lvy0/x;

    .line 20
    .line 21
    new-instance v1, Laz0/f;

    .line 22
    .line 23
    invoke-direct {v1, v0, p0}, Laz0/f;-><init>(Lvy0/x;Lrx0/c;)V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    move-object v1, p0

    .line 28
    :goto_0
    iput-object v1, p0, Lrx0/c;->intercepted:Lkotlin/coroutines/Continuation;

    .line 29
    .line 30
    return-object v1

    .line 31
    :cond_1
    return-object v0
.end method

.method public releaseIntercepted()V
    .locals 4

    .line 1
    iget-object v0, p0, Lrx0/c;->intercepted:Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    if-eqz v0, :cond_2

    .line 4
    .line 5
    if-eq v0, p0, :cond_2

    .line 6
    .line 7
    invoke-virtual {p0}, Lrx0/c;->getContext()Lpx0/g;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    sget-object v2, Lpx0/c;->d:Lpx0/c;

    .line 12
    .line 13
    invoke-interface {v1, v2}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    check-cast v1, Lpx0/d;

    .line 21
    .line 22
    check-cast v0, Laz0/f;

    .line 23
    .line 24
    sget-object v1, Laz0/f;->k:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 25
    .line 26
    :cond_0
    invoke-virtual {v1, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    sget-object v3, Laz0/b;->c:Lj51/i;

    .line 31
    .line 32
    if-eq v2, v3, :cond_0

    .line 33
    .line 34
    invoke-virtual {v1, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    instance-of v1, v0, Lvy0/l;

    .line 39
    .line 40
    if-eqz v1, :cond_1

    .line 41
    .line 42
    check-cast v0, Lvy0/l;

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_1
    const/4 v0, 0x0

    .line 46
    :goto_0
    if-eqz v0, :cond_2

    .line 47
    .line 48
    invoke-virtual {v0}, Lvy0/l;->m()V

    .line 49
    .line 50
    .line 51
    :cond_2
    sget-object v0, Lrx0/b;->d:Lrx0/b;

    .line 52
    .line 53
    iput-object v0, p0, Lrx0/c;->intercepted:Lkotlin/coroutines/Continuation;

    .line 54
    .line 55
    return-void
.end method
