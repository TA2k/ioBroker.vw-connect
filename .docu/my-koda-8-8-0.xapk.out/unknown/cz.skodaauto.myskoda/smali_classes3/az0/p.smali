.class public Laz0/p;
.super Lvy0/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lrx0/d;


# instance fields
.field public final g:Lkotlin/coroutines/Continuation;


# direct methods
.method public constructor <init>(Lkotlin/coroutines/Continuation;Lpx0/g;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-direct {p0, p2, v0, v0}, Lvy0/a;-><init>(Lpx0/g;ZZ)V

    .line 3
    .line 4
    .line 5
    iput-object p1, p0, Laz0/p;->g:Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final V()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final getCallerFrame()Lrx0/d;
    .locals 1

    .line 1
    iget-object p0, p0, Laz0/p;->g:Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    instance-of v0, p0, Lrx0/d;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    check-cast p0, Lrx0/d;

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    return-object p0
.end method

.method public o0()V
    .locals 0

    .line 1
    return-void
.end method

.method public v(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-object p0, p0, Laz0/p;->g:Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    invoke-static {p0}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-static {p1}, Lvy0/e0;->I(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    invoke-static {p1, p0}, Laz0/b;->h(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public x(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-object p0, p0, Laz0/p;->g:Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    invoke-static {p1}, Lvy0/e0;->I(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-interface {p0, p1}, Lkotlin/coroutines/Continuation;->resumeWith(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method
