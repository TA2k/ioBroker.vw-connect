.class public final Lzy0/j;
.super Lzy0/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lrx0/i;


# direct methods
.method public constructor <init>(Lay0/o;Lyy0/i;Lpx0/g;ILxy0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0, p2, p3, p4, p5}, Lzy0/f;-><init>(Lyy0/i;Lpx0/g;ILxy0/a;)V

    .line 2
    .line 3
    .line 4
    check-cast p1, Lrx0/i;

    .line 5
    .line 6
    iput-object p1, p0, Lzy0/j;->h:Lrx0/i;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final f(Lpx0/g;ILxy0/a;)Lzy0/e;
    .locals 6

    .line 1
    new-instance v0, Lzy0/j;

    .line 2
    .line 3
    iget-object v1, p0, Lzy0/j;->h:Lrx0/i;

    .line 4
    .line 5
    iget-object v2, p0, Lzy0/f;->g:Lyy0/i;

    .line 6
    .line 7
    move-object v3, p1

    .line 8
    move v4, p2

    .line 9
    move-object v5, p3

    .line 10
    invoke-direct/range {v0 .. v5}, Lzy0/j;-><init>(Lay0/o;Lyy0/i;Lpx0/g;ILxy0/a;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public final i(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    new-instance v0, Lzy0/h;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, p1, v1}, Lzy0/h;-><init>(Lzy0/j;Lyy0/j;Lkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    invoke-static {v0, p2}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 12
    .line 13
    if-ne p0, p1, :cond_0

    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    return-object p0
.end method
