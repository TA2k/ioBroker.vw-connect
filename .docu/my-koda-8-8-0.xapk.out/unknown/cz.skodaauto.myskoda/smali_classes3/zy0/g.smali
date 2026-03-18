.class public final Lzy0/g;
.super Lzy0/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public constructor <init>(Lyy0/i;Lpx0/g;ILxy0/a;I)V
    .locals 1

    .line 1
    and-int/lit8 v0, p5, 0x2

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object p2, Lpx0/h;->d:Lpx0/h;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 v0, p5, 0x4

    .line 8
    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    const/4 p3, -0x3

    .line 12
    :cond_1
    and-int/lit8 p5, p5, 0x8

    .line 13
    .line 14
    if-eqz p5, :cond_2

    .line 15
    .line 16
    sget-object p4, Lxy0/a;->d:Lxy0/a;

    .line 17
    .line 18
    :cond_2
    invoke-direct {p0, p1, p2, p3, p4}, Lzy0/f;-><init>(Lyy0/i;Lpx0/g;ILxy0/a;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final f(Lpx0/g;ILxy0/a;)Lzy0/e;
    .locals 1

    .line 1
    new-instance v0, Lzy0/g;

    .line 2
    .line 3
    iget-object p0, p0, Lzy0/f;->g:Lyy0/i;

    .line 4
    .line 5
    invoke-direct {v0, p0, p1, p2, p3}, Lzy0/f;-><init>(Lyy0/i;Lpx0/g;ILxy0/a;)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method

.method public final g()Lyy0/i;
    .locals 0

    .line 1
    iget-object p0, p0, Lzy0/f;->g:Lyy0/i;

    .line 2
    .line 3
    return-object p0
.end method

.method public final i(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lzy0/f;->g:Lyy0/i;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 8
    .line 9
    if-ne p0, p1, :cond_0

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    return-object p0
.end method
