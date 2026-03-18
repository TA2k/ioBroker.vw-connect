.class public Lyy0/e;
.super Lzy0/e;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic g:I

.field public final h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lay0/n;Lpx0/g;ILxy0/a;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lyy0/e;->g:I

    .line 3
    invoke-direct {p0, p2, p3, p4}, Lzy0/e;-><init>(Lpx0/g;ILxy0/a;)V

    .line 4
    check-cast p1, Lrx0/i;

    iput-object p1, p0, Lyy0/e;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/lang/Iterable;Lpx0/g;ILxy0/a;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lyy0/e;->g:I

    .line 1
    invoke-direct {p0, p2, p3, p4}, Lzy0/e;-><init>(Lpx0/g;ILxy0/a;)V

    .line 2
    iput-object p1, p0, Lyy0/e;->h:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public e(Lxy0/x;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lyy0/e;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p2, Lzy0/u;

    .line 7
    .line 8
    invoke-direct {p2, p1}, Lzy0/u;-><init>(Lxy0/x;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lyy0/e;->h:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Ljava/lang/Iterable;

    .line 14
    .line 15
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    check-cast v0, Lyy0/i;

    .line 30
    .line 31
    new-instance v1, Lyz/b;

    .line 32
    .line 33
    const/16 v2, 0xb

    .line 34
    .line 35
    const/4 v3, 0x0

    .line 36
    invoke-direct {v1, v2, v0, p2, v3}, Lyz/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 37
    .line 38
    .line 39
    const/4 v0, 0x3

    .line 40
    invoke-static {p1, v3, v3, v1, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 45
    .line 46
    return-object p0

    .line 47
    :pswitch_0
    iget-object p0, p0, Lyy0/e;->h:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast p0, Lrx0/i;

    .line 50
    .line 51
    invoke-interface {p0, p1, p2}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 56
    .line 57
    if-ne p0, p1, :cond_1

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 61
    .line 62
    :goto_1
    return-object p0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public f(Lpx0/g;ILxy0/a;)Lzy0/e;
    .locals 1

    .line 1
    iget v0, p0, Lyy0/e;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lyy0/e;

    .line 7
    .line 8
    iget-object p0, p0, Lyy0/e;->h:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Ljava/lang/Iterable;

    .line 11
    .line 12
    invoke-direct {v0, p0, p1, p2, p3}, Lyy0/e;-><init>(Ljava/lang/Iterable;Lpx0/g;ILxy0/a;)V

    .line 13
    .line 14
    .line 15
    return-object v0

    .line 16
    :pswitch_0
    new-instance v0, Lyy0/e;

    .line 17
    .line 18
    iget-object p0, p0, Lyy0/e;->h:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Lrx0/i;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1, p2, p3}, Lyy0/e;-><init>(Lay0/n;Lpx0/g;ILxy0/a;)V

    .line 23
    .line 24
    .line 25
    return-object v0

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public h(Lvy0/b0;)Lxy0/z;
    .locals 5

    .line 1
    iget v0, p0, Lyy0/e;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Lzy0/e;->h(Lvy0/b0;)Lxy0/z;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    new-instance v0, Lyz/b;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    const/16 v2, 0x9

    .line 15
    .line 16
    invoke-direct {v0, p0, v1, v2}, Lyz/b;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 17
    .line 18
    .line 19
    sget-object v1, Lxy0/a;->d:Lxy0/a;

    .line 20
    .line 21
    sget-object v2, Lvy0/c0;->d:Lvy0/c0;

    .line 22
    .line 23
    const/4 v3, 0x4

    .line 24
    iget v4, p0, Lzy0/e;->e:I

    .line 25
    .line 26
    invoke-static {v4, v3, v1}, Llp/jf;->a(IILxy0/a;)Lxy0/j;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    iget-object p0, p0, Lzy0/e;->d:Lpx0/g;

    .line 31
    .line 32
    invoke-static {p1, p0}, Lvy0/e0;->F(Lvy0/b0;Lpx0/g;)Lpx0/g;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    new-instance p1, Lxy0/w;

    .line 37
    .line 38
    const/4 v3, 0x1

    .line 39
    invoke-direct {p1, p0, v1, v3, v3}, Lxy0/w;-><init>(Lpx0/g;Lxy0/j;ZZ)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {p1, v2, p1, v0}, Lvy0/a;->n0(Lvy0/c0;Lvy0/a;Lay0/n;)V

    .line 43
    .line 44
    .line 45
    return-object p1

    .line 46
    nop

    .line 47
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget v0, p0, Lyy0/e;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Lzy0/e;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v1, "block["

    .line 14
    .line 15
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lyy0/e;->h:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v1, Lrx0/i;

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v1, "] -> "

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-super {p0}, Lzy0/e;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0

    .line 42
    nop

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
