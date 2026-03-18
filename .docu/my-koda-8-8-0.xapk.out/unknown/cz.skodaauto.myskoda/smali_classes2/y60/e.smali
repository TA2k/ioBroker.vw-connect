.class public final Ly60/e;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx60/n;

.field public final synthetic f:Lvy0/b0;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lh2/r8;


# direct methods
.method public synthetic constructor <init>(Lx60/n;Lvy0/b0;Lay0/a;Lh2/r8;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p6, p0, Ly60/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly60/e;->e:Lx60/n;

    .line 4
    .line 5
    iput-object p2, p0, Ly60/e;->f:Lvy0/b0;

    .line 6
    .line 7
    iput-object p3, p0, Ly60/e;->g:Lay0/a;

    .line 8
    .line 9
    iput-object p4, p0, Ly60/e;->h:Lh2/r8;

    .line 10
    .line 11
    const/4 p1, 0x2

    .line 12
    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 8

    .line 1
    iget p1, p0, Ly60/e;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Ly60/e;

    .line 7
    .line 8
    iget-object v4, p0, Ly60/e;->h:Lh2/r8;

    .line 9
    .line 10
    const/4 v6, 0x1

    .line 11
    iget-object v1, p0, Ly60/e;->e:Lx60/n;

    .line 12
    .line 13
    iget-object v2, p0, Ly60/e;->f:Lvy0/b0;

    .line 14
    .line 15
    iget-object v3, p0, Ly60/e;->g:Lay0/a;

    .line 16
    .line 17
    move-object v5, p2

    .line 18
    invoke-direct/range {v0 .. v6}, Ly60/e;-><init>(Lx60/n;Lvy0/b0;Lay0/a;Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 19
    .line 20
    .line 21
    return-object v0

    .line 22
    :pswitch_0
    move-object v5, p2

    .line 23
    new-instance v1, Ly60/e;

    .line 24
    .line 25
    move-object v6, v5

    .line 26
    iget-object v5, p0, Ly60/e;->h:Lh2/r8;

    .line 27
    .line 28
    const/4 v7, 0x0

    .line 29
    iget-object v2, p0, Ly60/e;->e:Lx60/n;

    .line 30
    .line 31
    iget-object v3, p0, Ly60/e;->f:Lvy0/b0;

    .line 32
    .line 33
    iget-object v4, p0, Ly60/e;->g:Lay0/a;

    .line 34
    .line 35
    invoke-direct/range {v1 .. v7}, Ly60/e;-><init>(Lx60/n;Lvy0/b0;Lay0/a;Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    return-object v1

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ly60/e;->d:I

    .line 2
    .line 3
    check-cast p1, Lvy0/b0;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Ly60/e;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ly60/e;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ly60/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ly60/e;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    check-cast p0, Ly60/e;

    .line 27
    .line 28
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    invoke-virtual {p0, p1}, Ly60/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    return-object p1

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Ly60/e;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    iget-object v2, p0, Ly60/e;->g:Lay0/a;

    .line 6
    .line 7
    const/4 v3, 0x3

    .line 8
    iget-object v4, p0, Ly60/e;->h:Lh2/r8;

    .line 9
    .line 10
    iget-object v5, p0, Ly60/e;->f:Lvy0/b0;

    .line 11
    .line 12
    iget-object p0, p0, Ly60/e;->e:Lx60/n;

    .line 13
    .line 14
    const/4 v6, 0x0

    .line 15
    packed-switch v0, :pswitch_data_0

    .line 16
    .line 17
    .line 18
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 19
    .line 20
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    iget-boolean p0, p0, Lx60/n;->o:Z

    .line 24
    .line 25
    if-eqz p0, :cond_0

    .line 26
    .line 27
    new-instance p0, Lxk0/c0;

    .line 28
    .line 29
    const/4 p1, 0x2

    .line 30
    invoke-direct {p0, v4, v6, p1}, Lxk0/c0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 31
    .line 32
    .line 33
    invoke-static {v5, v6, v6, p0, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 34
    .line 35
    .line 36
    invoke-interface {v2}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    :cond_0
    return-object v1

    .line 40
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 41
    .line 42
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    iget-boolean p0, p0, Lx60/n;->n:Z

    .line 46
    .line 47
    if-eqz p0, :cond_1

    .line 48
    .line 49
    new-instance p0, Lxk0/c0;

    .line 50
    .line 51
    const/4 p1, 0x1

    .line 52
    invoke-direct {p0, v4, v6, p1}, Lxk0/c0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 53
    .line 54
    .line 55
    invoke-static {v5, v6, v6, p0, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 56
    .line 57
    .line 58
    invoke-interface {v2}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    :cond_1
    return-object v1

    .line 62
    nop

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
