.class public final Ly70/n1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ly70/u1;


# direct methods
.method public synthetic constructor <init>(Ly70/u1;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ly70/n1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly70/n1;->f:Ly70/u1;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget v0, p0, Ly70/n1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Ly70/n1;

    .line 7
    .line 8
    iget-object p0, p0, Ly70/n1;->f:Ly70/u1;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, p0, p2, v1}, Ly70/n1;-><init>(Ly70/u1;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Ly70/n1;->e:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Ly70/n1;

    .line 18
    .line 19
    iget-object p0, p0, Ly70/n1;->f:Ly70/u1;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-direct {v0, p0, p2, v1}, Ly70/n1;-><init>(Ly70/u1;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Ly70/n1;->e:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ly70/n1;->d:I

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
    invoke-virtual {p0, p1, p2}, Ly70/n1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ly70/n1;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ly70/n1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ly70/n1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    check-cast p0, Ly70/n1;

    .line 27
    .line 28
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    invoke-virtual {p0, p1}, Ly70/n1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 5

    .line 1
    iget v0, p0, Ly70/n1;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    iget-object v3, p0, Ly70/n1;->f:Ly70/u1;

    .line 7
    .line 8
    const/4 v4, 0x3

    .line 9
    iget-object p0, p0, Ly70/n1;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Lvy0/b0;

    .line 12
    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 17
    .line 18
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    new-instance p1, Ly70/k1;

    .line 22
    .line 23
    const/16 v0, 0xb

    .line 24
    .line 25
    invoke-direct {p1, v3, v0}, Ly70/k1;-><init>(Ly70/u1;I)V

    .line 26
    .line 27
    .line 28
    invoke-static {p0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    invoke-static {v3}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    new-instance p1, Ly70/l1;

    .line 39
    .line 40
    const/4 v0, 0x6

    .line 41
    invoke-direct {p1, v3, v2, v0}, Ly70/l1;-><init>(Ly70/u1;Lkotlin/coroutines/Continuation;I)V

    .line 42
    .line 43
    .line 44
    invoke-static {p0, v2, v2, p1, v4}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 45
    .line 46
    .line 47
    return-object v1

    .line 48
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 49
    .line 50
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    new-instance p1, Ly70/l1;

    .line 54
    .line 55
    const/4 v0, 0x1

    .line 56
    invoke-direct {p1, v3, v2, v0}, Ly70/l1;-><init>(Ly70/u1;Lkotlin/coroutines/Continuation;I)V

    .line 57
    .line 58
    .line 59
    invoke-static {p0, v2, v2, p1, v4}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 60
    .line 61
    .line 62
    new-instance p1, Ly70/l1;

    .line 63
    .line 64
    const/4 v0, 0x2

    .line 65
    invoke-direct {p1, v3, v2, v0}, Ly70/l1;-><init>(Ly70/u1;Lkotlin/coroutines/Continuation;I)V

    .line 66
    .line 67
    .line 68
    invoke-static {p0, v2, v2, p1, v4}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 69
    .line 70
    .line 71
    new-instance p1, Ly70/l1;

    .line 72
    .line 73
    invoke-direct {p1, v3, v2, v4}, Ly70/l1;-><init>(Ly70/u1;Lkotlin/coroutines/Continuation;I)V

    .line 74
    .line 75
    .line 76
    invoke-static {p0, v2, v2, p1, v4}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 77
    .line 78
    .line 79
    new-instance p1, Ly70/l1;

    .line 80
    .line 81
    const/4 v0, 0x4

    .line 82
    invoke-direct {p1, v3, v2, v0}, Ly70/l1;-><init>(Ly70/u1;Lkotlin/coroutines/Continuation;I)V

    .line 83
    .line 84
    .line 85
    invoke-static {p0, v2, v2, p1, v4}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 86
    .line 87
    .line 88
    return-object v1

    .line 89
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
