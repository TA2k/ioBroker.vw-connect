.class public final Lc00/r0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Lc00/k1;


# direct methods
.method public synthetic constructor <init>(Lc00/k1;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lc00/r0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc00/r0;->f:Lc00/k1;

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
    iget v0, p0, Lc00/r0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lc00/r0;

    .line 7
    .line 8
    iget-object p0, p0, Lc00/r0;->f:Lc00/k1;

    .line 9
    .line 10
    const/4 v1, 0x3

    .line 11
    invoke-direct {v0, p0, p2, v1}, Lc00/r0;-><init>(Lc00/k1;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lc00/r0;->e:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lc00/r0;

    .line 18
    .line 19
    iget-object p0, p0, Lc00/r0;->f:Lc00/k1;

    .line 20
    .line 21
    const/4 v1, 0x2

    .line 22
    invoke-direct {v0, p0, p2, v1}, Lc00/r0;-><init>(Lc00/k1;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lc00/r0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

    .line 28
    :pswitch_1
    new-instance v0, Lc00/r0;

    .line 29
    .line 30
    iget-object p0, p0, Lc00/r0;->f:Lc00/k1;

    .line 31
    .line 32
    const/4 v1, 0x1

    .line 33
    invoke-direct {v0, p0, p2, v1}, Lc00/r0;-><init>(Lc00/k1;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    iput-object p1, v0, Lc00/r0;->e:Ljava/lang/Object;

    .line 37
    .line 38
    return-object v0

    .line 39
    :pswitch_2
    new-instance v0, Lc00/r0;

    .line 40
    .line 41
    iget-object p0, p0, Lc00/r0;->f:Lc00/k1;

    .line 42
    .line 43
    const/4 v1, 0x0

    .line 44
    invoke-direct {v0, p0, p2, v1}, Lc00/r0;-><init>(Lc00/k1;Lkotlin/coroutines/Continuation;I)V

    .line 45
    .line 46
    .line 47
    iput-object p1, v0, Lc00/r0;->e:Ljava/lang/Object;

    .line 48
    .line 49
    return-object v0

    .line 50
    nop

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lc00/r0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lvy0/b0;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lc00/r0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lc00/r0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lc00/r0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lvy0/b0;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Lc00/r0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lc00/r0;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lc00/r0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    return-object p1

    .line 39
    :pswitch_1
    check-cast p1, Lss0/b;

    .line 40
    .line 41
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 42
    .line 43
    invoke-virtual {p0, p1, p2}, Lc00/r0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    check-cast p0, Lc00/r0;

    .line 48
    .line 49
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 50
    .line 51
    invoke-virtual {p0, p1}, Lc00/r0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    return-object p1

    .line 55
    :pswitch_2
    check-cast p1, Lss0/b;

    .line 56
    .line 57
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 58
    .line 59
    invoke-virtual {p0, p1, p2}, Lc00/r0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    check-cast p0, Lc00/r0;

    .line 64
    .line 65
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 66
    .line 67
    invoke-virtual {p0, p1}, Lc00/r0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    return-object p1

    .line 71
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lc00/r0;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 5
    .line 6
    const/4 v3, 0x3

    .line 7
    iget-object v4, p0, Lc00/r0;->f:Lc00/k1;

    .line 8
    .line 9
    iget-object p0, p0, Lc00/r0;->e:Ljava/lang/Object;

    .line 10
    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    check-cast p0, Lvy0/b0;

    .line 15
    .line 16
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 17
    .line 18
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    new-instance p1, Lc00/t0;

    .line 22
    .line 23
    const/4 v0, 0x2

    .line 24
    invoke-direct {p1, v4, v1, v0}, Lc00/t0;-><init>(Lc00/k1;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    invoke-static {p0, v1, v1, p1, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 28
    .line 29
    .line 30
    new-instance p1, Lc00/t0;

    .line 31
    .line 32
    invoke-direct {p1, v4, v1, v3}, Lc00/t0;-><init>(Lc00/k1;Lkotlin/coroutines/Continuation;I)V

    .line 33
    .line 34
    .line 35
    invoke-static {p0, v1, v1, p1, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 36
    .line 37
    .line 38
    new-instance p1, Lc00/t0;

    .line 39
    .line 40
    const/4 v0, 0x4

    .line 41
    invoke-direct {p1, v4, v1, v0}, Lc00/t0;-><init>(Lc00/k1;Lkotlin/coroutines/Continuation;I)V

    .line 42
    .line 43
    .line 44
    invoke-static {p0, v1, v1, p1, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_0
    check-cast p0, Lvy0/b0;

    .line 50
    .line 51
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 52
    .line 53
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    new-instance p1, Lc00/t0;

    .line 57
    .line 58
    const/4 v0, 0x0

    .line 59
    invoke-direct {p1, v4, v1, v0}, Lc00/t0;-><init>(Lc00/k1;Lkotlin/coroutines/Continuation;I)V

    .line 60
    .line 61
    .line 62
    invoke-static {p0, v1, v1, p1, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 63
    .line 64
    .line 65
    new-instance p1, Lc00/t0;

    .line 66
    .line 67
    const/4 v0, 0x1

    .line 68
    invoke-direct {p1, v4, v1, v0}, Lc00/t0;-><init>(Lc00/k1;Lkotlin/coroutines/Continuation;I)V

    .line 69
    .line 70
    .line 71
    invoke-static {p0, v1, v1, p1, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 72
    .line 73
    .line 74
    return-object v2

    .line 75
    :pswitch_1
    check-cast p0, Lss0/b;

    .line 76
    .line 77
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 78
    .line 79
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    iget-object p1, v4, Lc00/k1;->j:Lij0/a;

    .line 83
    .line 84
    invoke-static {p0, p1}, Ljp/ec;->a(Lss0/b;Lij0/a;)Lc00/y0;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    invoke-virtual {v4, p0}, Lql0/j;->g(Lql0/h;)V

    .line 89
    .line 90
    .line 91
    return-object v2

    .line 92
    :pswitch_2
    check-cast p0, Lss0/b;

    .line 93
    .line 94
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 95
    .line 96
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    iget-object p1, v4, Lc00/k1;->j:Lij0/a;

    .line 100
    .line 101
    invoke-static {p0, p1}, Ljp/ec;->a(Lss0/b;Lij0/a;)Lc00/y0;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    invoke-virtual {v4, p0}, Lql0/j;->g(Lql0/h;)V

    .line 106
    .line 107
    .line 108
    return-object v2

    .line 109
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
