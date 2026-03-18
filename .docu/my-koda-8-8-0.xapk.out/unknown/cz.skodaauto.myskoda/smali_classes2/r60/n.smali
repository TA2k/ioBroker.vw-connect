.class public final Lr60/n;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lr60/p;


# direct methods
.method public synthetic constructor <init>(Lr60/p;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lr60/n;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lr60/n;->f:Lr60/p;

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
    .locals 1

    .line 1
    iget p1, p0, Lr60/n;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lr60/n;

    .line 7
    .line 8
    iget-object p0, p0, Lr60/n;->f:Lr60/p;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lr60/n;-><init>(Lr60/p;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lr60/n;

    .line 16
    .line 17
    iget-object p0, p0, Lr60/n;->f:Lr60/p;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lr60/n;-><init>(Lr60/p;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lr60/n;->d:I

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
    invoke-virtual {p0, p1, p2}, Lr60/n;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lr60/n;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lr60/n;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lr60/n;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lr60/n;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lr60/n;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lr60/n;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    iget-object v2, p0, Lr60/n;->f:Lr60/p;

    .line 6
    .line 7
    const-string v3, "call to \'resume\' before \'invoke\' with coroutine"

    .line 8
    .line 9
    const/4 v4, 0x1

    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 14
    .line 15
    iget v5, p0, Lr60/n;->e:I

    .line 16
    .line 17
    if-eqz v5, :cond_1

    .line 18
    .line 19
    if-ne v5, v4, :cond_0

    .line 20
    .line 21
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 26
    .line 27
    invoke-direct {p0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    iput v4, p0, Lr60/n;->e:I

    .line 35
    .line 36
    invoke-static {v2, p0}, Lr60/p;->h(Lr60/p;Lrx0/c;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    if-ne p0, v0, :cond_2

    .line 41
    .line 42
    move-object v1, v0

    .line 43
    :cond_2
    :goto_0
    return-object v1

    .line 44
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 45
    .line 46
    iget v5, p0, Lr60/n;->e:I

    .line 47
    .line 48
    if-eqz v5, :cond_4

    .line 49
    .line 50
    if-ne v5, v4, :cond_3

    .line 51
    .line 52
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    goto :goto_3

    .line 56
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 57
    .line 58
    invoke-direct {p0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    throw p0

    .line 62
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    iget-object p1, v2, Lr60/p;->l:Lp60/e;

    .line 66
    .line 67
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    check-cast p1, Lyy0/i;

    .line 72
    .line 73
    iget-object v3, v2, Lr60/p;->k:Lnn0/e;

    .line 74
    .line 75
    invoke-static {v3}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v3

    .line 79
    check-cast v3, Lyy0/i;

    .line 80
    .line 81
    new-instance v5, Lhk0/a;

    .line 82
    .line 83
    const/4 v6, 0x5

    .line 84
    const/4 v7, 0x0

    .line 85
    invoke-direct {v5, v2, v7, v6}, Lhk0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 86
    .line 87
    .line 88
    iput v4, p0, Lr60/n;->e:I

    .line 89
    .line 90
    const/4 v2, 0x2

    .line 91
    new-array v2, v2, [Lyy0/i;

    .line 92
    .line 93
    const/4 v6, 0x0

    .line 94
    aput-object p1, v2, v6

    .line 95
    .line 96
    aput-object v3, v2, v4

    .line 97
    .line 98
    new-instance p1, Lyy0/g1;

    .line 99
    .line 100
    invoke-direct {p1, v5, v7}, Lyy0/g1;-><init>(Lay0/o;Lkotlin/coroutines/Continuation;)V

    .line 101
    .line 102
    .line 103
    sget-object v3, Lyy0/h1;->d:Lyy0/h1;

    .line 104
    .line 105
    sget-object v4, Lzy0/q;->d:Lzy0/q;

    .line 106
    .line 107
    invoke-static {v3, p1, p0, v4, v2}, Lzy0/c;->a(Lay0/a;Lay0/o;Lkotlin/coroutines/Continuation;Lyy0/j;[Lyy0/i;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 112
    .line 113
    if-ne p0, p1, :cond_5

    .line 114
    .line 115
    goto :goto_1

    .line 116
    :cond_5
    move-object p0, v1

    .line 117
    :goto_1
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 118
    .line 119
    if-ne p0, p1, :cond_6

    .line 120
    .line 121
    goto :goto_2

    .line 122
    :cond_6
    move-object p0, v1

    .line 123
    :goto_2
    if-ne p0, v0, :cond_7

    .line 124
    .line 125
    move-object v1, v0

    .line 126
    :cond_7
    :goto_3
    return-object v1

    .line 127
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
