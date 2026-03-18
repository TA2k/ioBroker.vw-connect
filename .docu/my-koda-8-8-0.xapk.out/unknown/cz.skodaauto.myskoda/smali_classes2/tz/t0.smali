.class public final Ltz/t0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ltz/u0;

.field public final synthetic g:Lrd0/d;


# direct methods
.method public synthetic constructor <init>(Ltz/u0;Lrd0/d;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Ltz/t0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltz/t0;->f:Ltz/u0;

    .line 4
    .line 5
    iput-object p2, p0, Ltz/t0;->g:Lrd0/d;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget p1, p0, Ltz/t0;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ltz/t0;

    .line 7
    .line 8
    iget-object v0, p0, Ltz/t0;->g:Lrd0/d;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    iget-object p0, p0, Ltz/t0;->f:Ltz/u0;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Ltz/t0;-><init>(Ltz/u0;Lrd0/d;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Ltz/t0;

    .line 18
    .line 19
    iget-object v0, p0, Ltz/t0;->g:Lrd0/d;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    iget-object p0, p0, Ltz/t0;->f:Ltz/u0;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Ltz/t0;-><init>(Ltz/u0;Lrd0/d;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object p1

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
    iget v0, p0, Ltz/t0;->d:I

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
    invoke-virtual {p0, p1, p2}, Ltz/t0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ltz/t0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ltz/t0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ltz/t0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ltz/t0;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ltz/t0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 5

    .line 1
    iget v0, p0, Ltz/t0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Ltz/t0;->e:I

    .line 9
    .line 10
    iget-object v2, p0, Ltz/t0;->f:Ltz/u0;

    .line 11
    .line 12
    const/4 v3, 0x2

    .line 13
    const/4 v4, 0x1

    .line 14
    if-eqz v1, :cond_2

    .line 15
    .line 16
    if-eq v1, v4, :cond_1

    .line 17
    .line 18
    if-ne v1, v3, :cond_0

    .line 19
    .line 20
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 25
    .line 26
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 27
    .line 28
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0

    .line 32
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    iget-object p1, v2, Ltz/u0;->l:Lqd0/b1;

    .line 40
    .line 41
    iput v4, p0, Ltz/t0;->e:I

    .line 42
    .line 43
    iget-object v1, p0, Ltz/t0;->g:Lrd0/d;

    .line 44
    .line 45
    invoke-virtual {p1, v1}, Lqd0/b1;->b(Lrd0/d;)Lam0/i;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    if-ne p1, v0, :cond_3

    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_3
    :goto_0
    check-cast p1, Lyy0/i;

    .line 53
    .line 54
    new-instance v1, Ltz/s0;

    .line 55
    .line 56
    const/4 v4, 0x1

    .line 57
    invoke-direct {v1, v2, v4}, Ltz/s0;-><init>(Ltz/u0;I)V

    .line 58
    .line 59
    .line 60
    iput v3, p0, Ltz/t0;->e:I

    .line 61
    .line 62
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    if-ne p0, v0, :cond_4

    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_4
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 70
    .line 71
    :goto_2
    return-object v0

    .line 72
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 73
    .line 74
    iget v1, p0, Ltz/t0;->e:I

    .line 75
    .line 76
    iget-object v2, p0, Ltz/t0;->f:Ltz/u0;

    .line 77
    .line 78
    const/4 v3, 0x2

    .line 79
    const/4 v4, 0x1

    .line 80
    if-eqz v1, :cond_7

    .line 81
    .line 82
    if-eq v1, v4, :cond_6

    .line 83
    .line 84
    if-ne v1, v3, :cond_5

    .line 85
    .line 86
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    goto :goto_4

    .line 90
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 91
    .line 92
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 93
    .line 94
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    throw p0

    .line 98
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    goto :goto_3

    .line 102
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    iget-object p1, v2, Ltz/u0;->j:Lqd0/s;

    .line 106
    .line 107
    iput v4, p0, Ltz/t0;->e:I

    .line 108
    .line 109
    iget-object v1, p0, Ltz/t0;->g:Lrd0/d;

    .line 110
    .line 111
    invoke-virtual {p1, v1}, Lqd0/s;->b(Lrd0/d;)Lam0/i;

    .line 112
    .line 113
    .line 114
    move-result-object p1

    .line 115
    if-ne p1, v0, :cond_8

    .line 116
    .line 117
    goto :goto_5

    .line 118
    :cond_8
    :goto_3
    check-cast p1, Lyy0/i;

    .line 119
    .line 120
    new-instance v1, Ltz/s0;

    .line 121
    .line 122
    const/4 v4, 0x0

    .line 123
    invoke-direct {v1, v2, v4}, Ltz/s0;-><init>(Ltz/u0;I)V

    .line 124
    .line 125
    .line 126
    iput v3, p0, Ltz/t0;->e:I

    .line 127
    .line 128
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    if-ne p0, v0, :cond_9

    .line 133
    .line 134
    goto :goto_5

    .line 135
    :cond_9
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 136
    .line 137
    :goto_5
    return-object v0

    .line 138
    nop

    .line 139
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
