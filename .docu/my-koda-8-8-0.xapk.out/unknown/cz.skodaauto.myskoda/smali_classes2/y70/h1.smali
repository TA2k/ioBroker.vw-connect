.class public final Ly70/h1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ly70/j1;


# direct methods
.method public synthetic constructor <init>(Ly70/j1;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ly70/h1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly70/h1;->g:Ly70/j1;

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
    iget v0, p0, Ly70/h1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Ly70/h1;

    .line 7
    .line 8
    iget-object p0, p0, Ly70/h1;->g:Ly70/j1;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, p0, p2, v1}, Ly70/h1;-><init>(Ly70/j1;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Ly70/h1;->f:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Ly70/h1;

    .line 18
    .line 19
    iget-object p0, p0, Ly70/h1;->g:Ly70/j1;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-direct {v0, p0, p2, v1}, Ly70/h1;-><init>(Ly70/j1;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Ly70/h1;->f:Ljava/lang/Object;

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
    iget v0, p0, Ly70/h1;->d:I

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
    invoke-virtual {p0, p1, p2}, Ly70/h1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ly70/h1;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ly70/h1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ly70/h1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ly70/h1;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ly70/h1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Ly70/h1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ly70/h1;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lvy0/b0;

    .line 9
    .line 10
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    iget v2, p0, Ly70/h1;->e:I

    .line 13
    .line 14
    const/4 v3, 0x1

    .line 15
    iget-object v4, p0, Ly70/h1;->g:Ly70/j1;

    .line 16
    .line 17
    if-eqz v2, :cond_1

    .line 18
    .line 19
    if-ne v2, v3, :cond_0

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
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 28
    .line 29
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    new-instance p1, Ly70/t0;

    .line 37
    .line 38
    const/16 v2, 0xb

    .line 39
    .line 40
    invoke-direct {p1, v4, v2}, Ly70/t0;-><init>(Ly70/j1;I)V

    .line 41
    .line 42
    .line 43
    invoke-static {v0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v4}, Ly70/j1;->E()V

    .line 47
    .line 48
    .line 49
    iget-object p1, v4, Ly70/j1;->q:Lw70/s0;

    .line 50
    .line 51
    const/4 v0, 0x0

    .line 52
    iput-object v0, p0, Ly70/h1;->f:Ljava/lang/Object;

    .line 53
    .line 54
    iput v3, p0, Ly70/h1;->e:I

    .line 55
    .line 56
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 57
    .line 58
    .line 59
    invoke-virtual {p1, p0}, Lw70/s0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    if-ne p0, v1, :cond_2

    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_2
    :goto_0
    iget-object p0, v4, Ly70/j1;->l:Lw70/d0;

    .line 67
    .line 68
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 72
    .line 73
    :goto_1
    return-object v1

    .line 74
    :pswitch_0
    iget-object v0, p0, Ly70/h1;->f:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast v0, Lvy0/b0;

    .line 77
    .line 78
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 79
    .line 80
    iget v2, p0, Ly70/h1;->e:I

    .line 81
    .line 82
    const/4 v3, 0x1

    .line 83
    iget-object v4, p0, Ly70/h1;->g:Ly70/j1;

    .line 84
    .line 85
    if-eqz v2, :cond_4

    .line 86
    .line 87
    if-ne v2, v3, :cond_3

    .line 88
    .line 89
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    goto :goto_2

    .line 93
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 94
    .line 95
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 96
    .line 97
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    throw p0

    .line 101
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    new-instance p1, Ly70/t0;

    .line 105
    .line 106
    const/16 v2, 0xa

    .line 107
    .line 108
    invoke-direct {p1, v4, v2}, Ly70/t0;-><init>(Ly70/j1;I)V

    .line 109
    .line 110
    .line 111
    invoke-static {v0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 112
    .line 113
    .line 114
    iget-object p1, v4, Ly70/j1;->q:Lw70/s0;

    .line 115
    .line 116
    const/4 v0, 0x0

    .line 117
    iput-object v0, p0, Ly70/h1;->f:Ljava/lang/Object;

    .line 118
    .line 119
    iput v3, p0, Ly70/h1;->e:I

    .line 120
    .line 121
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 122
    .line 123
    .line 124
    invoke-virtual {p1, p0}, Lw70/s0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    if-ne p0, v1, :cond_5

    .line 129
    .line 130
    goto :goto_3

    .line 131
    :cond_5
    :goto_2
    invoke-virtual {v4}, Ly70/j1;->E()V

    .line 132
    .line 133
    .line 134
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 135
    .line 136
    :goto_3
    return-object v1

    .line 137
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
