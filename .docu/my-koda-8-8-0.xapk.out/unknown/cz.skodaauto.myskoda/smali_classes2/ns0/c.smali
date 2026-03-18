.class public final Lns0/c;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lns0/f;


# direct methods
.method public synthetic constructor <init>(Lns0/f;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lns0/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lns0/c;->f:Lns0/f;

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
    iget p1, p0, Lns0/c;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lns0/c;

    .line 7
    .line 8
    iget-object p0, p0, Lns0/c;->f:Lns0/f;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lns0/c;-><init>(Lns0/f;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lns0/c;

    .line 16
    .line 17
    iget-object p0, p0, Lns0/c;->f:Lns0/f;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lns0/c;-><init>(Lns0/f;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lns0/c;->d:I

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
    invoke-virtual {p0, p1, p2}, Lns0/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lns0/c;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lns0/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lns0/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lns0/c;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lns0/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Lns0/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lns0/c;->e:I

    .line 9
    .line 10
    iget-object v2, p0, Lns0/c;->f:Lns0/f;

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    const/4 v4, 0x0

    .line 14
    if-eqz v1, :cond_1

    .line 15
    .line 16
    if-ne v1, v3, :cond_0

    .line 17
    .line 18
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 23
    .line 24
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    iget-object p1, v2, Lns0/f;->q:Lrq0/f;

    .line 34
    .line 35
    new-instance v1, Lsq0/c;

    .line 36
    .line 37
    iget-object v5, v2, Lns0/f;->r:Lij0/a;

    .line 38
    .line 39
    new-array v6, v4, [Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v5, Ljj0/f;

    .line 42
    .line 43
    const v7, 0x7f120eef

    .line 44
    .line 45
    .line 46
    invoke-virtual {v5, v7, v6}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v5

    .line 50
    const/4 v6, 0x6

    .line 51
    const/4 v7, 0x0

    .line 52
    invoke-direct {v1, v6, v5, v7, v7}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    iput v3, p0, Lns0/c;->e:I

    .line 56
    .line 57
    invoke-virtual {p1, v1, v4, p0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    if-ne p1, v0, :cond_2

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_2
    :goto_0
    sget-object p0, Lsq0/d;->e:Lsq0/d;

    .line 65
    .line 66
    if-ne p1, p0, :cond_3

    .line 67
    .line 68
    iput-boolean v4, v2, Lns0/f;->t:Z

    .line 69
    .line 70
    :cond_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 71
    .line 72
    :goto_1
    return-object v0

    .line 73
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 74
    .line 75
    iget v1, p0, Lns0/c;->e:I

    .line 76
    .line 77
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 78
    .line 79
    iget-object v3, p0, Lns0/c;->f:Lns0/f;

    .line 80
    .line 81
    const/4 v4, 0x2

    .line 82
    const/4 v5, 0x1

    .line 83
    if-eqz v1, :cond_7

    .line 84
    .line 85
    if-eq v1, v5, :cond_6

    .line 86
    .line 87
    if-ne v1, v4, :cond_5

    .line 88
    .line 89
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    :cond_4
    move-object v0, v2

    .line 93
    goto :goto_3

    .line 94
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 95
    .line 96
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 97
    .line 98
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    throw p0

    .line 102
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    goto :goto_2

    .line 106
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    iget-object p1, v3, Lns0/f;->h:Lks0/e;

    .line 110
    .line 111
    iput v5, p0, Lns0/c;->e:I

    .line 112
    .line 113
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 114
    .line 115
    .line 116
    invoke-virtual {p1, p0}, Lks0/e;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    if-ne p1, v0, :cond_8

    .line 121
    .line 122
    goto :goto_3

    .line 123
    :cond_8
    :goto_2
    check-cast p1, Lyy0/i;

    .line 124
    .line 125
    new-instance v1, Lns0/b;

    .line 126
    .line 127
    const/4 v5, 0x0

    .line 128
    invoke-direct {v1, v3, v5}, Lns0/b;-><init>(Lns0/f;I)V

    .line 129
    .line 130
    .line 131
    iput v4, p0, Lns0/c;->e:I

    .line 132
    .line 133
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    if-ne p0, v0, :cond_4

    .line 138
    .line 139
    :goto_3
    return-object v0

    .line 140
    nop

    .line 141
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
