.class public final Lld/c;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lp1/v;

.field public final synthetic g:I


# direct methods
.method public synthetic constructor <init>(Lp1/v;ILkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lld/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lld/c;->f:Lp1/v;

    .line 4
    .line 5
    iput p2, p0, Lld/c;->g:I

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
    iget p1, p0, Lld/c;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lld/c;

    .line 7
    .line 8
    iget v0, p0, Lld/c;->g:I

    .line 9
    .line 10
    const/4 v1, 0x2

    .line 11
    iget-object p0, p0, Lld/c;->f:Lp1/v;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Lld/c;-><init>(Lp1/v;ILkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lld/c;

    .line 18
    .line 19
    iget v0, p0, Lld/c;->g:I

    .line 20
    .line 21
    const/4 v1, 0x1

    .line 22
    iget-object p0, p0, Lld/c;->f:Lp1/v;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Lld/c;-><init>(Lp1/v;ILkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object p1

    .line 28
    :pswitch_1
    new-instance p1, Lld/c;

    .line 29
    .line 30
    iget v0, p0, Lld/c;->g:I

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    iget-object p0, p0, Lld/c;->f:Lp1/v;

    .line 34
    .line 35
    invoke-direct {p1, p0, v0, p2, v1}, Lld/c;-><init>(Lp1/v;ILkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    return-object p1

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lld/c;->d:I

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
    invoke-virtual {p0, p1, p2}, Lld/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lld/c;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lld/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lg1/e2;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Lld/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lld/c;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lld/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_1
    check-cast p1, Lvy0/b0;

    .line 41
    .line 42
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 43
    .line 44
    invoke-virtual {p0, p1, p2}, Lld/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Lld/c;

    .line 49
    .line 50
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    invoke-virtual {p0, p1}, Lld/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lld/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lld/c;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    if-ne v1, v2, :cond_0

    .line 14
    .line 15
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 20
    .line 21
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 22
    .line 23
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0

    .line 27
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    iget-object p1, p0, Lld/c;->f:Lp1/v;

    .line 31
    .line 32
    invoke-virtual {p1}, Lp1/v;->k()I

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    iget v3, p0, Lld/c;->g:I

    .line 37
    .line 38
    if-eq v1, v3, :cond_2

    .line 39
    .line 40
    iput v2, p0, Lld/c;->e:I

    .line 41
    .line 42
    invoke-static {p1, v3, p0}, Lp1/v;->t(Lp1/v;ILrx0/i;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    if-ne p0, v0, :cond_2

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 50
    .line 51
    :goto_1
    return-object v0

    .line 52
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 53
    .line 54
    iget v1, p0, Lld/c;->e:I

    .line 55
    .line 56
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 57
    .line 58
    iget-object v3, p0, Lld/c;->f:Lp1/v;

    .line 59
    .line 60
    const/4 v4, 0x1

    .line 61
    if-eqz v1, :cond_4

    .line 62
    .line 63
    if-ne v1, v4, :cond_3

    .line 64
    .line 65
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    goto :goto_3

    .line 69
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 70
    .line 71
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 72
    .line 73
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    throw p0

    .line 77
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    iput v4, p0, Lld/c;->e:I

    .line 81
    .line 82
    iget-object p1, v3, Lp1/v;->x:Lo1/d;

    .line 83
    .line 84
    invoke-virtual {p1, p0}, Lo1/d;->h(Lrx0/c;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    if-ne p1, v0, :cond_5

    .line 89
    .line 90
    goto :goto_2

    .line 91
    :cond_5
    move-object p1, v2

    .line 92
    :goto_2
    if-ne p1, v0, :cond_6

    .line 93
    .line 94
    goto :goto_5

    .line 95
    :cond_6
    :goto_3
    const/4 p1, 0x0

    .line 96
    float-to-double v0, p1

    .line 97
    const-wide/high16 v5, -0x4020000000000000L    # -0.5

    .line 98
    .line 99
    cmpg-double v5, v5, v0

    .line 100
    .line 101
    if-gtz v5, :cond_7

    .line 102
    .line 103
    const-wide/high16 v5, 0x3fe0000000000000L    # 0.5

    .line 104
    .line 105
    cmpg-double v0, v0, v5

    .line 106
    .line 107
    if-gtz v0, :cond_7

    .line 108
    .line 109
    goto :goto_4

    .line 110
    :cond_7
    const-string v0, "pageOffsetFraction 0.0 is not within the range -0.5 to 0.5"

    .line 111
    .line 112
    invoke-static {v0}, Lj1/b;->a(Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    :goto_4
    iget p0, p0, Lld/c;->g:I

    .line 116
    .line 117
    invoke-virtual {v3, p0}, Lp1/v;->j(I)I

    .line 118
    .line 119
    .line 120
    move-result p0

    .line 121
    invoke-virtual {v3, p0, p1, v4}, Lp1/v;->u(IFZ)V

    .line 122
    .line 123
    .line 124
    move-object v0, v2

    .line 125
    :goto_5
    return-object v0

    .line 126
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 127
    .line 128
    iget v1, p0, Lld/c;->e:I

    .line 129
    .line 130
    const/4 v2, 0x1

    .line 131
    if-eqz v1, :cond_9

    .line 132
    .line 133
    if-ne v1, v2, :cond_8

    .line 134
    .line 135
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    goto :goto_6

    .line 139
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 140
    .line 141
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 142
    .line 143
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 144
    .line 145
    .line 146
    throw p0

    .line 147
    :cond_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    iput v2, p0, Lld/c;->e:I

    .line 151
    .line 152
    iget-object p1, p0, Lld/c;->f:Lp1/v;

    .line 153
    .line 154
    iget v1, p0, Lld/c;->g:I

    .line 155
    .line 156
    invoke-static {p1, v1, p0}, Lp1/v;->g(Lp1/v;ILrx0/i;)Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object p0

    .line 160
    if-ne p0, v0, :cond_a

    .line 161
    .line 162
    goto :goto_7

    .line 163
    :cond_a
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 164
    .line 165
    :goto_7
    return-object v0

    .line 166
    nop

    .line 167
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
