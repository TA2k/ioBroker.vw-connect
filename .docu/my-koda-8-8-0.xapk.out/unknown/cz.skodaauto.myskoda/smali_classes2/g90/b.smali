.class public final Lg90/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;ILkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lg90/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lg90/b;->g:Ljava/lang/Object;

    .line 4
    .line 5
    iput p2, p0, Lg90/b;->f:I

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
    iget p1, p0, Lg90/b;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lg90/b;

    .line 7
    .line 8
    iget-object v0, p0, Lg90/b;->g:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lo1/u0;

    .line 11
    .line 12
    iget p0, p0, Lg90/b;->f:I

    .line 13
    .line 14
    const/4 v1, 0x3

    .line 15
    invoke-direct {p1, v0, p0, p2, v1}, Lg90/b;-><init>(Ljava/lang/Object;ILkotlin/coroutines/Continuation;I)V

    .line 16
    .line 17
    .line 18
    return-object p1

    .line 19
    :pswitch_0
    new-instance p1, Lg90/b;

    .line 20
    .line 21
    iget-object v0, p0, Lg90/b;->g:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v0, Lkn/c0;

    .line 24
    .line 25
    iget p0, p0, Lg90/b;->f:I

    .line 26
    .line 27
    const/4 v1, 0x2

    .line 28
    invoke-direct {p1, v0, p0, p2, v1}, Lg90/b;-><init>(Ljava/lang/Object;ILkotlin/coroutines/Continuation;I)V

    .line 29
    .line 30
    .line 31
    return-object p1

    .line 32
    :pswitch_1
    new-instance p1, Lg90/b;

    .line 33
    .line 34
    iget-object v0, p0, Lg90/b;->g:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v0, Lg90/e;

    .line 37
    .line 38
    iget p0, p0, Lg90/b;->f:I

    .line 39
    .line 40
    const/4 v1, 0x1

    .line 41
    invoke-direct {p1, v0, p0, p2, v1}, Lg90/b;-><init>(Ljava/lang/Object;ILkotlin/coroutines/Continuation;I)V

    .line 42
    .line 43
    .line 44
    return-object p1

    .line 45
    :pswitch_2
    new-instance p1, Lg90/b;

    .line 46
    .line 47
    iget-object v0, p0, Lg90/b;->g:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast v0, Lg90/c;

    .line 50
    .line 51
    iget p0, p0, Lg90/b;->f:I

    .line 52
    .line 53
    const/4 v1, 0x0

    .line 54
    invoke-direct {p1, v0, p0, p2, v1}, Lg90/b;-><init>(Ljava/lang/Object;ILkotlin/coroutines/Continuation;I)V

    .line 55
    .line 56
    .line 57
    return-object p1

    .line 58
    nop

    .line 59
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
    iget v0, p0, Lg90/b;->d:I

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
    invoke-virtual {p0, p1, p2}, Lg90/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lg90/b;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lg90/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lg90/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lg90/b;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lg90/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lg90/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lg90/b;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lg90/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lg90/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lg90/b;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lg90/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    nop

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lg90/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lg90/b;->e:I

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
    iget-object p1, p0, Lg90/b;->g:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p1, Lo1/u0;

    .line 33
    .line 34
    iget-object p1, p1, Lo1/u0;->s:Lo1/r0;

    .line 35
    .line 36
    iput v2, p0, Lg90/b;->e:I

    .line 37
    .line 38
    iget v1, p0, Lg90/b;->f:I

    .line 39
    .line 40
    invoke-interface {p1, v1, p0}, Lo1/r0;->f(ILg90/b;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    if-ne p0, v0, :cond_2

    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    :goto_1
    return-object v0

    .line 50
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 51
    .line 52
    iget v1, p0, Lg90/b;->e:I

    .line 53
    .line 54
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 55
    .line 56
    const/4 v3, 0x1

    .line 57
    if-eqz v1, :cond_5

    .line 58
    .line 59
    if-ne v1, v3, :cond_4

    .line 60
    .line 61
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    :cond_3
    move-object v0, v2

    .line 65
    goto :goto_3

    .line 66
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 67
    .line 68
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 69
    .line 70
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    throw p0

    .line 74
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    iget-object p1, p0, Lg90/b;->g:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast p1, Lkn/c0;

    .line 80
    .line 81
    iput v3, p0, Lg90/b;->e:I

    .line 82
    .line 83
    iget v1, p0, Lg90/b;->f:I

    .line 84
    .line 85
    int-to-float v1, v1

    .line 86
    invoke-virtual {p1, v1, p0}, Lkn/c0;->a(FLrx0/i;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    if-ne p0, v0, :cond_6

    .line 91
    .line 92
    goto :goto_2

    .line 93
    :cond_6
    move-object p0, v2

    .line 94
    :goto_2
    if-ne p0, v0, :cond_3

    .line 95
    .line 96
    :goto_3
    return-object v0

    .line 97
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 98
    .line 99
    iget v1, p0, Lg90/b;->e:I

    .line 100
    .line 101
    const/4 v2, 0x1

    .line 102
    if-eqz v1, :cond_8

    .line 103
    .line 104
    if-ne v1, v2, :cond_7

    .line 105
    .line 106
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    goto :goto_4

    .line 110
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 111
    .line 112
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 113
    .line 114
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    throw p0

    .line 118
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    iget-object p1, p0, Lg90/b;->g:Ljava/lang/Object;

    .line 122
    .line 123
    check-cast p1, Lg90/e;

    .line 124
    .line 125
    iget-object p1, p1, Lg90/e;->i:Lcs0/h0;

    .line 126
    .line 127
    sget-object v1, Lqr0/s;->h:Lsx0/b;

    .line 128
    .line 129
    iget v3, p0, Lg90/b;->f:I

    .line 130
    .line 131
    invoke-virtual {v1, v3}, Lsx0/b;->get(I)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object v1

    .line 135
    check-cast v1, Lqr0/s;

    .line 136
    .line 137
    iput v2, p0, Lg90/b;->e:I

    .line 138
    .line 139
    invoke-virtual {p1, v1, p0}, Lcs0/h0;->b(Lqr0/s;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    if-ne p0, v0, :cond_9

    .line 144
    .line 145
    goto :goto_5

    .line 146
    :cond_9
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 147
    .line 148
    :goto_5
    return-object v0

    .line 149
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 150
    .line 151
    iget v1, p0, Lg90/b;->e:I

    .line 152
    .line 153
    const/4 v2, 0x1

    .line 154
    if-eqz v1, :cond_b

    .line 155
    .line 156
    if-ne v1, v2, :cond_a

    .line 157
    .line 158
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 159
    .line 160
    .line 161
    goto :goto_6

    .line 162
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 163
    .line 164
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 165
    .line 166
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 167
    .line 168
    .line 169
    throw p0

    .line 170
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 171
    .line 172
    .line 173
    iget-object p1, p0, Lg90/b;->g:Ljava/lang/Object;

    .line 174
    .line 175
    check-cast p1, Lg90/c;

    .line 176
    .line 177
    iget-object p1, p1, Lg90/c;->i:Lcs0/f0;

    .line 178
    .line 179
    sget-object v1, Lds0/d;->h:Lsx0/b;

    .line 180
    .line 181
    iget v3, p0, Lg90/b;->f:I

    .line 182
    .line 183
    invoke-virtual {v1, v3}, Lsx0/b;->get(I)Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    move-result-object v1

    .line 187
    check-cast v1, Lds0/d;

    .line 188
    .line 189
    iput v2, p0, Lg90/b;->e:I

    .line 190
    .line 191
    invoke-virtual {p1, v1, p0}, Lcs0/f0;->b(Lds0/d;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object p0

    .line 195
    if-ne p0, v0, :cond_c

    .line 196
    .line 197
    goto :goto_7

    .line 198
    :cond_c
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 199
    .line 200
    :goto_7
    return-object v0

    .line 201
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
