.class public final Lew/f;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lay0/k;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lew/f;->d:I

    iput-object p1, p0, Lew/f;->g:Lay0/k;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/coroutines/Continuation;Lay0/k;I)V
    .locals 0

    .line 2
    iput p3, p0, Lew/f;->d:I

    iput-object p2, p0, Lew/f;->g:Lay0/k;

    const/4 p2, 0x2

    invoke-direct {p0, p2, p1}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget v0, p0, Lew/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lew/f;

    .line 7
    .line 8
    iget-object p0, p0, Lew/f;->g:Lay0/k;

    .line 9
    .line 10
    const/4 v1, 0x5

    .line 11
    invoke-direct {v0, p2, p0, v1}, Lew/f;-><init>(Lkotlin/coroutines/Continuation;Lay0/k;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lew/f;->f:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lew/f;

    .line 18
    .line 19
    iget-object p0, p0, Lew/f;->g:Lay0/k;

    .line 20
    .line 21
    const/4 v1, 0x4

    .line 22
    invoke-direct {v0, p2, p0, v1}, Lew/f;-><init>(Lkotlin/coroutines/Continuation;Lay0/k;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lew/f;->f:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

    .line 28
    :pswitch_1
    new-instance v0, Lew/f;

    .line 29
    .line 30
    iget-object p0, p0, Lew/f;->g:Lay0/k;

    .line 31
    .line 32
    const/4 v1, 0x3

    .line 33
    invoke-direct {v0, p0, p2, v1}, Lew/f;-><init>(Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    iput-object p1, v0, Lew/f;->f:Ljava/lang/Object;

    .line 37
    .line 38
    return-object v0

    .line 39
    :pswitch_2
    new-instance v0, Lew/f;

    .line 40
    .line 41
    iget-object p0, p0, Lew/f;->g:Lay0/k;

    .line 42
    .line 43
    const/4 v1, 0x2

    .line 44
    invoke-direct {v0, p0, p2, v1}, Lew/f;-><init>(Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 45
    .line 46
    .line 47
    iput-object p1, v0, Lew/f;->f:Ljava/lang/Object;

    .line 48
    .line 49
    return-object v0

    .line 50
    :pswitch_3
    new-instance v0, Lew/f;

    .line 51
    .line 52
    iget-object p0, p0, Lew/f;->g:Lay0/k;

    .line 53
    .line 54
    const/4 v1, 0x1

    .line 55
    invoke-direct {v0, p0, p2, v1}, Lew/f;-><init>(Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 56
    .line 57
    .line 58
    iput-object p1, v0, Lew/f;->f:Ljava/lang/Object;

    .line 59
    .line 60
    return-object v0

    .line 61
    :pswitch_4
    new-instance v0, Lew/f;

    .line 62
    .line 63
    iget-object p0, p0, Lew/f;->g:Lay0/k;

    .line 64
    .line 65
    const/4 v1, 0x0

    .line 66
    invoke-direct {v0, p0, p2, v1}, Lew/f;-><init>(Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 67
    .line 68
    .line 69
    iput-object p1, v0, Lew/f;->f:Ljava/lang/Object;

    .line 70
    .line 71
    return-object v0

    .line 72
    nop

    .line 73
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lew/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lna/k;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lew/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lew/f;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lew/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lna/k;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Lew/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lew/f;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lew/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Lew/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Lew/f;

    .line 49
    .line 50
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    invoke-virtual {p0, p1}, Lew/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :pswitch_2
    check-cast p1, Lp3/x;

    .line 58
    .line 59
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 60
    .line 61
    invoke-virtual {p0, p1, p2}, Lew/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    check-cast p0, Lew/f;

    .line 66
    .line 67
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    invoke-virtual {p0, p1}, Lew/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0

    .line 74
    :pswitch_3
    check-cast p1, Lp3/x;

    .line 75
    .line 76
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 77
    .line 78
    invoke-virtual {p0, p1, p2}, Lew/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    check-cast p0, Lew/f;

    .line 83
    .line 84
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 85
    .line 86
    invoke-virtual {p0, p1}, Lew/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    return-object p0

    .line 91
    :pswitch_4
    check-cast p1, Lp3/x;

    .line 92
    .line 93
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 94
    .line 95
    invoke-virtual {p0, p1, p2}, Lew/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    check-cast p0, Lew/f;

    .line 100
    .line 101
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 102
    .line 103
    invoke-virtual {p0, p1}, Lew/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    return-object p0

    .line 108
    nop

    .line 109
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    iget v0, p0, Lew/f;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x7

    .line 5
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v4, p0, Lew/f;->g:Lay0/k;

    .line 8
    .line 9
    const-string v5, "call to \'resume\' before \'invoke\' with coroutine"

    .line 10
    .line 11
    const/4 v6, 0x1

    .line 12
    packed-switch v0, :pswitch_data_0

    .line 13
    .line 14
    .line 15
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 16
    .line 17
    iget v1, p0, Lew/f;->e:I

    .line 18
    .line 19
    if-eqz v1, :cond_1

    .line 20
    .line 21
    if-ne v1, v6, :cond_0

    .line 22
    .line 23
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

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
    iget-object p1, p0, Lew/f;->f:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p1, Lna/k;

    .line 39
    .line 40
    iput v6, p0, Lew/f;->e:I

    .line 41
    .line 42
    invoke-interface {v4, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    if-ne p1, v0, :cond_2

    .line 47
    .line 48
    move-object p1, v0

    .line 49
    :cond_2
    :goto_0
    return-object p1

    .line 50
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 51
    .line 52
    iget v1, p0, Lew/f;->e:I

    .line 53
    .line 54
    if-eqz v1, :cond_4

    .line 55
    .line 56
    if-ne v1, v6, :cond_3

    .line 57
    .line 58
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 63
    .line 64
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    throw p0

    .line 68
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    iget-object p1, p0, Lew/f;->f:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast p1, Lna/k;

    .line 74
    .line 75
    iput v6, p0, Lew/f;->e:I

    .line 76
    .line 77
    invoke-interface {v4, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    if-ne p1, v0, :cond_5

    .line 82
    .line 83
    move-object p1, v0

    .line 84
    :cond_5
    :goto_1
    return-object p1

    .line 85
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 86
    .line 87
    iget v1, p0, Lew/f;->e:I

    .line 88
    .line 89
    if-eqz v1, :cond_7

    .line 90
    .line 91
    if-ne v1, v6, :cond_6

    .line 92
    .line 93
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    goto :goto_2

    .line 97
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 98
    .line 99
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    throw p0

    .line 103
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    iget-object p1, p0, Lew/f;->f:Ljava/lang/Object;

    .line 107
    .line 108
    check-cast p1, Lvy0/b0;

    .line 109
    .line 110
    invoke-interface {p1}, Lvy0/b0;->getCoroutineContext()Lpx0/g;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    sget-object v1, Lla/z;->e:Lla/y;

    .line 115
    .line 116
    invoke-interface {p1, v1}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    if-eqz p1, :cond_9

    .line 121
    .line 122
    iput v6, p0, Lew/f;->e:I

    .line 123
    .line 124
    invoke-interface {v4, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object p1

    .line 128
    if-ne p1, v0, :cond_8

    .line 129
    .line 130
    move-object p1, v0

    .line 131
    :cond_8
    :goto_2
    return-object p1

    .line 132
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 133
    .line 134
    const-string p1, "Expected a TransactionElement in the CoroutineContext but none was found."

    .line 135
    .line 136
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    throw p0

    .line 140
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 141
    .line 142
    iget v1, p0, Lew/f;->e:I

    .line 143
    .line 144
    if-eqz v1, :cond_b

    .line 145
    .line 146
    if-ne v1, v6, :cond_a

    .line 147
    .line 148
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 149
    .line 150
    .line 151
    goto :goto_4

    .line 152
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 153
    .line 154
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 155
    .line 156
    .line 157
    throw p0

    .line 158
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 159
    .line 160
    .line 161
    iget-object p1, p0, Lew/f;->f:Ljava/lang/Object;

    .line 162
    .line 163
    check-cast p1, Lp3/x;

    .line 164
    .line 165
    new-instance v8, Laa/c0;

    .line 166
    .line 167
    const/16 v1, 0x18

    .line 168
    .line 169
    invoke-direct {v8, v1, v4}, Laa/c0;-><init>(ILay0/k;)V

    .line 170
    .line 171
    .line 172
    new-instance v10, Le41/b;

    .line 173
    .line 174
    const/4 v1, 0x6

    .line 175
    invoke-direct {v10, v1, v4}, Le41/b;-><init>(ILay0/k;)V

    .line 176
    .line 177
    .line 178
    new-instance v11, Le41/b;

    .line 179
    .line 180
    invoke-direct {v11, v2, v4}, Le41/b;-><init>(ILay0/k;)V

    .line 181
    .line 182
    .line 183
    new-instance v9, Lal/c;

    .line 184
    .line 185
    const/4 v1, 0x4

    .line 186
    invoke-direct {v9, v1, v4}, Lal/c;-><init>(ILay0/k;)V

    .line 187
    .line 188
    .line 189
    iput v6, p0, Lew/f;->e:I

    .line 190
    .line 191
    sget v1, Lg1/w0;->a:F

    .line 192
    .line 193
    new-instance v7, Lg1/s0;

    .line 194
    .line 195
    const/4 v12, 0x0

    .line 196
    const/4 v13, 0x0

    .line 197
    invoke-direct/range {v7 .. v13}, Lg1/s0;-><init>(Lay0/k;Lay0/n;Lay0/a;Lay0/a;Lkotlin/coroutines/Continuation;I)V

    .line 198
    .line 199
    .line 200
    invoke-static {p1, v7, p0}, Lg1/h3;->c(Lp3/x;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object p0

    .line 204
    if-ne p0, v0, :cond_c

    .line 205
    .line 206
    goto :goto_3

    .line 207
    :cond_c
    move-object p0, v3

    .line 208
    :goto_3
    if-ne p0, v0, :cond_d

    .line 209
    .line 210
    move-object v3, v0

    .line 211
    :cond_d
    :goto_4
    return-object v3

    .line 212
    :pswitch_3
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 213
    .line 214
    iget v2, p0, Lew/f;->e:I

    .line 215
    .line 216
    if-eqz v2, :cond_f

    .line 217
    .line 218
    if-ne v2, v6, :cond_e

    .line 219
    .line 220
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 221
    .line 222
    .line 223
    goto :goto_5

    .line 224
    :cond_e
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 225
    .line 226
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 227
    .line 228
    .line 229
    throw p0

    .line 230
    :cond_f
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 231
    .line 232
    .line 233
    iget-object p1, p0, Lew/f;->f:Ljava/lang/Object;

    .line 234
    .line 235
    check-cast p1, Lp3/x;

    .line 236
    .line 237
    new-instance v2, Le2/a0;

    .line 238
    .line 239
    invoke-direct {v2, v4, v1, v6}, Le2/a0;-><init>(Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 240
    .line 241
    .line 242
    iput v6, p0, Lew/f;->e:I

    .line 243
    .line 244
    check-cast p1, Lp3/j0;

    .line 245
    .line 246
    invoke-virtual {p1, v2, p0}, Lp3/j0;->X0(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 247
    .line 248
    .line 249
    move-result-object p0

    .line 250
    if-ne p0, v0, :cond_10

    .line 251
    .line 252
    move-object v3, v0

    .line 253
    :cond_10
    :goto_5
    return-object v3

    .line 254
    :pswitch_4
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 255
    .line 256
    iget v7, p0, Lew/f;->e:I

    .line 257
    .line 258
    if-eqz v7, :cond_12

    .line 259
    .line 260
    if-ne v7, v6, :cond_11

    .line 261
    .line 262
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 263
    .line 264
    .line 265
    goto :goto_6

    .line 266
    :cond_11
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 267
    .line 268
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 269
    .line 270
    .line 271
    throw p0

    .line 272
    :cond_12
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 273
    .line 274
    .line 275
    iget-object p1, p0, Lew/f;->f:Ljava/lang/Object;

    .line 276
    .line 277
    check-cast p1, Lp3/x;

    .line 278
    .line 279
    new-instance v5, Laa/c0;

    .line 280
    .line 281
    const/16 v7, 0x17

    .line 282
    .line 283
    invoke-direct {v5, v7, v4}, Laa/c0;-><init>(ILay0/k;)V

    .line 284
    .line 285
    .line 286
    iput v6, p0, Lew/f;->e:I

    .line 287
    .line 288
    invoke-static {p1, v1, v5, p0, v2}, Lg1/g3;->e(Lp3/x;Lay0/o;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 289
    .line 290
    .line 291
    move-result-object p0

    .line 292
    if-ne p0, v0, :cond_13

    .line 293
    .line 294
    move-object v3, v0

    .line 295
    :cond_13
    :goto_6
    return-object v3

    .line 296
    nop

    .line 297
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
