.class public final Lm70/w0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lm70/g1;


# direct methods
.method public synthetic constructor <init>(Lm70/g1;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lm70/w0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lm70/w0;->f:Lm70/g1;

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
    iget p1, p0, Lm70/w0;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lm70/w0;

    .line 7
    .line 8
    iget-object p0, p0, Lm70/w0;->f:Lm70/g1;

    .line 9
    .line 10
    const/4 v0, 0x4

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lm70/w0;-><init>(Lm70/g1;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lm70/w0;

    .line 16
    .line 17
    iget-object p0, p0, Lm70/w0;->f:Lm70/g1;

    .line 18
    .line 19
    const/4 v0, 0x3

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lm70/w0;-><init>(Lm70/g1;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lm70/w0;

    .line 25
    .line 26
    iget-object p0, p0, Lm70/w0;->f:Lm70/g1;

    .line 27
    .line 28
    const/4 v0, 0x2

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lm70/w0;-><init>(Lm70/g1;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lm70/w0;

    .line 34
    .line 35
    iget-object p0, p0, Lm70/w0;->f:Lm70/g1;

    .line 36
    .line 37
    const/4 v0, 0x1

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lm70/w0;-><init>(Lm70/g1;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    :pswitch_3
    new-instance p1, Lm70/w0;

    .line 43
    .line 44
    iget-object p0, p0, Lm70/w0;->f:Lm70/g1;

    .line 45
    .line 46
    const/4 v0, 0x0

    .line 47
    invoke-direct {p1, p0, p2, v0}, Lm70/w0;-><init>(Lm70/g1;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    return-object p1

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lm70/w0;->d:I

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
    invoke-virtual {p0, p1, p2}, Lm70/w0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lm70/w0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lm70/w0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lne0/c;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Lm70/w0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lm70/w0;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lm70/w0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Lm70/w0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Lm70/w0;

    .line 49
    .line 50
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    invoke-virtual {p0, p1}, Lm70/w0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :pswitch_2
    check-cast p1, Lvy0/b0;

    .line 58
    .line 59
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 60
    .line 61
    invoke-virtual {p0, p1, p2}, Lm70/w0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    check-cast p0, Lm70/w0;

    .line 66
    .line 67
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    invoke-virtual {p0, p1}, Lm70/w0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0

    .line 74
    :pswitch_3
    check-cast p1, Lvy0/b0;

    .line 75
    .line 76
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 77
    .line 78
    invoke-virtual {p0, p1, p2}, Lm70/w0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    check-cast p0, Lm70/w0;

    .line 83
    .line 84
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 85
    .line 86
    invoke-virtual {p0, p1}, Lm70/w0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    return-object p0

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lm70/w0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lm70/w0;->e:I

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
    iget-object p1, p0, Lm70/w0;->f:Lm70/g1;

    .line 31
    .line 32
    iget-object v1, p1, Lm70/g1;->o:Lk70/k;

    .line 33
    .line 34
    const/4 v3, 0x0

    .line 35
    invoke-virtual {v1, v3}, Lk70/k;->a(Z)Lyy0/i;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    new-instance v3, Lam0/i;

    .line 40
    .line 41
    check-cast v1, Lk70/j;

    .line 42
    .line 43
    const/16 v4, 0x10

    .line 44
    .line 45
    invoke-direct {v3, v1, v4}, Lam0/i;-><init>(Ljava/lang/Object;I)V

    .line 46
    .line 47
    .line 48
    new-instance v1, Lm70/w0;

    .line 49
    .line 50
    const/4 v4, 0x0

    .line 51
    const/4 v5, 0x3

    .line 52
    invoke-direct {v1, p1, v4, v5}, Lm70/w0;-><init>(Lm70/g1;Lkotlin/coroutines/Continuation;I)V

    .line 53
    .line 54
    .line 55
    iput v2, p0, Lm70/w0;->e:I

    .line 56
    .line 57
    invoke-static {v1, p0, v3}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    if-ne p0, v0, :cond_2

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 65
    .line 66
    :goto_1
    return-object v0

    .line 67
    :pswitch_0
    iget-object v0, p0, Lm70/w0;->f:Lm70/g1;

    .line 68
    .line 69
    iget-object v1, v0, Lm70/g1;->h:Lij0/a;

    .line 70
    .line 71
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 72
    .line 73
    iget v3, p0, Lm70/w0;->e:I

    .line 74
    .line 75
    const/4 v4, 0x0

    .line 76
    const/4 v5, 0x1

    .line 77
    if-eqz v3, :cond_4

    .line 78
    .line 79
    if-ne v3, v5, :cond_3

    .line 80
    .line 81
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    goto :goto_2

    .line 85
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 86
    .line 87
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 88
    .line 89
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    throw p0

    .line 93
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    iget-object p1, v0, Lm70/g1;->j:Lrq0/f;

    .line 97
    .line 98
    new-instance v3, Lsq0/c;

    .line 99
    .line 100
    const/4 v6, 0x0

    .line 101
    new-array v7, v6, [Ljava/lang/Object;

    .line 102
    .line 103
    move-object v8, v1

    .line 104
    check-cast v8, Ljj0/f;

    .line 105
    .line 106
    const v9, 0x7f121460

    .line 107
    .line 108
    .line 109
    invoke-virtual {v8, v9, v7}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object v7

    .line 113
    new-array v8, v6, [Ljava/lang/Object;

    .line 114
    .line 115
    check-cast v1, Ljj0/f;

    .line 116
    .line 117
    const v9, 0x7f12038b

    .line 118
    .line 119
    .line 120
    invoke-virtual {v1, v9, v8}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object v1

    .line 124
    const/4 v8, 0x4

    .line 125
    invoke-direct {v3, v8, v7, v1, v4}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    iput v5, p0, Lm70/w0;->e:I

    .line 129
    .line 130
    invoke-virtual {p1, v3, v6, p0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 131
    .line 132
    .line 133
    move-result-object p1

    .line 134
    if-ne p1, v2, :cond_5

    .line 135
    .line 136
    goto :goto_4

    .line 137
    :cond_5
    :goto_2
    move-object p0, p1

    .line 138
    check-cast p0, Lsq0/d;

    .line 139
    .line 140
    sget-object v1, Lsq0/d;->d:Lsq0/d;

    .line 141
    .line 142
    if-ne p0, v1, :cond_6

    .line 143
    .line 144
    goto :goto_3

    .line 145
    :cond_6
    move-object p1, v4

    .line 146
    :goto_3
    check-cast p1, Lsq0/d;

    .line 147
    .line 148
    if-eqz p1, :cond_7

    .line 149
    .line 150
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 151
    .line 152
    .line 153
    move-result-object p0

    .line 154
    new-instance p1, Lm70/w0;

    .line 155
    .line 156
    const/4 v1, 0x4

    .line 157
    invoke-direct {p1, v0, v4, v1}, Lm70/w0;-><init>(Lm70/g1;Lkotlin/coroutines/Continuation;I)V

    .line 158
    .line 159
    .line 160
    const/4 v1, 0x3

    .line 161
    invoke-static {p0, v4, v4, p1, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    iput-object p0, v0, Lm70/g1;->w:Lvy0/x1;

    .line 166
    .line 167
    :cond_7
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 168
    .line 169
    :goto_4
    return-object v2

    .line 170
    :pswitch_1
    iget-object v0, p0, Lm70/w0;->f:Lm70/g1;

    .line 171
    .line 172
    iget-object v1, v0, Lm70/g1;->h:Lij0/a;

    .line 173
    .line 174
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 175
    .line 176
    iget v3, p0, Lm70/w0;->e:I

    .line 177
    .line 178
    const/4 v4, 0x0

    .line 179
    const/4 v5, 0x1

    .line 180
    if-eqz v3, :cond_9

    .line 181
    .line 182
    if-ne v3, v5, :cond_8

    .line 183
    .line 184
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 185
    .line 186
    .line 187
    goto :goto_5

    .line 188
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 189
    .line 190
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 191
    .line 192
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 193
    .line 194
    .line 195
    throw p0

    .line 196
    :cond_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 197
    .line 198
    .line 199
    iget-object p1, v0, Lm70/g1;->j:Lrq0/f;

    .line 200
    .line 201
    new-instance v3, Lsq0/c;

    .line 202
    .line 203
    const/4 v6, 0x0

    .line 204
    new-array v7, v6, [Ljava/lang/Object;

    .line 205
    .line 206
    move-object v8, v1

    .line 207
    check-cast v8, Ljj0/f;

    .line 208
    .line 209
    const v9, 0x7f121462

    .line 210
    .line 211
    .line 212
    invoke-virtual {v8, v9, v7}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 213
    .line 214
    .line 215
    move-result-object v7

    .line 216
    new-array v8, v6, [Ljava/lang/Object;

    .line 217
    .line 218
    check-cast v1, Ljj0/f;

    .line 219
    .line 220
    const v9, 0x7f12038b

    .line 221
    .line 222
    .line 223
    invoke-virtual {v1, v9, v8}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    move-result-object v1

    .line 227
    const/4 v8, 0x4

    .line 228
    invoke-direct {v3, v8, v7, v1, v4}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 229
    .line 230
    .line 231
    iput v5, p0, Lm70/w0;->e:I

    .line 232
    .line 233
    invoke-virtual {p1, v3, v6, p0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 234
    .line 235
    .line 236
    move-result-object p1

    .line 237
    if-ne p1, v2, :cond_a

    .line 238
    .line 239
    goto :goto_6

    .line 240
    :cond_a
    :goto_5
    check-cast p1, Lsq0/d;

    .line 241
    .line 242
    sget-object p0, Lsq0/d;->d:Lsq0/d;

    .line 243
    .line 244
    if-ne p1, p0, :cond_b

    .line 245
    .line 246
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 247
    .line 248
    .line 249
    move-result-object p0

    .line 250
    new-instance p1, Lm70/v0;

    .line 251
    .line 252
    const/4 v1, 0x1

    .line 253
    invoke-direct {p1, v0, v4, v1}, Lm70/v0;-><init>(Lm70/g1;Lkotlin/coroutines/Continuation;I)V

    .line 254
    .line 255
    .line 256
    const/4 v0, 0x3

    .line 257
    invoke-static {p0, v4, v4, p1, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 258
    .line 259
    .line 260
    :cond_b
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 261
    .line 262
    :goto_6
    return-object v2

    .line 263
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 264
    .line 265
    iget v1, p0, Lm70/w0;->e:I

    .line 266
    .line 267
    const/4 v2, 0x1

    .line 268
    if-eqz v1, :cond_d

    .line 269
    .line 270
    if-ne v1, v2, :cond_c

    .line 271
    .line 272
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 273
    .line 274
    .line 275
    goto :goto_7

    .line 276
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 277
    .line 278
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 279
    .line 280
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 281
    .line 282
    .line 283
    throw p0

    .line 284
    :cond_d
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 285
    .line 286
    .line 287
    iget-object p1, p0, Lm70/w0;->f:Lm70/g1;

    .line 288
    .line 289
    iget-object v1, p1, Lm70/g1;->j:Lrq0/f;

    .line 290
    .line 291
    new-instance v3, Lsq0/c;

    .line 292
    .line 293
    iget-object p1, p1, Lm70/g1;->h:Lij0/a;

    .line 294
    .line 295
    const/4 v4, 0x0

    .line 296
    new-array v5, v4, [Ljava/lang/Object;

    .line 297
    .line 298
    check-cast p1, Ljj0/f;

    .line 299
    .line 300
    const v6, 0x7f121461

    .line 301
    .line 302
    .line 303
    invoke-virtual {p1, v6, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 304
    .line 305
    .line 306
    move-result-object p1

    .line 307
    const/4 v5, 0x6

    .line 308
    const/4 v6, 0x0

    .line 309
    invoke-direct {v3, v5, p1, v6, v6}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 310
    .line 311
    .line 312
    iput v2, p0, Lm70/w0;->e:I

    .line 313
    .line 314
    invoke-virtual {v1, v3, v4, p0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 315
    .line 316
    .line 317
    move-result-object p0

    .line 318
    if-ne p0, v0, :cond_e

    .line 319
    .line 320
    goto :goto_8

    .line 321
    :cond_e
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 322
    .line 323
    :goto_8
    return-object v0

    .line 324
    :pswitch_3
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 325
    .line 326
    iget v1, p0, Lm70/w0;->e:I

    .line 327
    .line 328
    const/4 v2, 0x1

    .line 329
    if-eqz v1, :cond_10

    .line 330
    .line 331
    if-ne v1, v2, :cond_f

    .line 332
    .line 333
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 334
    .line 335
    .line 336
    goto :goto_9

    .line 337
    :cond_f
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 338
    .line 339
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 340
    .line 341
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 342
    .line 343
    .line 344
    throw p0

    .line 345
    :cond_10
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 346
    .line 347
    .line 348
    iget-object v5, p0, Lm70/w0;->f:Lm70/g1;

    .line 349
    .line 350
    iget-object p1, v5, Lm70/g1;->q:Lk70/i0;

    .line 351
    .line 352
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 353
    .line 354
    .line 355
    move-result-object p1

    .line 356
    check-cast p1, Lyy0/i;

    .line 357
    .line 358
    new-instance v3, La50/d;

    .line 359
    .line 360
    const/4 v9, 0x4

    .line 361
    const/16 v10, 0xf

    .line 362
    .line 363
    const/4 v4, 0x2

    .line 364
    const-class v6, Lm70/g1;

    .line 365
    .line 366
    const-string v7, "setSingleTripStatisticsFilter"

    .line 367
    .line 368
    const-string v8, "setSingleTripStatisticsFilter(Lcz/skodaauto/myskoda/feature/remotetripstatistics/model/SingleTripStatisticsFilter;)V"

    .line 369
    .line 370
    invoke-direct/range {v3 .. v10}, La50/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 371
    .line 372
    .line 373
    iput v2, p0, Lm70/w0;->e:I

    .line 374
    .line 375
    invoke-static {v3, p0, p1}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 376
    .line 377
    .line 378
    move-result-object p0

    .line 379
    if-ne p0, v0, :cond_11

    .line 380
    .line 381
    goto :goto_a

    .line 382
    :cond_11
    :goto_9
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 383
    .line 384
    :goto_a
    return-object v0

    .line 385
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
