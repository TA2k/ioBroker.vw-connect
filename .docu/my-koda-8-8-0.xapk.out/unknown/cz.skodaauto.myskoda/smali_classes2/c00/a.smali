.class public final Lc00/a;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lc00/h;


# direct methods
.method public synthetic constructor <init>(Lc00/h;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lc00/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc00/a;->f:Lc00/h;

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
    iget p1, p0, Lc00/a;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lc00/a;

    .line 7
    .line 8
    iget-object p0, p0, Lc00/a;->f:Lc00/h;

    .line 9
    .line 10
    const/4 v0, 0x3

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lc00/a;-><init>(Lc00/h;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lc00/a;

    .line 16
    .line 17
    iget-object p0, p0, Lc00/a;->f:Lc00/h;

    .line 18
    .line 19
    const/4 v0, 0x2

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lc00/a;-><init>(Lc00/h;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lc00/a;

    .line 25
    .line 26
    iget-object p0, p0, Lc00/a;->f:Lc00/h;

    .line 27
    .line 28
    const/4 v0, 0x1

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lc00/a;-><init>(Lc00/h;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lc00/a;

    .line 34
    .line 35
    iget-object p0, p0, Lc00/a;->f:Lc00/h;

    .line 36
    .line 37
    const/4 v0, 0x0

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lc00/a;-><init>(Lc00/h;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    nop

    .line 43
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
    iget v0, p0, Lc00/a;->d:I

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
    invoke-virtual {p0, p1, p2}, Lc00/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lc00/a;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lc00/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lc00/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lc00/a;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lc00/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lc00/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lc00/a;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lc00/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lc00/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lc00/a;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lc00/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lc00/a;->d:I

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x2

    .line 7
    const/4 v4, 0x0

    .line 8
    iget-object v5, v0, Lc00/a;->f:Lc00/h;

    .line 9
    .line 10
    const-string v6, "call to \'resume\' before \'invoke\' with coroutine"

    .line 11
    .line 12
    sget-object v7, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    const/4 v8, 0x1

    .line 15
    packed-switch v1, :pswitch_data_0

    .line 16
    .line 17
    .line 18
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 19
    .line 20
    iget v2, v0, Lc00/a;->e:I

    .line 21
    .line 22
    if-eqz v2, :cond_1

    .line 23
    .line 24
    if-ne v2, v8, :cond_0

    .line 25
    .line 26
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 31
    .line 32
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    throw v0

    .line 36
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    iput v8, v0, Lc00/a;->e:I

    .line 40
    .line 41
    iget-object v2, v5, Lc00/h;->s:Llb0/g;

    .line 42
    .line 43
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    check-cast v2, Lyy0/i;

    .line 48
    .line 49
    new-instance v3, La90/c;

    .line 50
    .line 51
    const/16 v6, 0xb

    .line 52
    .line 53
    invoke-direct {v3, v4, v5, v6}, La90/c;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 54
    .line 55
    .line 56
    invoke-static {v2, v3}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    invoke-static {v2, v0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    if-ne v0, v1, :cond_2

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_2
    move-object v0, v7

    .line 68
    :goto_0
    if-ne v0, v1, :cond_3

    .line 69
    .line 70
    move-object v7, v1

    .line 71
    :cond_3
    :goto_1
    return-object v7

    .line 72
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 73
    .line 74
    iget v2, v0, Lc00/a;->e:I

    .line 75
    .line 76
    if-eqz v2, :cond_5

    .line 77
    .line 78
    if-ne v2, v8, :cond_4

    .line 79
    .line 80
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    goto :goto_2

    .line 84
    :cond_4
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 85
    .line 86
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    throw v0

    .line 90
    :cond_5
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    iget-object v2, v5, Lc00/h;->k:Lkf0/b0;

    .line 94
    .line 95
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v2

    .line 99
    check-cast v2, Lyy0/i;

    .line 100
    .line 101
    new-instance v3, Lc00/b;

    .line 102
    .line 103
    invoke-direct {v3, v5, v8}, Lc00/b;-><init>(Lc00/h;I)V

    .line 104
    .line 105
    .line 106
    iput v8, v0, Lc00/a;->e:I

    .line 107
    .line 108
    invoke-interface {v2, v3, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    if-ne v0, v1, :cond_6

    .line 113
    .line 114
    move-object v7, v1

    .line 115
    :cond_6
    :goto_2
    return-object v7

    .line 116
    :pswitch_1
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 117
    .line 118
    iget v4, v0, Lc00/a;->e:I

    .line 119
    .line 120
    if-eqz v4, :cond_9

    .line 121
    .line 122
    if-eq v4, v8, :cond_8

    .line 123
    .line 124
    if-ne v4, v3, :cond_7

    .line 125
    .line 126
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    goto :goto_5

    .line 130
    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 131
    .line 132
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    throw v0

    .line 136
    :cond_8
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 137
    .line 138
    .line 139
    move-object/from16 v4, p1

    .line 140
    .line 141
    goto :goto_3

    .line 142
    :cond_9
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    iget-object v4, v5, Lc00/h;->w:Lcf0/e;

    .line 146
    .line 147
    iput v8, v0, Lc00/a;->e:I

    .line 148
    .line 149
    invoke-virtual {v4, v7, v0}, Lcf0/e;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v4

    .line 153
    if-ne v4, v1, :cond_a

    .line 154
    .line 155
    goto :goto_4

    .line 156
    :cond_a
    :goto_3
    check-cast v4, Ljava/lang/Boolean;

    .line 157
    .line 158
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 159
    .line 160
    .line 161
    move-result v14

    .line 162
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 163
    .line 164
    .line 165
    move-result-object v4

    .line 166
    move-object v8, v4

    .line 167
    check-cast v8, Lc00/c;

    .line 168
    .line 169
    const/16 v17, 0x0

    .line 170
    .line 171
    const/16 v18, 0x3bf

    .line 172
    .line 173
    const/4 v9, 0x0

    .line 174
    const/4 v10, 0x0

    .line 175
    const/4 v11, 0x0

    .line 176
    const/4 v12, 0x0

    .line 177
    const/4 v13, 0x0

    .line 178
    const/4 v15, 0x0

    .line 179
    const/16 v16, 0x0

    .line 180
    .line 181
    invoke-static/range {v8 .. v18}, Lc00/c;->a(Lc00/c;ZLjava/lang/String;Ljava/lang/String;ZLlf0/i;ZZLqr0/q;ZI)Lc00/c;

    .line 182
    .line 183
    .line 184
    move-result-object v4

    .line 185
    invoke-virtual {v5, v4}, Lql0/j;->g(Lql0/h;)V

    .line 186
    .line 187
    .line 188
    if-eqz v14, :cond_b

    .line 189
    .line 190
    iget-object v4, v5, Lc00/h;->v:Llb0/j;

    .line 191
    .line 192
    invoke-static {v4}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v4

    .line 196
    check-cast v4, Lyy0/i;

    .line 197
    .line 198
    new-instance v6, Lc00/b;

    .line 199
    .line 200
    invoke-direct {v6, v5, v2}, Lc00/b;-><init>(Lc00/h;I)V

    .line 201
    .line 202
    .line 203
    iput v3, v0, Lc00/a;->e:I

    .line 204
    .line 205
    invoke-interface {v4, v6, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v0

    .line 209
    if-ne v0, v1, :cond_b

    .line 210
    .line 211
    :goto_4
    move-object v7, v1

    .line 212
    :cond_b
    :goto_5
    return-object v7

    .line 213
    :pswitch_2
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 214
    .line 215
    iget v9, v0, Lc00/a;->e:I

    .line 216
    .line 217
    if-eqz v9, :cond_d

    .line 218
    .line 219
    if-ne v9, v8, :cond_c

    .line 220
    .line 221
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 222
    .line 223
    .line 224
    goto :goto_8

    .line 225
    :cond_c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 226
    .line 227
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 228
    .line 229
    .line 230
    throw v0

    .line 231
    :cond_d
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 232
    .line 233
    .line 234
    iget-object v6, v5, Lc00/h;->x:Lkf0/v;

    .line 235
    .line 236
    invoke-static {v6}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    move-result-object v6

    .line 240
    check-cast v6, Lyy0/i;

    .line 241
    .line 242
    iget-object v9, v5, Lc00/h;->j:Lkf0/e0;

    .line 243
    .line 244
    sget-object v10, Lss0/e;->g:Lss0/e;

    .line 245
    .line 246
    invoke-virtual {v9, v10}, Lkf0/e0;->a(Lss0/e;)Lne0/k;

    .line 247
    .line 248
    .line 249
    move-result-object v9

    .line 250
    new-instance v10, La90/c;

    .line 251
    .line 252
    const/16 v11, 0xa

    .line 253
    .line 254
    invoke-direct {v10, v5, v4, v11}, La90/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 255
    .line 256
    .line 257
    iput v8, v0, Lc00/a;->e:I

    .line 258
    .line 259
    new-array v3, v3, [Lyy0/i;

    .line 260
    .line 261
    aput-object v6, v3, v2

    .line 262
    .line 263
    aput-object v9, v3, v8

    .line 264
    .line 265
    new-instance v2, Lyy0/g1;

    .line 266
    .line 267
    invoke-direct {v2, v10, v4}, Lyy0/g1;-><init>(Lay0/o;Lkotlin/coroutines/Continuation;)V

    .line 268
    .line 269
    .line 270
    sget-object v4, Lyy0/h1;->d:Lyy0/h1;

    .line 271
    .line 272
    sget-object v5, Lzy0/q;->d:Lzy0/q;

    .line 273
    .line 274
    invoke-static {v4, v2, v0, v5, v3}, Lzy0/c;->a(Lay0/a;Lay0/o;Lkotlin/coroutines/Continuation;Lyy0/j;[Lyy0/i;)Ljava/lang/Object;

    .line 275
    .line 276
    .line 277
    move-result-object v0

    .line 278
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 279
    .line 280
    if-ne v0, v2, :cond_e

    .line 281
    .line 282
    goto :goto_6

    .line 283
    :cond_e
    move-object v0, v7

    .line 284
    :goto_6
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 285
    .line 286
    if-ne v0, v2, :cond_f

    .line 287
    .line 288
    goto :goto_7

    .line 289
    :cond_f
    move-object v0, v7

    .line 290
    :goto_7
    if-ne v0, v1, :cond_10

    .line 291
    .line 292
    move-object v7, v1

    .line 293
    :cond_10
    :goto_8
    return-object v7

    .line 294
    nop

    .line 295
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
