.class public final Ltz/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ltz/s;


# direct methods
.method public synthetic constructor <init>(Ltz/s;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ltz/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltz/b;->f:Ltz/s;

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
    iget p1, p0, Ltz/b;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ltz/b;

    .line 7
    .line 8
    iget-object p0, p0, Ltz/b;->f:Ltz/s;

    .line 9
    .line 10
    const/4 v0, 0x3

    .line 11
    invoke-direct {p1, p0, p2, v0}, Ltz/b;-><init>(Ltz/s;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Ltz/b;

    .line 16
    .line 17
    iget-object p0, p0, Ltz/b;->f:Ltz/s;

    .line 18
    .line 19
    const/4 v0, 0x2

    .line 20
    invoke-direct {p1, p0, p2, v0}, Ltz/b;-><init>(Ltz/s;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Ltz/b;

    .line 25
    .line 26
    iget-object p0, p0, Ltz/b;->f:Ltz/s;

    .line 27
    .line 28
    const/4 v0, 0x1

    .line 29
    invoke-direct {p1, p0, p2, v0}, Ltz/b;-><init>(Ltz/s;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Ltz/b;

    .line 34
    .line 35
    iget-object p0, p0, Ltz/b;->f:Ltz/s;

    .line 36
    .line 37
    const/4 v0, 0x0

    .line 38
    invoke-direct {p1, p0, p2, v0}, Ltz/b;-><init>(Ltz/s;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Ltz/b;->d:I

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
    invoke-virtual {p0, p1, p2}, Ltz/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ltz/b;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ltz/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ltz/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ltz/b;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ltz/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Ltz/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Ltz/b;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Ltz/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Ltz/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Ltz/b;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Ltz/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ltz/b;->d:I

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/16 v3, 0x8

    .line 7
    .line 8
    const/4 v4, 0x2

    .line 9
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    const-string v6, "call to \'resume\' before \'invoke\' with coroutine"

    .line 12
    .line 13
    iget-object v7, v0, Ltz/b;->f:Ltz/s;

    .line 14
    .line 15
    const/4 v8, 0x1

    .line 16
    packed-switch v1, :pswitch_data_0

    .line 17
    .line 18
    .line 19
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 20
    .line 21
    iget v2, v0, Ltz/b;->e:I

    .line 22
    .line 23
    if-eqz v2, :cond_1

    .line 24
    .line 25
    if-ne v2, v8, :cond_0

    .line 26
    .line 27
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 32
    .line 33
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw v0

    .line 37
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    iget-object v2, v7, Ltz/s;->j:Lkf0/b0;

    .line 41
    .line 42
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    check-cast v2, Lyy0/i;

    .line 47
    .line 48
    new-instance v3, Ltz/c;

    .line 49
    .line 50
    invoke-direct {v3, v7, v8}, Ltz/c;-><init>(Ltz/s;I)V

    .line 51
    .line 52
    .line 53
    iput v8, v0, Ltz/b;->e:I

    .line 54
    .line 55
    invoke-interface {v2, v3, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    if-ne v0, v1, :cond_2

    .line 60
    .line 61
    move-object v5, v1

    .line 62
    :cond_2
    :goto_0
    return-object v5

    .line 63
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 64
    .line 65
    iget v2, v0, Ltz/b;->e:I

    .line 66
    .line 67
    if-eqz v2, :cond_5

    .line 68
    .line 69
    if-eq v2, v8, :cond_4

    .line 70
    .line 71
    if-ne v2, v4, :cond_3

    .line 72
    .line 73
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    goto :goto_3

    .line 77
    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 78
    .line 79
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    throw v0

    .line 83
    :cond_4
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    move-object/from16 v2, p1

    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_5
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    iget-object v2, v7, Ltz/s;->v:Lcf0/e;

    .line 93
    .line 94
    iput v8, v0, Ltz/b;->e:I

    .line 95
    .line 96
    invoke-virtual {v2, v5, v0}, Lcf0/e;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v2

    .line 100
    if-ne v2, v1, :cond_6

    .line 101
    .line 102
    goto :goto_2

    .line 103
    :cond_6
    :goto_1
    check-cast v2, Ljava/lang/Boolean;

    .line 104
    .line 105
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 106
    .line 107
    .line 108
    move-result v15

    .line 109
    sget-object v2, Ltz/s;->z:Ljava/util/List;

    .line 110
    .line 111
    invoke-virtual {v7}, Lql0/j;->a()Lql0/h;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    move-object v8, v2

    .line 116
    check-cast v8, Ltz/i;

    .line 117
    .line 118
    const/16 v28, 0x0

    .line 119
    .line 120
    const v29, 0xfffbf

    .line 121
    .line 122
    .line 123
    const/4 v9, 0x0

    .line 124
    const/4 v10, 0x0

    .line 125
    const/4 v11, 0x0

    .line 126
    const/4 v12, 0x0

    .line 127
    const/4 v13, 0x0

    .line 128
    const/4 v14, 0x0

    .line 129
    const/16 v16, 0x0

    .line 130
    .line 131
    const/16 v17, 0x0

    .line 132
    .line 133
    const/16 v18, 0x0

    .line 134
    .line 135
    const/16 v19, 0x0

    .line 136
    .line 137
    const/16 v20, 0x0

    .line 138
    .line 139
    const/16 v21, 0x0

    .line 140
    .line 141
    const/16 v22, 0x0

    .line 142
    .line 143
    const/16 v23, 0x0

    .line 144
    .line 145
    const/16 v24, 0x0

    .line 146
    .line 147
    const/16 v25, 0x0

    .line 148
    .line 149
    const/16 v26, 0x0

    .line 150
    .line 151
    const/16 v27, 0x0

    .line 152
    .line 153
    invoke-static/range {v8 .. v29}, Ltz/i;->a(Ltz/i;Ltz/g;Ljava/lang/String;ZZLlf0/i;Ltz/h;ZZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lqr0/l;ZZZZZI)Ltz/i;

    .line 154
    .line 155
    .line 156
    move-result-object v2

    .line 157
    invoke-virtual {v7, v2}, Lql0/j;->g(Lql0/h;)V

    .line 158
    .line 159
    .line 160
    if-eqz v15, :cond_7

    .line 161
    .line 162
    iget-object v2, v7, Ltz/s;->u:Lqd0/l0;

    .line 163
    .line 164
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v2

    .line 168
    check-cast v2, Lyy0/i;

    .line 169
    .line 170
    new-instance v3, Ltz/c;

    .line 171
    .line 172
    const/4 v6, 0x0

    .line 173
    invoke-direct {v3, v7, v6}, Ltz/c;-><init>(Ltz/s;I)V

    .line 174
    .line 175
    .line 176
    iput v4, v0, Ltz/b;->e:I

    .line 177
    .line 178
    invoke-interface {v2, v3, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object v0

    .line 182
    if-ne v0, v1, :cond_7

    .line 183
    .line 184
    :goto_2
    move-object v5, v1

    .line 185
    :cond_7
    :goto_3
    return-object v5

    .line 186
    :pswitch_1
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 187
    .line 188
    iget v9, v0, Ltz/b;->e:I

    .line 189
    .line 190
    if-eqz v9, :cond_a

    .line 191
    .line 192
    if-eq v9, v8, :cond_9

    .line 193
    .line 194
    if-ne v9, v4, :cond_8

    .line 195
    .line 196
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 197
    .line 198
    .line 199
    goto :goto_6

    .line 200
    :cond_8
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 201
    .line 202
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 203
    .line 204
    .line 205
    throw v0

    .line 206
    :cond_9
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 207
    .line 208
    .line 209
    move-object/from16 v2, p1

    .line 210
    .line 211
    goto :goto_4

    .line 212
    :cond_a
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 213
    .line 214
    .line 215
    iget-object v6, v7, Ltz/s;->k:Lqd0/d0;

    .line 216
    .line 217
    iput v8, v0, Ltz/b;->e:I

    .line 218
    .line 219
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 220
    .line 221
    .line 222
    iget-object v7, v6, Lqd0/d0;->a:Lyb0/l;

    .line 223
    .line 224
    new-instance v8, Lyb0/i;

    .line 225
    .line 226
    sget-object v9, Lzb0/d;->e:Lzb0/d;

    .line 227
    .line 228
    const/4 v12, 0x0

    .line 229
    const/16 v13, 0x3c

    .line 230
    .line 231
    const-string v10, "charging"

    .line 232
    .line 233
    const/4 v11, 0x0

    .line 234
    invoke-direct/range {v8 .. v13}, Lyb0/i;-><init>(Lzb0/d;Ljava/lang/String;Ljava/util/Set;Lyb0/h;I)V

    .line 235
    .line 236
    .line 237
    invoke-virtual {v7, v8}, Lyb0/l;->a(Lyb0/i;)Lzy0/j;

    .line 238
    .line 239
    .line 240
    move-result-object v7

    .line 241
    new-instance v8, Llb0/y;

    .line 242
    .line 243
    invoke-direct {v8, v3, v7, v6}, Llb0/y;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 244
    .line 245
    .line 246
    new-instance v3, Lny/f0;

    .line 247
    .line 248
    const/16 v7, 0x11

    .line 249
    .line 250
    invoke-direct {v3, v6, v2, v7}, Lny/f0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 251
    .line 252
    .line 253
    new-instance v2, Lne0/n;

    .line 254
    .line 255
    const/4 v6, 0x5

    .line 256
    invoke-direct {v2, v8, v3, v6}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 257
    .line 258
    .line 259
    if-ne v2, v1, :cond_b

    .line 260
    .line 261
    goto :goto_5

    .line 262
    :cond_b
    :goto_4
    check-cast v2, Lyy0/i;

    .line 263
    .line 264
    iput v4, v0, Ltz/b;->e:I

    .line 265
    .line 266
    invoke-static {v2, v0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    move-result-object v0

    .line 270
    if-ne v0, v1, :cond_c

    .line 271
    .line 272
    :goto_5
    move-object v5, v1

    .line 273
    :cond_c
    :goto_6
    return-object v5

    .line 274
    :pswitch_2
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 275
    .line 276
    iget v4, v0, Ltz/b;->e:I

    .line 277
    .line 278
    if-eqz v4, :cond_e

    .line 279
    .line 280
    if-ne v4, v8, :cond_d

    .line 281
    .line 282
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 283
    .line 284
    .line 285
    goto :goto_7

    .line 286
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 287
    .line 288
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 289
    .line 290
    .line 291
    throw v0

    .line 292
    :cond_e
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 293
    .line 294
    .line 295
    iget-object v4, v7, Ltz/s;->l:Lkf0/e0;

    .line 296
    .line 297
    sget-object v6, Lss0/e;->s:Lss0/e;

    .line 298
    .line 299
    invoke-virtual {v4, v6}, Lkf0/e0;->a(Lss0/e;)Lne0/k;

    .line 300
    .line 301
    .line 302
    move-result-object v4

    .line 303
    new-instance v6, Lbp0/g;

    .line 304
    .line 305
    invoke-direct {v6, v7, v2, v3}, Lbp0/g;-><init>(Lql0/j;Lkotlin/coroutines/Continuation;I)V

    .line 306
    .line 307
    .line 308
    iput v8, v0, Ltz/b;->e:I

    .line 309
    .line 310
    invoke-static {v6, v0, v4}, Lbb/j0;->a(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 311
    .line 312
    .line 313
    move-result-object v0

    .line 314
    if-ne v0, v1, :cond_f

    .line 315
    .line 316
    move-object v5, v1

    .line 317
    :cond_f
    :goto_7
    return-object v5

    .line 318
    nop

    .line 319
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
