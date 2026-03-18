.class public final Ltz/s2;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ltz/a3;


# direct methods
.method public synthetic constructor <init>(Ltz/a3;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ltz/s2;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltz/s2;->f:Ltz/a3;

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
    iget p1, p0, Ltz/s2;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ltz/s2;

    .line 7
    .line 8
    iget-object p0, p0, Ltz/s2;->f:Ltz/a3;

    .line 9
    .line 10
    const/4 v0, 0x3

    .line 11
    invoke-direct {p1, p0, p2, v0}, Ltz/s2;-><init>(Ltz/a3;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Ltz/s2;

    .line 16
    .line 17
    iget-object p0, p0, Ltz/s2;->f:Ltz/a3;

    .line 18
    .line 19
    const/4 v0, 0x2

    .line 20
    invoke-direct {p1, p0, p2, v0}, Ltz/s2;-><init>(Ltz/a3;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Ltz/s2;

    .line 25
    .line 26
    iget-object p0, p0, Ltz/s2;->f:Ltz/a3;

    .line 27
    .line 28
    const/4 v0, 0x1

    .line 29
    invoke-direct {p1, p0, p2, v0}, Ltz/s2;-><init>(Ltz/a3;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Ltz/s2;

    .line 34
    .line 35
    iget-object p0, p0, Ltz/s2;->f:Ltz/a3;

    .line 36
    .line 37
    const/4 v0, 0x0

    .line 38
    invoke-direct {p1, p0, p2, v0}, Ltz/s2;-><init>(Ltz/a3;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Ltz/s2;->d:I

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
    invoke-virtual {p0, p1, p2}, Ltz/s2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ltz/s2;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ltz/s2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ltz/s2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ltz/s2;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ltz/s2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Ltz/s2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Ltz/s2;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Ltz/s2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Ltz/s2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Ltz/s2;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Ltz/s2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 29

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ltz/s2;->d:I

    .line 4
    .line 5
    iget-object v2, v0, Ltz/s2;->f:Ltz/a3;

    .line 6
    .line 7
    const/4 v3, 0x2

    .line 8
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 9
    .line 10
    const-string v5, "call to \'resume\' before \'invoke\' with coroutine"

    .line 11
    .line 12
    const/4 v6, 0x1

    .line 13
    packed-switch v1, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 17
    .line 18
    iget v2, v0, Ltz/s2;->e:I

    .line 19
    .line 20
    if-eqz v2, :cond_1

    .line 21
    .line 22
    if-ne v2, v6, :cond_0

    .line 23
    .line 24
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 29
    .line 30
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw v0

    .line 34
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    iget-object v9, v0, Ltz/s2;->f:Ltz/a3;

    .line 38
    .line 39
    iget-object v2, v9, Ltz/a3;->k:Lqd0/k0;

    .line 40
    .line 41
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    check-cast v2, Lyy0/i;

    .line 46
    .line 47
    new-instance v7, La50/d;

    .line 48
    .line 49
    const/4 v13, 0x4

    .line 50
    const/16 v14, 0x1a

    .line 51
    .line 52
    const/4 v8, 0x2

    .line 53
    const-class v10, Ltz/a3;

    .line 54
    .line 55
    const-string v11, "onChargingProfiles"

    .line 56
    .line 57
    const-string v12, "onChargingProfiles(Lcz/skodaauto/myskoda/library/charging/model/ChargingProfiles;)V"

    .line 58
    .line 59
    invoke-direct/range {v7 .. v14}, La50/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 60
    .line 61
    .line 62
    iput v6, v0, Ltz/s2;->e:I

    .line 63
    .line 64
    invoke-static {v7, v0, v2}, Lbb/j0;->a(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    if-ne v0, v1, :cond_2

    .line 69
    .line 70
    move-object v4, v1

    .line 71
    :cond_2
    :goto_0
    return-object v4

    .line 72
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 73
    .line 74
    iget v3, v0, Ltz/s2;->e:I

    .line 75
    .line 76
    if-eqz v3, :cond_4

    .line 77
    .line 78
    if-ne v3, v6, :cond_3

    .line 79
    .line 80
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    goto :goto_1

    .line 84
    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 85
    .line 86
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    throw v0

    .line 90
    :cond_4
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    iget-object v3, v2, Ltz/a3;->j:Lqd0/e0;

    .line 94
    .line 95
    invoke-static {v3}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v3

    .line 99
    check-cast v3, Lyy0/i;

    .line 100
    .line 101
    new-instance v5, Lh50/y0;

    .line 102
    .line 103
    const/16 v7, 0xf

    .line 104
    .line 105
    invoke-direct {v5, v2, v7}, Lh50/y0;-><init>(Ljava/lang/Object;I)V

    .line 106
    .line 107
    .line 108
    iput v6, v0, Ltz/s2;->e:I

    .line 109
    .line 110
    invoke-interface {v3, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v0

    .line 114
    if-ne v0, v1, :cond_5

    .line 115
    .line 116
    move-object v4, v1

    .line 117
    :cond_5
    :goto_1
    return-object v4

    .line 118
    :pswitch_1
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 119
    .line 120
    iget v7, v0, Ltz/s2;->e:I

    .line 121
    .line 122
    if-eqz v7, :cond_8

    .line 123
    .line 124
    if-eq v7, v6, :cond_7

    .line 125
    .line 126
    if-ne v7, v3, :cond_6

    .line 127
    .line 128
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    goto/16 :goto_4

    .line 132
    .line 133
    :cond_6
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 134
    .line 135
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    throw v0

    .line 139
    :cond_7
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 140
    .line 141
    .line 142
    move-object/from16 v5, p1

    .line 143
    .line 144
    goto :goto_2

    .line 145
    :cond_8
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    iput v6, v0, Ltz/s2;->e:I

    .line 149
    .line 150
    invoke-static {v2, v0}, Ltz/a3;->h(Ltz/a3;Lrx0/c;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v5

    .line 154
    if-ne v5, v1, :cond_9

    .line 155
    .line 156
    goto :goto_3

    .line 157
    :cond_9
    :goto_2
    check-cast v5, Ljava/lang/Boolean;

    .line 158
    .line 159
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 160
    .line 161
    .line 162
    move-result v5

    .line 163
    if-eqz v5, :cond_a

    .line 164
    .line 165
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 166
    .line 167
    .line 168
    move-result-object v5

    .line 169
    move-object v6, v5

    .line 170
    check-cast v6, Ltz/u2;

    .line 171
    .line 172
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 173
    .line 174
    .line 175
    move-result-object v5

    .line 176
    check-cast v5, Ltz/u2;

    .line 177
    .line 178
    iget-object v7, v5, Ltz/u2;->g:Ltz/t2;

    .line 179
    .line 180
    const/16 v27, 0x0

    .line 181
    .line 182
    const v28, 0xfffff

    .line 183
    .line 184
    .line 185
    const/4 v8, 0x0

    .line 186
    const/4 v9, 0x0

    .line 187
    const/4 v10, 0x0

    .line 188
    const/4 v11, 0x0

    .line 189
    const/4 v12, 0x0

    .line 190
    const/4 v13, 0x0

    .line 191
    const/4 v14, 0x0

    .line 192
    const/4 v15, 0x0

    .line 193
    const/16 v16, 0x0

    .line 194
    .line 195
    const/16 v17, 0x0

    .line 196
    .line 197
    const/16 v18, 0x0

    .line 198
    .line 199
    const/16 v19, 0x0

    .line 200
    .line 201
    const/16 v20, 0x0

    .line 202
    .line 203
    const/16 v21, 0x0

    .line 204
    .line 205
    const/16 v22, 0x0

    .line 206
    .line 207
    const/16 v23, 0x0

    .line 208
    .line 209
    const/16 v24, 0x0

    .line 210
    .line 211
    const/16 v25, 0x0

    .line 212
    .line 213
    const/16 v26, 0x0

    .line 214
    .line 215
    invoke-static/range {v7 .. v28}, Ltz/t2;->a(Ltz/t2;ZLjava/lang/String;ZZZLjava/lang/String;ZZZLrd0/d0;ZZZZZZZZZLjava/lang/String;I)Ltz/t2;

    .line 216
    .line 217
    .line 218
    move-result-object v13

    .line 219
    const/16 v14, 0x3f

    .line 220
    .line 221
    const/4 v7, 0x0

    .line 222
    const/4 v9, 0x0

    .line 223
    const/4 v12, 0x0

    .line 224
    invoke-static/range {v6 .. v14}, Ltz/u2;->a(Ltz/u2;Lql0/g;ZZZZLjava/lang/String;Ltz/t2;I)Ltz/u2;

    .line 225
    .line 226
    .line 227
    move-result-object v5

    .line 228
    invoke-virtual {v2, v5}, Lql0/j;->g(Lql0/h;)V

    .line 229
    .line 230
    .line 231
    iget-object v2, v2, Ltz/a3;->l:Lqd0/i;

    .line 232
    .line 233
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    move-result-object v2

    .line 237
    check-cast v2, Lyy0/i;

    .line 238
    .line 239
    iput v3, v0, Ltz/s2;->e:I

    .line 240
    .line 241
    invoke-static {v2, v0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    move-result-object v0

    .line 245
    if-ne v0, v1, :cond_a

    .line 246
    .line 247
    :goto_3
    move-object v4, v1

    .line 248
    :cond_a
    :goto_4
    return-object v4

    .line 249
    :pswitch_2
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 250
    .line 251
    iget v7, v0, Ltz/s2;->e:I

    .line 252
    .line 253
    if-eqz v7, :cond_c

    .line 254
    .line 255
    if-ne v7, v6, :cond_b

    .line 256
    .line 257
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 258
    .line 259
    .line 260
    goto/16 :goto_8

    .line 261
    .line 262
    :cond_b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 263
    .line 264
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 265
    .line 266
    .line 267
    throw v0

    .line 268
    :cond_c
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 269
    .line 270
    .line 271
    iput v6, v0, Ltz/s2;->e:I

    .line 272
    .line 273
    iget-object v5, v2, Ltz/a3;->h:Lqd0/o0;

    .line 274
    .line 275
    invoke-static {v5}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 276
    .line 277
    .line 278
    move-result-object v5

    .line 279
    check-cast v5, Lyy0/i;

    .line 280
    .line 281
    iget-object v7, v2, Ltz/a3;->i:Lqd0/j0;

    .line 282
    .line 283
    sget-object v8, Lrd0/f0;->g:Lrd0/f0;

    .line 284
    .line 285
    invoke-virtual {v7, v8}, Lqd0/j0;->b(Lrd0/f0;)Lyy0/i;

    .line 286
    .line 287
    .line 288
    move-result-object v8

    .line 289
    new-instance v9, Lru0/l;

    .line 290
    .line 291
    const/16 v10, 0x12

    .line 292
    .line 293
    const/4 v11, 0x0

    .line 294
    invoke-direct {v9, v3, v11, v10}, Lru0/l;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 295
    .line 296
    .line 297
    new-instance v10, Lne0/n;

    .line 298
    .line 299
    invoke-direct {v10, v9, v8}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 300
    .line 301
    .line 302
    sget-object v8, Lrd0/f0;->f:Lrd0/f0;

    .line 303
    .line 304
    invoke-virtual {v7, v8}, Lqd0/j0;->b(Lrd0/f0;)Lyy0/i;

    .line 305
    .line 306
    .line 307
    move-result-object v8

    .line 308
    new-instance v9, Lru0/l;

    .line 309
    .line 310
    const/16 v12, 0x13

    .line 311
    .line 312
    invoke-direct {v9, v3, v11, v12}, Lru0/l;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 313
    .line 314
    .line 315
    new-instance v12, Lne0/n;

    .line 316
    .line 317
    invoke-direct {v12, v9, v8}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 318
    .line 319
    .line 320
    sget-object v8, Lrd0/f0;->m:Lrd0/f0;

    .line 321
    .line 322
    invoke-virtual {v7, v8}, Lqd0/j0;->b(Lrd0/f0;)Lyy0/i;

    .line 323
    .line 324
    .line 325
    move-result-object v8

    .line 326
    new-instance v9, Lru0/l;

    .line 327
    .line 328
    const/16 v13, 0x14

    .line 329
    .line 330
    invoke-direct {v9, v3, v11, v13}, Lru0/l;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 331
    .line 332
    .line 333
    new-instance v13, Lne0/n;

    .line 334
    .line 335
    invoke-direct {v13, v9, v8}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 336
    .line 337
    .line 338
    sget-object v8, Lrd0/f0;->i:Lrd0/f0;

    .line 339
    .line 340
    invoke-virtual {v7, v8}, Lqd0/j0;->b(Lrd0/f0;)Lyy0/i;

    .line 341
    .line 342
    .line 343
    move-result-object v8

    .line 344
    new-instance v9, Lru0/l;

    .line 345
    .line 346
    const/16 v14, 0x15

    .line 347
    .line 348
    invoke-direct {v9, v3, v11, v14}, Lru0/l;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 349
    .line 350
    .line 351
    new-instance v14, Lne0/n;

    .line 352
    .line 353
    invoke-direct {v14, v9, v8}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 354
    .line 355
    .line 356
    sget-object v8, Lrd0/f0;->h:Lrd0/f0;

    .line 357
    .line 358
    invoke-virtual {v7, v8}, Lqd0/j0;->b(Lrd0/f0;)Lyy0/i;

    .line 359
    .line 360
    .line 361
    move-result-object v7

    .line 362
    new-instance v8, Lru0/l;

    .line 363
    .line 364
    const/16 v9, 0x16

    .line 365
    .line 366
    invoke-direct {v8, v3, v11, v9}, Lru0/l;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 367
    .line 368
    .line 369
    new-instance v9, Lne0/n;

    .line 370
    .line 371
    invoke-direct {v9, v8, v7}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 372
    .line 373
    .line 374
    new-instance v7, Ltz/h0;

    .line 375
    .line 376
    invoke-direct {v7, v6, v11}, Ltz/h0;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 377
    .line 378
    .line 379
    const/4 v8, 0x5

    .line 380
    new-array v8, v8, [Lyy0/i;

    .line 381
    .line 382
    const/4 v15, 0x0

    .line 383
    aput-object v10, v8, v15

    .line 384
    .line 385
    aput-object v12, v8, v6

    .line 386
    .line 387
    aput-object v13, v8, v3

    .line 388
    .line 389
    const/4 v10, 0x3

    .line 390
    aput-object v14, v8, v10

    .line 391
    .line 392
    const/4 v10, 0x4

    .line 393
    aput-object v9, v8, v10

    .line 394
    .line 395
    new-instance v9, Lyy0/f1;

    .line 396
    .line 397
    invoke-direct {v9, v8, v7}, Lyy0/f1;-><init>([Lyy0/i;Lay0/r;)V

    .line 398
    .line 399
    .line 400
    new-instance v7, Lqa0/a;

    .line 401
    .line 402
    const/16 v8, 0x11

    .line 403
    .line 404
    invoke-direct {v7, v2, v11, v8}, Lqa0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 405
    .line 406
    .line 407
    new-array v2, v3, [Lyy0/i;

    .line 408
    .line 409
    aput-object v5, v2, v15

    .line 410
    .line 411
    aput-object v9, v2, v6

    .line 412
    .line 413
    new-instance v3, Lyy0/g1;

    .line 414
    .line 415
    invoke-direct {v3, v7, v11}, Lyy0/g1;-><init>(Lay0/o;Lkotlin/coroutines/Continuation;)V

    .line 416
    .line 417
    .line 418
    sget-object v5, Lyy0/h1;->d:Lyy0/h1;

    .line 419
    .line 420
    sget-object v6, Lzy0/q;->d:Lzy0/q;

    .line 421
    .line 422
    invoke-static {v5, v3, v0, v6, v2}, Lzy0/c;->a(Lay0/a;Lay0/o;Lkotlin/coroutines/Continuation;Lyy0/j;[Lyy0/i;)Ljava/lang/Object;

    .line 423
    .line 424
    .line 425
    move-result-object v0

    .line 426
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 427
    .line 428
    if-ne v0, v2, :cond_d

    .line 429
    .line 430
    goto :goto_5

    .line 431
    :cond_d
    move-object v0, v4

    .line 432
    :goto_5
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 433
    .line 434
    if-ne v0, v2, :cond_e

    .line 435
    .line 436
    goto :goto_6

    .line 437
    :cond_e
    move-object v0, v4

    .line 438
    :goto_6
    if-ne v0, v1, :cond_f

    .line 439
    .line 440
    goto :goto_7

    .line 441
    :cond_f
    move-object v0, v4

    .line 442
    :goto_7
    if-ne v0, v1, :cond_10

    .line 443
    .line 444
    move-object v4, v1

    .line 445
    :cond_10
    :goto_8
    return-object v4

    .line 446
    nop

    .line 447
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
