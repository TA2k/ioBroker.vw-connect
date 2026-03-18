.class public final Lne/j;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lne/k;


# direct methods
.method public synthetic constructor <init>(Lne/k;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lne/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lne/j;->f:Lne/k;

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
    iget p1, p0, Lne/j;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lne/j;

    .line 7
    .line 8
    iget-object p0, p0, Lne/j;->f:Lne/k;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lne/j;-><init>(Lne/k;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lne/j;

    .line 16
    .line 17
    iget-object p0, p0, Lne/j;->f:Lne/k;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lne/j;-><init>(Lne/k;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lne/j;->d:I

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
    invoke-virtual {p0, p1, p2}, Lne/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lne/j;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lne/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lne/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lne/j;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lne/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lne/j;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    iget v2, v0, Lne/j;->e:I

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    iget-object v4, v0, Lne/j;->f:Lne/k;

    .line 14
    .line 15
    if-eqz v2, :cond_1

    .line 16
    .line 17
    if-ne v2, v3, :cond_0

    .line 18
    .line 19
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    move-object/from16 v0, p1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 26
    .line 27
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 28
    .line 29
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw v0

    .line 33
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    iget-object v2, v4, Lne/k;->e:La30/b;

    .line 37
    .line 38
    iput v3, v0, Lne/j;->e:I

    .line 39
    .line 40
    invoke-virtual {v2, v0}, La30/b;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    if-ne v0, v1, :cond_2

    .line 45
    .line 46
    goto/16 :goto_8

    .line 47
    .line 48
    :cond_2
    :goto_0
    check-cast v0, Llx0/o;

    .line 49
    .line 50
    iget-object v0, v0, Llx0/o;->d:Ljava/lang/Object;

    .line 51
    .line 52
    instance-of v1, v0, Llx0/n;

    .line 53
    .line 54
    if-nez v1, :cond_d

    .line 55
    .line 56
    move-object v1, v0

    .line 57
    check-cast v1, Lje/c1;

    .line 58
    .line 59
    iget-object v2, v4, Lne/k;->h:Lyy0/c2;

    .line 60
    .line 61
    iget-object v1, v1, Lje/c1;->a:Lje/w0;

    .line 62
    .line 63
    if-eqz v1, :cond_b

    .line 64
    .line 65
    iget-object v3, v1, Lje/w0;->b:Lje/i;

    .line 66
    .line 67
    instance-of v5, v3, Lje/h;

    .line 68
    .line 69
    if-eqz v5, :cond_9

    .line 70
    .line 71
    :goto_1
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v5

    .line 75
    move-object v7, v5

    .line 76
    check-cast v7, Lne/i;

    .line 77
    .line 78
    move-object v8, v3

    .line 79
    check-cast v8, Lje/h;

    .line 80
    .line 81
    iget-object v9, v1, Lje/w0;->a:Ljava/lang/String;

    .line 82
    .line 83
    const-string v10, "id"

    .line 84
    .line 85
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    new-instance v10, Lne/p;

    .line 89
    .line 90
    iget-object v11, v8, Lje/h;->e:Ljava/util/List;

    .line 91
    .line 92
    check-cast v11, Ljava/lang/Iterable;

    .line 93
    .line 94
    new-instance v12, Ljava/util/ArrayList;

    .line 95
    .line 96
    invoke-direct {v12}, Ljava/util/ArrayList;-><init>()V

    .line 97
    .line 98
    .line 99
    invoke-interface {v11}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 100
    .line 101
    .line 102
    move-result-object v11

    .line 103
    :goto_2
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    .line 104
    .line 105
    .line 106
    move-result v13

    .line 107
    if-eqz v13, :cond_7

    .line 108
    .line 109
    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v13

    .line 113
    check-cast v13, Lje/t0;

    .line 114
    .line 115
    iget-object v14, v13, Lje/t0;->a:Ljava/util/List;

    .line 116
    .line 117
    invoke-static {v14}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v15

    .line 121
    check-cast v15, Lje/n0;

    .line 122
    .line 123
    iget-object v15, v15, Lje/n0;->a:Lje/m0;

    .line 124
    .line 125
    invoke-static {v14}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v16

    .line 129
    move-object/from16 v6, v16

    .line 130
    .line 131
    check-cast v6, Lje/n0;

    .line 132
    .line 133
    iget-object v6, v6, Lje/n0;->a:Lje/m0;

    .line 134
    .line 135
    invoke-static {v14}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v14

    .line 139
    check-cast v14, Lje/n0;

    .line 140
    .line 141
    iget-object v14, v14, Lje/n0;->a:Lje/m0;

    .line 142
    .line 143
    if-eq v6, v14, :cond_3

    .line 144
    .line 145
    goto :goto_3

    .line 146
    :cond_3
    const/4 v6, 0x0

    .line 147
    :goto_3
    new-instance v14, Llx0/l;

    .line 148
    .line 149
    invoke-direct {v14, v15, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 150
    .line 151
    .line 152
    new-instance v6, Lne/m;

    .line 153
    .line 154
    invoke-direct {v6, v14}, Lne/m;-><init>(Llx0/l;)V

    .line 155
    .line 156
    .line 157
    iget-object v13, v13, Lje/t0;->b:Ljava/util/List;

    .line 158
    .line 159
    check-cast v13, Ljava/lang/Iterable;

    .line 160
    .line 161
    new-instance v14, Ljava/util/ArrayList;

    .line 162
    .line 163
    invoke-direct {v14}, Ljava/util/ArrayList;-><init>()V

    .line 164
    .line 165
    .line 166
    invoke-interface {v13}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 167
    .line 168
    .line 169
    move-result-object v13

    .line 170
    :goto_4
    invoke-interface {v13}, Ljava/util/Iterator;->hasNext()Z

    .line 171
    .line 172
    .line 173
    move-result v15

    .line 174
    if-eqz v15, :cond_6

    .line 175
    .line 176
    invoke-interface {v13}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object v15

    .line 180
    check-cast v15, Lje/c0;

    .line 181
    .line 182
    move-object/from16 v16, v0

    .line 183
    .line 184
    iget-object v0, v15, Lje/c0;->a:Ljava/util/List;

    .line 185
    .line 186
    invoke-static {v0}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object v17

    .line 190
    move-object/from16 p1, v0

    .line 191
    .line 192
    move-object/from16 v0, v17

    .line 193
    .line 194
    check-cast v0, Lje/z;

    .line 195
    .line 196
    iget-object v0, v0, Lje/z;->d:Lje/y;

    .line 197
    .line 198
    invoke-static/range {p1 .. p1}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v17

    .line 202
    move-object/from16 v18, v6

    .line 203
    .line 204
    move-object/from16 v6, v17

    .line 205
    .line 206
    check-cast v6, Lje/z;

    .line 207
    .line 208
    iget-object v6, v6, Lje/z;->d:Lje/y;

    .line 209
    .line 210
    invoke-static/range {p1 .. p1}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object v17

    .line 214
    move-object/from16 p1, v7

    .line 215
    .line 216
    move-object/from16 v7, v17

    .line 217
    .line 218
    check-cast v7, Lje/z;

    .line 219
    .line 220
    iget-object v7, v7, Lje/z;->d:Lje/y;

    .line 221
    .line 222
    if-eq v6, v7, :cond_4

    .line 223
    .line 224
    goto :goto_5

    .line 225
    :cond_4
    const/4 v6, 0x0

    .line 226
    :goto_5
    new-instance v7, Llx0/l;

    .line 227
    .line 228
    invoke-direct {v7, v0, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 229
    .line 230
    .line 231
    new-instance v0, Lne/l;

    .line 232
    .line 233
    invoke-direct {v0, v7}, Lne/l;-><init>(Llx0/l;)V

    .line 234
    .line 235
    .line 236
    iget-object v6, v15, Lje/c0;->b:Ljava/util/List;

    .line 237
    .line 238
    check-cast v6, Ljava/lang/Iterable;

    .line 239
    .line 240
    new-instance v7, Ljava/util/ArrayList;

    .line 241
    .line 242
    const/16 v15, 0xa

    .line 243
    .line 244
    invoke-static {v6, v15}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 245
    .line 246
    .line 247
    move-result v15

    .line 248
    invoke-direct {v7, v15}, Ljava/util/ArrayList;-><init>(I)V

    .line 249
    .line 250
    .line 251
    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 252
    .line 253
    .line 254
    move-result-object v6

    .line 255
    :goto_6
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 256
    .line 257
    .line 258
    move-result v15

    .line 259
    if-eqz v15, :cond_5

    .line 260
    .line 261
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 262
    .line 263
    .line 264
    move-result-object v15

    .line 265
    check-cast v15, Lje/i0;

    .line 266
    .line 267
    move-object/from16 v17, v0

    .line 268
    .line 269
    new-instance v0, Lne/n;

    .line 270
    .line 271
    move-object/from16 v19, v6

    .line 272
    .line 273
    new-instance v6, Llx0/l;

    .line 274
    .line 275
    move-object/from16 v20, v11

    .line 276
    .line 277
    iget-object v11, v15, Lje/i0;->b:Ljava/lang/String;

    .line 278
    .line 279
    move-object/from16 v21, v13

    .line 280
    .line 281
    iget-object v13, v15, Lje/i0;->c:Ljava/lang/String;

    .line 282
    .line 283
    invoke-direct {v6, v11, v13}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 284
    .line 285
    .line 286
    new-instance v11, Llx0/l;

    .line 287
    .line 288
    iget v13, v15, Lje/i0;->a:F

    .line 289
    .line 290
    invoke-static {v13}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 291
    .line 292
    .line 293
    move-result-object v13

    .line 294
    iget-object v15, v8, Lje/h;->b:Lje/r;

    .line 295
    .line 296
    invoke-direct {v11, v13, v15}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 297
    .line 298
    .line 299
    invoke-direct {v0, v6, v11}, Lne/n;-><init>(Llx0/l;Llx0/l;)V

    .line 300
    .line 301
    .line 302
    invoke-virtual {v7, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 303
    .line 304
    .line 305
    move-object/from16 v0, v17

    .line 306
    .line 307
    move-object/from16 v6, v19

    .line 308
    .line 309
    move-object/from16 v11, v20

    .line 310
    .line 311
    move-object/from16 v13, v21

    .line 312
    .line 313
    goto :goto_6

    .line 314
    :cond_5
    move-object/from16 v17, v0

    .line 315
    .line 316
    move-object/from16 v20, v11

    .line 317
    .line 318
    move-object/from16 v21, v13

    .line 319
    .line 320
    invoke-static/range {v17 .. v17}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 321
    .line 322
    .line 323
    move-result-object v0

    .line 324
    check-cast v0, Ljava/util/Collection;

    .line 325
    .line 326
    invoke-static {v7, v0}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 327
    .line 328
    .line 329
    move-result-object v0

    .line 330
    invoke-static {v0, v14}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 331
    .line 332
    .line 333
    move-object/from16 v7, p1

    .line 334
    .line 335
    move-object/from16 v0, v16

    .line 336
    .line 337
    move-object/from16 v6, v18

    .line 338
    .line 339
    goto/16 :goto_4

    .line 340
    .line 341
    :cond_6
    move-object/from16 v16, v0

    .line 342
    .line 343
    move-object/from16 v18, v6

    .line 344
    .line 345
    move-object/from16 p1, v7

    .line 346
    .line 347
    move-object/from16 v20, v11

    .line 348
    .line 349
    invoke-static/range {v18 .. v18}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 350
    .line 351
    .line 352
    move-result-object v0

    .line 353
    check-cast v0, Ljava/util/Collection;

    .line 354
    .line 355
    invoke-static {v14, v0}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 356
    .line 357
    .line 358
    move-result-object v0

    .line 359
    invoke-static {v0, v12}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 360
    .line 361
    .line 362
    move-object/from16 v0, v16

    .line 363
    .line 364
    goto/16 :goto_2

    .line 365
    .line 366
    :cond_7
    move-object/from16 v16, v0

    .line 367
    .line 368
    move-object/from16 p1, v7

    .line 369
    .line 370
    invoke-direct {v10, v9, v12}, Lne/p;-><init>(Ljava/lang/String;Ljava/util/ArrayList;)V

    .line 371
    .line 372
    .line 373
    const/4 v11, 0x0

    .line 374
    const/4 v12, 0x4

    .line 375
    const/4 v9, 0x0

    .line 376
    move-object v8, v10

    .line 377
    const/4 v10, 0x0

    .line 378
    invoke-static/range {v7 .. v12}, Lne/i;->a(Lne/i;Ljp/na;ZZLlc/l;I)Lne/i;

    .line 379
    .line 380
    .line 381
    move-result-object v0

    .line 382
    invoke-virtual {v2, v5, v0}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 383
    .line 384
    .line 385
    move-result v0

    .line 386
    if-eqz v0, :cond_8

    .line 387
    .line 388
    goto :goto_7

    .line 389
    :cond_8
    move-object/from16 v0, v16

    .line 390
    .line 391
    goto/16 :goto_1

    .line 392
    .line 393
    :cond_9
    move-object/from16 v16, v0

    .line 394
    .line 395
    instance-of v0, v3, Lje/d;

    .line 396
    .line 397
    if-eqz v0, :cond_a

    .line 398
    .line 399
    invoke-static {v4}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 400
    .line 401
    .line 402
    move-result-object v0

    .line 403
    new-instance v2, Lna/e;

    .line 404
    .line 405
    const/4 v3, 0x4

    .line 406
    const/4 v5, 0x0

    .line 407
    invoke-direct {v2, v3, v4, v1, v5}, Lna/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 408
    .line 409
    .line 410
    const/4 v1, 0x3

    .line 411
    invoke-static {v0, v5, v5, v2, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 412
    .line 413
    .line 414
    goto :goto_7

    .line 415
    :cond_a
    new-instance v0, La8/r0;

    .line 416
    .line 417
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 418
    .line 419
    .line 420
    throw v0

    .line 421
    :cond_b
    move-object/from16 v16, v0

    .line 422
    .line 423
    :cond_c
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 424
    .line 425
    .line 426
    move-result-object v0

    .line 427
    move-object v5, v0

    .line 428
    check-cast v5, Lne/i;

    .line 429
    .line 430
    const/4 v9, 0x0

    .line 431
    const/16 v10, 0xd

    .line 432
    .line 433
    const/4 v6, 0x0

    .line 434
    const/4 v7, 0x0

    .line 435
    const/4 v8, 0x0

    .line 436
    invoke-static/range {v5 .. v10}, Lne/i;->a(Lne/i;Ljp/na;ZZLlc/l;I)Lne/i;

    .line 437
    .line 438
    .line 439
    move-result-object v1

    .line 440
    invoke-virtual {v2, v0, v1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 441
    .line 442
    .line 443
    move-result v0

    .line 444
    if-eqz v0, :cond_c

    .line 445
    .line 446
    iget-object v0, v4, Lne/k;->d:Lay0/a;

    .line 447
    .line 448
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 449
    .line 450
    .line 451
    goto :goto_7

    .line 452
    :cond_d
    move-object/from16 v16, v0

    .line 453
    .line 454
    :goto_7
    invoke-static/range {v16 .. v16}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 455
    .line 456
    .line 457
    move-result-object v0

    .line 458
    if-eqz v0, :cond_e

    .line 459
    .line 460
    invoke-static {v4, v0}, Lne/k;->a(Lne/k;Ljava/lang/Throwable;)V

    .line 461
    .line 462
    .line 463
    :cond_e
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 464
    .line 465
    :goto_8
    return-object v1

    .line 466
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 467
    .line 468
    iget v2, v0, Lne/j;->e:I

    .line 469
    .line 470
    const/4 v3, 0x1

    .line 471
    iget-object v4, v0, Lne/j;->f:Lne/k;

    .line 472
    .line 473
    if-eqz v2, :cond_10

    .line 474
    .line 475
    if-ne v2, v3, :cond_f

    .line 476
    .line 477
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 478
    .line 479
    .line 480
    move-object/from16 v0, p1

    .line 481
    .line 482
    goto :goto_9

    .line 483
    :cond_f
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 484
    .line 485
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 486
    .line 487
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 488
    .line 489
    .line 490
    throw v0

    .line 491
    :cond_10
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 492
    .line 493
    .line 494
    iget-object v2, v4, Lne/k;->g:Lne/b;

    .line 495
    .line 496
    new-instance v5, Lje/f0;

    .line 497
    .line 498
    iget-object v6, v4, Lne/k;->i:Lyy0/l1;

    .line 499
    .line 500
    iget-object v6, v6, Lyy0/l1;->d:Lyy0/a2;

    .line 501
    .line 502
    invoke-interface {v6}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 503
    .line 504
    .line 505
    move-result-object v6

    .line 506
    check-cast v6, Lne/i;

    .line 507
    .line 508
    iget-object v6, v6, Lne/i;->a:Ljp/na;

    .line 509
    .line 510
    if-eqz v6, :cond_11

    .line 511
    .line 512
    invoke-virtual {v6}, Ljp/na;->a()Ljava/lang/String;

    .line 513
    .line 514
    .line 515
    move-result-object v6

    .line 516
    if-nez v6, :cond_12

    .line 517
    .line 518
    :cond_11
    const-string v6, ""

    .line 519
    .line 520
    :cond_12
    invoke-direct {v5, v6}, Lje/f0;-><init>(Ljava/lang/String;)V

    .line 521
    .line 522
    .line 523
    iput v3, v0, Lne/j;->e:I

    .line 524
    .line 525
    invoke-virtual {v2, v5, v0}, Lne/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 526
    .line 527
    .line 528
    move-result-object v0

    .line 529
    if-ne v0, v1, :cond_13

    .line 530
    .line 531
    goto :goto_a

    .line 532
    :cond_13
    :goto_9
    check-cast v0, Llx0/o;

    .line 533
    .line 534
    iget-object v0, v0, Llx0/o;->d:Ljava/lang/Object;

    .line 535
    .line 536
    instance-of v1, v0, Llx0/n;

    .line 537
    .line 538
    if-nez v1, :cond_15

    .line 539
    .line 540
    move-object v1, v0

    .line 541
    check-cast v1, Llx0/b0;

    .line 542
    .line 543
    iget-object v1, v4, Lne/k;->h:Lyy0/c2;

    .line 544
    .line 545
    :cond_14
    invoke-virtual {v1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 546
    .line 547
    .line 548
    move-result-object v2

    .line 549
    move-object v5, v2

    .line 550
    check-cast v5, Lne/i;

    .line 551
    .line 552
    const/4 v9, 0x0

    .line 553
    const/16 v10, 0xb

    .line 554
    .line 555
    const/4 v6, 0x0

    .line 556
    const/4 v7, 0x0

    .line 557
    const/4 v8, 0x0

    .line 558
    invoke-static/range {v5 .. v10}, Lne/i;->a(Lne/i;Ljp/na;ZZLlc/l;I)Lne/i;

    .line 559
    .line 560
    .line 561
    move-result-object v3

    .line 562
    invoke-virtual {v1, v2, v3}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 563
    .line 564
    .line 565
    move-result v2

    .line 566
    if-eqz v2, :cond_14

    .line 567
    .line 568
    iget-object v1, v4, Lne/k;->d:Lay0/a;

    .line 569
    .line 570
    invoke-interface {v1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 571
    .line 572
    .line 573
    :cond_15
    invoke-static {v0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 574
    .line 575
    .line 576
    move-result-object v0

    .line 577
    if-eqz v0, :cond_16

    .line 578
    .line 579
    invoke-static {v4, v0}, Lne/k;->a(Lne/k;Ljava/lang/Throwable;)V

    .line 580
    .line 581
    .line 582
    :cond_16
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 583
    .line 584
    :goto_a
    return-object v1

    .line 585
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
