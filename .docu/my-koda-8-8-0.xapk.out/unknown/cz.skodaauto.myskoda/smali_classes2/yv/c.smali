.class public final Lyv/c;
.super Lrx0/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;

.field public g:Lkotlin/jvm/internal/f0;

.field public h:J

.field public i:I

.field public synthetic j:Ljava/lang/Object;

.field public final synthetic k:Lay0/k;

.field public final synthetic l:Lg1/z1;

.field public final synthetic m:Lay0/o;

.field public final synthetic n:Lvy0/b0;

.field public final synthetic o:Lb1/e;


# direct methods
.method public constructor <init>(Lay0/k;Lg1/z1;Lay0/o;Lvy0/b0;Lb1/e;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lyv/c;->k:Lay0/k;

    .line 2
    .line 3
    iput-object p2, p0, Lyv/c;->l:Lg1/z1;

    .line 4
    .line 5
    iput-object p3, p0, Lyv/c;->m:Lay0/o;

    .line 6
    .line 7
    iput-object p4, p0, Lyv/c;->n:Lvy0/b0;

    .line 8
    .line 9
    iput-object p5, p0, Lyv/c;->o:Lb1/e;

    .line 10
    .line 11
    const/4 p1, 0x2

    .line 12
    invoke-direct {p0, p1, p6}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 7

    .line 1
    new-instance v0, Lyv/c;

    .line 2
    .line 3
    iget-object v4, p0, Lyv/c;->n:Lvy0/b0;

    .line 4
    .line 5
    iget-object v5, p0, Lyv/c;->o:Lb1/e;

    .line 6
    .line 7
    iget-object v1, p0, Lyv/c;->k:Lay0/k;

    .line 8
    .line 9
    iget-object v2, p0, Lyv/c;->l:Lg1/z1;

    .line 10
    .line 11
    iget-object v3, p0, Lyv/c;->m:Lay0/o;

    .line 12
    .line 13
    move-object v6, p2

    .line 14
    invoke-direct/range {v0 .. v6}, Lyv/c;-><init>(Lay0/k;Lg1/z1;Lay0/o;Lvy0/b0;Lb1/e;Lkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    iput-object p1, v0, Lyv/c;->j:Ljava/lang/Object;

    .line 18
    .line 19
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lp3/i0;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lyv/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lyv/c;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lyv/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v4, v0, Lyv/c;->o:Lb1/e;

    .line 4
    .line 5
    iget-object v1, v4, Lb1/e;->h:Ljava/lang/Object;

    .line 6
    .line 7
    move-object v7, v1

    .line 8
    check-cast v7, Lkotlin/jvm/internal/n;

    .line 9
    .line 10
    iget-object v1, v4, Lb1/e;->g:Ljava/lang/Object;

    .line 11
    .line 12
    move-object v8, v1

    .line 13
    check-cast v8, Ll2/b1;

    .line 14
    .line 15
    iget-object v11, v0, Lyv/c;->l:Lg1/z1;

    .line 16
    .line 17
    iget-object v15, v11, Lg1/z1;->h:Lez0/c;

    .line 18
    .line 19
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 20
    .line 21
    iget v2, v0, Lyv/c;->i:I

    .line 22
    .line 23
    iget-object v3, v0, Lyv/c;->n:Lvy0/b0;

    .line 24
    .line 25
    const/4 v5, 0x0

    .line 26
    const/4 v6, 0x3

    .line 27
    const/4 v9, 0x1

    .line 28
    iget-object v10, v0, Lyv/c;->m:Lay0/o;

    .line 29
    .line 30
    sget-object v16, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    const/4 v13, 0x0

    .line 33
    packed-switch v2, :pswitch_data_0

    .line 34
    .line 35
    .line 36
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 37
    .line 38
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 39
    .line 40
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw v0

    .line 44
    :pswitch_0
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    move v1, v9

    .line 48
    move-object v3, v11

    .line 49
    goto/16 :goto_6

    .line 50
    .line 51
    :pswitch_1
    iget-object v2, v0, Lyv/c;->f:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast v2, Lp3/t;

    .line 54
    .line 55
    iget-object v2, v0, Lyv/c;->e:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast v2, Lkotlin/jvm/internal/f0;

    .line 58
    .line 59
    iget-object v3, v0, Lyv/c;->j:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast v3, Lp3/i0;

    .line 62
    .line 63
    :try_start_0
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Lp3/n; {:try_start_0 .. :try_end_0} :catch_0

    .line 64
    .line 65
    .line 66
    return-object v16

    .line 67
    :catch_0
    move-object v9, v1

    .line 68
    move-object v14, v3

    .line 69
    move-object v3, v11

    .line 70
    goto/16 :goto_5

    .line 71
    .line 72
    :pswitch_2
    move-object/from16 v17, v3

    .line 73
    .line 74
    iget-wide v2, v0, Lyv/c;->h:J

    .line 75
    .line 76
    iget-object v12, v0, Lyv/c;->e:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast v12, Lkotlin/jvm/internal/f0;

    .line 79
    .line 80
    iget-object v14, v0, Lyv/c;->j:Ljava/lang/Object;

    .line 81
    .line 82
    check-cast v14, Lp3/i0;

    .line 83
    .line 84
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    move-object/from16 v18, p1

    .line 88
    .line 89
    check-cast v18, Lp3/t;

    .line 90
    .line 91
    if-nez v18, :cond_1

    .line 92
    .line 93
    iget-object v0, v12, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast v0, Lp3/t;

    .line 96
    .line 97
    iget-wide v0, v0, Lp3/t;->c:J

    .line 98
    .line 99
    invoke-interface {v8}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v2

    .line 103
    check-cast v2, Lg4/l0;

    .line 104
    .line 105
    if-eqz v2, :cond_0

    .line 106
    .line 107
    iget-object v2, v2, Lg4/l0;->b:Lg4/o;

    .line 108
    .line 109
    invoke-virtual {v2, v0, v1}, Lg4/o;->g(J)I

    .line 110
    .line 111
    .line 112
    move-result v0

    .line 113
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 114
    .line 115
    .line 116
    move-result-object v0

    .line 117
    invoke-interface {v7, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    :cond_0
    return-object v16

    .line 121
    :cond_1
    invoke-virtual {v15}, Lez0/c;->tryLock()Z

    .line 122
    .line 123
    .line 124
    iput-boolean v5, v11, Lg1/z1;->f:Z

    .line 125
    .line 126
    iput-boolean v5, v11, Lg1/z1;->g:Z

    .line 127
    .line 128
    sget-object v5, Lyv/e;->a:Lg1/e1;

    .line 129
    .line 130
    if-eq v10, v5, :cond_2

    .line 131
    .line 132
    move v5, v9

    .line 133
    new-instance v9, Lyv/b;

    .line 134
    .line 135
    move-object/from16 v19, v14

    .line 136
    .line 137
    const/4 v14, 0x1

    .line 138
    move-object v5, v12

    .line 139
    move-object/from16 v12, v18

    .line 140
    .line 141
    move-object/from16 v20, v19

    .line 142
    .line 143
    invoke-direct/range {v9 .. v14}, Lyv/b;-><init>(Lay0/o;Lg1/z1;Lp3/t;Lkotlin/coroutines/Continuation;I)V

    .line 144
    .line 145
    .line 146
    move-object/from16 v10, v17

    .line 147
    .line 148
    invoke-static {v10, v13, v13, v9, v6}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 149
    .line 150
    .line 151
    :goto_0
    move-object v6, v1

    .line 152
    goto :goto_1

    .line 153
    :cond_2
    move-object v5, v12

    .line 154
    move-object/from16 v20, v14

    .line 155
    .line 156
    move-object/from16 v12, v18

    .line 157
    .line 158
    goto :goto_0

    .line 159
    :goto_1
    :try_start_1
    new-instance v1, Lb2/a;
    :try_end_1
    .catch Lp3/n; {:try_start_1 .. :try_end_1} :catch_3

    .line 160
    .line 161
    move-wide v9, v2

    .line 162
    const/4 v2, 0x6

    .line 163
    move-object v3, v11

    .line 164
    move-wide v10, v9

    .line 165
    move-object v9, v6

    .line 166
    move-object v6, v13

    .line 167
    :try_start_2
    invoke-direct/range {v1 .. v6}, Lb2/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V
    :try_end_2
    .catch Lp3/n; {:try_start_2 .. :try_end_2} :catch_2

    .line 168
    .line 169
    .line 170
    move-object/from16 v14, v20

    .line 171
    .line 172
    :try_start_3
    iput-object v14, v0, Lyv/c;->j:Ljava/lang/Object;

    .line 173
    .line 174
    iput-object v5, v0, Lyv/c;->e:Ljava/lang/Object;

    .line 175
    .line 176
    iput-object v12, v0, Lyv/c;->f:Ljava/lang/Object;

    .line 177
    .line 178
    const/4 v2, 0x5

    .line 179
    iput v2, v0, Lyv/c;->i:I

    .line 180
    .line 181
    invoke-virtual {v14, v10, v11, v1, v0}, Lp3/i0;->g(JLay0/n;Lrx0/a;)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object v0
    :try_end_3
    .catch Lp3/n; {:try_start_3 .. :try_end_3} :catch_1

    .line 185
    if-ne v0, v9, :cond_b

    .line 186
    .line 187
    :goto_2
    move-object v5, v9

    .line 188
    goto/16 :goto_b

    .line 189
    .line 190
    :catch_1
    :goto_3
    move-object v2, v5

    .line 191
    goto :goto_5

    .line 192
    :catch_2
    move-object v13, v6

    .line 193
    :goto_4
    move-object/from16 v14, v20

    .line 194
    .line 195
    goto :goto_3

    .line 196
    :catch_3
    move-object v9, v6

    .line 197
    move-object v3, v11

    .line 198
    goto :goto_4

    .line 199
    :goto_5
    iget-object v1, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 200
    .line 201
    check-cast v1, Lp3/t;

    .line 202
    .line 203
    iget-wide v1, v1, Lp3/t;->c:J

    .line 204
    .line 205
    invoke-interface {v8}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v4

    .line 209
    check-cast v4, Lg4/l0;

    .line 210
    .line 211
    if-eqz v4, :cond_3

    .line 212
    .line 213
    iget-object v4, v4, Lg4/l0;->b:Lg4/o;

    .line 214
    .line 215
    invoke-virtual {v4, v1, v2}, Lg4/o;->g(J)I

    .line 216
    .line 217
    .line 218
    move-result v1

    .line 219
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 220
    .line 221
    .line 222
    move-result-object v1

    .line 223
    invoke-interface {v7, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    :cond_3
    iput-object v13, v0, Lyv/c;->j:Ljava/lang/Object;

    .line 227
    .line 228
    iput-object v13, v0, Lyv/c;->e:Ljava/lang/Object;

    .line 229
    .line 230
    iput-object v13, v0, Lyv/c;->f:Ljava/lang/Object;

    .line 231
    .line 232
    const/4 v1, 0x6

    .line 233
    iput v1, v0, Lyv/c;->i:I

    .line 234
    .line 235
    invoke-static {v14, v0}, Lyv/e;->a(Lp3/i0;Lrx0/a;)Ljava/lang/Object;

    .line 236
    .line 237
    .line 238
    move-result-object v0

    .line 239
    if-ne v0, v9, :cond_4

    .line 240
    .line 241
    goto :goto_2

    .line 242
    :cond_4
    const/4 v1, 0x1

    .line 243
    :goto_6
    iput-boolean v1, v3, Lg1/z1;->f:Z

    .line 244
    .line 245
    invoke-virtual {v15, v13}, Lez0/c;->d(Ljava/lang/Object;)V

    .line 246
    .line 247
    .line 248
    goto/16 :goto_e

    .line 249
    .line 250
    :pswitch_3
    move v1, v9

    .line 251
    move-object v3, v11

    .line 252
    iget-object v2, v0, Lyv/c;->e:Ljava/lang/Object;

    .line 253
    .line 254
    check-cast v2, Lkotlin/jvm/internal/f0;

    .line 255
    .line 256
    iget-object v0, v0, Lyv/c;->j:Ljava/lang/Object;

    .line 257
    .line 258
    check-cast v0, Lp3/i0;

    .line 259
    .line 260
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 261
    .line 262
    .line 263
    goto/16 :goto_c

    .line 264
    .line 265
    :pswitch_4
    move v3, v9

    .line 266
    move-object v9, v1

    .line 267
    move v1, v3

    .line 268
    move-object v3, v11

    .line 269
    iget-wide v4, v0, Lyv/c;->h:J

    .line 270
    .line 271
    iget-object v2, v0, Lyv/c;->g:Lkotlin/jvm/internal/f0;

    .line 272
    .line 273
    iget-object v10, v0, Lyv/c;->f:Ljava/lang/Object;

    .line 274
    .line 275
    check-cast v10, Lkotlin/jvm/internal/f0;

    .line 276
    .line 277
    iget-object v11, v0, Lyv/c;->e:Ljava/lang/Object;

    .line 278
    .line 279
    check-cast v11, Lp3/t;

    .line 280
    .line 281
    iget-object v11, v0, Lyv/c;->j:Ljava/lang/Object;

    .line 282
    .line 283
    check-cast v11, Lp3/i0;

    .line 284
    .line 285
    :try_start_4
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_4
    .catch Lp3/n; {:try_start_4 .. :try_end_4} :catch_4

    .line 286
    .line 287
    .line 288
    move-object v6, v11

    .line 289
    move-object v11, v3

    .line 290
    move-object/from16 v3, p1

    .line 291
    .line 292
    move-wide/from16 v21, v4

    .line 293
    .line 294
    move-object v5, v9

    .line 295
    move-object v4, v10

    .line 296
    move-wide/from16 v9, v21

    .line 297
    .line 298
    goto/16 :goto_9

    .line 299
    .line 300
    :catch_4
    move-object v2, v10

    .line 301
    move-object/from16 v21, v11

    .line 302
    .line 303
    move-object v11, v3

    .line 304
    move-wide/from16 v22, v4

    .line 305
    .line 306
    move-object v5, v9

    .line 307
    move-wide/from16 v9, v22

    .line 308
    .line 309
    move-object/from16 v4, v21

    .line 310
    .line 311
    goto/16 :goto_a

    .line 312
    .line 313
    :pswitch_5
    move v2, v9

    .line 314
    move-object v9, v1

    .line 315
    move v1, v2

    .line 316
    move-object v2, v10

    .line 317
    move-object v10, v3

    .line 318
    move-object v3, v11

    .line 319
    iget-object v4, v0, Lyv/c;->j:Ljava/lang/Object;

    .line 320
    .line 321
    check-cast v4, Lp3/i0;

    .line 322
    .line 323
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 324
    .line 325
    .line 326
    move-object/from16 v11, p1

    .line 327
    .line 328
    goto :goto_7

    .line 329
    :pswitch_6
    move v2, v9

    .line 330
    move-object v9, v1

    .line 331
    move v1, v2

    .line 332
    move-object v2, v10

    .line 333
    move-object v10, v3

    .line 334
    move-object v3, v11

    .line 335
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 336
    .line 337
    .line 338
    iget-object v4, v0, Lyv/c;->j:Ljava/lang/Object;

    .line 339
    .line 340
    check-cast v4, Lp3/i0;

    .line 341
    .line 342
    iput-object v4, v0, Lyv/c;->j:Ljava/lang/Object;

    .line 343
    .line 344
    iput v1, v0, Lyv/c;->i:I

    .line 345
    .line 346
    invoke-static {v4, v0, v6}, Lg1/g3;->c(Lp3/i0;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 347
    .line 348
    .line 349
    move-result-object v11

    .line 350
    if-ne v11, v9, :cond_5

    .line 351
    .line 352
    goto/16 :goto_2

    .line 353
    .line 354
    :cond_5
    :goto_7
    move-object v12, v11

    .line 355
    check-cast v12, Lp3/t;

    .line 356
    .line 357
    iget-wide v13, v12, Lp3/t;->c:J

    .line 358
    .line 359
    new-instance v11, Ld3/b;

    .line 360
    .line 361
    invoke-direct {v11, v13, v14}, Ld3/b;-><init>(J)V

    .line 362
    .line 363
    .line 364
    iget-object v13, v0, Lyv/c;->k:Lay0/k;

    .line 365
    .line 366
    invoke-interface {v13, v11}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 367
    .line 368
    .line 369
    move-result-object v11

    .line 370
    check-cast v11, Ljava/lang/Boolean;

    .line 371
    .line 372
    invoke-virtual {v11}, Ljava/lang/Boolean;->booleanValue()Z

    .line 373
    .line 374
    .line 375
    move-result v11

    .line 376
    if-nez v11, :cond_6

    .line 377
    .line 378
    invoke-virtual {v15}, Lez0/c;->tryLock()Z

    .line 379
    .line 380
    .line 381
    iput-boolean v5, v3, Lg1/z1;->f:Z

    .line 382
    .line 383
    iput-boolean v5, v3, Lg1/z1;->g:Z

    .line 384
    .line 385
    return-object v16

    .line 386
    :cond_6
    invoke-virtual {v12}, Lp3/t;->a()V

    .line 387
    .line 388
    .line 389
    invoke-virtual {v15}, Lez0/c;->tryLock()Z

    .line 390
    .line 391
    .line 392
    iput-boolean v5, v3, Lg1/z1;->f:Z

    .line 393
    .line 394
    iput-boolean v5, v3, Lg1/z1;->g:Z

    .line 395
    .line 396
    sget-object v5, Lyv/e;->a:Lg1/e1;

    .line 397
    .line 398
    if-eq v2, v5, :cond_7

    .line 399
    .line 400
    move-object v5, v9

    .line 401
    new-instance v9, Lyv/b;

    .line 402
    .line 403
    const/4 v14, 0x0

    .line 404
    move-object v11, v10

    .line 405
    move-object v10, v2

    .line 406
    move-object v2, v11

    .line 407
    move-object v11, v3

    .line 408
    const/4 v13, 0x0

    .line 409
    invoke-direct/range {v9 .. v14}, Lyv/b;-><init>(Lay0/o;Lg1/z1;Lp3/t;Lkotlin/coroutines/Continuation;I)V

    .line 410
    .line 411
    .line 412
    invoke-static {v2, v13, v13, v9, v6}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 413
    .line 414
    .line 415
    goto :goto_8

    .line 416
    :cond_7
    move-object v11, v3

    .line 417
    move-object v5, v9

    .line 418
    const/4 v13, 0x0

    .line 419
    :goto_8
    new-instance v2, Lkotlin/jvm/internal/f0;

    .line 420
    .line 421
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 422
    .line 423
    .line 424
    const-wide v9, 0x3fffffffffffffffL    # 1.9999999999999998

    .line 425
    .line 426
    .line 427
    .line 428
    .line 429
    :try_start_5
    new-instance v3, Llc/m;

    .line 430
    .line 431
    const/4 v14, 0x1

    .line 432
    const/4 v6, 0x2

    .line 433
    invoke-direct {v3, v6, v13, v14}, Llc/m;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 434
    .line 435
    .line 436
    iput-object v4, v0, Lyv/c;->j:Ljava/lang/Object;

    .line 437
    .line 438
    iput-object v12, v0, Lyv/c;->e:Ljava/lang/Object;

    .line 439
    .line 440
    iput-object v2, v0, Lyv/c;->f:Ljava/lang/Object;

    .line 441
    .line 442
    iput-object v2, v0, Lyv/c;->g:Lkotlin/jvm/internal/f0;

    .line 443
    .line 444
    iput-wide v9, v0, Lyv/c;->h:J

    .line 445
    .line 446
    iput v6, v0, Lyv/c;->i:I

    .line 447
    .line 448
    invoke-virtual {v4, v9, v10, v3, v0}, Lp3/i0;->g(JLay0/n;Lrx0/a;)Ljava/lang/Object;

    .line 449
    .line 450
    .line 451
    move-result-object v3
    :try_end_5
    .catch Lp3/n; {:try_start_5 .. :try_end_5} :catch_6

    .line 452
    if-ne v3, v5, :cond_8

    .line 453
    .line 454
    goto :goto_b

    .line 455
    :cond_8
    move-object v6, v4

    .line 456
    move-object v4, v2

    .line 457
    :goto_9
    :try_start_6
    iput-object v3, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 458
    .line 459
    iget-object v2, v4, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 460
    .line 461
    if-nez v2, :cond_9

    .line 462
    .line 463
    iput-boolean v1, v11, Lg1/z1;->g:Z

    .line 464
    .line 465
    invoke-virtual {v15, v13}, Lez0/c;->d(Ljava/lang/Object;)V

    .line 466
    .line 467
    .line 468
    goto :goto_d

    .line 469
    :catch_5
    move-object v2, v4

    .line 470
    move-object v4, v6

    .line 471
    goto :goto_a

    .line 472
    :cond_9
    check-cast v2, Lp3/t;

    .line 473
    .line 474
    invoke-virtual {v2}, Lp3/t;->a()V

    .line 475
    .line 476
    .line 477
    iput-boolean v1, v11, Lg1/z1;->f:Z

    .line 478
    .line 479
    invoke-virtual {v15, v13}, Lez0/c;->d(Ljava/lang/Object;)V
    :try_end_6
    .catch Lp3/n; {:try_start_6 .. :try_end_6} :catch_5

    .line 480
    .line 481
    .line 482
    goto :goto_d

    .line 483
    :catch_6
    :goto_a
    iput-object v4, v0, Lyv/c;->j:Ljava/lang/Object;

    .line 484
    .line 485
    iput-object v2, v0, Lyv/c;->e:Ljava/lang/Object;

    .line 486
    .line 487
    iput-object v13, v0, Lyv/c;->f:Ljava/lang/Object;

    .line 488
    .line 489
    iput-object v13, v0, Lyv/c;->g:Lkotlin/jvm/internal/f0;

    .line 490
    .line 491
    iput-wide v9, v0, Lyv/c;->h:J

    .line 492
    .line 493
    const/4 v3, 0x3

    .line 494
    iput v3, v0, Lyv/c;->i:I

    .line 495
    .line 496
    invoke-static {v4, v0}, Lyv/e;->a(Lp3/i0;Lrx0/a;)Ljava/lang/Object;

    .line 497
    .line 498
    .line 499
    move-result-object v0

    .line 500
    if-ne v0, v5, :cond_a

    .line 501
    .line 502
    :goto_b
    return-object v5

    .line 503
    :cond_a
    :goto_c
    iput-boolean v1, v11, Lg1/z1;->f:Z

    .line 504
    .line 505
    invoke-virtual {v15, v13}, Lez0/c;->d(Ljava/lang/Object;)V

    .line 506
    .line 507
    .line 508
    move-object v4, v2

    .line 509
    :goto_d
    iget-object v0, v4, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 510
    .line 511
    if-eqz v0, :cond_b

    .line 512
    .line 513
    check-cast v0, Lp3/t;

    .line 514
    .line 515
    iget-wide v0, v0, Lp3/t;->c:J

    .line 516
    .line 517
    invoke-interface {v8}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 518
    .line 519
    .line 520
    move-result-object v2

    .line 521
    check-cast v2, Lg4/l0;

    .line 522
    .line 523
    if-eqz v2, :cond_b

    .line 524
    .line 525
    iget-object v2, v2, Lg4/l0;->b:Lg4/o;

    .line 526
    .line 527
    invoke-virtual {v2, v0, v1}, Lg4/o;->g(J)I

    .line 528
    .line 529
    .line 530
    move-result v0

    .line 531
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 532
    .line 533
    .line 534
    move-result-object v0

    .line 535
    invoke-interface {v7, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 536
    .line 537
    .line 538
    :cond_b
    :goto_e
    return-object v16

    .line 539
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
