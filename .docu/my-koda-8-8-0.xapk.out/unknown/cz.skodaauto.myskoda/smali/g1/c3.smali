.class public final Lg1/c3;
.super Lrx0/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;

.field public g:Lp3/t;

.field public h:I

.field public synthetic i:Ljava/lang/Object;

.field public final synthetic j:Lvy0/b0;

.field public final synthetic k:Lay0/o;

.field public final synthetic l:Lay0/k;

.field public final synthetic m:Lay0/k;

.field public final synthetic n:Lay0/k;

.field public final synthetic o:Lg1/z1;


# direct methods
.method public constructor <init>(Lvy0/b0;Lay0/o;Lay0/k;Lay0/k;Lay0/k;Lg1/z1;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lg1/c3;->j:Lvy0/b0;

    .line 2
    .line 3
    iput-object p2, p0, Lg1/c3;->k:Lay0/o;

    .line 4
    .line 5
    iput-object p3, p0, Lg1/c3;->l:Lay0/k;

    .line 6
    .line 7
    iput-object p4, p0, Lg1/c3;->m:Lay0/k;

    .line 8
    .line 9
    iput-object p5, p0, Lg1/c3;->n:Lay0/k;

    .line 10
    .line 11
    iput-object p6, p0, Lg1/c3;->o:Lg1/z1;

    .line 12
    .line 13
    const/4 p1, 0x2

    .line 14
    invoke-direct {p0, p1, p7}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 8

    .line 1
    new-instance v0, Lg1/c3;

    .line 2
    .line 3
    iget-object v5, p0, Lg1/c3;->n:Lay0/k;

    .line 4
    .line 5
    iget-object v6, p0, Lg1/c3;->o:Lg1/z1;

    .line 6
    .line 7
    iget-object v1, p0, Lg1/c3;->j:Lvy0/b0;

    .line 8
    .line 9
    iget-object v2, p0, Lg1/c3;->k:Lay0/o;

    .line 10
    .line 11
    iget-object v3, p0, Lg1/c3;->l:Lay0/k;

    .line 12
    .line 13
    iget-object v4, p0, Lg1/c3;->m:Lay0/k;

    .line 14
    .line 15
    move-object v7, p2

    .line 16
    invoke-direct/range {v0 .. v7}, Lg1/c3;-><init>(Lvy0/b0;Lay0/o;Lay0/k;Lay0/k;Lay0/k;Lg1/z1;Lkotlin/coroutines/Continuation;)V

    .line 17
    .line 18
    .line 19
    iput-object p1, v0, Lg1/c3;->i:Ljava/lang/Object;

    .line 20
    .line 21
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
    invoke-virtual {p0, p1, p2}, Lg1/c3;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lg1/c3;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lg1/c3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 4
    .line 5
    iget v2, v0, Lg1/c3;->h:I

    .line 6
    .line 7
    const/4 v7, 0x2

    .line 8
    const/4 v8, 0x3

    .line 9
    iget-object v9, v0, Lg1/c3;->j:Lvy0/b0;

    .line 10
    .line 11
    iget-object v10, v0, Lg1/c3;->m:Lay0/k;

    .line 12
    .line 13
    sget-object v11, Lg1/o1;->a:Lg1/o1;

    .line 14
    .line 15
    iget-object v13, v0, Lg1/c3;->k:Lay0/o;

    .line 16
    .line 17
    iget-object v12, v0, Lg1/c3;->n:Lay0/k;

    .line 18
    .line 19
    sget-object v18, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    iget-object v14, v0, Lg1/c3;->l:Lay0/k;

    .line 22
    .line 23
    const/4 v15, 0x1

    .line 24
    move-object/from16 v16, v14

    .line 25
    .line 26
    iget-object v14, v0, Lg1/c3;->o:Lg1/z1;

    .line 27
    .line 28
    const/4 v3, 0x0

    .line 29
    packed-switch v2, :pswitch_data_0

    .line 30
    .line 31
    .line 32
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 33
    .line 34
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 35
    .line 36
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    throw v0

    .line 40
    :pswitch_0
    iget-object v0, v0, Lg1/c3;->i:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v0, Lvy0/i1;

    .line 43
    .line 44
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    move-object v12, v3

    .line 48
    goto/16 :goto_c

    .line 49
    .line 50
    :pswitch_1
    iget-object v2, v0, Lg1/c3;->g:Lp3/t;

    .line 51
    .line 52
    iget-object v6, v0, Lg1/c3;->f:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v6, Lp3/t;

    .line 55
    .line 56
    iget-object v7, v0, Lg1/c3;->e:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast v7, Lvy0/i1;

    .line 59
    .line 60
    iget-object v8, v0, Lg1/c3;->i:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v8, Lp3/i0;

    .line 63
    .line 64
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    move-object v15, v2

    .line 68
    move-object v2, v7

    .line 69
    move-object v7, v6

    .line 70
    move-object v6, v12

    .line 71
    move-object v12, v3

    .line 72
    move-object/from16 v3, p1

    .line 73
    .line 74
    move-object/from16 p1, v16

    .line 75
    .line 76
    goto/16 :goto_a

    .line 77
    .line 78
    :pswitch_2
    iget-object v1, v0, Lg1/c3;->e:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast v1, Lp3/t;

    .line 81
    .line 82
    iget-object v0, v0, Lg1/c3;->i:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v0, Lvy0/i1;

    .line 85
    .line 86
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    move-object v2, v0

    .line 90
    move-object v6, v12

    .line 91
    move-object/from16 v0, p1

    .line 92
    .line 93
    move-object v12, v3

    .line 94
    goto/16 :goto_9

    .line 95
    .line 96
    :pswitch_3
    iget-object v2, v0, Lg1/c3;->f:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast v2, Lvy0/i1;

    .line 99
    .line 100
    iget-object v6, v0, Lg1/c3;->e:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast v6, Lp3/t;

    .line 103
    .line 104
    iget-object v7, v0, Lg1/c3;->i:Ljava/lang/Object;

    .line 105
    .line 106
    check-cast v7, Lp3/i0;

    .line 107
    .line 108
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    move-object v8, v7

    .line 112
    move-object v4, v14

    .line 113
    move-object v7, v6

    .line 114
    move-object v6, v12

    .line 115
    move-object v14, v13

    .line 116
    move-object v13, v2

    .line 117
    move-object v12, v3

    .line 118
    move-object/from16 v2, p1

    .line 119
    .line 120
    move-object/from16 p1, v16

    .line 121
    .line 122
    goto/16 :goto_7

    .line 123
    .line 124
    :pswitch_4
    iget-object v0, v0, Lg1/c3;->i:Ljava/lang/Object;

    .line 125
    .line 126
    check-cast v0, Lvy0/i1;

    .line 127
    .line 128
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    move-object v12, v3

    .line 132
    move-object v4, v14

    .line 133
    goto/16 :goto_4

    .line 134
    .line 135
    :pswitch_5
    iget-object v2, v0, Lg1/c3;->f:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast v2, Lvy0/i1;

    .line 138
    .line 139
    iget-object v4, v0, Lg1/c3;->e:Ljava/lang/Object;

    .line 140
    .line 141
    check-cast v4, Lp3/t;

    .line 142
    .line 143
    iget-object v5, v0, Lg1/c3;->i:Ljava/lang/Object;

    .line 144
    .line 145
    check-cast v5, Lp3/i0;

    .line 146
    .line 147
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    move-object v15, v4

    .line 151
    move-object v6, v12

    .line 152
    move-object v4, v14

    .line 153
    move-object v12, v3

    .line 154
    move-object v14, v13

    .line 155
    move-object/from16 v3, v16

    .line 156
    .line 157
    move-object/from16 v13, p1

    .line 158
    .line 159
    goto/16 :goto_3

    .line 160
    .line 161
    :pswitch_6
    iget-object v2, v0, Lg1/c3;->e:Ljava/lang/Object;

    .line 162
    .line 163
    check-cast v2, Lvy0/i1;

    .line 164
    .line 165
    iget-object v4, v0, Lg1/c3;->i:Ljava/lang/Object;

    .line 166
    .line 167
    check-cast v4, Lp3/i0;

    .line 168
    .line 169
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 170
    .line 171
    .line 172
    move-object/from16 v7, p1

    .line 173
    .line 174
    move-object v5, v4

    .line 175
    move-object v6, v12

    .line 176
    move-object v4, v14

    .line 177
    move-object v12, v3

    .line 178
    move-object v14, v13

    .line 179
    move-object/from16 v3, v16

    .line 180
    .line 181
    goto/16 :goto_2

    .line 182
    .line 183
    :pswitch_7
    iget-object v2, v0, Lg1/c3;->i:Ljava/lang/Object;

    .line 184
    .line 185
    check-cast v2, Lp3/i0;

    .line 186
    .line 187
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 188
    .line 189
    .line 190
    move-object/from16 v4, p1

    .line 191
    .line 192
    :cond_0
    move-object v5, v2

    .line 193
    goto :goto_0

    .line 194
    :pswitch_8
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 195
    .line 196
    .line 197
    iget-object v2, v0, Lg1/c3;->i:Ljava/lang/Object;

    .line 198
    .line 199
    check-cast v2, Lp3/i0;

    .line 200
    .line 201
    iput-object v2, v0, Lg1/c3;->i:Ljava/lang/Object;

    .line 202
    .line 203
    iput v15, v0, Lg1/c3;->h:I

    .line 204
    .line 205
    invoke-static {v2, v0, v8}, Lg1/g3;->c(Lp3/i0;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v4

    .line 209
    if-ne v4, v1, :cond_0

    .line 210
    .line 211
    goto/16 :goto_b

    .line 212
    .line 213
    :goto_0
    check-cast v4, Lp3/t;

    .line 214
    .line 215
    invoke-virtual {v4}, Lp3/t;->a()V

    .line 216
    .line 217
    .line 218
    sget-object v2, Lg1/g3;->a:Lg1/e1;

    .line 219
    .line 220
    sget-object v2, Lvy0/c0;->g:Lvy0/c0;

    .line 221
    .line 222
    new-instance v6, Lg1/a3;

    .line 223
    .line 224
    invoke-direct {v6, v14, v3, v15}, Lg1/a3;-><init>(Lg1/z1;Lkotlin/coroutines/Continuation;I)V

    .line 225
    .line 226
    .line 227
    invoke-static {v9, v3, v2, v6, v15}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 228
    .line 229
    .line 230
    move-result-object v2

    .line 231
    sget-object v6, Lg1/g3;->a:Lg1/e1;

    .line 232
    .line 233
    if-eq v13, v6, :cond_1

    .line 234
    .line 235
    move-object v6, v12

    .line 236
    new-instance v12, Lg1/b3;

    .line 237
    .line 238
    const/16 v17, 0x0

    .line 239
    .line 240
    move-object/from16 v19, v16

    .line 241
    .line 242
    move-object/from16 v16, v3

    .line 243
    .line 244
    move-object/from16 v3, v19

    .line 245
    .line 246
    move/from16 v19, v15

    .line 247
    .line 248
    move-object v15, v4

    .line 249
    move/from16 v4, v19

    .line 250
    .line 251
    invoke-direct/range {v12 .. v17}, Lg1/b3;-><init>(Lay0/o;Lg1/z1;Lp3/t;Lkotlin/coroutines/Continuation;I)V

    .line 252
    .line 253
    .line 254
    move-object v4, v14

    .line 255
    move-object v14, v13

    .line 256
    move-object v13, v12

    .line 257
    move-object/from16 v12, v16

    .line 258
    .line 259
    invoke-static {v9, v2, v13}, Lg1/g3;->g(Lvy0/b0;Lvy0/i1;Lay0/n;)Lvy0/x1;

    .line 260
    .line 261
    .line 262
    goto :goto_1

    .line 263
    :cond_1
    move-object v15, v4

    .line 264
    move-object v6, v12

    .line 265
    move-object v4, v14

    .line 266
    move-object v12, v3

    .line 267
    move-object v14, v13

    .line 268
    move-object/from16 v3, v16

    .line 269
    .line 270
    :goto_1
    if-nez v3, :cond_3

    .line 271
    .line 272
    iput-object v5, v0, Lg1/c3;->i:Ljava/lang/Object;

    .line 273
    .line 274
    iput-object v2, v0, Lg1/c3;->e:Ljava/lang/Object;

    .line 275
    .line 276
    iput v7, v0, Lg1/c3;->h:I

    .line 277
    .line 278
    sget-object v7, Lp3/l;->e:Lp3/l;

    .line 279
    .line 280
    invoke-static {v5, v7, v0}, Lg1/g3;->i(Lp3/i0;Lp3/l;Lrx0/a;)Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    move-result-object v7

    .line 284
    if-ne v7, v1, :cond_2

    .line 285
    .line 286
    goto/16 :goto_b

    .line 287
    .line 288
    :cond_2
    :goto_2
    check-cast v7, Lp3/t;

    .line 289
    .line 290
    goto :goto_5

    .line 291
    :cond_3
    iput-object v5, v0, Lg1/c3;->i:Ljava/lang/Object;

    .line 292
    .line 293
    iput-object v15, v0, Lg1/c3;->e:Ljava/lang/Object;

    .line 294
    .line 295
    iput-object v2, v0, Lg1/c3;->f:Ljava/lang/Object;

    .line 296
    .line 297
    iput v8, v0, Lg1/c3;->h:I

    .line 298
    .line 299
    sget-object v13, Lp3/l;->e:Lp3/l;

    .line 300
    .line 301
    invoke-static {v5, v13, v0}, Lg1/g3;->h(Lp3/i0;Lp3/l;Lrx0/a;)Ljava/lang/Object;

    .line 302
    .line 303
    .line 304
    move-result-object v13

    .line 305
    if-ne v13, v1, :cond_4

    .line 306
    .line 307
    goto/16 :goto_b

    .line 308
    .line 309
    :cond_4
    :goto_3
    check-cast v13, Lg1/p1;

    .line 310
    .line 311
    invoke-static {v13, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 312
    .line 313
    .line 314
    move-result v17

    .line 315
    if-eqz v17, :cond_6

    .line 316
    .line 317
    iget-wide v10, v15, Lp3/t;->c:J

    .line 318
    .line 319
    new-instance v6, Ld3/b;

    .line 320
    .line 321
    invoke-direct {v6, v10, v11}, Ld3/b;-><init>(J)V

    .line 322
    .line 323
    .line 324
    invoke-interface {v3, v6}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 325
    .line 326
    .line 327
    iput-object v2, v0, Lg1/c3;->i:Ljava/lang/Object;

    .line 328
    .line 329
    iput-object v12, v0, Lg1/c3;->e:Ljava/lang/Object;

    .line 330
    .line 331
    iput-object v12, v0, Lg1/c3;->f:Ljava/lang/Object;

    .line 332
    .line 333
    const/4 v3, 0x4

    .line 334
    iput v3, v0, Lg1/c3;->h:I

    .line 335
    .line 336
    invoke-static {v5, v0}, Lg1/g3;->a(Lp3/i0;Lrx0/a;)Ljava/lang/Object;

    .line 337
    .line 338
    .line 339
    move-result-object v0

    .line 340
    if-ne v0, v1, :cond_5

    .line 341
    .line 342
    goto/16 :goto_b

    .line 343
    .line 344
    :cond_5
    move-object v0, v2

    .line 345
    :goto_4
    new-instance v1, Lg1/z2;

    .line 346
    .line 347
    invoke-direct {v1, v4, v12, v7}, Lg1/z2;-><init>(Lg1/z1;Lkotlin/coroutines/Continuation;I)V

    .line 348
    .line 349
    .line 350
    invoke-static {v9, v0, v1}, Lg1/g3;->g(Lvy0/b0;Lvy0/i1;Lay0/n;)Lvy0/x1;

    .line 351
    .line 352
    .line 353
    return-object v18

    .line 354
    :cond_6
    instance-of v7, v13, Lg1/n1;

    .line 355
    .line 356
    if-eqz v7, :cond_7

    .line 357
    .line 358
    check-cast v13, Lg1/n1;

    .line 359
    .line 360
    iget-object v7, v13, Lg1/n1;->a:Lp3/t;

    .line 361
    .line 362
    goto :goto_5

    .line 363
    :cond_7
    instance-of v7, v13, Lg1/m1;

    .line 364
    .line 365
    if-eqz v7, :cond_16

    .line 366
    .line 367
    move-object v7, v12

    .line 368
    :goto_5
    if-nez v7, :cond_8

    .line 369
    .line 370
    new-instance v13, Lg1/z2;

    .line 371
    .line 372
    invoke-direct {v13, v4, v12, v8}, Lg1/z2;-><init>(Lg1/z1;Lkotlin/coroutines/Continuation;I)V

    .line 373
    .line 374
    .line 375
    invoke-static {v9, v2, v13}, Lg1/g3;->g(Lvy0/b0;Lvy0/i1;Lay0/n;)Lvy0/x1;

    .line 376
    .line 377
    .line 378
    move-result-object v2

    .line 379
    goto :goto_6

    .line 380
    :cond_8
    invoke-virtual {v7}, Lp3/t;->a()V

    .line 381
    .line 382
    .line 383
    new-instance v8, Lg1/z2;

    .line 384
    .line 385
    const/4 v13, 0x4

    .line 386
    invoke-direct {v8, v4, v12, v13}, Lg1/z2;-><init>(Lg1/z1;Lkotlin/coroutines/Continuation;I)V

    .line 387
    .line 388
    .line 389
    invoke-static {v9, v2, v8}, Lg1/g3;->g(Lvy0/b0;Lvy0/i1;Lay0/n;)Lvy0/x1;

    .line 390
    .line 391
    .line 392
    move-result-object v2

    .line 393
    :goto_6
    if-eqz v7, :cond_15

    .line 394
    .line 395
    if-nez v10, :cond_9

    .line 396
    .line 397
    if-eqz v6, :cond_15

    .line 398
    .line 399
    iget-wide v0, v7, Lp3/t;->c:J

    .line 400
    .line 401
    new-instance v2, Ld3/b;

    .line 402
    .line 403
    invoke-direct {v2, v0, v1}, Ld3/b;-><init>(J)V

    .line 404
    .line 405
    .line 406
    invoke-interface {v6, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 407
    .line 408
    .line 409
    return-object v18

    .line 410
    :cond_9
    iput-object v5, v0, Lg1/c3;->i:Ljava/lang/Object;

    .line 411
    .line 412
    iput-object v7, v0, Lg1/c3;->e:Ljava/lang/Object;

    .line 413
    .line 414
    iput-object v2, v0, Lg1/c3;->f:Ljava/lang/Object;

    .line 415
    .line 416
    const/4 v8, 0x5

    .line 417
    iput v8, v0, Lg1/c3;->h:I

    .line 418
    .line 419
    invoke-virtual {v5}, Lp3/i0;->f()Lw3/h2;

    .line 420
    .line 421
    .line 422
    move-result-object v8

    .line 423
    move-object v13, v2

    .line 424
    move-object/from16 p1, v3

    .line 425
    .line 426
    invoke-interface {v8}, Lw3/h2;->a()J

    .line 427
    .line 428
    .line 429
    move-result-wide v2

    .line 430
    new-instance v8, Lg1/w2;

    .line 431
    .line 432
    invoke-direct {v8, v7, v12}, Lg1/w2;-><init>(Lp3/t;Lkotlin/coroutines/Continuation;)V

    .line 433
    .line 434
    .line 435
    invoke-virtual {v5, v2, v3, v8, v0}, Lp3/i0;->i(JLay0/n;Lrx0/a;)Ljava/lang/Object;

    .line 436
    .line 437
    .line 438
    move-result-object v2

    .line 439
    if-ne v2, v1, :cond_a

    .line 440
    .line 441
    goto/16 :goto_b

    .line 442
    .line 443
    :cond_a
    move-object v8, v5

    .line 444
    :goto_7
    move-object v15, v2

    .line 445
    check-cast v15, Lp3/t;

    .line 446
    .line 447
    if-nez v15, :cond_b

    .line 448
    .line 449
    if-eqz v6, :cond_15

    .line 450
    .line 451
    iget-wide v0, v7, Lp3/t;->c:J

    .line 452
    .line 453
    new-instance v2, Ld3/b;

    .line 454
    .line 455
    invoke-direct {v2, v0, v1}, Ld3/b;-><init>(J)V

    .line 456
    .line 457
    .line 458
    invoke-interface {v6, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 459
    .line 460
    .line 461
    return-object v18

    .line 462
    :cond_b
    sget-object v2, Lg1/g3;->a:Lg1/e1;

    .line 463
    .line 464
    sget-object v2, Lvy0/c0;->g:Lvy0/c0;

    .line 465
    .line 466
    new-instance v3, Le60/m;

    .line 467
    .line 468
    const/16 v5, 0x13

    .line 469
    .line 470
    invoke-direct {v3, v5, v13, v4, v12}, Le60/m;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 471
    .line 472
    .line 473
    const/4 v5, 0x1

    .line 474
    invoke-static {v9, v12, v2, v3, v5}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 475
    .line 476
    .line 477
    move-result-object v2

    .line 478
    sget-object v3, Lg1/g3;->a:Lg1/e1;

    .line 479
    .line 480
    if-eq v14, v3, :cond_c

    .line 481
    .line 482
    move-object/from16 v16, v12

    .line 483
    .line 484
    new-instance v12, Lg1/b3;

    .line 485
    .line 486
    const/16 v17, 0x1

    .line 487
    .line 488
    move-object v13, v14

    .line 489
    move-object v14, v4

    .line 490
    invoke-direct/range {v12 .. v17}, Lg1/b3;-><init>(Lay0/o;Lg1/z1;Lp3/t;Lkotlin/coroutines/Continuation;I)V

    .line 491
    .line 492
    .line 493
    move-object v3, v12

    .line 494
    move-object/from16 v12, v16

    .line 495
    .line 496
    invoke-static {v9, v2, v3}, Lg1/g3;->g(Lvy0/b0;Lvy0/i1;Lay0/n;)Lvy0/x1;

    .line 497
    .line 498
    .line 499
    goto :goto_8

    .line 500
    :cond_c
    move-object v14, v4

    .line 501
    :goto_8
    if-nez p1, :cond_e

    .line 502
    .line 503
    iput-object v2, v0, Lg1/c3;->i:Ljava/lang/Object;

    .line 504
    .line 505
    iput-object v7, v0, Lg1/c3;->e:Ljava/lang/Object;

    .line 506
    .line 507
    iput-object v12, v0, Lg1/c3;->f:Ljava/lang/Object;

    .line 508
    .line 509
    const/4 v3, 0x6

    .line 510
    iput v3, v0, Lg1/c3;->h:I

    .line 511
    .line 512
    sget-object v3, Lp3/l;->e:Lp3/l;

    .line 513
    .line 514
    invoke-static {v8, v3, v0}, Lg1/g3;->i(Lp3/i0;Lp3/l;Lrx0/a;)Ljava/lang/Object;

    .line 515
    .line 516
    .line 517
    move-result-object v0

    .line 518
    if-ne v0, v1, :cond_d

    .line 519
    .line 520
    goto :goto_b

    .line 521
    :cond_d
    move-object v1, v7

    .line 522
    :goto_9
    move-object v3, v0

    .line 523
    check-cast v3, Lp3/t;

    .line 524
    .line 525
    goto :goto_d

    .line 526
    :cond_e
    iput-object v8, v0, Lg1/c3;->i:Ljava/lang/Object;

    .line 527
    .line 528
    iput-object v2, v0, Lg1/c3;->e:Ljava/lang/Object;

    .line 529
    .line 530
    iput-object v7, v0, Lg1/c3;->f:Ljava/lang/Object;

    .line 531
    .line 532
    iput-object v15, v0, Lg1/c3;->g:Lp3/t;

    .line 533
    .line 534
    const/4 v3, 0x7

    .line 535
    iput v3, v0, Lg1/c3;->h:I

    .line 536
    .line 537
    sget-object v3, Lp3/l;->e:Lp3/l;

    .line 538
    .line 539
    invoke-static {v8, v3, v0}, Lg1/g3;->h(Lp3/i0;Lp3/l;Lrx0/a;)Ljava/lang/Object;

    .line 540
    .line 541
    .line 542
    move-result-object v3

    .line 543
    if-ne v3, v1, :cond_f

    .line 544
    .line 545
    goto :goto_b

    .line 546
    :cond_f
    :goto_a
    check-cast v3, Lg1/p1;

    .line 547
    .line 548
    invoke-static {v3, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 549
    .line 550
    .line 551
    move-result v4

    .line 552
    if-eqz v4, :cond_11

    .line 553
    .line 554
    iget-wide v3, v15, Lp3/t;->c:J

    .line 555
    .line 556
    new-instance v5, Ld3/b;

    .line 557
    .line 558
    invoke-direct {v5, v3, v4}, Ld3/b;-><init>(J)V

    .line 559
    .line 560
    .line 561
    move-object/from16 v3, p1

    .line 562
    .line 563
    invoke-interface {v3, v5}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 564
    .line 565
    .line 566
    iput-object v2, v0, Lg1/c3;->i:Ljava/lang/Object;

    .line 567
    .line 568
    iput-object v12, v0, Lg1/c3;->e:Ljava/lang/Object;

    .line 569
    .line 570
    iput-object v12, v0, Lg1/c3;->f:Ljava/lang/Object;

    .line 571
    .line 572
    iput-object v12, v0, Lg1/c3;->g:Lp3/t;

    .line 573
    .line 574
    const/16 v3, 0x8

    .line 575
    .line 576
    iput v3, v0, Lg1/c3;->h:I

    .line 577
    .line 578
    invoke-static {v8, v0}, Lg1/g3;->a(Lp3/i0;Lrx0/a;)Ljava/lang/Object;

    .line 579
    .line 580
    .line 581
    move-result-object v0

    .line 582
    if-ne v0, v1, :cond_10

    .line 583
    .line 584
    :goto_b
    return-object v1

    .line 585
    :cond_10
    move-object v0, v2

    .line 586
    :goto_c
    new-instance v1, Lg1/z2;

    .line 587
    .line 588
    const/4 v3, 0x7

    .line 589
    invoke-direct {v1, v14, v12, v3}, Lg1/z2;-><init>(Lg1/z1;Lkotlin/coroutines/Continuation;I)V

    .line 590
    .line 591
    .line 592
    invoke-static {v9, v0, v1}, Lg1/g3;->g(Lvy0/b0;Lvy0/i1;Lay0/n;)Lvy0/x1;

    .line 593
    .line 594
    .line 595
    return-object v18

    .line 596
    :cond_11
    instance-of v0, v3, Lg1/n1;

    .line 597
    .line 598
    if-eqz v0, :cond_12

    .line 599
    .line 600
    check-cast v3, Lg1/n1;

    .line 601
    .line 602
    iget-object v3, v3, Lg1/n1;->a:Lp3/t;

    .line 603
    .line 604
    move-object v1, v7

    .line 605
    goto :goto_d

    .line 606
    :cond_12
    instance-of v0, v3, Lg1/m1;

    .line 607
    .line 608
    if-eqz v0, :cond_14

    .line 609
    .line 610
    move-object v1, v7

    .line 611
    move-object v3, v12

    .line 612
    :goto_d
    if-eqz v3, :cond_13

    .line 613
    .line 614
    invoke-virtual {v3}, Lp3/t;->a()V

    .line 615
    .line 616
    .line 617
    new-instance v0, Lg1/z2;

    .line 618
    .line 619
    const/4 v8, 0x5

    .line 620
    invoke-direct {v0, v14, v12, v8}, Lg1/z2;-><init>(Lg1/z1;Lkotlin/coroutines/Continuation;I)V

    .line 621
    .line 622
    .line 623
    invoke-static {v9, v2, v0}, Lg1/g3;->g(Lvy0/b0;Lvy0/i1;Lay0/n;)Lvy0/x1;

    .line 624
    .line 625
    .line 626
    iget-wide v0, v3, Lp3/t;->c:J

    .line 627
    .line 628
    new-instance v2, Ld3/b;

    .line 629
    .line 630
    invoke-direct {v2, v0, v1}, Ld3/b;-><init>(J)V

    .line 631
    .line 632
    .line 633
    invoke-interface {v10, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 634
    .line 635
    .line 636
    return-object v18

    .line 637
    :cond_13
    new-instance v0, Lg1/z2;

    .line 638
    .line 639
    const/4 v3, 0x6

    .line 640
    invoke-direct {v0, v14, v12, v3}, Lg1/z2;-><init>(Lg1/z1;Lkotlin/coroutines/Continuation;I)V

    .line 641
    .line 642
    .line 643
    invoke-static {v9, v2, v0}, Lg1/g3;->g(Lvy0/b0;Lvy0/i1;Lay0/n;)Lvy0/x1;

    .line 644
    .line 645
    .line 646
    if-eqz v6, :cond_15

    .line 647
    .line 648
    iget-wide v0, v1, Lp3/t;->c:J

    .line 649
    .line 650
    new-instance v2, Ld3/b;

    .line 651
    .line 652
    invoke-direct {v2, v0, v1}, Ld3/b;-><init>(J)V

    .line 653
    .line 654
    .line 655
    invoke-interface {v6, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 656
    .line 657
    .line 658
    return-object v18

    .line 659
    :cond_14
    new-instance v0, La8/r0;

    .line 660
    .line 661
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 662
    .line 663
    .line 664
    throw v0

    .line 665
    :cond_15
    return-object v18

    .line 666
    :cond_16
    new-instance v0, La8/r0;

    .line 667
    .line 668
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 669
    .line 670
    .line 671
    throw v0

    .line 672
    nop

    .line 673
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
