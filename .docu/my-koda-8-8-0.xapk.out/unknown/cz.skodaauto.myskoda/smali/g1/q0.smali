.class public final Lg1/q0;
.super Lrx0/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;

.field public h:Lkotlin/jvm/internal/e0;

.field public i:Lg1/i3;

.field public j:Lp3/t;

.field public k:Z

.field public l:F

.field public m:I

.field public synthetic n:Ljava/lang/Object;

.field public final synthetic o:Lay0/a;

.field public final synthetic p:Lkotlin/jvm/internal/e0;

.field public final synthetic q:Lg1/w1;

.field public final synthetic r:Lay0/o;

.field public final synthetic s:Lay0/n;

.field public final synthetic t:Lay0/a;

.field public final synthetic u:Lay0/k;


# direct methods
.method public constructor <init>(Lay0/a;Lkotlin/jvm/internal/e0;Lg1/w1;Lay0/o;Lay0/n;Lay0/a;Lay0/k;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lg1/q0;->o:Lay0/a;

    .line 2
    .line 3
    iput-object p2, p0, Lg1/q0;->p:Lkotlin/jvm/internal/e0;

    .line 4
    .line 5
    iput-object p3, p0, Lg1/q0;->q:Lg1/w1;

    .line 6
    .line 7
    iput-object p4, p0, Lg1/q0;->r:Lay0/o;

    .line 8
    .line 9
    iput-object p5, p0, Lg1/q0;->s:Lay0/n;

    .line 10
    .line 11
    iput-object p6, p0, Lg1/q0;->t:Lay0/a;

    .line 12
    .line 13
    iput-object p7, p0, Lg1/q0;->u:Lay0/k;

    .line 14
    .line 15
    const/4 p1, 0x2

    .line 16
    invoke-direct {p0, p1, p8}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 9

    .line 1
    new-instance v0, Lg1/q0;

    .line 2
    .line 3
    iget-object v6, p0, Lg1/q0;->t:Lay0/a;

    .line 4
    .line 5
    iget-object v7, p0, Lg1/q0;->u:Lay0/k;

    .line 6
    .line 7
    iget-object v1, p0, Lg1/q0;->o:Lay0/a;

    .line 8
    .line 9
    iget-object v2, p0, Lg1/q0;->p:Lkotlin/jvm/internal/e0;

    .line 10
    .line 11
    iget-object v3, p0, Lg1/q0;->q:Lg1/w1;

    .line 12
    .line 13
    iget-object v4, p0, Lg1/q0;->r:Lay0/o;

    .line 14
    .line 15
    iget-object v5, p0, Lg1/q0;->s:Lay0/n;

    .line 16
    .line 17
    move-object v8, p2

    .line 18
    invoke-direct/range {v0 .. v8}, Lg1/q0;-><init>(Lay0/a;Lkotlin/jvm/internal/e0;Lg1/w1;Lay0/o;Lay0/n;Lay0/a;Lay0/k;Lkotlin/coroutines/Continuation;)V

    .line 19
    .line 20
    .line 21
    iput-object p1, v0, Lg1/q0;->n:Ljava/lang/Object;

    .line 22
    .line 23
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
    invoke-virtual {p0, p1, p2}, Lg1/q0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lg1/q0;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lg1/q0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 4
    .line 5
    iget v2, v0, Lg1/q0;->m:I

    .line 6
    .line 7
    iget-object v7, v0, Lg1/q0;->q:Lg1/w1;

    .line 8
    .line 9
    const-wide/16 v8, 0x0

    .line 10
    .line 11
    iget-object v10, v0, Lg1/q0;->p:Lkotlin/jvm/internal/e0;

    .line 12
    .line 13
    const/4 v11, 0x0

    .line 14
    const/4 v12, 0x1

    .line 15
    packed-switch v2, :pswitch_data_0

    .line 16
    .line 17
    .line 18
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 19
    .line 20
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 21
    .line 22
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    throw v0

    .line 26
    :pswitch_0
    iget-object v2, v0, Lg1/q0;->h:Lkotlin/jvm/internal/e0;

    .line 27
    .line 28
    iget-object v3, v0, Lg1/q0;->g:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v3, Lp3/i0;

    .line 31
    .line 32
    iget-object v4, v0, Lg1/q0;->f:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v4, Lg1/w1;

    .line 35
    .line 36
    iget-object v5, v0, Lg1/q0;->e:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v5, Lay0/n;

    .line 39
    .line 40
    iget-object v6, v0, Lg1/q0;->n:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v6, Lp3/i0;

    .line 43
    .line 44
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    move-object/from16 v7, p1

    .line 48
    .line 49
    const/4 v15, 0x0

    .line 50
    goto/16 :goto_25

    .line 51
    .line 52
    :pswitch_1
    iget v2, v0, Lg1/q0;->l:F

    .line 53
    .line 54
    iget-object v14, v0, Lg1/q0;->j:Lp3/t;

    .line 55
    .line 56
    iget-object v15, v0, Lg1/q0;->i:Lg1/i3;

    .line 57
    .line 58
    const-wide v16, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 59
    .line 60
    .line 61
    .line 62
    .line 63
    iget-object v3, v0, Lg1/q0;->h:Lkotlin/jvm/internal/e0;

    .line 64
    .line 65
    iget-object v4, v0, Lg1/q0;->g:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast v4, Lkotlin/jvm/internal/e0;

    .line 68
    .line 69
    const-wide v18, 0x7fffffff7fffffffL

    .line 70
    .line 71
    .line 72
    .line 73
    .line 74
    iget-object v5, v0, Lg1/q0;->f:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast v5, Lp3/i0;

    .line 77
    .line 78
    iget-object v6, v0, Lg1/q0;->e:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast v6, Lp3/t;

    .line 81
    .line 82
    iget-object v13, v0, Lg1/q0;->n:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v13, Lp3/i0;

    .line 85
    .line 86
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    move-object v11, v3

    .line 90
    move-object v3, v6

    .line 91
    move-object/from16 v20, v7

    .line 92
    .line 93
    move-object v6, v4

    .line 94
    move-object v4, v5

    .line 95
    move-object v5, v13

    .line 96
    move-wide v12, v8

    .line 97
    move-object v8, v15

    .line 98
    goto/16 :goto_20

    .line 99
    .line 100
    :pswitch_2
    const-wide v16, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 101
    .line 102
    .line 103
    .line 104
    .line 105
    const-wide v18, 0x7fffffff7fffffffL

    .line 106
    .line 107
    .line 108
    .line 109
    .line 110
    iget v2, v0, Lg1/q0;->l:F

    .line 111
    .line 112
    iget-object v3, v0, Lg1/q0;->i:Lg1/i3;

    .line 113
    .line 114
    iget-object v4, v0, Lg1/q0;->h:Lkotlin/jvm/internal/e0;

    .line 115
    .line 116
    iget-object v5, v0, Lg1/q0;->g:Ljava/lang/Object;

    .line 117
    .line 118
    check-cast v5, Lkotlin/jvm/internal/e0;

    .line 119
    .line 120
    iget-object v6, v0, Lg1/q0;->f:Ljava/lang/Object;

    .line 121
    .line 122
    check-cast v6, Lp3/i0;

    .line 123
    .line 124
    iget-object v13, v0, Lg1/q0;->e:Ljava/lang/Object;

    .line 125
    .line 126
    check-cast v13, Lp3/t;

    .line 127
    .line 128
    iget-object v14, v0, Lg1/q0;->n:Ljava/lang/Object;

    .line 129
    .line 130
    check-cast v14, Lp3/i0;

    .line 131
    .line 132
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    move-object/from16 v9, p1

    .line 136
    .line 137
    move-object v8, v3

    .line 138
    move-object v11, v4

    .line 139
    move-object v4, v6

    .line 140
    move-object v3, v13

    .line 141
    move-object v6, v5

    .line 142
    move-object v5, v14

    .line 143
    goto/16 :goto_18

    .line 144
    .line 145
    :pswitch_3
    const-wide v16, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 146
    .line 147
    .line 148
    .line 149
    .line 150
    const-wide v18, 0x7fffffff7fffffffL

    .line 151
    .line 152
    .line 153
    .line 154
    .line 155
    iget-object v2, v0, Lg1/q0;->f:Ljava/lang/Object;

    .line 156
    .line 157
    check-cast v2, Lp3/t;

    .line 158
    .line 159
    iget-object v3, v0, Lg1/q0;->e:Ljava/lang/Object;

    .line 160
    .line 161
    check-cast v3, Lp3/t;

    .line 162
    .line 163
    iget-object v4, v0, Lg1/q0;->n:Ljava/lang/Object;

    .line 164
    .line 165
    check-cast v4, Lp3/i0;

    .line 166
    .line 167
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 168
    .line 169
    .line 170
    move-object/from16 v5, p1

    .line 171
    .line 172
    goto/16 :goto_12

    .line 173
    .line 174
    :pswitch_4
    const-wide v16, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 175
    .line 176
    .line 177
    .line 178
    .line 179
    const-wide v18, 0x7fffffff7fffffffL

    .line 180
    .line 181
    .line 182
    .line 183
    .line 184
    iget v2, v0, Lg1/q0;->l:F

    .line 185
    .line 186
    iget-object v3, v0, Lg1/q0;->j:Lp3/t;

    .line 187
    .line 188
    iget-object v4, v0, Lg1/q0;->i:Lg1/i3;

    .line 189
    .line 190
    iget-object v5, v0, Lg1/q0;->h:Lkotlin/jvm/internal/e0;

    .line 191
    .line 192
    iget-object v6, v0, Lg1/q0;->g:Ljava/lang/Object;

    .line 193
    .line 194
    check-cast v6, Lkotlin/jvm/internal/e0;

    .line 195
    .line 196
    iget-object v13, v0, Lg1/q0;->f:Ljava/lang/Object;

    .line 197
    .line 198
    check-cast v13, Lp3/i0;

    .line 199
    .line 200
    iget-object v14, v0, Lg1/q0;->e:Ljava/lang/Object;

    .line 201
    .line 202
    check-cast v14, Lp3/t;

    .line 203
    .line 204
    iget-object v15, v0, Lg1/q0;->n:Ljava/lang/Object;

    .line 205
    .line 206
    check-cast v15, Lp3/i0;

    .line 207
    .line 208
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 209
    .line 210
    .line 211
    move-object/from16 v23, v6

    .line 212
    .line 213
    move v6, v2

    .line 214
    move-object v2, v4

    .line 215
    move-object v4, v13

    .line 216
    move-object v13, v5

    .line 217
    move-object v5, v14

    .line 218
    move-object/from16 v14, v23

    .line 219
    .line 220
    goto/16 :goto_c

    .line 221
    .line 222
    :pswitch_5
    const-wide v16, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 223
    .line 224
    .line 225
    .line 226
    .line 227
    const-wide v18, 0x7fffffff7fffffffL

    .line 228
    .line 229
    .line 230
    .line 231
    .line 232
    iget v2, v0, Lg1/q0;->l:F

    .line 233
    .line 234
    iget-object v3, v0, Lg1/q0;->i:Lg1/i3;

    .line 235
    .line 236
    iget-object v4, v0, Lg1/q0;->h:Lkotlin/jvm/internal/e0;

    .line 237
    .line 238
    iget-object v5, v0, Lg1/q0;->g:Ljava/lang/Object;

    .line 239
    .line 240
    check-cast v5, Lkotlin/jvm/internal/e0;

    .line 241
    .line 242
    iget-object v6, v0, Lg1/q0;->f:Ljava/lang/Object;

    .line 243
    .line 244
    check-cast v6, Lp3/i0;

    .line 245
    .line 246
    iget-object v13, v0, Lg1/q0;->e:Ljava/lang/Object;

    .line 247
    .line 248
    check-cast v13, Lp3/t;

    .line 249
    .line 250
    iget-object v14, v0, Lg1/q0;->n:Ljava/lang/Object;

    .line 251
    .line 252
    check-cast v14, Lp3/i0;

    .line 253
    .line 254
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 255
    .line 256
    .line 257
    move-object v15, v6

    .line 258
    move v6, v2

    .line 259
    move-object v2, v3

    .line 260
    move-object v3, v14

    .line 261
    move-object v14, v5

    .line 262
    move-object v5, v13

    .line 263
    move-object v13, v4

    .line 264
    move-object v4, v15

    .line 265
    move-object/from16 v15, p1

    .line 266
    .line 267
    goto/16 :goto_5

    .line 268
    .line 269
    :pswitch_6
    const-wide v16, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 270
    .line 271
    .line 272
    .line 273
    .line 274
    const-wide v18, 0x7fffffff7fffffffL

    .line 275
    .line 276
    .line 277
    .line 278
    .line 279
    iget-boolean v2, v0, Lg1/q0;->k:Z

    .line 280
    .line 281
    iget-object v3, v0, Lg1/q0;->e:Ljava/lang/Object;

    .line 282
    .line 283
    check-cast v3, Lp3/t;

    .line 284
    .line 285
    iget-object v4, v0, Lg1/q0;->n:Ljava/lang/Object;

    .line 286
    .line 287
    check-cast v4, Lp3/i0;

    .line 288
    .line 289
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 290
    .line 291
    .line 292
    move-object/from16 v5, p1

    .line 293
    .line 294
    goto :goto_1

    .line 295
    :pswitch_7
    const-wide v16, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 296
    .line 297
    .line 298
    .line 299
    .line 300
    const-wide v18, 0x7fffffff7fffffffL

    .line 301
    .line 302
    .line 303
    .line 304
    .line 305
    iget-object v2, v0, Lg1/q0;->n:Ljava/lang/Object;

    .line 306
    .line 307
    check-cast v2, Lp3/i0;

    .line 308
    .line 309
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 310
    .line 311
    .line 312
    move-object/from16 v3, p1

    .line 313
    .line 314
    :cond_0
    move-object v4, v2

    .line 315
    goto :goto_0

    .line 316
    :pswitch_8
    const-wide v16, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 317
    .line 318
    .line 319
    .line 320
    .line 321
    const-wide v18, 0x7fffffff7fffffffL

    .line 322
    .line 323
    .line 324
    .line 325
    .line 326
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 327
    .line 328
    .line 329
    iget-object v2, v0, Lg1/q0;->n:Ljava/lang/Object;

    .line 330
    .line 331
    check-cast v2, Lp3/i0;

    .line 332
    .line 333
    sget-object v3, Lp3/l;->d:Lp3/l;

    .line 334
    .line 335
    iput-object v2, v0, Lg1/q0;->n:Ljava/lang/Object;

    .line 336
    .line 337
    iput v12, v0, Lg1/q0;->m:I

    .line 338
    .line 339
    invoke-static {v2, v11, v3, v0}, Lg1/g3;->b(Lp3/i0;ZLp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 340
    .line 341
    .line 342
    move-result-object v3

    .line 343
    if-ne v3, v1, :cond_0

    .line 344
    .line 345
    goto/16 :goto_24

    .line 346
    .line 347
    :goto_0
    check-cast v3, Lp3/t;

    .line 348
    .line 349
    iget-object v2, v0, Lg1/q0;->o:Lay0/a;

    .line 350
    .line 351
    invoke-interface {v2}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 352
    .line 353
    .line 354
    move-result-object v2

    .line 355
    check-cast v2, Ljava/lang/Boolean;

    .line 356
    .line 357
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 358
    .line 359
    .line 360
    move-result v2

    .line 361
    if-nez v2, :cond_1

    .line 362
    .line 363
    invoke-virtual {v3}, Lp3/t;->a()V

    .line 364
    .line 365
    .line 366
    :cond_1
    iput-object v4, v0, Lg1/q0;->n:Ljava/lang/Object;

    .line 367
    .line 368
    iput-object v3, v0, Lg1/q0;->e:Ljava/lang/Object;

    .line 369
    .line 370
    iput-boolean v2, v0, Lg1/q0;->k:Z

    .line 371
    .line 372
    const/4 v5, 0x2

    .line 373
    iput v5, v0, Lg1/q0;->m:I

    .line 374
    .line 375
    invoke-static {v4, v0, v5}, Lg1/g3;->c(Lp3/i0;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 376
    .line 377
    .line 378
    move-result-object v5

    .line 379
    if-ne v5, v1, :cond_2

    .line 380
    .line 381
    goto/16 :goto_24

    .line 382
    .line 383
    :cond_2
    :goto_1
    check-cast v5, Lp3/t;

    .line 384
    .line 385
    iput-wide v8, v10, Lkotlin/jvm/internal/e0;->d:J

    .line 386
    .line 387
    if-eqz v2, :cond_13

    .line 388
    .line 389
    :goto_2
    iget-wide v2, v5, Lp3/t;->a:J

    .line 390
    .line 391
    iget v6, v5, Lp3/t;->i:I

    .line 392
    .line 393
    iget-object v13, v4, Lp3/i0;->i:Lp3/j0;

    .line 394
    .line 395
    iget-object v13, v13, Lp3/j0;->w:Lp3/k;

    .line 396
    .line 397
    invoke-static {v13, v2, v3}, Lg1/w0;->g(Lp3/k;J)Z

    .line 398
    .line 399
    .line 400
    move-result v13

    .line 401
    if-eqz v13, :cond_3

    .line 402
    .line 403
    :goto_3
    const/4 v8, 0x0

    .line 404
    goto/16 :goto_d

    .line 405
    .line 406
    :cond_3
    invoke-virtual {v4}, Lp3/i0;->f()Lw3/h2;

    .line 407
    .line 408
    .line 409
    move-result-object v13

    .line 410
    invoke-static {v13, v6}, Lg1/w0;->h(Lw3/h2;I)F

    .line 411
    .line 412
    .line 413
    move-result v6

    .line 414
    new-instance v13, Lkotlin/jvm/internal/e0;

    .line 415
    .line 416
    invoke-direct {v13}, Ljava/lang/Object;-><init>()V

    .line 417
    .line 418
    .line 419
    iput-wide v2, v13, Lkotlin/jvm/internal/e0;->d:J

    .line 420
    .line 421
    new-instance v2, Lg1/i3;

    .line 422
    .line 423
    const/4 v3, 0x0

    .line 424
    invoke-direct {v2, v7, v8, v9, v3}, Lg1/i3;-><init>(Ljava/lang/Object;JI)V

    .line 425
    .line 426
    .line 427
    move-object v3, v4

    .line 428
    move-object v14, v10

    .line 429
    :goto_4
    iput-object v3, v0, Lg1/q0;->n:Ljava/lang/Object;

    .line 430
    .line 431
    iput-object v5, v0, Lg1/q0;->e:Ljava/lang/Object;

    .line 432
    .line 433
    iput-object v4, v0, Lg1/q0;->f:Ljava/lang/Object;

    .line 434
    .line 435
    iput-object v14, v0, Lg1/q0;->g:Ljava/lang/Object;

    .line 436
    .line 437
    iput-object v13, v0, Lg1/q0;->h:Lkotlin/jvm/internal/e0;

    .line 438
    .line 439
    iput-object v2, v0, Lg1/q0;->i:Lg1/i3;

    .line 440
    .line 441
    const/4 v15, 0x0

    .line 442
    iput-object v15, v0, Lg1/q0;->j:Lp3/t;

    .line 443
    .line 444
    iput v6, v0, Lg1/q0;->l:F

    .line 445
    .line 446
    const/4 v15, 0x3

    .line 447
    iput v15, v0, Lg1/q0;->m:I

    .line 448
    .line 449
    sget-object v15, Lp3/l;->e:Lp3/l;

    .line 450
    .line 451
    invoke-virtual {v4, v15, v0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 452
    .line 453
    .line 454
    move-result-object v15

    .line 455
    if-ne v15, v1, :cond_4

    .line 456
    .line 457
    goto/16 :goto_24

    .line 458
    .line 459
    :cond_4
    :goto_5
    check-cast v15, Lp3/k;

    .line 460
    .line 461
    iget-object v12, v15, Lp3/k;->a:Ljava/lang/Object;

    .line 462
    .line 463
    move-object/from16 v20, v12

    .line 464
    .line 465
    check-cast v20, Ljava/util/Collection;

    .line 466
    .line 467
    invoke-interface/range {v20 .. v20}, Ljava/util/Collection;->size()I

    .line 468
    .line 469
    .line 470
    move-result v11

    .line 471
    const/4 v8, 0x0

    .line 472
    :goto_6
    if-ge v8, v11, :cond_6

    .line 473
    .line 474
    invoke-interface {v12, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 475
    .line 476
    .line 477
    move-result-object v9

    .line 478
    move/from16 v20, v8

    .line 479
    .line 480
    move-object v8, v9

    .line 481
    check-cast v8, Lp3/t;

    .line 482
    .line 483
    move-object/from16 p1, v9

    .line 484
    .line 485
    iget-wide v8, v8, Lp3/t;->a:J

    .line 486
    .line 487
    move/from16 v22, v11

    .line 488
    .line 489
    move-object/from16 v21, v12

    .line 490
    .line 491
    iget-wide v11, v13, Lkotlin/jvm/internal/e0;->d:J

    .line 492
    .line 493
    invoke-static {v8, v9, v11, v12}, Lp3/s;->e(JJ)Z

    .line 494
    .line 495
    .line 496
    move-result v8

    .line 497
    if-eqz v8, :cond_5

    .line 498
    .line 499
    move-object/from16 v8, p1

    .line 500
    .line 501
    goto :goto_7

    .line 502
    :cond_5
    add-int/lit8 v8, v20, 0x1

    .line 503
    .line 504
    move-object/from16 v12, v21

    .line 505
    .line 506
    move/from16 v11, v22

    .line 507
    .line 508
    goto :goto_6

    .line 509
    :cond_6
    const/4 v8, 0x0

    .line 510
    :goto_7
    check-cast v8, Lp3/t;

    .line 511
    .line 512
    if-nez v8, :cond_7

    .line 513
    .line 514
    :goto_8
    move-object v4, v3

    .line 515
    goto :goto_3

    .line 516
    :cond_7
    invoke-virtual {v8}, Lp3/t;->b()Z

    .line 517
    .line 518
    .line 519
    move-result v9

    .line 520
    if-eqz v9, :cond_8

    .line 521
    .line 522
    goto :goto_8

    .line 523
    :cond_8
    invoke-static {v8}, Lp3/s;->d(Lp3/t;)Z

    .line 524
    .line 525
    .line 526
    move-result v9

    .line 527
    if-eqz v9, :cond_c

    .line 528
    .line 529
    iget-object v8, v15, Lp3/k;->a:Ljava/lang/Object;

    .line 530
    .line 531
    move-object v9, v8

    .line 532
    check-cast v9, Ljava/util/Collection;

    .line 533
    .line 534
    invoke-interface {v9}, Ljava/util/Collection;->size()I

    .line 535
    .line 536
    .line 537
    move-result v9

    .line 538
    const/4 v11, 0x0

    .line 539
    :goto_9
    if-ge v11, v9, :cond_a

    .line 540
    .line 541
    invoke-interface {v8, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 542
    .line 543
    .line 544
    move-result-object v12

    .line 545
    move-object v15, v12

    .line 546
    check-cast v15, Lp3/t;

    .line 547
    .line 548
    iget-boolean v15, v15, Lp3/t;->d:Z

    .line 549
    .line 550
    if-eqz v15, :cond_9

    .line 551
    .line 552
    goto :goto_a

    .line 553
    :cond_9
    add-int/lit8 v11, v11, 0x1

    .line 554
    .line 555
    goto :goto_9

    .line 556
    :cond_a
    const/4 v12, 0x0

    .line 557
    :goto_a
    check-cast v12, Lp3/t;

    .line 558
    .line 559
    if-nez v12, :cond_b

    .line 560
    .line 561
    goto :goto_8

    .line 562
    :cond_b
    iget-wide v8, v12, Lp3/t;->a:J

    .line 563
    .line 564
    iput-wide v8, v13, Lkotlin/jvm/internal/e0;->d:J

    .line 565
    .line 566
    goto :goto_b

    .line 567
    :cond_c
    invoke-virtual {v2, v8, v6}, Lg1/i3;->p(Lp3/t;F)J

    .line 568
    .line 569
    .line 570
    move-result-wide v11

    .line 571
    and-long v21, v11, v18

    .line 572
    .line 573
    cmp-long v9, v21, v16

    .line 574
    .line 575
    if-eqz v9, :cond_e

    .line 576
    .line 577
    invoke-virtual {v8}, Lp3/t;->a()V

    .line 578
    .line 579
    .line 580
    iput-wide v11, v14, Lkotlin/jvm/internal/e0;->d:J

    .line 581
    .line 582
    invoke-virtual {v8}, Lp3/t;->b()Z

    .line 583
    .line 584
    .line 585
    move-result v9

    .line 586
    if-eqz v9, :cond_d

    .line 587
    .line 588
    move-object v4, v3

    .line 589
    goto :goto_d

    .line 590
    :cond_d
    const-wide/16 v8, 0x0

    .line 591
    .line 592
    iput-wide v8, v2, Lg1/i3;->e:J

    .line 593
    .line 594
    :goto_b
    const-wide/16 v8, 0x0

    .line 595
    .line 596
    const/4 v11, 0x0

    .line 597
    const/4 v12, 0x1

    .line 598
    goto/16 :goto_4

    .line 599
    .line 600
    :cond_e
    sget-object v9, Lp3/l;->f:Lp3/l;

    .line 601
    .line 602
    iput-object v3, v0, Lg1/q0;->n:Ljava/lang/Object;

    .line 603
    .line 604
    iput-object v5, v0, Lg1/q0;->e:Ljava/lang/Object;

    .line 605
    .line 606
    iput-object v4, v0, Lg1/q0;->f:Ljava/lang/Object;

    .line 607
    .line 608
    iput-object v14, v0, Lg1/q0;->g:Ljava/lang/Object;

    .line 609
    .line 610
    iput-object v13, v0, Lg1/q0;->h:Lkotlin/jvm/internal/e0;

    .line 611
    .line 612
    iput-object v2, v0, Lg1/q0;->i:Lg1/i3;

    .line 613
    .line 614
    iput-object v8, v0, Lg1/q0;->j:Lp3/t;

    .line 615
    .line 616
    iput v6, v0, Lg1/q0;->l:F

    .line 617
    .line 618
    const/4 v11, 0x4

    .line 619
    iput v11, v0, Lg1/q0;->m:I

    .line 620
    .line 621
    invoke-virtual {v4, v9, v0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 622
    .line 623
    .line 624
    move-result-object v9

    .line 625
    if-ne v9, v1, :cond_f

    .line 626
    .line 627
    goto/16 :goto_24

    .line 628
    .line 629
    :cond_f
    move-object v15, v3

    .line 630
    move-object v3, v8

    .line 631
    :goto_c
    invoke-virtual {v3}, Lp3/t;->b()Z

    .line 632
    .line 633
    .line 634
    move-result v3

    .line 635
    if-eqz v3, :cond_12

    .line 636
    .line 637
    move-object v4, v15

    .line 638
    goto/16 :goto_3

    .line 639
    .line 640
    :goto_d
    if-eqz v8, :cond_11

    .line 641
    .line 642
    invoke-virtual {v8}, Lp3/t;->b()Z

    .line 643
    .line 644
    .line 645
    move-result v2

    .line 646
    if-eqz v2, :cond_10

    .line 647
    .line 648
    goto :goto_e

    .line 649
    :cond_10
    const-wide/16 v8, 0x0

    .line 650
    .line 651
    const/4 v11, 0x0

    .line 652
    const/4 v12, 0x1

    .line 653
    goto/16 :goto_2

    .line 654
    .line 655
    :cond_11
    :goto_e
    move-object v3, v8

    .line 656
    goto :goto_f

    .line 657
    :cond_12
    move-object v3, v15

    .line 658
    goto :goto_b

    .line 659
    :cond_13
    :goto_f
    if-nez v3, :cond_2a

    .line 660
    .line 661
    iget-object v2, v4, Lp3/i0;->i:Lp3/j0;

    .line 662
    .line 663
    iget-object v2, v2, Lp3/j0;->w:Lp3/k;

    .line 664
    .line 665
    iget-object v2, v2, Lp3/k;->a:Ljava/lang/Object;

    .line 666
    .line 667
    move-object v6, v2

    .line 668
    check-cast v6, Ljava/util/Collection;

    .line 669
    .line 670
    invoke-interface {v6}, Ljava/util/Collection;->size()I

    .line 671
    .line 672
    .line 673
    move-result v6

    .line 674
    const/4 v8, 0x0

    .line 675
    :goto_10
    if-ge v8, v6, :cond_2a

    .line 676
    .line 677
    invoke-interface {v2, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 678
    .line 679
    .line 680
    move-result-object v9

    .line 681
    check-cast v9, Lp3/t;

    .line 682
    .line 683
    iget-boolean v9, v9, Lp3/t;->d:Z

    .line 684
    .line 685
    if-eqz v9, :cond_29

    .line 686
    .line 687
    move-object v2, v3

    .line 688
    move-object v3, v5

    .line 689
    :goto_11
    sget-object v5, Lp3/l;->f:Lp3/l;

    .line 690
    .line 691
    iput-object v4, v0, Lg1/q0;->n:Ljava/lang/Object;

    .line 692
    .line 693
    iput-object v3, v0, Lg1/q0;->e:Ljava/lang/Object;

    .line 694
    .line 695
    iput-object v2, v0, Lg1/q0;->f:Ljava/lang/Object;

    .line 696
    .line 697
    const/4 v15, 0x0

    .line 698
    iput-object v15, v0, Lg1/q0;->g:Ljava/lang/Object;

    .line 699
    .line 700
    iput-object v15, v0, Lg1/q0;->h:Lkotlin/jvm/internal/e0;

    .line 701
    .line 702
    iput-object v15, v0, Lg1/q0;->i:Lg1/i3;

    .line 703
    .line 704
    iput-object v15, v0, Lg1/q0;->j:Lp3/t;

    .line 705
    .line 706
    const/4 v6, 0x5

    .line 707
    iput v6, v0, Lg1/q0;->m:I

    .line 708
    .line 709
    invoke-virtual {v4, v5, v0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 710
    .line 711
    .line 712
    move-result-object v5

    .line 713
    if-ne v5, v1, :cond_14

    .line 714
    .line 715
    goto/16 :goto_24

    .line 716
    .line 717
    :cond_14
    :goto_12
    check-cast v5, Lp3/k;

    .line 718
    .line 719
    iget-object v5, v5, Lp3/k;->a:Ljava/lang/Object;

    .line 720
    .line 721
    move-object v6, v5

    .line 722
    check-cast v6, Ljava/util/Collection;

    .line 723
    .line 724
    invoke-interface {v6}, Ljava/util/Collection;->size()I

    .line 725
    .line 726
    .line 727
    move-result v6

    .line 728
    const/4 v8, 0x0

    .line 729
    :goto_13
    if-ge v8, v6, :cond_17

    .line 730
    .line 731
    invoke-interface {v5, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 732
    .line 733
    .line 734
    move-result-object v9

    .line 735
    check-cast v9, Lp3/t;

    .line 736
    .line 737
    invoke-virtual {v9}, Lp3/t;->b()Z

    .line 738
    .line 739
    .line 740
    move-result v9

    .line 741
    if-eqz v9, :cond_16

    .line 742
    .line 743
    move-object v6, v5

    .line 744
    check-cast v6, Ljava/util/Collection;

    .line 745
    .line 746
    invoke-interface {v6}, Ljava/util/Collection;->size()I

    .line 747
    .line 748
    .line 749
    move-result v6

    .line 750
    const/4 v8, 0x0

    .line 751
    :goto_14
    if-ge v8, v6, :cond_17

    .line 752
    .line 753
    invoke-interface {v5, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 754
    .line 755
    .line 756
    move-result-object v9

    .line 757
    check-cast v9, Lp3/t;

    .line 758
    .line 759
    iget-boolean v9, v9, Lp3/t;->d:Z

    .line 760
    .line 761
    if-eqz v9, :cond_15

    .line 762
    .line 763
    goto :goto_11

    .line 764
    :cond_15
    add-int/lit8 v8, v8, 0x1

    .line 765
    .line 766
    goto :goto_14

    .line 767
    :cond_16
    add-int/lit8 v8, v8, 0x1

    .line 768
    .line 769
    goto :goto_13

    .line 770
    :cond_17
    move-object v6, v5

    .line 771
    check-cast v6, Ljava/util/Collection;

    .line 772
    .line 773
    invoke-interface {v6}, Ljava/util/Collection;->size()I

    .line 774
    .line 775
    .line 776
    move-result v6

    .line 777
    const/4 v8, 0x0

    .line 778
    :goto_15
    if-ge v8, v6, :cond_28

    .line 779
    .line 780
    invoke-interface {v5, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 781
    .line 782
    .line 783
    move-result-object v9

    .line 784
    check-cast v9, Lp3/t;

    .line 785
    .line 786
    iget-boolean v9, v9, Lp3/t;->d:Z

    .line 787
    .line 788
    if-eqz v9, :cond_27

    .line 789
    .line 790
    invoke-static {v5}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 791
    .line 792
    .line 793
    move-result-object v2

    .line 794
    check-cast v2, Lp3/t;

    .line 795
    .line 796
    if-eqz v2, :cond_18

    .line 797
    .line 798
    iget-wide v8, v2, Lp3/t;->c:J

    .line 799
    .line 800
    goto :goto_16

    .line 801
    :cond_18
    const-wide/16 v8, 0x0

    .line 802
    .line 803
    :goto_16
    iget-wide v5, v3, Lp3/t;->c:J

    .line 804
    .line 805
    invoke-static {v8, v9, v5, v6}, Ld3/b;->g(JJ)J

    .line 806
    .line 807
    .line 808
    move-result-wide v5

    .line 809
    iget-wide v8, v3, Lp3/t;->a:J

    .line 810
    .line 811
    iget v2, v3, Lp3/t;->i:I

    .line 812
    .line 813
    iget-object v11, v4, Lp3/i0;->i:Lp3/j0;

    .line 814
    .line 815
    iget-object v11, v11, Lp3/j0;->w:Lp3/k;

    .line 816
    .line 817
    invoke-static {v11, v8, v9}, Lg1/w0;->g(Lp3/k;J)Z

    .line 818
    .line 819
    .line 820
    move-result v11

    .line 821
    if-eqz v11, :cond_19

    .line 822
    .line 823
    move-object v5, v3

    .line 824
    move-object/from16 v20, v7

    .line 825
    .line 826
    const/4 v3, 0x0

    .line 827
    const-wide/16 v12, 0x0

    .line 828
    .line 829
    goto/16 :goto_21

    .line 830
    .line 831
    :cond_19
    invoke-virtual {v4}, Lp3/i0;->f()Lw3/h2;

    .line 832
    .line 833
    .line 834
    move-result-object v11

    .line 835
    invoke-static {v11, v2}, Lg1/w0;->h(Lw3/h2;I)F

    .line 836
    .line 837
    .line 838
    move-result v2

    .line 839
    new-instance v11, Lkotlin/jvm/internal/e0;

    .line 840
    .line 841
    invoke-direct {v11}, Ljava/lang/Object;-><init>()V

    .line 842
    .line 843
    .line 844
    iput-wide v8, v11, Lkotlin/jvm/internal/e0;->d:J

    .line 845
    .line 846
    new-instance v8, Lg1/i3;

    .line 847
    .line 848
    const/4 v9, 0x0

    .line 849
    invoke-direct {v8, v7, v5, v6, v9}, Lg1/i3;-><init>(Ljava/lang/Object;JI)V

    .line 850
    .line 851
    .line 852
    move-object v5, v4

    .line 853
    move-object v6, v10

    .line 854
    :goto_17
    iput-object v5, v0, Lg1/q0;->n:Ljava/lang/Object;

    .line 855
    .line 856
    iput-object v3, v0, Lg1/q0;->e:Ljava/lang/Object;

    .line 857
    .line 858
    iput-object v4, v0, Lg1/q0;->f:Ljava/lang/Object;

    .line 859
    .line 860
    iput-object v6, v0, Lg1/q0;->g:Ljava/lang/Object;

    .line 861
    .line 862
    iput-object v11, v0, Lg1/q0;->h:Lkotlin/jvm/internal/e0;

    .line 863
    .line 864
    iput-object v8, v0, Lg1/q0;->i:Lg1/i3;

    .line 865
    .line 866
    const/4 v15, 0x0

    .line 867
    iput-object v15, v0, Lg1/q0;->j:Lp3/t;

    .line 868
    .line 869
    iput v2, v0, Lg1/q0;->l:F

    .line 870
    .line 871
    const/4 v9, 0x6

    .line 872
    iput v9, v0, Lg1/q0;->m:I

    .line 873
    .line 874
    sget-object v9, Lp3/l;->e:Lp3/l;

    .line 875
    .line 876
    invoke-virtual {v4, v9, v0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 877
    .line 878
    .line 879
    move-result-object v9

    .line 880
    if-ne v9, v1, :cond_1a

    .line 881
    .line 882
    goto/16 :goto_24

    .line 883
    .line 884
    :cond_1a
    :goto_18
    check-cast v9, Lp3/k;

    .line 885
    .line 886
    iget-object v12, v9, Lp3/k;->a:Ljava/lang/Object;

    .line 887
    .line 888
    move-object v13, v12

    .line 889
    check-cast v13, Ljava/util/Collection;

    .line 890
    .line 891
    invoke-interface {v13}, Ljava/util/Collection;->size()I

    .line 892
    .line 893
    .line 894
    move-result v13

    .line 895
    const/4 v14, 0x0

    .line 896
    :goto_19
    if-ge v14, v13, :cond_1c

    .line 897
    .line 898
    invoke-interface {v12, v14}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 899
    .line 900
    .line 901
    move-result-object v15

    .line 902
    move-object/from16 v20, v7

    .line 903
    .line 904
    move-object v7, v15

    .line 905
    check-cast v7, Lp3/t;

    .line 906
    .line 907
    move-object/from16 v21, v12

    .line 908
    .line 909
    move/from16 p1, v13

    .line 910
    .line 911
    iget-wide v12, v7, Lp3/t;->a:J

    .line 912
    .line 913
    move v7, v14

    .line 914
    move-object/from16 v22, v15

    .line 915
    .line 916
    iget-wide v14, v11, Lkotlin/jvm/internal/e0;->d:J

    .line 917
    .line 918
    invoke-static {v12, v13, v14, v15}, Lp3/s;->e(JJ)Z

    .line 919
    .line 920
    .line 921
    move-result v12

    .line 922
    if-eqz v12, :cond_1b

    .line 923
    .line 924
    move-object/from16 v15, v22

    .line 925
    .line 926
    goto :goto_1a

    .line 927
    :cond_1b
    add-int/lit8 v14, v7, 0x1

    .line 928
    .line 929
    move/from16 v13, p1

    .line 930
    .line 931
    move-object/from16 v7, v20

    .line 932
    .line 933
    move-object/from16 v12, v21

    .line 934
    .line 935
    goto :goto_19

    .line 936
    :cond_1c
    move-object/from16 v20, v7

    .line 937
    .line 938
    const/4 v15, 0x0

    .line 939
    :goto_1a
    move-object v14, v15

    .line 940
    check-cast v14, Lp3/t;

    .line 941
    .line 942
    if-nez v14, :cond_1d

    .line 943
    .line 944
    :goto_1b
    move-object v4, v5

    .line 945
    const-wide/16 v12, 0x0

    .line 946
    .line 947
    :goto_1c
    move-object v5, v3

    .line 948
    const/4 v3, 0x0

    .line 949
    goto/16 :goto_21

    .line 950
    .line 951
    :cond_1d
    invoke-virtual {v14}, Lp3/t;->b()Z

    .line 952
    .line 953
    .line 954
    move-result v7

    .line 955
    if-eqz v7, :cond_1e

    .line 956
    .line 957
    goto :goto_1b

    .line 958
    :cond_1e
    invoke-static {v14}, Lp3/s;->d(Lp3/t;)Z

    .line 959
    .line 960
    .line 961
    move-result v7

    .line 962
    if-eqz v7, :cond_22

    .line 963
    .line 964
    iget-object v7, v9, Lp3/k;->a:Ljava/lang/Object;

    .line 965
    .line 966
    move-object v9, v7

    .line 967
    check-cast v9, Ljava/util/Collection;

    .line 968
    .line 969
    invoke-interface {v9}, Ljava/util/Collection;->size()I

    .line 970
    .line 971
    .line 972
    move-result v9

    .line 973
    const/4 v12, 0x0

    .line 974
    :goto_1d
    if-ge v12, v9, :cond_20

    .line 975
    .line 976
    invoke-interface {v7, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 977
    .line 978
    .line 979
    move-result-object v15

    .line 980
    move-object v13, v15

    .line 981
    check-cast v13, Lp3/t;

    .line 982
    .line 983
    iget-boolean v13, v13, Lp3/t;->d:Z

    .line 984
    .line 985
    if-eqz v13, :cond_1f

    .line 986
    .line 987
    goto :goto_1e

    .line 988
    :cond_1f
    add-int/lit8 v12, v12, 0x1

    .line 989
    .line 990
    goto :goto_1d

    .line 991
    :cond_20
    const/4 v15, 0x0

    .line 992
    :goto_1e
    check-cast v15, Lp3/t;

    .line 993
    .line 994
    if-nez v15, :cond_21

    .line 995
    .line 996
    goto :goto_1b

    .line 997
    :cond_21
    iget-wide v12, v15, Lp3/t;->a:J

    .line 998
    .line 999
    iput-wide v12, v11, Lkotlin/jvm/internal/e0;->d:J

    .line 1000
    .line 1001
    const-wide/16 v12, 0x0

    .line 1002
    .line 1003
    goto :goto_1f

    .line 1004
    :cond_22
    invoke-virtual {v8, v14, v2}, Lg1/i3;->p(Lp3/t;F)J

    .line 1005
    .line 1006
    .line 1007
    move-result-wide v12

    .line 1008
    and-long v12, v12, v18

    .line 1009
    .line 1010
    cmp-long v7, v12, v16

    .line 1011
    .line 1012
    if-eqz v7, :cond_25

    .line 1013
    .line 1014
    invoke-virtual {v14}, Lp3/t;->a()V

    .line 1015
    .line 1016
    .line 1017
    const/4 v7, 0x0

    .line 1018
    invoke-static {v14, v7}, Lp3/s;->h(Lp3/t;Z)J

    .line 1019
    .line 1020
    .line 1021
    move-result-wide v12

    .line 1022
    iput-wide v12, v6, Lkotlin/jvm/internal/e0;->d:J

    .line 1023
    .line 1024
    invoke-virtual {v14}, Lp3/t;->b()Z

    .line 1025
    .line 1026
    .line 1027
    move-result v7

    .line 1028
    if-eqz v7, :cond_23

    .line 1029
    .line 1030
    move-object v4, v5

    .line 1031
    const-wide/16 v12, 0x0

    .line 1032
    .line 1033
    move-object v5, v3

    .line 1034
    move-object v3, v14

    .line 1035
    goto :goto_21

    .line 1036
    :cond_23
    const-wide/16 v12, 0x0

    .line 1037
    .line 1038
    iput-wide v12, v8, Lg1/i3;->e:J

    .line 1039
    .line 1040
    :cond_24
    :goto_1f
    move-object/from16 v7, v20

    .line 1041
    .line 1042
    goto/16 :goto_17

    .line 1043
    .line 1044
    :cond_25
    const-wide/16 v12, 0x0

    .line 1045
    .line 1046
    sget-object v7, Lp3/l;->f:Lp3/l;

    .line 1047
    .line 1048
    iput-object v5, v0, Lg1/q0;->n:Ljava/lang/Object;

    .line 1049
    .line 1050
    iput-object v3, v0, Lg1/q0;->e:Ljava/lang/Object;

    .line 1051
    .line 1052
    iput-object v4, v0, Lg1/q0;->f:Ljava/lang/Object;

    .line 1053
    .line 1054
    iput-object v6, v0, Lg1/q0;->g:Ljava/lang/Object;

    .line 1055
    .line 1056
    iput-object v11, v0, Lg1/q0;->h:Lkotlin/jvm/internal/e0;

    .line 1057
    .line 1058
    iput-object v8, v0, Lg1/q0;->i:Lg1/i3;

    .line 1059
    .line 1060
    iput-object v14, v0, Lg1/q0;->j:Lp3/t;

    .line 1061
    .line 1062
    iput v2, v0, Lg1/q0;->l:F

    .line 1063
    .line 1064
    const/4 v9, 0x7

    .line 1065
    iput v9, v0, Lg1/q0;->m:I

    .line 1066
    .line 1067
    invoke-virtual {v4, v7, v0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1068
    .line 1069
    .line 1070
    move-result-object v7

    .line 1071
    if-ne v7, v1, :cond_26

    .line 1072
    .line 1073
    goto/16 :goto_24

    .line 1074
    .line 1075
    :cond_26
    :goto_20
    invoke-virtual {v14}, Lp3/t;->b()Z

    .line 1076
    .line 1077
    .line 1078
    move-result v7

    .line 1079
    if-eqz v7, :cond_24

    .line 1080
    .line 1081
    move-object v4, v5

    .line 1082
    goto/16 :goto_1c

    .line 1083
    .line 1084
    :goto_21
    move-object/from16 v7, v20

    .line 1085
    .line 1086
    goto/16 :goto_f

    .line 1087
    .line 1088
    :cond_27
    move-object/from16 v20, v7

    .line 1089
    .line 1090
    const-wide/16 v12, 0x0

    .line 1091
    .line 1092
    add-int/lit8 v8, v8, 0x1

    .line 1093
    .line 1094
    goto/16 :goto_15

    .line 1095
    .line 1096
    :cond_28
    move-object v5, v3

    .line 1097
    move-object v3, v2

    .line 1098
    goto/16 :goto_f

    .line 1099
    .line 1100
    :cond_29
    move-object/from16 v20, v7

    .line 1101
    .line 1102
    const-wide/16 v12, 0x0

    .line 1103
    .line 1104
    add-int/lit8 v8, v8, 0x1

    .line 1105
    .line 1106
    goto/16 :goto_10

    .line 1107
    .line 1108
    :cond_2a
    if-eqz v3, :cond_3b

    .line 1109
    .line 1110
    iget-wide v6, v10, Lkotlin/jvm/internal/e0;->d:J

    .line 1111
    .line 1112
    new-instance v2, Ld3/b;

    .line 1113
    .line 1114
    invoke-direct {v2, v6, v7}, Ld3/b;-><init>(J)V

    .line 1115
    .line 1116
    .line 1117
    iget-object v6, v0, Lg1/q0;->r:Lay0/o;

    .line 1118
    .line 1119
    invoke-interface {v6, v5, v3, v2}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1120
    .line 1121
    .line 1122
    iget-wide v5, v10, Lkotlin/jvm/internal/e0;->d:J

    .line 1123
    .line 1124
    new-instance v2, Ld3/b;

    .line 1125
    .line 1126
    invoke-direct {v2, v5, v6}, Ld3/b;-><init>(J)V

    .line 1127
    .line 1128
    .line 1129
    iget-object v5, v0, Lg1/q0;->s:Lay0/n;

    .line 1130
    .line 1131
    invoke-interface {v5, v3, v2}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1132
    .line 1133
    .line 1134
    iget-wide v2, v3, Lp3/t;->a:J

    .line 1135
    .line 1136
    iget-object v6, v4, Lp3/i0;->i:Lp3/j0;

    .line 1137
    .line 1138
    iget-object v6, v6, Lp3/j0;->w:Lp3/k;

    .line 1139
    .line 1140
    invoke-static {v6, v2, v3}, Lg1/w0;->g(Lp3/k;J)Z

    .line 1141
    .line 1142
    .line 1143
    move-result v6

    .line 1144
    if-eqz v6, :cond_2b

    .line 1145
    .line 1146
    const/4 v13, 0x0

    .line 1147
    goto/16 :goto_2f

    .line 1148
    .line 1149
    :cond_2b
    const/4 v15, 0x0

    .line 1150
    :goto_22
    new-instance v6, Lkotlin/jvm/internal/e0;

    .line 1151
    .line 1152
    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    .line 1153
    .line 1154
    .line 1155
    iput-wide v2, v6, Lkotlin/jvm/internal/e0;->d:J

    .line 1156
    .line 1157
    move-object v3, v4

    .line 1158
    move-object v2, v6

    .line 1159
    move-object v6, v3

    .line 1160
    move-object v4, v15

    .line 1161
    :goto_23
    iput-object v6, v0, Lg1/q0;->n:Ljava/lang/Object;

    .line 1162
    .line 1163
    iput-object v5, v0, Lg1/q0;->e:Ljava/lang/Object;

    .line 1164
    .line 1165
    iput-object v4, v0, Lg1/q0;->f:Ljava/lang/Object;

    .line 1166
    .line 1167
    iput-object v3, v0, Lg1/q0;->g:Ljava/lang/Object;

    .line 1168
    .line 1169
    iput-object v2, v0, Lg1/q0;->h:Lkotlin/jvm/internal/e0;

    .line 1170
    .line 1171
    const/4 v15, 0x0

    .line 1172
    iput-object v15, v0, Lg1/q0;->i:Lg1/i3;

    .line 1173
    .line 1174
    iput-object v15, v0, Lg1/q0;->j:Lp3/t;

    .line 1175
    .line 1176
    const/16 v7, 0x8

    .line 1177
    .line 1178
    iput v7, v0, Lg1/q0;->m:I

    .line 1179
    .line 1180
    sget-object v7, Lp3/l;->e:Lp3/l;

    .line 1181
    .line 1182
    invoke-virtual {v3, v7, v0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1183
    .line 1184
    .line 1185
    move-result-object v7

    .line 1186
    if-ne v7, v1, :cond_2c

    .line 1187
    .line 1188
    :goto_24
    return-object v1

    .line 1189
    :cond_2c
    :goto_25
    check-cast v7, Lp3/k;

    .line 1190
    .line 1191
    iget-object v8, v7, Lp3/k;->a:Ljava/lang/Object;

    .line 1192
    .line 1193
    move-object v9, v8

    .line 1194
    check-cast v9, Ljava/util/Collection;

    .line 1195
    .line 1196
    invoke-interface {v9}, Ljava/util/Collection;->size()I

    .line 1197
    .line 1198
    .line 1199
    move-result v9

    .line 1200
    const/4 v10, 0x0

    .line 1201
    :goto_26
    if-ge v10, v9, :cond_2e

    .line 1202
    .line 1203
    invoke-interface {v8, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1204
    .line 1205
    .line 1206
    move-result-object v11

    .line 1207
    move-object v12, v11

    .line 1208
    check-cast v12, Lp3/t;

    .line 1209
    .line 1210
    iget-wide v12, v12, Lp3/t;->a:J

    .line 1211
    .line 1212
    move-object v14, v8

    .line 1213
    move/from16 p1, v9

    .line 1214
    .line 1215
    iget-wide v8, v2, Lkotlin/jvm/internal/e0;->d:J

    .line 1216
    .line 1217
    invoke-static {v12, v13, v8, v9}, Lp3/s;->e(JJ)Z

    .line 1218
    .line 1219
    .line 1220
    move-result v8

    .line 1221
    if-eqz v8, :cond_2d

    .line 1222
    .line 1223
    goto :goto_27

    .line 1224
    :cond_2d
    add-int/lit8 v10, v10, 0x1

    .line 1225
    .line 1226
    move/from16 v9, p1

    .line 1227
    .line 1228
    move-object v8, v14

    .line 1229
    goto :goto_26

    .line 1230
    :cond_2e
    move-object v11, v15

    .line 1231
    :goto_27
    move-object v8, v11

    .line 1232
    check-cast v8, Lp3/t;

    .line 1233
    .line 1234
    if-nez v8, :cond_2f

    .line 1235
    .line 1236
    move-object v8, v15

    .line 1237
    :goto_28
    const/4 v7, 0x1

    .line 1238
    goto :goto_2d

    .line 1239
    :cond_2f
    invoke-static {v8}, Lp3/s;->d(Lp3/t;)Z

    .line 1240
    .line 1241
    .line 1242
    move-result v9

    .line 1243
    if-eqz v9, :cond_33

    .line 1244
    .line 1245
    iget-object v7, v7, Lp3/k;->a:Ljava/lang/Object;

    .line 1246
    .line 1247
    move-object v9, v7

    .line 1248
    check-cast v9, Ljava/util/Collection;

    .line 1249
    .line 1250
    invoke-interface {v9}, Ljava/util/Collection;->size()I

    .line 1251
    .line 1252
    .line 1253
    move-result v9

    .line 1254
    const/4 v10, 0x0

    .line 1255
    :goto_29
    if-ge v10, v9, :cond_31

    .line 1256
    .line 1257
    invoke-interface {v7, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1258
    .line 1259
    .line 1260
    move-result-object v11

    .line 1261
    move-object v12, v11

    .line 1262
    check-cast v12, Lp3/t;

    .line 1263
    .line 1264
    iget-boolean v12, v12, Lp3/t;->d:Z

    .line 1265
    .line 1266
    if-eqz v12, :cond_30

    .line 1267
    .line 1268
    goto :goto_2a

    .line 1269
    :cond_30
    add-int/lit8 v10, v10, 0x1

    .line 1270
    .line 1271
    goto :goto_29

    .line 1272
    :cond_31
    move-object v11, v15

    .line 1273
    :goto_2a
    check-cast v11, Lp3/t;

    .line 1274
    .line 1275
    if-nez v11, :cond_32

    .line 1276
    .line 1277
    goto :goto_28

    .line 1278
    :cond_32
    iget-wide v7, v11, Lp3/t;->a:J

    .line 1279
    .line 1280
    iput-wide v7, v2, Lkotlin/jvm/internal/e0;->d:J

    .line 1281
    .line 1282
    const/4 v7, 0x1

    .line 1283
    goto :goto_23

    .line 1284
    :cond_33
    const/4 v7, 0x1

    .line 1285
    invoke-static {v8, v7}, Lp3/s;->h(Lp3/t;Z)J

    .line 1286
    .line 1287
    .line 1288
    move-result-wide v9

    .line 1289
    if-nez v4, :cond_34

    .line 1290
    .line 1291
    invoke-static {v9, v10}, Ld3/b;->d(J)F

    .line 1292
    .line 1293
    .line 1294
    move-result v9

    .line 1295
    goto :goto_2c

    .line 1296
    :cond_34
    sget-object v11, Lg1/w1;->d:Lg1/w1;

    .line 1297
    .line 1298
    if-ne v4, v11, :cond_35

    .line 1299
    .line 1300
    const-wide v11, 0xffffffffL

    .line 1301
    .line 1302
    .line 1303
    .line 1304
    .line 1305
    and-long/2addr v9, v11

    .line 1306
    :goto_2b
    long-to-int v9, v9

    .line 1307
    invoke-static {v9}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 1308
    .line 1309
    .line 1310
    move-result v9

    .line 1311
    goto :goto_2c

    .line 1312
    :cond_35
    const/16 v11, 0x20

    .line 1313
    .line 1314
    shr-long/2addr v9, v11

    .line 1315
    goto :goto_2b

    .line 1316
    :goto_2c
    const/4 v10, 0x0

    .line 1317
    cmpg-float v9, v9, v10

    .line 1318
    .line 1319
    if-nez v9, :cond_36

    .line 1320
    .line 1321
    goto/16 :goto_23

    .line 1322
    .line 1323
    :cond_36
    :goto_2d
    if-nez v8, :cond_37

    .line 1324
    .line 1325
    :goto_2e
    move-object v13, v15

    .line 1326
    goto :goto_2f

    .line 1327
    :cond_37
    invoke-virtual {v8}, Lp3/t;->b()Z

    .line 1328
    .line 1329
    .line 1330
    move-result v2

    .line 1331
    if-eqz v2, :cond_38

    .line 1332
    .line 1333
    goto :goto_2e

    .line 1334
    :cond_38
    invoke-static {v8}, Lp3/s;->d(Lp3/t;)Z

    .line 1335
    .line 1336
    .line 1337
    move-result v2

    .line 1338
    if-eqz v2, :cond_3a

    .line 1339
    .line 1340
    move-object v13, v8

    .line 1341
    :goto_2f
    if-nez v13, :cond_39

    .line 1342
    .line 1343
    iget-object v0, v0, Lg1/q0;->t:Lay0/a;

    .line 1344
    .line 1345
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 1346
    .line 1347
    .line 1348
    goto :goto_30

    .line 1349
    :cond_39
    iget-object v0, v0, Lg1/q0;->u:Lay0/k;

    .line 1350
    .line 1351
    invoke-interface {v0, v13}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1352
    .line 1353
    .line 1354
    goto :goto_30

    .line 1355
    :cond_3a
    const/4 v2, 0x0

    .line 1356
    invoke-static {v8, v2}, Lp3/s;->h(Lp3/t;Z)J

    .line 1357
    .line 1358
    .line 1359
    move-result-wide v9

    .line 1360
    new-instance v3, Ld3/b;

    .line 1361
    .line 1362
    invoke-direct {v3, v9, v10}, Ld3/b;-><init>(J)V

    .line 1363
    .line 1364
    .line 1365
    invoke-interface {v5, v8, v3}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1366
    .line 1367
    .line 1368
    invoke-virtual {v8}, Lp3/t;->a()V

    .line 1369
    .line 1370
    .line 1371
    iget-wide v8, v8, Lp3/t;->a:J

    .line 1372
    .line 1373
    move-object v15, v4

    .line 1374
    move-object v4, v6

    .line 1375
    move-wide v2, v8

    .line 1376
    goto/16 :goto_22

    .line 1377
    .line 1378
    :cond_3b
    :goto_30
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1379
    .line 1380
    return-object v0

    .line 1381
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
