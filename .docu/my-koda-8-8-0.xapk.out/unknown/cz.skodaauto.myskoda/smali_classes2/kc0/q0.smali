.class public final Lkc0/q0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lic0/a;

.field public final b:Lbd0/c;

.field public final c:Lkc0/g;

.field public final d:Lkc0/h;

.field public final e:Lam0/c;

.field public final f:Lwr0/e;

.field public final g:Lwr0/c;

.field public final h:Lwr0/o;


# direct methods
.method public constructor <init>(Lic0/a;Lbd0/c;Lkc0/g;Lkc0/h;Lam0/c;Lwr0/e;Lwr0/c;Lwr0/o;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkc0/q0;->a:Lic0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lkc0/q0;->b:Lbd0/c;

    .line 7
    .line 8
    iput-object p3, p0, Lkc0/q0;->c:Lkc0/g;

    .line 9
    .line 10
    iput-object p4, p0, Lkc0/q0;->d:Lkc0/h;

    .line 11
    .line 12
    iput-object p5, p0, Lkc0/q0;->e:Lam0/c;

    .line 13
    .line 14
    iput-object p6, p0, Lkc0/q0;->f:Lwr0/e;

    .line 15
    .line 16
    iput-object p7, p0, Lkc0/q0;->g:Lwr0/c;

    .line 17
    .line 18
    iput-object p8, p0, Lkc0/q0;->h:Lwr0/o;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, [Llc0/l;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lkc0/q0;->b([Llc0/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b([Llc0/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p2

    .line 4
    .line 5
    instance-of v2, v0, Lkc0/o0;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v0

    .line 10
    check-cast v2, Lkc0/o0;

    .line 11
    .line 12
    iget v3, v2, Lkc0/o0;->r:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Lkc0/o0;->r:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lkc0/o0;

    .line 25
    .line 26
    invoke-direct {v2, v1, v0}, Lkc0/o0;-><init>(Lkc0/q0;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v0, v2, Lkc0/o0;->p:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lkc0/o0;->r:I

    .line 34
    .line 35
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    const/4 v6, 0x1

    .line 38
    const/4 v7, 0x0

    .line 39
    const/4 v8, 0x0

    .line 40
    packed-switch v4, :pswitch_data_0

    .line 41
    .line 42
    .line 43
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw v0

    .line 51
    :pswitch_0
    iget-object v3, v2, Lkc0/o0;->g:[Llc0/l;

    .line 52
    .line 53
    check-cast v3, Ljava/util/List;

    .line 54
    .line 55
    iget-object v2, v2, Lkc0/o0;->f:Ljava/util/List;

    .line 56
    .line 57
    check-cast v2, Ljava/util/List;

    .line 58
    .line 59
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    goto/16 :goto_12

    .line 63
    .line 64
    :pswitch_1
    iget v4, v2, Lkc0/o0;->l:I

    .line 65
    .line 66
    iget-object v9, v2, Lkc0/o0;->i:Ljava/lang/Throwable;

    .line 67
    .line 68
    check-cast v9, Lne0/t;

    .line 69
    .line 70
    iget-object v9, v2, Lkc0/o0;->h:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast v9, Ljava/util/Iterator;

    .line 73
    .line 74
    iget-object v10, v2, Lkc0/o0;->g:[Llc0/l;

    .line 75
    .line 76
    check-cast v10, Ljava/util/List;

    .line 77
    .line 78
    iget-object v10, v2, Lkc0/o0;->f:Ljava/util/List;

    .line 79
    .line 80
    check-cast v10, Ljava/util/List;

    .line 81
    .line 82
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    move v10, v6

    .line 86
    goto/16 :goto_10

    .line 87
    .line 88
    :pswitch_2
    iget v4, v2, Lkc0/o0;->n:I

    .line 89
    .line 90
    iget v9, v2, Lkc0/o0;->m:I

    .line 91
    .line 92
    iget v10, v2, Lkc0/o0;->l:I

    .line 93
    .line 94
    iget-object v11, v2, Lkc0/o0;->j:Llc0/k;

    .line 95
    .line 96
    iget-object v12, v2, Lkc0/o0;->i:Ljava/lang/Throwable;

    .line 97
    .line 98
    check-cast v12, Lne0/t;

    .line 99
    .line 100
    iget-object v12, v2, Lkc0/o0;->h:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast v12, Ljava/util/Iterator;

    .line 103
    .line 104
    iget-object v13, v2, Lkc0/o0;->g:[Llc0/l;

    .line 105
    .line 106
    check-cast v13, Ljava/util/List;

    .line 107
    .line 108
    iget-object v13, v2, Lkc0/o0;->f:Ljava/util/List;

    .line 109
    .line 110
    check-cast v13, Ljava/util/List;

    .line 111
    .line 112
    :try_start_0
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 113
    .line 114
    .line 115
    move v0, v4

    .line 116
    move v4, v10

    .line 117
    move v10, v6

    .line 118
    move v6, v9

    .line 119
    move-object v9, v12

    .line 120
    goto/16 :goto_f

    .line 121
    .line 122
    :pswitch_3
    iget-object v4, v2, Lkc0/o0;->f:Ljava/util/List;

    .line 123
    .line 124
    check-cast v4, Ljava/util/List;

    .line 125
    .line 126
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    move/from16 p2, v6

    .line 130
    .line 131
    goto/16 :goto_c

    .line 132
    .line 133
    :pswitch_4
    iget v1, v2, Lkc0/o0;->o:I

    .line 134
    .line 135
    iget v4, v2, Lkc0/o0;->n:I

    .line 136
    .line 137
    iget v5, v2, Lkc0/o0;->m:I

    .line 138
    .line 139
    iget v6, v2, Lkc0/o0;->l:I

    .line 140
    .line 141
    iget-object v7, v2, Lkc0/o0;->k:Ljava/util/Iterator;

    .line 142
    .line 143
    iget-object v9, v2, Lkc0/o0;->j:Llc0/k;

    .line 144
    .line 145
    check-cast v9, Ljava/lang/Iterable;

    .line 146
    .line 147
    iget-object v9, v2, Lkc0/o0;->i:Ljava/lang/Throwable;

    .line 148
    .line 149
    iget-object v10, v2, Lkc0/o0;->h:Ljava/lang/Object;

    .line 150
    .line 151
    check-cast v10, Llc0/l;

    .line 152
    .line 153
    iget-object v10, v2, Lkc0/o0;->f:Ljava/util/List;

    .line 154
    .line 155
    check-cast v10, Ljava/util/List;

    .line 156
    .line 157
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    move v0, v4

    .line 161
    move-object v10, v9

    .line 162
    goto/16 :goto_a

    .line 163
    .line 164
    :pswitch_5
    iget v4, v2, Lkc0/o0;->o:I

    .line 165
    .line 166
    iget v9, v2, Lkc0/o0;->n:I

    .line 167
    .line 168
    iget v10, v2, Lkc0/o0;->m:I

    .line 169
    .line 170
    iget v11, v2, Lkc0/o0;->l:I

    .line 171
    .line 172
    iget-object v12, v2, Lkc0/o0;->i:Ljava/lang/Throwable;

    .line 173
    .line 174
    check-cast v12, Lkc0/q0;

    .line 175
    .line 176
    iget-object v12, v2, Lkc0/o0;->h:Ljava/lang/Object;

    .line 177
    .line 178
    check-cast v12, Llc0/l;

    .line 179
    .line 180
    iget-object v12, v2, Lkc0/o0;->g:[Llc0/l;

    .line 181
    .line 182
    iget-object v13, v2, Lkc0/o0;->f:Ljava/util/List;

    .line 183
    .line 184
    check-cast v13, Ljava/util/List;

    .line 185
    .line 186
    iget-object v14, v2, Lkc0/o0;->e:Lcm0/b;

    .line 187
    .line 188
    :try_start_1
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 189
    .line 190
    .line 191
    move/from16 p2, v6

    .line 192
    .line 193
    goto/16 :goto_5

    .line 194
    .line 195
    :catchall_0
    move-exception v0

    .line 196
    move/from16 p2, v6

    .line 197
    .line 198
    goto/16 :goto_8

    .line 199
    .line 200
    :pswitch_6
    iget v4, v2, Lkc0/o0;->o:I

    .line 201
    .line 202
    iget v9, v2, Lkc0/o0;->n:I

    .line 203
    .line 204
    iget v10, v2, Lkc0/o0;->m:I

    .line 205
    .line 206
    iget v11, v2, Lkc0/o0;->l:I

    .line 207
    .line 208
    iget-object v12, v2, Lkc0/o0;->h:Ljava/lang/Object;

    .line 209
    .line 210
    check-cast v12, Llc0/l;

    .line 211
    .line 212
    iget-object v13, v2, Lkc0/o0;->g:[Llc0/l;

    .line 213
    .line 214
    iget-object v14, v2, Lkc0/o0;->f:Ljava/util/List;

    .line 215
    .line 216
    check-cast v14, Ljava/util/List;

    .line 217
    .line 218
    iget-object v15, v2, Lkc0/o0;->e:Lcm0/b;

    .line 219
    .line 220
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 221
    .line 222
    .line 223
    goto/16 :goto_3

    .line 224
    .line 225
    :pswitch_7
    iget-object v4, v2, Lkc0/o0;->d:[Llc0/l;

    .line 226
    .line 227
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 228
    .line 229
    .line 230
    move-object/from16 v16, v4

    .line 231
    .line 232
    move-object v4, v0

    .line 233
    move-object/from16 v0, v16

    .line 234
    .line 235
    goto :goto_1

    .line 236
    :pswitch_8
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 237
    .line 238
    .line 239
    move-object/from16 v0, p1

    .line 240
    .line 241
    iput-object v0, v2, Lkc0/o0;->d:[Llc0/l;

    .line 242
    .line 243
    iput v6, v2, Lkc0/o0;->r:I

    .line 244
    .line 245
    iget-object v4, v1, Lkc0/q0;->e:Lam0/c;

    .line 246
    .line 247
    invoke-virtual {v4, v5, v2}, Lam0/c;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    move-result-object v4

    .line 251
    if-ne v4, v3, :cond_1

    .line 252
    .line 253
    goto/16 :goto_11

    .line 254
    .line 255
    :cond_1
    :goto_1
    check-cast v4, Lcm0/b;

    .line 256
    .line 257
    new-instance v9, Ljava/util/ArrayList;

    .line 258
    .line 259
    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    .line 260
    .line 261
    .line 262
    array-length v10, v0

    .line 263
    move v11, v7

    .line 264
    move v12, v11

    .line 265
    :goto_2
    if-ge v11, v10, :cond_8

    .line 266
    .line 267
    aget-object v13, v0, v11

    .line 268
    .line 269
    iput-object v8, v2, Lkc0/o0;->d:[Llc0/l;

    .line 270
    .line 271
    iput-object v4, v2, Lkc0/o0;->e:Lcm0/b;

    .line 272
    .line 273
    move-object v14, v9

    .line 274
    check-cast v14, Ljava/util/List;

    .line 275
    .line 276
    iput-object v14, v2, Lkc0/o0;->f:Ljava/util/List;

    .line 277
    .line 278
    iput-object v0, v2, Lkc0/o0;->g:[Llc0/l;

    .line 279
    .line 280
    iput-object v13, v2, Lkc0/o0;->h:Ljava/lang/Object;

    .line 281
    .line 282
    iput-object v8, v2, Lkc0/o0;->i:Ljava/lang/Throwable;

    .line 283
    .line 284
    iput v12, v2, Lkc0/o0;->l:I

    .line 285
    .line 286
    iput v11, v2, Lkc0/o0;->m:I

    .line 287
    .line 288
    iput v10, v2, Lkc0/o0;->n:I

    .line 289
    .line 290
    iput v7, v2, Lkc0/o0;->o:I

    .line 291
    .line 292
    const/4 v14, 0x2

    .line 293
    iput v14, v2, Lkc0/o0;->r:I

    .line 294
    .line 295
    iget-object v14, v1, Lkc0/q0;->f:Lwr0/e;

    .line 296
    .line 297
    iget-object v14, v14, Lwr0/e;->a:Lwr0/g;

    .line 298
    .line 299
    check-cast v14, Lur0/g;

    .line 300
    .line 301
    invoke-virtual {v14, v2}, Lur0/g;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 302
    .line 303
    .line 304
    move-result-object v14

    .line 305
    if-ne v14, v3, :cond_2

    .line 306
    .line 307
    goto/16 :goto_11

    .line 308
    .line 309
    :cond_2
    move-object v15, v13

    .line 310
    move-object v13, v0

    .line 311
    move-object v0, v14

    .line 312
    move-object v14, v9

    .line 313
    move v9, v10

    .line 314
    move v10, v11

    .line 315
    move v11, v12

    .line 316
    move-object v12, v15

    .line 317
    move-object v15, v4

    .line 318
    move v4, v7

    .line 319
    :goto_3
    check-cast v0, Lyr0/e;

    .line 320
    .line 321
    if-eqz v0, :cond_3

    .line 322
    .line 323
    iget-object v0, v0, Lyr0/e;->b:Ljava/lang/String;

    .line 324
    .line 325
    goto :goto_4

    .line 326
    :cond_3
    move-object v0, v8

    .line 327
    :goto_4
    :try_start_2
    iput-object v8, v2, Lkc0/o0;->d:[Llc0/l;

    .line 328
    .line 329
    iput-object v15, v2, Lkc0/o0;->e:Lcm0/b;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_3

    .line 330
    .line 331
    move/from16 p2, v6

    .line 332
    .line 333
    :try_start_3
    move-object v6, v14

    .line 334
    check-cast v6, Ljava/util/List;

    .line 335
    .line 336
    iput-object v6, v2, Lkc0/o0;->f:Ljava/util/List;

    .line 337
    .line 338
    iput-object v13, v2, Lkc0/o0;->g:[Llc0/l;

    .line 339
    .line 340
    iput-object v8, v2, Lkc0/o0;->h:Ljava/lang/Object;

    .line 341
    .line 342
    iput-object v8, v2, Lkc0/o0;->i:Ljava/lang/Throwable;

    .line 343
    .line 344
    iput v11, v2, Lkc0/o0;->l:I

    .line 345
    .line 346
    iput v10, v2, Lkc0/o0;->m:I

    .line 347
    .line 348
    iput v9, v2, Lkc0/o0;->n:I

    .line 349
    .line 350
    iput v4, v2, Lkc0/o0;->o:I

    .line 351
    .line 352
    const/4 v6, 0x3

    .line 353
    iput v6, v2, Lkc0/o0;->r:I

    .line 354
    .line 355
    invoke-virtual {v1, v12, v15, v0, v2}, Lkc0/q0;->d(Llc0/l;Lcm0/b;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 356
    .line 357
    .line 358
    move-result-object v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 359
    if-ne v0, v3, :cond_4

    .line 360
    .line 361
    goto/16 :goto_11

    .line 362
    .line 363
    :cond_4
    move-object v12, v13

    .line 364
    move-object v13, v14

    .line 365
    move-object v14, v15

    .line 366
    :goto_5
    :try_start_4
    check-cast v0, Lvy0/h0;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 367
    .line 368
    :goto_6
    move v6, v11

    .line 369
    move v11, v9

    .line 370
    move-object v9, v13

    .line 371
    move v13, v6

    .line 372
    move v6, v4

    .line 373
    move-object v4, v14

    .line 374
    goto :goto_9

    .line 375
    :catchall_1
    move-exception v0

    .line 376
    goto :goto_8

    .line 377
    :catchall_2
    move-exception v0

    .line 378
    :goto_7
    move-object v12, v13

    .line 379
    move-object v13, v14

    .line 380
    move-object v14, v15

    .line 381
    goto :goto_8

    .line 382
    :catchall_3
    move-exception v0

    .line 383
    move/from16 p2, v6

    .line 384
    .line 385
    goto :goto_7

    .line 386
    :goto_8
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 387
    .line 388
    .line 389
    move-result-object v0

    .line 390
    goto :goto_6

    .line 391
    :goto_9
    invoke-static {v0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 392
    .line 393
    .line 394
    move-result-object v14

    .line 395
    if-nez v14, :cond_5

    .line 396
    .line 397
    check-cast v0, Lvy0/h0;

    .line 398
    .line 399
    invoke-interface {v9, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 400
    .line 401
    .line 402
    add-int/lit8 v0, v10, 0x1

    .line 403
    .line 404
    move/from16 v6, p2

    .line 405
    .line 406
    move v10, v11

    .line 407
    move v11, v0

    .line 408
    move-object v0, v12

    .line 409
    move v12, v13

    .line 410
    goto/16 :goto_2

    .line 411
    .line 412
    :cond_5
    check-cast v9, Ljava/lang/Iterable;

    .line 413
    .line 414
    invoke-interface {v9}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 415
    .line 416
    .line 417
    move-result-object v0

    .line 418
    move v5, v6

    .line 419
    move v1, v7

    .line 420
    move v6, v13

    .line 421
    move-object v10, v14

    .line 422
    move-object v7, v0

    .line 423
    move v0, v1

    .line 424
    :cond_6
    :goto_a
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 425
    .line 426
    .line 427
    move-result v4

    .line 428
    if-eqz v4, :cond_7

    .line 429
    .line 430
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 431
    .line 432
    .line 433
    move-result-object v4

    .line 434
    check-cast v4, Lvy0/h0;

    .line 435
    .line 436
    iput-object v8, v2, Lkc0/o0;->d:[Llc0/l;

    .line 437
    .line 438
    iput-object v8, v2, Lkc0/o0;->e:Lcm0/b;

    .line 439
    .line 440
    iput-object v8, v2, Lkc0/o0;->f:Ljava/util/List;

    .line 441
    .line 442
    iput-object v8, v2, Lkc0/o0;->g:[Llc0/l;

    .line 443
    .line 444
    iput-object v8, v2, Lkc0/o0;->h:Ljava/lang/Object;

    .line 445
    .line 446
    iput-object v10, v2, Lkc0/o0;->i:Ljava/lang/Throwable;

    .line 447
    .line 448
    iput-object v8, v2, Lkc0/o0;->j:Llc0/k;

    .line 449
    .line 450
    iput-object v7, v2, Lkc0/o0;->k:Ljava/util/Iterator;

    .line 451
    .line 452
    iput v6, v2, Lkc0/o0;->l:I

    .line 453
    .line 454
    iput v5, v2, Lkc0/o0;->m:I

    .line 455
    .line 456
    iput v0, v2, Lkc0/o0;->n:I

    .line 457
    .line 458
    iput v1, v2, Lkc0/o0;->o:I

    .line 459
    .line 460
    const/4 v9, 0x4

    .line 461
    iput v9, v2, Lkc0/o0;->r:I

    .line 462
    .line 463
    invoke-static {v4, v2}, Lvy0/e0;->m(Lvy0/i1;Lrx0/c;)Ljava/lang/Object;

    .line 464
    .line 465
    .line 466
    move-result-object v4

    .line 467
    if-ne v4, v3, :cond_6

    .line 468
    .line 469
    goto/16 :goto_11

    .line 470
    .line 471
    :cond_7
    new-instance v9, Lne0/c;

    .line 472
    .line 473
    const/4 v13, 0x0

    .line 474
    const/16 v14, 0x1e

    .line 475
    .line 476
    const/4 v11, 0x0

    .line 477
    const/4 v12, 0x0

    .line 478
    invoke-direct/range {v9 .. v14}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 479
    .line 480
    .line 481
    return-object v9

    .line 482
    :cond_8
    move/from16 p2, v6

    .line 483
    .line 484
    check-cast v9, Ljava/util/Collection;

    .line 485
    .line 486
    new-array v0, v7, [Lvy0/h0;

    .line 487
    .line 488
    invoke-interface {v9, v0}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 489
    .line 490
    .line 491
    move-result-object v0

    .line 492
    check-cast v0, [Lvy0/h0;

    .line 493
    .line 494
    array-length v4, v0

    .line 495
    invoke-static {v0, v4}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 496
    .line 497
    .line 498
    move-result-object v0

    .line 499
    check-cast v0, [Lvy0/h0;

    .line 500
    .line 501
    iput-object v8, v2, Lkc0/o0;->d:[Llc0/l;

    .line 502
    .line 503
    iput-object v8, v2, Lkc0/o0;->e:Lcm0/b;

    .line 504
    .line 505
    iput-object v8, v2, Lkc0/o0;->f:Ljava/util/List;

    .line 506
    .line 507
    iput-object v8, v2, Lkc0/o0;->g:[Llc0/l;

    .line 508
    .line 509
    iput-object v8, v2, Lkc0/o0;->h:Ljava/lang/Object;

    .line 510
    .line 511
    iput-object v8, v2, Lkc0/o0;->i:Ljava/lang/Throwable;

    .line 512
    .line 513
    const/4 v4, 0x5

    .line 514
    iput v4, v2, Lkc0/o0;->r:I

    .line 515
    .line 516
    array-length v4, v0

    .line 517
    if-nez v4, :cond_9

    .line 518
    .line 519
    sget-object v0, Lmx0/s;->d:Lmx0/s;

    .line 520
    .line 521
    goto :goto_b

    .line 522
    :cond_9
    new-instance v4, Lvy0/e;

    .line 523
    .line 524
    invoke-direct {v4, v0}, Lvy0/e;-><init>([Lvy0/h0;)V

    .line 525
    .line 526
    .line 527
    invoke-virtual {v4, v2}, Lvy0/e;->a(Lrx0/c;)Ljava/lang/Object;

    .line 528
    .line 529
    .line 530
    move-result-object v0

    .line 531
    :goto_b
    if-ne v0, v3, :cond_a

    .line 532
    .line 533
    goto/16 :goto_11

    .line 534
    .line 535
    :cond_a
    :goto_c
    check-cast v0, Ljava/util/List;

    .line 536
    .line 537
    check-cast v0, Ljava/lang/Iterable;

    .line 538
    .line 539
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 540
    .line 541
    .line 542
    move-result-object v4

    .line 543
    :cond_b
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 544
    .line 545
    .line 546
    move-result v6

    .line 547
    if-eqz v6, :cond_c

    .line 548
    .line 549
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 550
    .line 551
    .line 552
    move-result-object v6

    .line 553
    move-object v9, v6

    .line 554
    check-cast v9, Lne0/t;

    .line 555
    .line 556
    instance-of v9, v9, Lne0/c;

    .line 557
    .line 558
    if-eqz v9, :cond_b

    .line 559
    .line 560
    goto :goto_d

    .line 561
    :cond_c
    move-object v6, v8

    .line 562
    :goto_d
    check-cast v6, Lne0/t;

    .line 563
    .line 564
    if-eqz v6, :cond_d

    .line 565
    .line 566
    new-instance v9, Lne0/c;

    .line 567
    .line 568
    check-cast v6, Lne0/c;

    .line 569
    .line 570
    iget-object v10, v6, Lne0/c;->a:Ljava/lang/Throwable;

    .line 571
    .line 572
    const/4 v13, 0x0

    .line 573
    const/16 v14, 0x1e

    .line 574
    .line 575
    const/4 v11, 0x0

    .line 576
    const/4 v12, 0x0

    .line 577
    invoke-direct/range {v9 .. v14}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 578
    .line 579
    .line 580
    return-object v9

    .line 581
    :cond_d
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 582
    .line 583
    .line 584
    move-result-object v0

    .line 585
    move-object v9, v0

    .line 586
    move v4, v7

    .line 587
    :goto_e
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 588
    .line 589
    .line 590
    move-result v0

    .line 591
    if-eqz v0, :cond_14

    .line 592
    .line 593
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 594
    .line 595
    .line 596
    move-result-object v0

    .line 597
    check-cast v0, Lne0/t;

    .line 598
    .line 599
    instance-of v6, v0, Lne0/e;

    .line 600
    .line 601
    const-string v10, "Check failed."

    .line 602
    .line 603
    if-eqz v6, :cond_13

    .line 604
    .line 605
    check-cast v0, Lne0/e;

    .line 606
    .line 607
    iget-object v0, v0, Lne0/e;->a:Ljava/lang/Object;

    .line 608
    .line 609
    move-object v11, v0

    .line 610
    check-cast v11, Llc0/k;

    .line 611
    .line 612
    iget-object v0, v11, Llc0/k;->b:Ljava/lang/String;

    .line 613
    .line 614
    iget-object v6, v11, Llc0/k;->c:Ljava/lang/String;

    .line 615
    .line 616
    iget-object v12, v11, Llc0/k;->d:Ljava/lang/String;

    .line 617
    .line 618
    if-eqz v0, :cond_12

    .line 619
    .line 620
    if-eqz v6, :cond_12

    .line 621
    .line 622
    if-eqz v12, :cond_12

    .line 623
    .line 624
    iget-object v0, v11, Llc0/k;->a:Llc0/l;

    .line 625
    .line 626
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 627
    .line 628
    .line 629
    move-result v0

    .line 630
    if-eqz v0, :cond_f

    .line 631
    .line 632
    move/from16 v10, p2

    .line 633
    .line 634
    if-ne v0, v10, :cond_e

    .line 635
    .line 636
    iget-object v0, v11, Llc0/k;->b:Ljava/lang/String;

    .line 637
    .line 638
    iput-object v8, v2, Lkc0/o0;->d:[Llc0/l;

    .line 639
    .line 640
    iput-object v8, v2, Lkc0/o0;->e:Lcm0/b;

    .line 641
    .line 642
    iput-object v8, v2, Lkc0/o0;->f:Ljava/util/List;

    .line 643
    .line 644
    iput-object v8, v2, Lkc0/o0;->g:[Llc0/l;

    .line 645
    .line 646
    iput-object v9, v2, Lkc0/o0;->h:Ljava/lang/Object;

    .line 647
    .line 648
    iput-object v8, v2, Lkc0/o0;->i:Ljava/lang/Throwable;

    .line 649
    .line 650
    iput-object v8, v2, Lkc0/o0;->j:Llc0/k;

    .line 651
    .line 652
    iput v4, v2, Lkc0/o0;->l:I

    .line 653
    .line 654
    iput v7, v2, Lkc0/o0;->m:I

    .line 655
    .line 656
    iput v7, v2, Lkc0/o0;->n:I

    .line 657
    .line 658
    const/16 v11, 0x8

    .line 659
    .line 660
    iput v11, v2, Lkc0/o0;->r:I

    .line 661
    .line 662
    iget-object v11, v1, Lkc0/q0;->d:Lkc0/h;

    .line 663
    .line 664
    check-cast v11, Lic0/p;

    .line 665
    .line 666
    invoke-virtual {v11, v0, v6, v12, v2}, Lic0/p;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 667
    .line 668
    .line 669
    move-result-object v0

    .line 670
    if-ne v0, v3, :cond_11

    .line 671
    .line 672
    goto/16 :goto_11

    .line 673
    .line 674
    :cond_e
    new-instance v0, La8/r0;

    .line 675
    .line 676
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 677
    .line 678
    .line 679
    throw v0

    .line 680
    :cond_f
    move/from16 v10, p2

    .line 681
    .line 682
    :try_start_5
    iput-object v8, v2, Lkc0/o0;->d:[Llc0/l;

    .line 683
    .line 684
    iput-object v8, v2, Lkc0/o0;->e:Lcm0/b;

    .line 685
    .line 686
    iput-object v8, v2, Lkc0/o0;->f:Ljava/util/List;

    .line 687
    .line 688
    iput-object v8, v2, Lkc0/o0;->g:[Llc0/l;

    .line 689
    .line 690
    iput-object v9, v2, Lkc0/o0;->h:Ljava/lang/Object;

    .line 691
    .line 692
    iput-object v8, v2, Lkc0/o0;->i:Ljava/lang/Throwable;

    .line 693
    .line 694
    iput-object v11, v2, Lkc0/o0;->j:Llc0/k;

    .line 695
    .line 696
    iput v4, v2, Lkc0/o0;->l:I

    .line 697
    .line 698
    iput v7, v2, Lkc0/o0;->m:I

    .line 699
    .line 700
    iput v7, v2, Lkc0/o0;->n:I

    .line 701
    .line 702
    const/4 v0, 0x6

    .line 703
    iput v0, v2, Lkc0/o0;->r:I

    .line 704
    .line 705
    invoke-virtual {v1, v12, v2}, Lkc0/q0;->c(Ljava/lang/String;Lkc0/o0;)Ljava/lang/Object;

    .line 706
    .line 707
    .line 708
    move-result-object v0
    :try_end_5
    .catch Ljava/lang/IllegalStateException; {:try_start_5 .. :try_end_5} :catch_0

    .line 709
    if-ne v0, v3, :cond_10

    .line 710
    .line 711
    goto :goto_11

    .line 712
    :cond_10
    move v0, v7

    .line 713
    move v6, v0

    .line 714
    :goto_f
    iget-object v12, v11, Llc0/k;->b:Ljava/lang/String;

    .line 715
    .line 716
    iget-object v13, v11, Llc0/k;->c:Ljava/lang/String;

    .line 717
    .line 718
    iget-object v11, v11, Llc0/k;->d:Ljava/lang/String;

    .line 719
    .line 720
    iput-object v8, v2, Lkc0/o0;->d:[Llc0/l;

    .line 721
    .line 722
    iput-object v8, v2, Lkc0/o0;->e:Lcm0/b;

    .line 723
    .line 724
    iput-object v8, v2, Lkc0/o0;->f:Ljava/util/List;

    .line 725
    .line 726
    iput-object v8, v2, Lkc0/o0;->g:[Llc0/l;

    .line 727
    .line 728
    iput-object v9, v2, Lkc0/o0;->h:Ljava/lang/Object;

    .line 729
    .line 730
    iput-object v8, v2, Lkc0/o0;->i:Ljava/lang/Throwable;

    .line 731
    .line 732
    iput-object v8, v2, Lkc0/o0;->j:Llc0/k;

    .line 733
    .line 734
    iput v4, v2, Lkc0/o0;->l:I

    .line 735
    .line 736
    iput v6, v2, Lkc0/o0;->m:I

    .line 737
    .line 738
    iput v0, v2, Lkc0/o0;->n:I

    .line 739
    .line 740
    const/4 v0, 0x7

    .line 741
    iput v0, v2, Lkc0/o0;->r:I

    .line 742
    .line 743
    iget-object v0, v1, Lkc0/q0;->c:Lkc0/g;

    .line 744
    .line 745
    check-cast v0, Lic0/p;

    .line 746
    .line 747
    invoke-virtual {v0, v12, v13, v11, v2}, Lic0/p;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 748
    .line 749
    .line 750
    move-result-object v0

    .line 751
    if-ne v0, v3, :cond_11

    .line 752
    .line 753
    goto :goto_11

    .line 754
    :cond_11
    :goto_10
    move/from16 p2, v10

    .line 755
    .line 756
    goto/16 :goto_e

    .line 757
    .line 758
    :catch_0
    move-exception v0

    .line 759
    move-object v2, v0

    .line 760
    new-instance v1, Lne0/c;

    .line 761
    .line 762
    const/4 v5, 0x0

    .line 763
    const/16 v6, 0x1e

    .line 764
    .line 765
    const/4 v3, 0x0

    .line 766
    const/4 v4, 0x0

    .line 767
    invoke-direct/range {v1 .. v6}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 768
    .line 769
    .line 770
    return-object v1

    .line 771
    :cond_12
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 772
    .line 773
    invoke-direct {v0, v10}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 774
    .line 775
    .line 776
    throw v0

    .line 777
    :cond_13
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 778
    .line 779
    invoke-direct {v0, v10}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 780
    .line 781
    .line 782
    throw v0

    .line 783
    :cond_14
    iget-object v0, v1, Lkc0/q0;->g:Lwr0/c;

    .line 784
    .line 785
    invoke-virtual {v0}, Lwr0/c;->invoke()Ljava/lang/Object;

    .line 786
    .line 787
    .line 788
    move-result-object v0

    .line 789
    check-cast v0, Lyy0/i;

    .line 790
    .line 791
    iput-object v8, v2, Lkc0/o0;->d:[Llc0/l;

    .line 792
    .line 793
    iput-object v8, v2, Lkc0/o0;->e:Lcm0/b;

    .line 794
    .line 795
    iput-object v8, v2, Lkc0/o0;->f:Ljava/util/List;

    .line 796
    .line 797
    iput-object v8, v2, Lkc0/o0;->g:[Llc0/l;

    .line 798
    .line 799
    iput-object v8, v2, Lkc0/o0;->h:Ljava/lang/Object;

    .line 800
    .line 801
    iput-object v8, v2, Lkc0/o0;->i:Ljava/lang/Throwable;

    .line 802
    .line 803
    iput-object v8, v2, Lkc0/o0;->j:Llc0/k;

    .line 804
    .line 805
    const/16 v4, 0x9

    .line 806
    .line 807
    iput v4, v2, Lkc0/o0;->r:I

    .line 808
    .line 809
    invoke-static {v0, v2}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 810
    .line 811
    .line 812
    move-result-object v0

    .line 813
    if-ne v0, v3, :cond_15

    .line 814
    .line 815
    :goto_11
    return-object v3

    .line 816
    :cond_15
    :goto_12
    new-instance v0, Ljv0/c;

    .line 817
    .line 818
    const/4 v2, 0x4

    .line 819
    invoke-direct {v0, v2}, Ljv0/c;-><init>(I)V

    .line 820
    .line 821
    .line 822
    const-string v2, "Authentication"

    .line 823
    .line 824
    invoke-static {v2, v1, v0}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 825
    .line 826
    .line 827
    new-instance v0, Lne0/e;

    .line 828
    .line 829
    invoke-direct {v0, v5}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 830
    .line 831
    .line 832
    return-object v0

    .line 833
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
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final c(Ljava/lang/String;Lkc0/o0;)Ljava/lang/Object;
    .locals 17

    .line 1
    new-instance v0, Lcom/auth0/android/jwt/c;

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lcom/auth0/android/jwt/c;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v1, "sub"

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Lcom/auth0/android/jwt/c;->b(Ljava/lang/String;)Lcom/auth0/android/jwt/a;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v1}, Lcom/auth0/android/jwt/a;->a()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    if-eqz v3, :cond_2

    .line 19
    .line 20
    const-string v1, "email"

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Lcom/auth0/android/jwt/c;->b(Ljava/lang/String;)Lcom/auth0/android/jwt/a;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-virtual {v0}, Lcom/auth0/android/jwt/a;->a()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v4

    .line 30
    if-eqz v4, :cond_1

    .line 31
    .line 32
    new-instance v0, Lwr0/m;

    .line 33
    .line 34
    new-instance v2, Lyr0/e;

    .line 35
    .line 36
    sget-object v16, Lmx0/s;->d:Lmx0/s;

    .line 37
    .line 38
    const/4 v5, 0x0

    .line 39
    const/4 v6, 0x0

    .line 40
    const/4 v7, 0x0

    .line 41
    const/4 v8, 0x0

    .line 42
    const/4 v9, 0x0

    .line 43
    const/4 v10, 0x0

    .line 44
    const/4 v11, 0x0

    .line 45
    const/4 v12, 0x0

    .line 46
    const/4 v13, 0x0

    .line 47
    const/4 v14, 0x0

    .line 48
    const/4 v15, 0x0

    .line 49
    invoke-direct/range {v2 .. v16}, Lyr0/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/time/LocalDate;Ljava/lang/String;Lyr0/a;Lyr0/c;Ljava/lang/String;Ljava/util/List;)V

    .line 50
    .line 51
    .line 52
    invoke-direct {v0, v2}, Lwr0/m;-><init>(Lyr0/e;)V

    .line 53
    .line 54
    .line 55
    move-object/from16 v1, p0

    .line 56
    .line 57
    iget-object v1, v1, Lkc0/q0;->h:Lwr0/o;

    .line 58
    .line 59
    move-object/from16 v2, p2

    .line 60
    .line 61
    invoke-virtual {v1, v0, v2}, Lwr0/o;->b(Lwr0/m;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 66
    .line 67
    if-ne v0, v1, :cond_0

    .line 68
    .line 69
    return-object v0

    .line 70
    :cond_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 71
    .line 72
    return-object v0

    .line 73
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 74
    .line 75
    const-string v1, "Email in JWT claims not found"

    .line 76
    .line 77
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    throw v0

    .line 81
    :cond_2
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 82
    .line 83
    const-string v1, "UserId in JWT claims not found"

    .line 84
    .line 85
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    throw v0
.end method

.method public final d(Llc0/l;Lcm0/b;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 23

    .line 1
    move-object/from16 v2, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v0, p2

    .line 6
    .line 7
    move-object/from16 v3, p3

    .line 8
    .line 9
    move-object/from16 v4, p4

    .line 10
    .line 11
    instance-of v5, v4, Lkc0/p0;

    .line 12
    .line 13
    if-eqz v5, :cond_0

    .line 14
    .line 15
    move-object v5, v4

    .line 16
    check-cast v5, Lkc0/p0;

    .line 17
    .line 18
    iget v6, v5, Lkc0/p0;->i:I

    .line 19
    .line 20
    const/high16 v7, -0x80000000

    .line 21
    .line 22
    and-int v8, v6, v7

    .line 23
    .line 24
    if-eqz v8, :cond_0

    .line 25
    .line 26
    sub-int/2addr v6, v7

    .line 27
    iput v6, v5, Lkc0/p0;->i:I

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    new-instance v5, Lkc0/p0;

    .line 31
    .line 32
    invoke-direct {v5, v2, v4}, Lkc0/p0;-><init>(Lkc0/q0;Lrx0/c;)V

    .line 33
    .line 34
    .line 35
    :goto_0
    iget-object v4, v5, Lkc0/p0;->g:Ljava/lang/Object;

    .line 36
    .line 37
    sget-object v6, Lqx0/a;->d:Lqx0/a;

    .line 38
    .line 39
    iget v7, v5, Lkc0/p0;->i:I

    .line 40
    .line 41
    const/4 v8, 0x3

    .line 42
    const/4 v9, 0x2

    .line 43
    const/4 v10, 0x1

    .line 44
    const/4 v11, 0x0

    .line 45
    if-eqz v7, :cond_3

    .line 46
    .line 47
    if-eq v7, v10, :cond_2

    .line 48
    .line 49
    if-ne v7, v9, :cond_1

    .line 50
    .line 51
    iget-object v0, v5, Lkc0/p0;->e:Lvy0/b0;

    .line 52
    .line 53
    iget-object v1, v5, Lkc0/p0;->d:Llc0/l;

    .line 54
    .line 55
    invoke-static {v4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    move-object v6, v0

    .line 59
    :goto_1
    move-object v3, v1

    .line 60
    goto/16 :goto_b

    .line 61
    .line 62
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 63
    .line 64
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 65
    .line 66
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    throw v0

    .line 70
    :cond_2
    iget-object v0, v5, Lkc0/p0;->f:Lvy0/i0;

    .line 71
    .line 72
    iget-object v1, v5, Lkc0/p0;->e:Lvy0/b0;

    .line 73
    .line 74
    iget-object v3, v5, Lkc0/p0;->d:Llc0/l;

    .line 75
    .line 76
    invoke-static {v4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    move-object/from16 p4, v3

    .line 80
    .line 81
    move-object v3, v1

    .line 82
    move-object/from16 v1, p4

    .line 83
    .line 84
    move/from16 p4, v9

    .line 85
    .line 86
    goto/16 :goto_9

    .line 87
    .line 88
    :cond_3
    invoke-static {v4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    new-instance v4, Lkc0/n0;

    .line 92
    .line 93
    const/4 v7, 0x0

    .line 94
    invoke-direct {v4, v1, v7}, Lkc0/n0;-><init>(Llc0/l;I)V

    .line 95
    .line 96
    .line 97
    const-string v7, "Authentication"

    .line 98
    .line 99
    invoke-static {v7, v2, v4}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 100
    .line 101
    .line 102
    iget-object v4, v2, Lkc0/q0;->a:Lic0/a;

    .line 103
    .line 104
    iget-object v12, v4, Lic0/a;->f:Ljava/util/EnumMap;

    .line 105
    .line 106
    iget-object v13, v4, Lic0/a;->e:Ljava/util/EnumMap;

    .line 107
    .line 108
    iget-object v14, v4, Lic0/a;->g:Ljava/util/HashMap;

    .line 109
    .line 110
    const-string v15, "tokenType"

    .line 111
    .line 112
    invoke-static {v1, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    const-string v15, "environment"

    .line 116
    .line 117
    invoke-static {v0, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    const/4 v15, 0x0

    .line 121
    move/from16 p4, v9

    .line 122
    .line 123
    :try_start_0
    iget-object v9, v4, Lic0/a;->a:Lic0/d;

    .line 124
    .line 125
    check-cast v9, Lnc0/a;

    .line 126
    .line 127
    invoke-virtual {v9}, Lnc0/a;->b()Lne0/t;

    .line 128
    .line 129
    .line 130
    move-result-object v9

    .line 131
    instance-of v10, v9, Lne0/e;

    .line 132
    .line 133
    if-eqz v10, :cond_a

    .line 134
    .line 135
    check-cast v9, Lne0/e;

    .line 136
    .line 137
    iget-object v9, v9, Lne0/e;->a:Ljava/lang/Object;

    .line 138
    .line 139
    invoke-virtual {v14, v1, v9}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 143
    .line 144
    .line 145
    move-result-object v9

    .line 146
    invoke-virtual {v9}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 147
    .line 148
    .line 149
    move-result-object v9

    .line 150
    invoke-interface {v13, v1, v9}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 154
    .line 155
    .line 156
    move-result-object v9

    .line 157
    invoke-virtual {v9}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 158
    .line 159
    .line 160
    move-result-object v9

    .line 161
    invoke-interface {v12, v1, v9}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    new-instance v9, Ld01/z;

    .line 165
    .line 166
    const/4 v10, 0x0

    .line 167
    invoke-direct {v9, v10}, Ld01/z;-><init>(I)V

    .line 168
    .line 169
    .line 170
    const-string v10, "https"

    .line 171
    .line 172
    invoke-virtual {v9, v10}, Ld01/z;->k(Ljava/lang/String;)V

    .line 173
    .line 174
    .line 175
    iget-object v4, v4, Lic0/a;->d:Lxl0/g;

    .line 176
    .line 177
    invoke-interface {v4, v0}, Lxl0/g;->a(Lcm0/b;)Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object v4

    .line 181
    invoke-virtual {v9, v4}, Ld01/z;->f(Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {v9}, Ld01/z;->e()V

    .line 185
    .line 186
    .line 187
    const-string v4, "client_id"

    .line 188
    .line 189
    invoke-static/range {p1 .. p2}, Lic0/a;->a(Llc0/l;Lcm0/b;)Ljava/lang/String;

    .line 190
    .line 191
    .line 192
    move-result-object v0

    .line 193
    invoke-virtual {v9, v4, v0}, Ld01/z;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    const-string v0, "nonce"

    .line 197
    .line 198
    invoke-virtual {v12, v1}, Ljava/util/EnumMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v4

    .line 202
    check-cast v4, Ljava/lang/String;

    .line 203
    .line 204
    invoke-virtual {v9, v0, v4}, Ld01/z;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    const-string v0, "redirect_uri"

    .line 208
    .line 209
    const-string v4, "myskoda://redirect/login/"

    .line 210
    .line 211
    invoke-virtual {v9, v0, v4}, Ld01/z;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    const-string v0, "response_type"

    .line 215
    .line 216
    const-string v4, "code"

    .line 217
    .line 218
    invoke-virtual {v9, v0, v4}, Ld01/z;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 219
    .line 220
    .line 221
    const-string v0, "scope"

    .line 222
    .line 223
    invoke-static {v1}, Lic0/a;->b(Llc0/l;)Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    move-result-object v4

    .line 227
    invoke-virtual {v9, v0, v4}, Ld01/z;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 228
    .line 229
    .line 230
    const-string v0, "state"

    .line 231
    .line 232
    invoke-virtual {v13, v1}, Ljava/util/EnumMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object v4

    .line 236
    check-cast v4, Ljava/lang/String;

    .line 237
    .line 238
    invoke-virtual {v9, v0, v4}, Ld01/z;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 239
    .line 240
    .line 241
    const-string v0, "code_challenge"

    .line 242
    .line 243
    invoke-virtual {v14, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 244
    .line 245
    .line 246
    move-result-object v4

    .line 247
    check-cast v4, Llc0/f;

    .line 248
    .line 249
    if-eqz v4, :cond_4

    .line 250
    .line 251
    iget-object v4, v4, Llc0/f;->a:Ljava/lang/String;

    .line 252
    .line 253
    goto :goto_2

    .line 254
    :catch_0
    move-exception v0

    .line 255
    move-object/from16 v17, v0

    .line 256
    .line 257
    goto :goto_3

    .line 258
    :cond_4
    move-object v4, v11

    .line 259
    :goto_2
    if-eqz v4, :cond_9

    .line 260
    .line 261
    invoke-virtual {v9, v0, v4}, Ld01/z;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 262
    .line 263
    .line 264
    const-string v0, "code_challenge_method"

    .line 265
    .line 266
    const-string v4, "s256"

    .line 267
    .line 268
    invoke-virtual {v9, v0, v4}, Ld01/z;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 269
    .line 270
    .line 271
    sget-object v0, Llc0/l;->e:Llc0/l;

    .line 272
    .line 273
    if-eq v1, v0, :cond_5

    .line 274
    .line 275
    sget-object v0, Llc0/l;->f:Llc0/l;

    .line 276
    .line 277
    if-ne v1, v0, :cond_6

    .line 278
    .line 279
    :cond_5
    const-string v0, "prompt"

    .line 280
    .line 281
    const-string v4, "login"

    .line 282
    .line 283
    invoke-virtual {v9, v0, v4}, Ld01/z;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 284
    .line 285
    .line 286
    :cond_6
    if-eqz v3, :cond_7

    .line 287
    .line 288
    const-string v0, "login_hint"

    .line 289
    .line 290
    invoke-virtual {v9, v0, v3}, Ld01/z;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 291
    .line 292
    .line 293
    :cond_7
    const-string v0, "ui_locales"

    .line 294
    .line 295
    invoke-static {}, Lh/n;->b()Ly5/c;

    .line 296
    .line 297
    .line 298
    move-result-object v3

    .line 299
    invoke-virtual {v3, v15}, Ly5/c;->b(I)Ljava/util/Locale;

    .line 300
    .line 301
    .line 302
    move-result-object v3

    .line 303
    if-nez v3, :cond_8

    .line 304
    .line 305
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 306
    .line 307
    .line 308
    move-result-object v3

    .line 309
    const-string v4, "getDefault(...)"

    .line 310
    .line 311
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 312
    .line 313
    .line 314
    :cond_8
    invoke-virtual {v3}, Ljava/util/Locale;->toString()Ljava/lang/String;

    .line 315
    .line 316
    .line 317
    move-result-object v3

    .line 318
    invoke-virtual {v9, v0, v3}, Ld01/z;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 319
    .line 320
    .line 321
    invoke-virtual {v9}, Ld01/z;->c()Ld01/a0;

    .line 322
    .line 323
    .line 324
    move-result-object v0

    .line 325
    invoke-virtual {v0}, Ld01/a0;->k()Ljava/net/URL;

    .line 326
    .line 327
    .line 328
    move-result-object v0

    .line 329
    new-instance v3, Lne0/e;

    .line 330
    .line 331
    invoke-direct {v3, v0}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 332
    .line 333
    .line 334
    goto :goto_4

    .line 335
    :cond_9
    const-string v0, "Required value was null."

    .line 336
    .line 337
    new-instance v3, Ljava/lang/IllegalStateException;

    .line 338
    .line 339
    invoke-direct {v3, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 340
    .line 341
    .line 342
    throw v3

    .line 343
    :cond_a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 344
    .line 345
    const-string v3, "Check failed."

    .line 346
    .line 347
    invoke-direct {v0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 348
    .line 349
    .line 350
    throw v0
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 351
    :goto_3
    new-instance v16, Lne0/c;

    .line 352
    .line 353
    const/16 v20, 0x0

    .line 354
    .line 355
    const/16 v21, 0x1e

    .line 356
    .line 357
    const/16 v18, 0x0

    .line 358
    .line 359
    const/16 v19, 0x0

    .line 360
    .line 361
    invoke-direct/range {v16 .. v21}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 362
    .line 363
    .line 364
    move-object/from16 v3, v16

    .line 365
    .line 366
    :goto_4
    instance-of v0, v3, Lne0/e;

    .line 367
    .line 368
    if-eqz v0, :cond_14

    .line 369
    .line 370
    check-cast v3, Lne0/e;

    .line 371
    .line 372
    iget-object v0, v3, Lne0/e;->a:Ljava/lang/Object;

    .line 373
    .line 374
    check-cast v0, Ljava/net/URL;

    .line 375
    .line 376
    new-instance v3, Li2/t;

    .line 377
    .line 378
    const/16 v4, 0x18

    .line 379
    .line 380
    invoke-direct {v3, v4, v1, v0}, Li2/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 381
    .line 382
    .line 383
    invoke-static {v7, v2, v3}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 384
    .line 385
    .line 386
    invoke-interface {v5}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 387
    .line 388
    .line 389
    move-result-object v3

    .line 390
    invoke-static {v3}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 391
    .line 392
    .line 393
    move-result-object v3

    .line 394
    new-instance v4, Lk20/a;

    .line 395
    .line 396
    const/4 v7, 0x6

    .line 397
    invoke-direct {v4, v2, v11, v7}, Lk20/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 398
    .line 399
    .line 400
    invoke-static {v3, v11, v4, v8}, Lvy0/e0;->g(Lvy0/b0;Lpx0/g;Lay0/n;I)Lvy0/i0;

    .line 401
    .line 402
    .line 403
    move-result-object v4

    .line 404
    invoke-virtual {v0}, Ljava/net/URL;->toString()Ljava/lang/String;

    .line 405
    .line 406
    .line 407
    move-result-object v0

    .line 408
    const-string v7, "toString(...)"

    .line 409
    .line 410
    invoke-static {v0, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 411
    .line 412
    .line 413
    const/16 v7, 0x10

    .line 414
    .line 415
    and-int/lit8 v7, v7, 0x2

    .line 416
    .line 417
    if-eqz v7, :cond_b

    .line 418
    .line 419
    const/16 v18, 0x1

    .line 420
    .line 421
    goto :goto_5

    .line 422
    :cond_b
    move/from16 v18, v15

    .line 423
    .line 424
    :goto_5
    const/16 v7, 0x10

    .line 425
    .line 426
    and-int/lit8 v9, v7, 0x4

    .line 427
    .line 428
    if-eqz v9, :cond_c

    .line 429
    .line 430
    const/16 v19, 0x1

    .line 431
    .line 432
    goto :goto_6

    .line 433
    :cond_c
    move/from16 v19, v15

    .line 434
    .line 435
    :goto_6
    and-int/lit8 v9, v7, 0x8

    .line 436
    .line 437
    if-eqz v9, :cond_d

    .line 438
    .line 439
    move/from16 v20, v15

    .line 440
    .line 441
    goto :goto_7

    .line 442
    :cond_d
    const/16 v20, 0x1

    .line 443
    .line 444
    :goto_7
    and-int/2addr v7, v7

    .line 445
    if-eqz v7, :cond_e

    .line 446
    .line 447
    move/from16 v21, v15

    .line 448
    .line 449
    goto :goto_8

    .line 450
    :cond_e
    const/16 v21, 0x1

    .line 451
    .line 452
    :goto_8
    iget-object v7, v2, Lkc0/q0;->b:Lbd0/c;

    .line 453
    .line 454
    iget-object v7, v7, Lbd0/c;->a:Lbd0/a;

    .line 455
    .line 456
    new-instance v9, Ljava/net/URL;

    .line 457
    .line 458
    invoke-direct {v9, v0}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 459
    .line 460
    .line 461
    move-object/from16 v16, v7

    .line 462
    .line 463
    check-cast v16, Lzc0/b;

    .line 464
    .line 465
    move-object/from16 v17, v9

    .line 466
    .line 467
    invoke-virtual/range {v16 .. v21}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 468
    .line 469
    .line 470
    move-result-object v0

    .line 471
    iput-object v1, v5, Lkc0/p0;->d:Llc0/l;

    .line 472
    .line 473
    iput-object v3, v5, Lkc0/p0;->e:Lvy0/b0;

    .line 474
    .line 475
    iput-object v4, v5, Lkc0/p0;->f:Lvy0/i0;

    .line 476
    .line 477
    const/4 v7, 0x1

    .line 478
    iput v7, v5, Lkc0/p0;->i:I

    .line 479
    .line 480
    invoke-static {v0, v5}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 481
    .line 482
    .line 483
    move-result-object v0

    .line 484
    if-ne v0, v6, :cond_f

    .line 485
    .line 486
    goto :goto_a

    .line 487
    :cond_f
    move-object/from16 v22, v4

    .line 488
    .line 489
    move-object v4, v0

    .line 490
    move-object/from16 v0, v22

    .line 491
    .line 492
    :goto_9
    check-cast v4, Lne0/t;

    .line 493
    .line 494
    instance-of v7, v4, Lne0/c;

    .line 495
    .line 496
    if-nez v7, :cond_13

    .line 497
    .line 498
    iput-object v1, v5, Lkc0/p0;->d:Llc0/l;

    .line 499
    .line 500
    iput-object v3, v5, Lkc0/p0;->e:Lvy0/b0;

    .line 501
    .line 502
    iput-object v11, v5, Lkc0/p0;->f:Lvy0/i0;

    .line 503
    .line 504
    move/from16 v4, p4

    .line 505
    .line 506
    iput v4, v5, Lkc0/p0;->i:I

    .line 507
    .line 508
    invoke-interface {v0, v5}, Lvy0/h0;->B(Lrx0/c;)Ljava/lang/Object;

    .line 509
    .line 510
    .line 511
    move-result-object v4

    .line 512
    if-ne v4, v6, :cond_10

    .line 513
    .line 514
    :goto_a
    return-object v6

    .line 515
    :cond_10
    move-object v6, v3

    .line 516
    goto/16 :goto_1

    .line 517
    .line 518
    :goto_b
    check-cast v4, Lne0/t;

    .line 519
    .line 520
    instance-of v0, v4, Lne0/c;

    .line 521
    .line 522
    if-nez v0, :cond_12

    .line 523
    .line 524
    instance-of v0, v4, Lne0/e;

    .line 525
    .line 526
    if-eqz v0, :cond_11

    .line 527
    .line 528
    check-cast v4, Lne0/e;

    .line 529
    .line 530
    iget-object v0, v4, Lne0/e;->a:Ljava/lang/Object;

    .line 531
    .line 532
    move-object v4, v0

    .line 533
    check-cast v4, Llc0/b;

    .line 534
    .line 535
    new-instance v0, Lh7/z;

    .line 536
    .line 537
    const/4 v1, 0x6

    .line 538
    move-object v5, v11

    .line 539
    invoke-direct/range {v0 .. v5}, Lh7/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 540
    .line 541
    .line 542
    invoke-static {v6, v5, v0, v8}, Lvy0/e0;->g(Lvy0/b0;Lpx0/g;Lay0/n;I)Lvy0/i0;

    .line 543
    .line 544
    .line 545
    move-result-object v0

    .line 546
    return-object v0

    .line 547
    :cond_11
    new-instance v0, La8/r0;

    .line 548
    .line 549
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 550
    .line 551
    .line 552
    throw v0

    .line 553
    :cond_12
    check-cast v4, Lne0/c;

    .line 554
    .line 555
    iget-object v0, v4, Lne0/c;->a:Ljava/lang/Throwable;

    .line 556
    .line 557
    throw v0

    .line 558
    :cond_13
    check-cast v4, Lne0/c;

    .line 559
    .line 560
    iget-object v0, v4, Lne0/c;->a:Ljava/lang/Throwable;

    .line 561
    .line 562
    throw v0

    .line 563
    :cond_14
    instance-of v0, v3, Lne0/c;

    .line 564
    .line 565
    if-eqz v0, :cond_15

    .line 566
    .line 567
    check-cast v3, Lne0/c;

    .line 568
    .line 569
    iget-object v0, v3, Lne0/c;->a:Ljava/lang/Throwable;

    .line 570
    .line 571
    throw v0

    .line 572
    :cond_15
    new-instance v0, La8/r0;

    .line 573
    .line 574
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 575
    .line 576
    .line 577
    throw v0
.end method
