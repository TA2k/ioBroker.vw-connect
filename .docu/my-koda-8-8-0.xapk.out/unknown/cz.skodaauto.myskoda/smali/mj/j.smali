.class public final Lmj/j;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:[Ljava/lang/Integer;

.field public e:Lmj/k;

.field public f:Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;

.field public g:Ljava/lang/Object;

.field public h:I

.field public i:I

.field public j:I

.field public k:I

.field public l:I

.field public m:I

.field public synthetic n:Ljava/lang/Object;

.field public final synthetic o:Lmj/k;


# direct methods
.method public constructor <init>(Lmj/k;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lmj/j;->o:Lmj/k;

    .line 2
    .line 3
    const/4 p1, 0x2

    .line 4
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    new-instance v0, Lmj/j;

    .line 2
    .line 3
    iget-object p0, p0, Lmj/j;->o:Lmj/k;

    .line 4
    .line 5
    invoke-direct {v0, p0, p2}, Lmj/j;-><init>(Lmj/k;Lkotlin/coroutines/Continuation;)V

    .line 6
    .line 7
    .line 8
    iput-object p1, v0, Lmj/j;->n:Ljava/lang/Object;

    .line 9
    .line 10
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lyy0/j;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lmj/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lmj/j;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lmj/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lmj/j;->n:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Lyy0/j;

    .line 6
    .line 7
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 8
    .line 9
    iget v3, v0, Lmj/j;->m:I

    .line 10
    .line 11
    const/4 v4, 0x5

    .line 12
    const/4 v5, 0x4

    .line 13
    const/4 v6, 0x3

    .line 14
    const-string v7, "Kt"

    .line 15
    .line 16
    const/4 v10, 0x1

    .line 17
    const/4 v11, 0x0

    .line 18
    const/4 v12, 0x2

    .line 19
    const/4 v13, 0x0

    .line 20
    if-eqz v3, :cond_5

    .line 21
    .line 22
    if-eq v3, v10, :cond_4

    .line 23
    .line 24
    if-eq v3, v12, :cond_3

    .line 25
    .line 26
    if-eq v3, v6, :cond_2

    .line 27
    .line 28
    if-eq v3, v5, :cond_1

    .line 29
    .line 30
    if-ne v3, v4, :cond_0

    .line 31
    .line 32
    iget v3, v0, Lmj/j;->j:I

    .line 33
    .line 34
    iget v14, v0, Lmj/j;->i:I

    .line 35
    .line 36
    iget v15, v0, Lmj/j;->h:I

    .line 37
    .line 38
    iget-object v4, v0, Lmj/j;->e:Lmj/k;

    .line 39
    .line 40
    iget-object v5, v0, Lmj/j;->d:[Ljava/lang/Integer;

    .line 41
    .line 42
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    move-object v6, v5

    .line 46
    move v5, v3

    .line 47
    move-object v3, v6

    .line 48
    move-object v9, v4

    .line 49
    move/from16 v17, v10

    .line 50
    .line 51
    move-object v12, v13

    .line 52
    move v6, v14

    .line 53
    const/16 v14, 0x2e

    .line 54
    .line 55
    move-object v10, v2

    .line 56
    const/4 v2, 0x5

    .line 57
    :goto_0
    move v8, v15

    .line 58
    goto/16 :goto_13

    .line 59
    .line 60
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 61
    .line 62
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 63
    .line 64
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    throw v0

    .line 68
    :cond_1
    iget v3, v0, Lmj/j;->l:I

    .line 69
    .line 70
    iget v4, v0, Lmj/j;->k:I

    .line 71
    .line 72
    iget v5, v0, Lmj/j;->j:I

    .line 73
    .line 74
    iget v14, v0, Lmj/j;->i:I

    .line 75
    .line 76
    iget v15, v0, Lmj/j;->h:I

    .line 77
    .line 78
    iget-object v6, v0, Lmj/j;->g:Ljava/lang/Object;

    .line 79
    .line 80
    iget-object v8, v0, Lmj/j;->f:Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;

    .line 81
    .line 82
    iget-object v9, v0, Lmj/j;->e:Lmj/k;

    .line 83
    .line 84
    iget-object v12, v0, Lmj/j;->d:[Ljava/lang/Integer;

    .line 85
    .line 86
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    move/from16 v17, v10

    .line 90
    .line 91
    move v11, v14

    .line 92
    const/4 v14, 0x4

    .line 93
    move-object v10, v2

    .line 94
    :goto_1
    move v2, v3

    .line 95
    move v3, v5

    .line 96
    move-object v5, v12

    .line 97
    goto/16 :goto_a

    .line 98
    .line 99
    :cond_2
    iget v3, v0, Lmj/j;->l:I

    .line 100
    .line 101
    iget v4, v0, Lmj/j;->k:I

    .line 102
    .line 103
    iget v5, v0, Lmj/j;->j:I

    .line 104
    .line 105
    iget v6, v0, Lmj/j;->i:I

    .line 106
    .line 107
    iget v8, v0, Lmj/j;->h:I

    .line 108
    .line 109
    iget-object v9, v0, Lmj/j;->g:Ljava/lang/Object;

    .line 110
    .line 111
    iget-object v12, v0, Lmj/j;->f:Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;

    .line 112
    .line 113
    iget-object v14, v0, Lmj/j;->e:Lmj/k;

    .line 114
    .line 115
    iget-object v15, v0, Lmj/j;->d:[Ljava/lang/Integer;

    .line 116
    .line 117
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    move/from16 v17, v10

    .line 121
    .line 122
    move-object v10, v2

    .line 123
    goto/16 :goto_8

    .line 124
    .line 125
    :cond_3
    iget v3, v0, Lmj/j;->l:I

    .line 126
    .line 127
    iget v4, v0, Lmj/j;->k:I

    .line 128
    .line 129
    iget v5, v0, Lmj/j;->j:I

    .line 130
    .line 131
    iget v6, v0, Lmj/j;->i:I

    .line 132
    .line 133
    iget v8, v0, Lmj/j;->h:I

    .line 134
    .line 135
    iget-object v9, v0, Lmj/j;->e:Lmj/k;

    .line 136
    .line 137
    iget-object v12, v0, Lmj/j;->d:[Ljava/lang/Integer;

    .line 138
    .line 139
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 140
    .line 141
    .line 142
    move-object/from16 v14, p1

    .line 143
    .line 144
    const/4 v15, 0x2

    .line 145
    goto/16 :goto_5

    .line 146
    .line 147
    :cond_4
    iget v3, v0, Lmj/j;->l:I

    .line 148
    .line 149
    iget v4, v0, Lmj/j;->k:I

    .line 150
    .line 151
    iget v5, v0, Lmj/j;->j:I

    .line 152
    .line 153
    iget v6, v0, Lmj/j;->i:I

    .line 154
    .line 155
    iget v8, v0, Lmj/j;->h:I

    .line 156
    .line 157
    iget-object v9, v0, Lmj/j;->e:Lmj/k;

    .line 158
    .line 159
    iget-object v12, v0, Lmj/j;->d:[Ljava/lang/Integer;

    .line 160
    .line 161
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 162
    .line 163
    .line 164
    goto :goto_4

    .line 165
    :cond_5
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 166
    .line 167
    .line 168
    sget-object v3, Lmj/l;->a:[Ljava/lang/Integer;

    .line 169
    .line 170
    iget-object v4, v0, Lmj/j;->o:Lmj/k;

    .line 171
    .line 172
    const/16 v5, 0xa

    .line 173
    .line 174
    move-object v9, v4

    .line 175
    move v6, v11

    .line 176
    move v8, v6

    .line 177
    :goto_2
    move-object v12, v3

    .line 178
    if-ge v6, v5, :cond_18

    .line 179
    .line 180
    aget-object v3, v12, v6

    .line 181
    .line 182
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 183
    .line 184
    .line 185
    move-result v4

    .line 186
    iget-object v3, v9, Lmj/k;->j:Lyy0/c2;

    .line 187
    .line 188
    invoke-virtual {v3}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object v3

    .line 192
    check-cast v3, Lri/d;

    .line 193
    .line 194
    invoke-static {v3}, Lkp/i0;->c(Lri/d;)Llx0/o;

    .line 195
    .line 196
    .line 197
    move-result-object v3

    .line 198
    if-eqz v3, :cond_6

    .line 199
    .line 200
    iget-object v3, v3, Llx0/o;->d:Ljava/lang/Object;

    .line 201
    .line 202
    new-instance v14, Lri/c;

    .line 203
    .line 204
    invoke-direct {v14, v3}, Lri/c;-><init>(Ljava/lang/Object;)V

    .line 205
    .line 206
    .line 207
    iput-object v1, v0, Lmj/j;->n:Ljava/lang/Object;

    .line 208
    .line 209
    iput-object v12, v0, Lmj/j;->d:[Ljava/lang/Integer;

    .line 210
    .line 211
    iput-object v9, v0, Lmj/j;->e:Lmj/k;

    .line 212
    .line 213
    iput-object v13, v0, Lmj/j;->f:Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;

    .line 214
    .line 215
    iput-object v13, v0, Lmj/j;->g:Ljava/lang/Object;

    .line 216
    .line 217
    iput v8, v0, Lmj/j;->h:I

    .line 218
    .line 219
    iput v6, v0, Lmj/j;->i:I

    .line 220
    .line 221
    iput v5, v0, Lmj/j;->j:I

    .line 222
    .line 223
    iput v4, v0, Lmj/j;->k:I

    .line 224
    .line 225
    iput v11, v0, Lmj/j;->l:I

    .line 226
    .line 227
    iput v10, v0, Lmj/j;->m:I

    .line 228
    .line 229
    invoke-interface {v1, v14, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 230
    .line 231
    .line 232
    move-result-object v3

    .line 233
    if-ne v3, v2, :cond_6

    .line 234
    .line 235
    :goto_3
    move-object v10, v2

    .line 236
    goto/16 :goto_12

    .line 237
    .line 238
    :cond_6
    move v3, v11

    .line 239
    :goto_4
    iget-object v14, v9, Lmj/k;->b:Ll20/g;

    .line 240
    .line 241
    iput-object v1, v0, Lmj/j;->n:Ljava/lang/Object;

    .line 242
    .line 243
    iput-object v12, v0, Lmj/j;->d:[Ljava/lang/Integer;

    .line 244
    .line 245
    iput-object v9, v0, Lmj/j;->e:Lmj/k;

    .line 246
    .line 247
    iput-object v13, v0, Lmj/j;->f:Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;

    .line 248
    .line 249
    iput-object v13, v0, Lmj/j;->g:Ljava/lang/Object;

    .line 250
    .line 251
    iput v8, v0, Lmj/j;->h:I

    .line 252
    .line 253
    iput v6, v0, Lmj/j;->i:I

    .line 254
    .line 255
    iput v5, v0, Lmj/j;->j:I

    .line 256
    .line 257
    iput v4, v0, Lmj/j;->k:I

    .line 258
    .line 259
    iput v3, v0, Lmj/j;->l:I

    .line 260
    .line 261
    const/4 v15, 0x2

    .line 262
    iput v15, v0, Lmj/j;->m:I

    .line 263
    .line 264
    invoke-virtual {v14, v0}, Ll20/g;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 265
    .line 266
    .line 267
    move-result-object v14

    .line 268
    if-ne v14, v2, :cond_7

    .line 269
    .line 270
    goto :goto_3

    .line 271
    :cond_7
    :goto_5
    check-cast v14, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;

    .line 272
    .line 273
    invoke-static {v14}, Lkp/j0;->b(Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;)Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    move-result-object v11

    .line 277
    instance-of v15, v11, Llx0/n;

    .line 278
    .line 279
    if-nez v15, :cond_b

    .line 280
    .line 281
    move-object v15, v11

    .line 282
    check-cast v15, Lnj/h;

    .line 283
    .line 284
    new-instance v13, Lmj/g;

    .line 285
    .line 286
    invoke-direct {v13, v10}, Lmj/g;-><init>(I)V

    .line 287
    .line 288
    .line 289
    move/from16 v17, v10

    .line 290
    .line 291
    sget-object v10, Lgi/b;->e:Lgi/b;

    .line 292
    .line 293
    move-object/from16 v18, v2

    .line 294
    .line 295
    sget-object v2, Lgi/a;->e:Lgi/a;

    .line 296
    .line 297
    move-object/from16 v19, v15

    .line 298
    .line 299
    instance-of v15, v1, Ljava/lang/String;

    .line 300
    .line 301
    if-eqz v15, :cond_8

    .line 302
    .line 303
    move-object v15, v1

    .line 304
    check-cast v15, Ljava/lang/String;

    .line 305
    .line 306
    move/from16 v20, v3

    .line 307
    .line 308
    move/from16 v21, v4

    .line 309
    .line 310
    :goto_6
    const/4 v3, 0x0

    .line 311
    goto :goto_7

    .line 312
    :cond_8
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 313
    .line 314
    .line 315
    move-result-object v15

    .line 316
    invoke-virtual {v15}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 317
    .line 318
    .line 319
    move-result-object v15

    .line 320
    move/from16 v20, v3

    .line 321
    .line 322
    move/from16 v21, v4

    .line 323
    .line 324
    const/16 v3, 0x24

    .line 325
    .line 326
    invoke-static {v15, v3}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 327
    .line 328
    .line 329
    move-result-object v4

    .line 330
    const/16 v3, 0x2e

    .line 331
    .line 332
    invoke-static {v3, v4, v4}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 333
    .line 334
    .line 335
    move-result-object v4

    .line 336
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 337
    .line 338
    .line 339
    move-result v3

    .line 340
    if-nez v3, :cond_9

    .line 341
    .line 342
    goto :goto_6

    .line 343
    :cond_9
    invoke-static {v4, v7}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 344
    .line 345
    .line 346
    move-result-object v3

    .line 347
    move-object v15, v3

    .line 348
    goto :goto_6

    .line 349
    :goto_7
    invoke-static {v15, v2, v10, v3, v13}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 350
    .line 351
    .line 352
    iget-object v2, v9, Lmj/k;->e:Ljd/b;

    .line 353
    .line 354
    iput-object v1, v0, Lmj/j;->n:Ljava/lang/Object;

    .line 355
    .line 356
    iput-object v12, v0, Lmj/j;->d:[Ljava/lang/Integer;

    .line 357
    .line 358
    iput-object v9, v0, Lmj/j;->e:Lmj/k;

    .line 359
    .line 360
    iput-object v14, v0, Lmj/j;->f:Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;

    .line 361
    .line 362
    iput-object v11, v0, Lmj/j;->g:Ljava/lang/Object;

    .line 363
    .line 364
    iput v8, v0, Lmj/j;->h:I

    .line 365
    .line 366
    iput v6, v0, Lmj/j;->i:I

    .line 367
    .line 368
    iput v5, v0, Lmj/j;->j:I

    .line 369
    .line 370
    move/from16 v4, v21

    .line 371
    .line 372
    iput v4, v0, Lmj/j;->k:I

    .line 373
    .line 374
    move/from16 v3, v20

    .line 375
    .line 376
    iput v3, v0, Lmj/j;->l:I

    .line 377
    .line 378
    const/4 v10, 0x3

    .line 379
    iput v10, v0, Lmj/j;->m:I

    .line 380
    .line 381
    move-object/from16 v10, v19

    .line 382
    .line 383
    invoke-virtual {v2, v10, v0}, Ljd/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 384
    .line 385
    .line 386
    move-result-object v2

    .line 387
    move-object/from16 v10, v18

    .line 388
    .line 389
    if-ne v2, v10, :cond_a

    .line 390
    .line 391
    goto/16 :goto_12

    .line 392
    .line 393
    :cond_a
    move-object v15, v12

    .line 394
    move-object v12, v14

    .line 395
    move-object v14, v9

    .line 396
    move-object v9, v11

    .line 397
    :goto_8
    move v2, v8

    .line 398
    move-object v11, v9

    .line 399
    move-object v8, v12

    .line 400
    move-object v9, v14

    .line 401
    move-object v12, v15

    .line 402
    goto :goto_9

    .line 403
    :cond_b
    move/from16 v17, v10

    .line 404
    .line 405
    move-object v10, v2

    .line 406
    move v2, v8

    .line 407
    move-object v8, v14

    .line 408
    :goto_9
    iget-object v13, v9, Lmj/k;->g:Lmj/f;

    .line 409
    .line 410
    instance-of v14, v11, Llx0/n;

    .line 411
    .line 412
    if-nez v14, :cond_c

    .line 413
    .line 414
    check-cast v11, Lnj/h;

    .line 415
    .line 416
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 417
    .line 418
    .line 419
    invoke-static {v11}, Lmj/f;->a(Lnj/h;)Llj/j;

    .line 420
    .line 421
    .line 422
    move-result-object v11

    .line 423
    :cond_c
    new-instance v13, Lri/a;

    .line 424
    .line 425
    invoke-direct {v13, v11}, Lri/a;-><init>(Ljava/lang/Object;)V

    .line 426
    .line 427
    .line 428
    iput-object v1, v0, Lmj/j;->n:Ljava/lang/Object;

    .line 429
    .line 430
    iput-object v12, v0, Lmj/j;->d:[Ljava/lang/Integer;

    .line 431
    .line 432
    iput-object v9, v0, Lmj/j;->e:Lmj/k;

    .line 433
    .line 434
    iput-object v8, v0, Lmj/j;->f:Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;

    .line 435
    .line 436
    iput-object v11, v0, Lmj/j;->g:Ljava/lang/Object;

    .line 437
    .line 438
    iput v2, v0, Lmj/j;->h:I

    .line 439
    .line 440
    iput v6, v0, Lmj/j;->i:I

    .line 441
    .line 442
    iput v5, v0, Lmj/j;->j:I

    .line 443
    .line 444
    iput v4, v0, Lmj/j;->k:I

    .line 445
    .line 446
    iput v3, v0, Lmj/j;->l:I

    .line 447
    .line 448
    const/4 v14, 0x4

    .line 449
    iput v14, v0, Lmj/j;->m:I

    .line 450
    .line 451
    invoke-interface {v1, v13, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 452
    .line 453
    .line 454
    move-result-object v13

    .line 455
    if-ne v13, v10, :cond_d

    .line 456
    .line 457
    goto/16 :goto_12

    .line 458
    .line 459
    :cond_d
    move-object v15, v11

    .line 460
    move v11, v6

    .line 461
    move-object v6, v15

    .line 462
    move v15, v2

    .line 463
    goto/16 :goto_1

    .line 464
    .line 465
    :goto_a
    new-instance v12, Lca/k;

    .line 466
    .line 467
    const/4 v13, 0x3

    .line 468
    invoke-direct {v12, v6, v13}, Lca/k;-><init>(Ljava/lang/Object;I)V

    .line 469
    .line 470
    .line 471
    sget-object v6, Lgi/b;->e:Lgi/b;

    .line 472
    .line 473
    sget-object v13, Lgi/a;->e:Lgi/a;

    .line 474
    .line 475
    instance-of v14, v1, Ljava/lang/String;

    .line 476
    .line 477
    if-eqz v14, :cond_e

    .line 478
    .line 479
    move-object/from16 v18, v1

    .line 480
    .line 481
    check-cast v18, Ljava/lang/String;

    .line 482
    .line 483
    move/from16 v20, v2

    .line 484
    .line 485
    move/from16 v19, v14

    .line 486
    .line 487
    move-object/from16 v14, v18

    .line 488
    .line 489
    move-object/from16 v18, v10

    .line 490
    .line 491
    :goto_b
    const/4 v2, 0x0

    .line 492
    goto :goto_c

    .line 493
    :cond_e
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 494
    .line 495
    .line 496
    move-result-object v18

    .line 497
    move/from16 v19, v14

    .line 498
    .line 499
    invoke-virtual/range {v18 .. v18}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 500
    .line 501
    .line 502
    move-result-object v14

    .line 503
    move/from16 v20, v2

    .line 504
    .line 505
    move-object/from16 v18, v10

    .line 506
    .line 507
    const/16 v10, 0x24

    .line 508
    .line 509
    invoke-static {v14, v10}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 510
    .line 511
    .line 512
    move-result-object v2

    .line 513
    const/16 v10, 0x2e

    .line 514
    .line 515
    invoke-static {v10, v2, v2}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 516
    .line 517
    .line 518
    move-result-object v2

    .line 519
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 520
    .line 521
    .line 522
    move-result v10

    .line 523
    if-nez v10, :cond_f

    .line 524
    .line 525
    goto :goto_b

    .line 526
    :cond_f
    invoke-static {v2, v7}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 527
    .line 528
    .line 529
    move-result-object v2

    .line 530
    move-object v14, v2

    .line 531
    goto :goto_b

    .line 532
    :goto_c
    invoke-static {v14, v13, v6, v2, v12}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 533
    .line 534
    .line 535
    instance-of v2, v8, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;

    .line 536
    .line 537
    if-eqz v2, :cond_11

    .line 538
    .line 539
    new-instance v2, Lla/p;

    .line 540
    .line 541
    move-object v10, v8

    .line 542
    check-cast v10, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;

    .line 543
    .line 544
    const/16 v12, 0xc

    .line 545
    .line 546
    invoke-direct {v2, v10, v12}, Lla/p;-><init>(Ljava/lang/Object;I)V

    .line 547
    .line 548
    .line 549
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 550
    .line 551
    .line 552
    move-result-object v8

    .line 553
    invoke-virtual {v8}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 554
    .line 555
    .line 556
    move-result-object v8

    .line 557
    const/16 v12, 0x24

    .line 558
    .line 559
    invoke-static {v8, v12}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 560
    .line 561
    .line 562
    move-result-object v14

    .line 563
    const/16 v12, 0x2e

    .line 564
    .line 565
    invoke-static {v12, v14, v14}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 566
    .line 567
    .line 568
    move-result-object v14

    .line 569
    invoke-virtual {v14}, Ljava/lang/String;->length()I

    .line 570
    .line 571
    .line 572
    move-result v12

    .line 573
    if-nez v12, :cond_10

    .line 574
    .line 575
    :goto_d
    const/4 v12, 0x0

    .line 576
    goto :goto_e

    .line 577
    :cond_10
    invoke-static {v14, v7}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 578
    .line 579
    .line 580
    move-result-object v8

    .line 581
    goto :goto_d

    .line 582
    :goto_e
    invoke-static {v8, v13, v6, v12, v2}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 583
    .line 584
    .line 585
    invoke-virtual {v10}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->getCode()I

    .line 586
    .line 587
    .line 588
    move-result v2

    .line 589
    const/16 v8, 0x1f4

    .line 590
    .line 591
    if-lt v2, v8, :cond_18

    .line 592
    .line 593
    goto :goto_f

    .line 594
    :cond_11
    instance-of v2, v8, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$NetworkError;

    .line 595
    .line 596
    if-eqz v2, :cond_12

    .line 597
    .line 598
    goto :goto_f

    .line 599
    :cond_12
    instance-of v2, v8, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;

    .line 600
    .line 601
    if-eqz v2, :cond_13

    .line 602
    .line 603
    goto/16 :goto_14

    .line 604
    .line 605
    :cond_13
    instance-of v2, v8, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$UnknownError;

    .line 606
    .line 607
    if-eqz v2, :cond_17

    .line 608
    .line 609
    :goto_f
    new-instance v2, Lac/g;

    .line 610
    .line 611
    const/4 v8, 0x7

    .line 612
    invoke-direct {v2, v4, v8}, Lac/g;-><init>(II)V

    .line 613
    .line 614
    .line 615
    if-eqz v19, :cond_14

    .line 616
    .line 617
    move-object v8, v1

    .line 618
    check-cast v8, Ljava/lang/String;

    .line 619
    .line 620
    const/16 v10, 0x24

    .line 621
    .line 622
    const/16 v14, 0x2e

    .line 623
    .line 624
    :goto_10
    const/4 v12, 0x0

    .line 625
    goto :goto_11

    .line 626
    :cond_14
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 627
    .line 628
    .line 629
    move-result-object v8

    .line 630
    invoke-virtual {v8}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 631
    .line 632
    .line 633
    move-result-object v8

    .line 634
    const/16 v10, 0x24

    .line 635
    .line 636
    invoke-static {v8, v10}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 637
    .line 638
    .line 639
    move-result-object v12

    .line 640
    const/16 v14, 0x2e

    .line 641
    .line 642
    invoke-static {v14, v12, v12}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 643
    .line 644
    .line 645
    move-result-object v12

    .line 646
    invoke-virtual {v12}, Ljava/lang/String;->length()I

    .line 647
    .line 648
    .line 649
    move-result v16

    .line 650
    if-nez v16, :cond_15

    .line 651
    .line 652
    goto :goto_10

    .line 653
    :cond_15
    invoke-static {v12, v7}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 654
    .line 655
    .line 656
    move-result-object v8

    .line 657
    goto :goto_10

    .line 658
    :goto_11
    invoke-static {v8, v13, v6, v12, v2}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 659
    .line 660
    .line 661
    sget v2, Lmy0/c;->g:I

    .line 662
    .line 663
    sget-object v2, Lmy0/e;->h:Lmy0/e;

    .line 664
    .line 665
    move v6, v11

    .line 666
    invoke-static {v4, v2}, Lmy0/h;->s(ILmy0/e;)J

    .line 667
    .line 668
    .line 669
    move-result-wide v10

    .line 670
    iput-object v1, v0, Lmj/j;->n:Ljava/lang/Object;

    .line 671
    .line 672
    iput-object v5, v0, Lmj/j;->d:[Ljava/lang/Integer;

    .line 673
    .line 674
    iput-object v9, v0, Lmj/j;->e:Lmj/k;

    .line 675
    .line 676
    iput-object v12, v0, Lmj/j;->f:Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;

    .line 677
    .line 678
    iput-object v12, v0, Lmj/j;->g:Ljava/lang/Object;

    .line 679
    .line 680
    iput v15, v0, Lmj/j;->h:I

    .line 681
    .line 682
    iput v6, v0, Lmj/j;->i:I

    .line 683
    .line 684
    iput v3, v0, Lmj/j;->j:I

    .line 685
    .line 686
    iput v4, v0, Lmj/j;->k:I

    .line 687
    .line 688
    move/from16 v2, v20

    .line 689
    .line 690
    iput v2, v0, Lmj/j;->l:I

    .line 691
    .line 692
    const/4 v2, 0x5

    .line 693
    iput v2, v0, Lmj/j;->m:I

    .line 694
    .line 695
    invoke-static {v10, v11, v0}, Lvy0/e0;->q(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 696
    .line 697
    .line 698
    move-result-object v4

    .line 699
    move-object/from16 v10, v18

    .line 700
    .line 701
    if-ne v4, v10, :cond_16

    .line 702
    .line 703
    :goto_12
    return-object v10

    .line 704
    :cond_16
    move-object v8, v5

    .line 705
    move v5, v3

    .line 706
    move-object v3, v8

    .line 707
    goto/16 :goto_0

    .line 708
    .line 709
    :goto_13
    add-int/lit8 v6, v6, 0x1

    .line 710
    .line 711
    move-object v2, v10

    .line 712
    move-object v13, v12

    .line 713
    move/from16 v10, v17

    .line 714
    .line 715
    const/4 v11, 0x0

    .line 716
    goto/16 :goto_2

    .line 717
    .line 718
    :cond_17
    new-instance v0, La8/r0;

    .line 719
    .line 720
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 721
    .line 722
    .line 723
    throw v0

    .line 724
    :cond_18
    :goto_14
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 725
    .line 726
    return-object v0
.end method
