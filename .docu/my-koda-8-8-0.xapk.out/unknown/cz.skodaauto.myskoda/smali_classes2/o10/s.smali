.class public final Lo10/s;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public d:Lo10/t;

.field public e:Ljava/lang/String;

.field public f:Ljava/util/Iterator;

.field public g:Lr10/b;

.field public h:Ljava/util/Iterator;

.field public i:Lao0/a;

.field public j:I

.field public k:I

.field public l:I

.field public m:I

.field public n:J

.field public o:I

.field public final synthetic p:Lo10/t;

.field public final synthetic q:Lr10/a;

.field public final synthetic r:Ljava/lang/String;


# direct methods
.method public constructor <init>(Lo10/t;Lr10/a;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lo10/s;->p:Lo10/t;

    .line 2
    .line 3
    iput-object p2, p0, Lo10/s;->q:Lr10/a;

    .line 4
    .line 5
    iput-object p3, p0, Lo10/s;->r:Ljava/lang/String;

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    new-instance v0, Lo10/s;

    .line 2
    .line 3
    iget-object v1, p0, Lo10/s;->q:Lr10/a;

    .line 4
    .line 5
    iget-object v2, p0, Lo10/s;->r:Ljava/lang/String;

    .line 6
    .line 7
    iget-object p0, p0, Lo10/s;->p:Lo10/t;

    .line 8
    .line 9
    invoke-direct {v0, p0, v1, v2, p1}, Lo10/s;-><init>(Lo10/t;Lr10/a;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lo10/s;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lo10/s;

    .line 8
    .line 9
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Lo10/s;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 40

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 4
    .line 5
    iget v2, v0, Lo10/s;->o:I

    .line 6
    .line 7
    const-string v3, "vin"

    .line 8
    .line 9
    iget-object v5, v0, Lo10/s;->r:Ljava/lang/String;

    .line 10
    .line 11
    iget-object v10, v0, Lo10/s;->q:Lr10/a;

    .line 12
    .line 13
    iget-object v11, v0, Lo10/s;->p:Lo10/t;

    .line 14
    .line 15
    const-string v12, "<this>"

    .line 16
    .line 17
    const/4 v13, 0x1

    .line 18
    packed-switch v2, :pswitch_data_0

    .line 19
    .line 20
    .line 21
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 24
    .line 25
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw v0

    .line 29
    :pswitch_0
    iget v2, v0, Lo10/s;->l:I

    .line 30
    .line 31
    iget-wide v4, v0, Lo10/s;->n:J

    .line 32
    .line 33
    iget v6, v0, Lo10/s;->k:I

    .line 34
    .line 35
    iget v7, v0, Lo10/s;->j:I

    .line 36
    .line 37
    iget-object v8, v0, Lo10/s;->h:Ljava/util/Iterator;

    .line 38
    .line 39
    iget-object v9, v0, Lo10/s;->f:Ljava/util/Iterator;

    .line 40
    .line 41
    iget-object v10, v0, Lo10/s;->e:Ljava/lang/String;

    .line 42
    .line 43
    iget-object v11, v0, Lo10/s;->d:Lo10/t;

    .line 44
    .line 45
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    move-object/from16 v31, v3

    .line 49
    .line 50
    move v3, v2

    .line 51
    move v2, v13

    .line 52
    move-wide v13, v4

    .line 53
    move-object v4, v8

    .line 54
    move-object v8, v11

    .line 55
    move-object v11, v9

    .line 56
    const/4 v9, 0x0

    .line 57
    :goto_0
    move v5, v7

    .line 58
    move-object v7, v10

    .line 59
    goto/16 :goto_e

    .line 60
    .line 61
    :pswitch_1
    iget v2, v0, Lo10/s;->m:I

    .line 62
    .line 63
    iget v4, v0, Lo10/s;->l:I

    .line 64
    .line 65
    iget-wide v5, v0, Lo10/s;->n:J

    .line 66
    .line 67
    iget v7, v0, Lo10/s;->k:I

    .line 68
    .line 69
    iget v8, v0, Lo10/s;->j:I

    .line 70
    .line 71
    iget-object v9, v0, Lo10/s;->i:Lao0/a;

    .line 72
    .line 73
    iget-object v10, v0, Lo10/s;->h:Ljava/util/Iterator;

    .line 74
    .line 75
    iget-object v11, v0, Lo10/s;->f:Ljava/util/Iterator;

    .line 76
    .line 77
    iget-object v15, v0, Lo10/s;->e:Ljava/lang/String;

    .line 78
    .line 79
    iget-object v14, v0, Lo10/s;->d:Lo10/t;

    .line 80
    .line 81
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    move-object/from16 v13, p1

    .line 85
    .line 86
    move-object/from16 v31, v3

    .line 87
    .line 88
    move-wide/from16 v19, v5

    .line 89
    .line 90
    move v6, v7

    .line 91
    move v7, v8

    .line 92
    move-object v8, v10

    .line 93
    move-object v10, v15

    .line 94
    move v3, v2

    .line 95
    move v2, v4

    .line 96
    goto/16 :goto_c

    .line 97
    .line 98
    :pswitch_2
    iget v2, v0, Lo10/s;->k:I

    .line 99
    .line 100
    iget v4, v0, Lo10/s;->j:I

    .line 101
    .line 102
    iget-object v5, v0, Lo10/s;->g:Lr10/b;

    .line 103
    .line 104
    iget-object v6, v0, Lo10/s;->f:Ljava/util/Iterator;

    .line 105
    .line 106
    iget-object v7, v0, Lo10/s;->e:Ljava/lang/String;

    .line 107
    .line 108
    iget-object v8, v0, Lo10/s;->d:Lo10/t;

    .line 109
    .line 110
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    move-object/from16 v10, p1

    .line 114
    .line 115
    move-object/from16 v31, v3

    .line 116
    .line 117
    goto/16 :goto_a

    .line 118
    .line 119
    :pswitch_3
    iget v2, v0, Lo10/s;->k:I

    .line 120
    .line 121
    iget v4, v0, Lo10/s;->j:I

    .line 122
    .line 123
    iget-object v5, v0, Lo10/s;->g:Lr10/b;

    .line 124
    .line 125
    iget-object v6, v0, Lo10/s;->f:Ljava/util/Iterator;

    .line 126
    .line 127
    iget-object v7, v0, Lo10/s;->e:Ljava/lang/String;

    .line 128
    .line 129
    iget-object v8, v0, Lo10/s;->d:Lo10/t;

    .line 130
    .line 131
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    move v9, v2

    .line 135
    move-object v2, v7

    .line 136
    move-object/from16 v7, p1

    .line 137
    .line 138
    goto/16 :goto_7

    .line 139
    .line 140
    :pswitch_4
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 141
    .line 142
    .line 143
    goto :goto_5

    .line 144
    :pswitch_5
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    move-object/from16 v2, p1

    .line 148
    .line 149
    goto :goto_1

    .line 150
    :pswitch_6
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 151
    .line 152
    .line 153
    iget-object v2, v11, Lo10/t;->a:Lti0/a;

    .line 154
    .line 155
    iput v13, v0, Lo10/s;->o:I

    .line 156
    .line 157
    invoke-interface {v2, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object v2

    .line 161
    if-ne v2, v1, :cond_0

    .line 162
    .line 163
    goto/16 :goto_d

    .line 164
    .line 165
    :cond_0
    :goto_1
    check-cast v2, Lo10/e;

    .line 166
    .line 167
    invoke-static {v10, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    invoke-static {v5, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 171
    .line 172
    .line 173
    new-instance v4, Lo10/f;

    .line 174
    .line 175
    iget-object v6, v10, Lr10/a;->a:Lqr0/q;

    .line 176
    .line 177
    if-eqz v6, :cond_1

    .line 178
    .line 179
    iget-wide v6, v6, Lqr0/q;->a:D

    .line 180
    .line 181
    invoke-static {v6, v7}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 182
    .line 183
    .line 184
    move-result-object v6

    .line 185
    goto :goto_2

    .line 186
    :cond_1
    const/4 v6, 0x0

    .line 187
    :goto_2
    iget-object v7, v10, Lr10/a;->b:Lqr0/l;

    .line 188
    .line 189
    if-eqz v7, :cond_2

    .line 190
    .line 191
    iget v7, v7, Lqr0/l;->d:I

    .line 192
    .line 193
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 194
    .line 195
    .line 196
    move-result-object v7

    .line 197
    goto :goto_3

    .line 198
    :cond_2
    const/4 v7, 0x0

    .line 199
    :goto_3
    iget-object v8, v10, Lr10/a;->d:Lao0/d;

    .line 200
    .line 201
    if-eqz v8, :cond_3

    .line 202
    .line 203
    iget-wide v8, v8, Lao0/d;->a:J

    .line 204
    .line 205
    invoke-static {v8, v9}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 206
    .line 207
    .line 208
    move-result-object v8

    .line 209
    goto :goto_4

    .line 210
    :cond_3
    const/4 v8, 0x0

    .line 211
    :goto_4
    iget-object v9, v10, Lr10/a;->e:Ljava/time/OffsetDateTime;

    .line 212
    .line 213
    invoke-direct/range {v4 .. v9}, Lo10/f;-><init>(Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Integer;Ljava/lang/Long;Ljava/time/OffsetDateTime;)V

    .line 214
    .line 215
    .line 216
    const/4 v6, 0x2

    .line 217
    iput v6, v0, Lo10/s;->o:I

    .line 218
    .line 219
    iget-object v6, v2, Lo10/e;->a:Lla/u;

    .line 220
    .line 221
    new-instance v7, Ll2/v1;

    .line 222
    .line 223
    const/16 v8, 0x18

    .line 224
    .line 225
    invoke-direct {v7, v8, v2, v4}, Ll2/v1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 226
    .line 227
    .line 228
    const/4 v2, 0x0

    .line 229
    invoke-static {v0, v6, v2, v13, v7}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 230
    .line 231
    .line 232
    move-result-object v4

    .line 233
    if-ne v4, v1, :cond_4

    .line 234
    .line 235
    goto/16 :goto_d

    .line 236
    .line 237
    :cond_4
    :goto_5
    iget-object v2, v10, Lr10/a;->c:Ljava/util/List;

    .line 238
    .line 239
    if-eqz v2, :cond_c

    .line 240
    .line 241
    check-cast v2, Ljava/lang/Iterable;

    .line 242
    .line 243
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 244
    .line 245
    .line 246
    move-result-object v2

    .line 247
    const/4 v4, 0x0

    .line 248
    :goto_6
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 249
    .line 250
    .line 251
    move-result v6

    .line 252
    if-eqz v6, :cond_c

    .line 253
    .line 254
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object v6

    .line 258
    check-cast v6, Lr10/b;

    .line 259
    .line 260
    iget-object v7, v11, Lo10/t;->b:Lti0/a;

    .line 261
    .line 262
    iput-object v11, v0, Lo10/s;->d:Lo10/t;

    .line 263
    .line 264
    iput-object v5, v0, Lo10/s;->e:Ljava/lang/String;

    .line 265
    .line 266
    iput-object v2, v0, Lo10/s;->f:Ljava/util/Iterator;

    .line 267
    .line 268
    iput-object v6, v0, Lo10/s;->g:Lr10/b;

    .line 269
    .line 270
    const/4 v8, 0x0

    .line 271
    iput-object v8, v0, Lo10/s;->h:Ljava/util/Iterator;

    .line 272
    .line 273
    iput-object v8, v0, Lo10/s;->i:Lao0/a;

    .line 274
    .line 275
    iput v4, v0, Lo10/s;->j:I

    .line 276
    .line 277
    const/4 v8, 0x0

    .line 278
    iput v8, v0, Lo10/s;->k:I

    .line 279
    .line 280
    const/4 v8, 0x3

    .line 281
    iput v8, v0, Lo10/s;->o:I

    .line 282
    .line 283
    invoke-interface {v7, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 284
    .line 285
    .line 286
    move-result-object v7

    .line 287
    if-ne v7, v1, :cond_5

    .line 288
    .line 289
    goto/16 :goto_d

    .line 290
    .line 291
    :cond_5
    move-object v8, v6

    .line 292
    move-object v6, v2

    .line 293
    move-object v2, v5

    .line 294
    move-object v5, v8

    .line 295
    move-object v8, v11

    .line 296
    const/4 v9, 0x0

    .line 297
    :goto_7
    check-cast v7, Lo10/h;

    .line 298
    .line 299
    invoke-static {v5, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 300
    .line 301
    .line 302
    iget-object v10, v5, Lr10/b;->g:Lao0/c;

    .line 303
    .line 304
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 305
    .line 306
    .line 307
    new-instance v16, Lo10/i;

    .line 308
    .line 309
    iget v11, v5, Lr10/b;->a:I

    .line 310
    .line 311
    iget-boolean v14, v5, Lr10/b;->b:Z

    .line 312
    .line 313
    iget-boolean v15, v5, Lr10/b;->c:Z

    .line 314
    .line 315
    iget-boolean v13, v5, Lr10/b;->d:Z

    .line 316
    .line 317
    move-object/from16 v19, v2

    .line 318
    .line 319
    iget-object v2, v5, Lr10/b;->e:Lqr0/l;

    .line 320
    .line 321
    if-eqz v2, :cond_6

    .line 322
    .line 323
    iget v2, v2, Lqr0/l;->d:I

    .line 324
    .line 325
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 326
    .line 327
    .line 328
    move-result-object v2

    .line 329
    move-object/from16 v24, v2

    .line 330
    .line 331
    :goto_8
    move-object/from16 v31, v3

    .line 332
    .line 333
    goto :goto_9

    .line 334
    :cond_6
    const/16 v24, 0x0

    .line 335
    .line 336
    goto :goto_8

    .line 337
    :goto_9
    iget-wide v2, v10, Lao0/c;->a:J

    .line 338
    .line 339
    move-wide/from16 v25, v2

    .line 340
    .line 341
    iget-boolean v2, v10, Lao0/c;->b:Z

    .line 342
    .line 343
    iget-object v3, v10, Lao0/c;->c:Ljava/time/LocalTime;

    .line 344
    .line 345
    move/from16 v27, v2

    .line 346
    .line 347
    iget-object v2, v10, Lao0/c;->d:Lao0/f;

    .line 348
    .line 349
    invoke-virtual {v2}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 350
    .line 351
    .line 352
    move-result-object v29

    .line 353
    iget-object v2, v10, Lao0/c;->e:Ljava/util/Set;

    .line 354
    .line 355
    move-object/from16 v32, v2

    .line 356
    .line 357
    check-cast v32, Ljava/lang/Iterable;

    .line 358
    .line 359
    const/16 v36, 0x0

    .line 360
    .line 361
    const/16 v37, 0x3e

    .line 362
    .line 363
    const-string v33, ","

    .line 364
    .line 365
    const/16 v34, 0x0

    .line 366
    .line 367
    const/16 v35, 0x0

    .line 368
    .line 369
    invoke-static/range {v32 .. v37}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 370
    .line 371
    .line 372
    move-result-object v30

    .line 373
    const-wide/16 v17, 0x0

    .line 374
    .line 375
    move-object/from16 v28, v3

    .line 376
    .line 377
    move/from16 v20, v11

    .line 378
    .line 379
    move/from16 v23, v13

    .line 380
    .line 381
    move/from16 v21, v14

    .line 382
    .line 383
    move/from16 v22, v15

    .line 384
    .line 385
    invoke-direct/range {v16 .. v30}, Lo10/i;-><init>(JLjava/lang/String;IZZZLjava/lang/Integer;JZLjava/time/LocalTime;Ljava/lang/String;Ljava/lang/String;)V

    .line 386
    .line 387
    .line 388
    move-object/from16 v3, v16

    .line 389
    .line 390
    move-object/from16 v2, v19

    .line 391
    .line 392
    iput-object v8, v0, Lo10/s;->d:Lo10/t;

    .line 393
    .line 394
    iput-object v2, v0, Lo10/s;->e:Ljava/lang/String;

    .line 395
    .line 396
    iput-object v6, v0, Lo10/s;->f:Ljava/util/Iterator;

    .line 397
    .line 398
    iput-object v5, v0, Lo10/s;->g:Lr10/b;

    .line 399
    .line 400
    iput v4, v0, Lo10/s;->j:I

    .line 401
    .line 402
    iput v9, v0, Lo10/s;->k:I

    .line 403
    .line 404
    const/4 v10, 0x4

    .line 405
    iput v10, v0, Lo10/s;->o:I

    .line 406
    .line 407
    iget-object v10, v7, Lo10/h;->a:Lla/u;

    .line 408
    .line 409
    new-instance v11, Ll2/v1;

    .line 410
    .line 411
    const/16 v13, 0x19

    .line 412
    .line 413
    invoke-direct {v11, v13, v7, v3}, Ll2/v1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 414
    .line 415
    .line 416
    const/4 v3, 0x1

    .line 417
    const/4 v7, 0x0

    .line 418
    invoke-static {v0, v10, v7, v3, v11}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 419
    .line 420
    .line 421
    move-result-object v10

    .line 422
    if-ne v10, v1, :cond_7

    .line 423
    .line 424
    goto/16 :goto_d

    .line 425
    .line 426
    :cond_7
    move-object v7, v2

    .line 427
    move v2, v9

    .line 428
    :goto_a
    check-cast v10, Ljava/lang/Number;

    .line 429
    .line 430
    invoke-virtual {v10}, Ljava/lang/Number;->longValue()J

    .line 431
    .line 432
    .line 433
    move-result-wide v9

    .line 434
    iget-object v3, v5, Lr10/b;->f:Ljava/util/List;

    .line 435
    .line 436
    if-eqz v3, :cond_b

    .line 437
    .line 438
    check-cast v3, Ljava/lang/Iterable;

    .line 439
    .line 440
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 441
    .line 442
    .line 443
    move-result-object v3

    .line 444
    move v5, v4

    .line 445
    move-object v4, v3

    .line 446
    const/4 v3, 0x0

    .line 447
    :goto_b
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 448
    .line 449
    .line 450
    move-result v11

    .line 451
    if-eqz v11, :cond_a

    .line 452
    .line 453
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 454
    .line 455
    .line 456
    move-result-object v11

    .line 457
    check-cast v11, Lao0/a;

    .line 458
    .line 459
    iget-object v13, v8, Lo10/t;->c:Lti0/a;

    .line 460
    .line 461
    iput-object v8, v0, Lo10/s;->d:Lo10/t;

    .line 462
    .line 463
    iput-object v7, v0, Lo10/s;->e:Ljava/lang/String;

    .line 464
    .line 465
    iput-object v6, v0, Lo10/s;->f:Ljava/util/Iterator;

    .line 466
    .line 467
    const/4 v14, 0x0

    .line 468
    iput-object v14, v0, Lo10/s;->g:Lr10/b;

    .line 469
    .line 470
    iput-object v4, v0, Lo10/s;->h:Ljava/util/Iterator;

    .line 471
    .line 472
    iput-object v11, v0, Lo10/s;->i:Lao0/a;

    .line 473
    .line 474
    iput v5, v0, Lo10/s;->j:I

    .line 475
    .line 476
    iput v2, v0, Lo10/s;->k:I

    .line 477
    .line 478
    iput-wide v9, v0, Lo10/s;->n:J

    .line 479
    .line 480
    iput v3, v0, Lo10/s;->l:I

    .line 481
    .line 482
    const/4 v14, 0x0

    .line 483
    iput v14, v0, Lo10/s;->m:I

    .line 484
    .line 485
    const/4 v14, 0x5

    .line 486
    iput v14, v0, Lo10/s;->o:I

    .line 487
    .line 488
    invoke-interface {v13, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 489
    .line 490
    .line 491
    move-result-object v13

    .line 492
    if-ne v13, v1, :cond_8

    .line 493
    .line 494
    goto :goto_d

    .line 495
    :cond_8
    move-object v14, v8

    .line 496
    move-wide/from16 v19, v9

    .line 497
    .line 498
    move-object v9, v11

    .line 499
    move-object v8, v4

    .line 500
    move-object v11, v6

    .line 501
    move-object v10, v7

    .line 502
    move v6, v2

    .line 503
    move v2, v3

    .line 504
    move v7, v5

    .line 505
    const/4 v3, 0x0

    .line 506
    :goto_c
    check-cast v13, Lo10/a;

    .line 507
    .line 508
    invoke-static {v9, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 509
    .line 510
    .line 511
    iget-wide v4, v9, Lao0/a;->a:J

    .line 512
    .line 513
    iget-boolean v15, v9, Lao0/a;->b:Z

    .line 514
    .line 515
    move-wide/from16 v21, v4

    .line 516
    .line 517
    iget-object v4, v9, Lao0/a;->c:Ljava/time/LocalTime;

    .line 518
    .line 519
    iget-object v5, v9, Lao0/a;->d:Ljava/time/LocalTime;

    .line 520
    .line 521
    new-instance v16, Lo10/b;

    .line 522
    .line 523
    const-wide/16 v17, 0x0

    .line 524
    .line 525
    move-object/from16 v24, v4

    .line 526
    .line 527
    move-object/from16 v25, v5

    .line 528
    .line 529
    move/from16 v23, v15

    .line 530
    .line 531
    invoke-direct/range {v16 .. v25}, Lo10/b;-><init>(JJJZLjava/time/LocalTime;Ljava/time/LocalTime;)V

    .line 532
    .line 533
    .line 534
    move-object/from16 v9, v16

    .line 535
    .line 536
    move-wide/from16 v4, v19

    .line 537
    .line 538
    iput-object v14, v0, Lo10/s;->d:Lo10/t;

    .line 539
    .line 540
    iput-object v10, v0, Lo10/s;->e:Ljava/lang/String;

    .line 541
    .line 542
    iput-object v11, v0, Lo10/s;->f:Ljava/util/Iterator;

    .line 543
    .line 544
    const/4 v15, 0x0

    .line 545
    iput-object v15, v0, Lo10/s;->g:Lr10/b;

    .line 546
    .line 547
    iput-object v8, v0, Lo10/s;->h:Ljava/util/Iterator;

    .line 548
    .line 549
    iput-object v15, v0, Lo10/s;->i:Lao0/a;

    .line 550
    .line 551
    iput v7, v0, Lo10/s;->j:I

    .line 552
    .line 553
    iput v6, v0, Lo10/s;->k:I

    .line 554
    .line 555
    iput-wide v4, v0, Lo10/s;->n:J

    .line 556
    .line 557
    iput v2, v0, Lo10/s;->l:I

    .line 558
    .line 559
    iput v3, v0, Lo10/s;->m:I

    .line 560
    .line 561
    const/4 v3, 0x6

    .line 562
    iput v3, v0, Lo10/s;->o:I

    .line 563
    .line 564
    iget-object v3, v13, Lo10/a;->a:Lla/u;

    .line 565
    .line 566
    new-instance v15, Ll2/v1;

    .line 567
    .line 568
    move/from16 v16, v2

    .line 569
    .line 570
    const/16 v2, 0x17

    .line 571
    .line 572
    invoke-direct {v15, v2, v13, v9}, Ll2/v1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 573
    .line 574
    .line 575
    const/4 v2, 0x1

    .line 576
    const/4 v9, 0x0

    .line 577
    invoke-static {v0, v3, v9, v2, v15}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 578
    .line 579
    .line 580
    move-result-object v3

    .line 581
    if-ne v3, v1, :cond_9

    .line 582
    .line 583
    :goto_d
    return-object v1

    .line 584
    :cond_9
    move-wide/from16 v38, v4

    .line 585
    .line 586
    move-object v4, v8

    .line 587
    move-object v8, v14

    .line 588
    move-wide/from16 v13, v38

    .line 589
    .line 590
    move/from16 v3, v16

    .line 591
    .line 592
    goto/16 :goto_0

    .line 593
    .line 594
    :goto_e
    move v2, v6

    .line 595
    move-object v6, v11

    .line 596
    move-wide v9, v13

    .line 597
    goto/16 :goto_b

    .line 598
    .line 599
    :cond_a
    move v4, v5

    .line 600
    :cond_b
    const/4 v2, 0x1

    .line 601
    const/4 v9, 0x0

    .line 602
    move-object v5, v7

    .line 603
    move-object v11, v8

    .line 604
    move v13, v2

    .line 605
    move-object v2, v6

    .line 606
    move-object/from16 v3, v31

    .line 607
    .line 608
    goto/16 :goto_6

    .line 609
    .line 610
    :cond_c
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 611
    .line 612
    return-object v0

    .line 613
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
