.class public final Lcb0/c;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:Ljava/lang/String;

.field public e:Lyr0/e;

.field public f:Ljava/lang/String;

.field public g:Lcq0/n;

.field public h:Ljava/lang/String;

.field public i:Ljava/lang/String;

.field public j:Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPayload;

.field public k:Lcb0/a;

.field public l:I

.field public synthetic m:Ljava/lang/Object;

.field public final synthetic n:Lcb0/d;

.field public final synthetic o:Ldb0/a;


# direct methods
.method public constructor <init>(Lcb0/d;Ldb0/a;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcb0/c;->n:Lcb0/d;

    .line 2
    .line 3
    iput-object p2, p0, Lcb0/c;->o:Ldb0/a;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    new-instance v0, Lcb0/c;

    .line 2
    .line 3
    iget-object v1, p0, Lcb0/c;->n:Lcb0/d;

    .line 4
    .line 5
    iget-object p0, p0, Lcb0/c;->o:Ldb0/a;

    .line 6
    .line 7
    invoke-direct {v0, v1, p0, p2}, Lcb0/c;-><init>(Lcb0/d;Ldb0/a;Lkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, v0, Lcb0/c;->m:Ljava/lang/Object;

    .line 11
    .line 12
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
    invoke-virtual {p0, p1, p2}, Lcb0/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lcb0/c;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lcb0/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 41

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lcb0/c;->m:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Lyy0/j;

    .line 6
    .line 7
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 8
    .line 9
    iget v3, v0, Lcb0/c;->l:I

    .line 10
    .line 11
    const/4 v5, 0x4

    .line 12
    const/4 v6, 0x3

    .line 13
    const/4 v7, 0x2

    .line 14
    const/4 v8, 0x1

    .line 15
    sget-object v9, Llx0/b0;->a:Llx0/b0;

    .line 16
    .line 17
    iget-object v10, v0, Lcb0/c;->n:Lcb0/d;

    .line 18
    .line 19
    const/4 v11, 0x0

    .line 20
    packed-switch v3, :pswitch_data_0

    .line 21
    .line 22
    .line 23
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 24
    .line 25
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 26
    .line 27
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw v0

    .line 31
    :pswitch_0
    iget-object v0, v0, Lcb0/c;->k:Lcb0/a;

    .line 32
    .line 33
    check-cast v0, Ljava/lang/String;

    .line 34
    .line 35
    :goto_0
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    return-object v9

    .line 39
    :pswitch_1
    iget-object v3, v0, Lcb0/c;->k:Lcb0/a;

    .line 40
    .line 41
    iget-object v12, v0, Lcb0/c;->j:Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPayload;

    .line 42
    .line 43
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    move-object/from16 v4, p1

    .line 47
    .line 48
    goto/16 :goto_d

    .line 49
    .line 50
    :pswitch_2
    iget-object v3, v0, Lcb0/c;->i:Ljava/lang/String;

    .line 51
    .line 52
    iget-object v12, v0, Lcb0/c;->h:Ljava/lang/String;

    .line 53
    .line 54
    iget-object v13, v0, Lcb0/c;->g:Lcq0/n;

    .line 55
    .line 56
    iget-object v14, v0, Lcb0/c;->f:Ljava/lang/String;

    .line 57
    .line 58
    iget-object v15, v0, Lcb0/c;->d:Ljava/lang/String;

    .line 59
    .line 60
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    move-object/from16 v5, p1

    .line 64
    .line 65
    move-object/from16 v29, v3

    .line 66
    .line 67
    move-object/from16 v34, v12

    .line 68
    .line 69
    :goto_1
    move-object/from16 v28, v14

    .line 70
    .line 71
    move-object/from16 v25, v15

    .line 72
    .line 73
    goto/16 :goto_b

    .line 74
    .line 75
    :pswitch_3
    iget-object v3, v0, Lcb0/c;->f:Ljava/lang/String;

    .line 76
    .line 77
    iget-object v12, v0, Lcb0/c;->e:Lyr0/e;

    .line 78
    .line 79
    iget-object v13, v0, Lcb0/c;->d:Ljava/lang/String;

    .line 80
    .line 81
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    move-object/from16 v4, p1

    .line 85
    .line 86
    :cond_0
    move-object v14, v3

    .line 87
    move-object v15, v13

    .line 88
    goto/16 :goto_8

    .line 89
    .line 90
    :pswitch_4
    iget-object v3, v0, Lcb0/c;->f:Ljava/lang/String;

    .line 91
    .line 92
    iget-object v12, v0, Lcb0/c;->e:Lyr0/e;

    .line 93
    .line 94
    iget-object v13, v0, Lcb0/c;->d:Ljava/lang/String;

    .line 95
    .line 96
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    move-object/from16 v4, p1

    .line 100
    .line 101
    goto/16 :goto_7

    .line 102
    .line 103
    :pswitch_5
    iget-object v0, v0, Lcb0/c;->f:Ljava/lang/String;

    .line 104
    .line 105
    :goto_2
    check-cast v0, Lyy0/j;

    .line 106
    .line 107
    goto :goto_0

    .line 108
    :pswitch_6
    iget-object v0, v0, Lcb0/c;->e:Lyr0/e;

    .line 109
    .line 110
    goto :goto_2

    .line 111
    :pswitch_7
    iget-object v3, v0, Lcb0/c;->d:Ljava/lang/String;

    .line 112
    .line 113
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    move-object/from16 v12, p1

    .line 117
    .line 118
    :cond_1
    move-object v13, v3

    .line 119
    goto/16 :goto_6

    .line 120
    .line 121
    :pswitch_8
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    return-object v9

    .line 125
    :pswitch_9
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    move-object/from16 v3, p1

    .line 129
    .line 130
    goto :goto_4

    .line 131
    :pswitch_a
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    goto :goto_3

    .line 135
    :pswitch_b
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    iput-object v1, v0, Lcb0/c;->m:Ljava/lang/Object;

    .line 139
    .line 140
    iput v8, v0, Lcb0/c;->l:I

    .line 141
    .line 142
    sget-object v3, Lne0/d;->a:Lne0/d;

    .line 143
    .line 144
    invoke-interface {v1, v3, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v3

    .line 148
    if-ne v3, v2, :cond_2

    .line 149
    .line 150
    goto/16 :goto_16

    .line 151
    .line 152
    :cond_2
    :goto_3
    iget-object v3, v10, Lcb0/d;->a:Lrs0/b;

    .line 153
    .line 154
    iput-object v1, v0, Lcb0/c;->m:Ljava/lang/Object;

    .line 155
    .line 156
    iput v7, v0, Lcb0/c;->l:I

    .line 157
    .line 158
    invoke-virtual {v3, v0}, Lrs0/b;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v3

    .line 162
    if-ne v3, v2, :cond_3

    .line 163
    .line 164
    goto/16 :goto_16

    .line 165
    .line 166
    :cond_3
    :goto_4
    instance-of v12, v3, Lne0/e;

    .line 167
    .line 168
    if-eqz v12, :cond_4

    .line 169
    .line 170
    check-cast v3, Lne0/e;

    .line 171
    .line 172
    goto :goto_5

    .line 173
    :cond_4
    move-object v3, v11

    .line 174
    :goto_5
    if-nez v3, :cond_5

    .line 175
    .line 176
    new-instance v12, Lne0/c;

    .line 177
    .line 178
    new-instance v13, Ljava/lang/Exception;

    .line 179
    .line 180
    const-string v3, "Missing vehicle VIN."

    .line 181
    .line 182
    invoke-direct {v13, v3}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 183
    .line 184
    .line 185
    const/16 v16, 0x0

    .line 186
    .line 187
    const/16 v17, 0x1e

    .line 188
    .line 189
    const/4 v14, 0x0

    .line 190
    const/4 v15, 0x0

    .line 191
    invoke-direct/range {v12 .. v17}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 192
    .line 193
    .line 194
    iput-object v11, v0, Lcb0/c;->m:Ljava/lang/Object;

    .line 195
    .line 196
    iput v6, v0, Lcb0/c;->l:I

    .line 197
    .line 198
    invoke-interface {v1, v12, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v0

    .line 202
    if-ne v0, v2, :cond_15

    .line 203
    .line 204
    goto/16 :goto_16

    .line 205
    .line 206
    :cond_5
    iget-object v3, v3, Lne0/e;->a:Ljava/lang/Object;

    .line 207
    .line 208
    const-string v12, "null cannot be cast to non-null type cz.skodaauto.myskoda.library.vehicle.model.Vin"

    .line 209
    .line 210
    invoke-static {v3, v12}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    check-cast v3, Lss0/j0;

    .line 214
    .line 215
    iget-object v3, v3, Lss0/j0;->d:Ljava/lang/String;

    .line 216
    .line 217
    iget-object v12, v10, Lcb0/d;->c:Lwr0/e;

    .line 218
    .line 219
    iput-object v1, v0, Lcb0/c;->m:Ljava/lang/Object;

    .line 220
    .line 221
    iput-object v3, v0, Lcb0/c;->d:Ljava/lang/String;

    .line 222
    .line 223
    iput v5, v0, Lcb0/c;->l:I

    .line 224
    .line 225
    iget-object v12, v12, Lwr0/e;->a:Lwr0/g;

    .line 226
    .line 227
    check-cast v12, Lur0/g;

    .line 228
    .line 229
    invoke-virtual {v12, v0}, Lur0/g;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 230
    .line 231
    .line 232
    move-result-object v12

    .line 233
    if-ne v12, v2, :cond_1

    .line 234
    .line 235
    goto/16 :goto_16

    .line 236
    .line 237
    :goto_6
    check-cast v12, Lyr0/e;

    .line 238
    .line 239
    if-nez v12, :cond_6

    .line 240
    .line 241
    new-instance v14, Lne0/c;

    .line 242
    .line 243
    new-instance v15, Ljava/lang/Exception;

    .line 244
    .line 245
    const-string v3, "Missing user."

    .line 246
    .line 247
    invoke-direct {v15, v3}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 248
    .line 249
    .line 250
    const/16 v18, 0x0

    .line 251
    .line 252
    const/16 v19, 0x1e

    .line 253
    .line 254
    const/16 v16, 0x0

    .line 255
    .line 256
    const/16 v17, 0x0

    .line 257
    .line 258
    invoke-direct/range {v14 .. v19}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 259
    .line 260
    .line 261
    iput-object v11, v0, Lcb0/c;->m:Ljava/lang/Object;

    .line 262
    .line 263
    iput-object v11, v0, Lcb0/c;->d:Ljava/lang/String;

    .line 264
    .line 265
    iput-object v11, v0, Lcb0/c;->e:Lyr0/e;

    .line 266
    .line 267
    const/4 v3, 0x5

    .line 268
    iput v3, v0, Lcb0/c;->l:I

    .line 269
    .line 270
    invoke-interface {v1, v14, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    move-result-object v0

    .line 274
    if-ne v0, v2, :cond_15

    .line 275
    .line 276
    goto/16 :goto_16

    .line 277
    .line 278
    :cond_6
    iget-object v3, v12, Lyr0/e;->g:Ljava/lang/String;

    .line 279
    .line 280
    if-nez v3, :cond_7

    .line 281
    .line 282
    new-instance v14, Lne0/c;

    .line 283
    .line 284
    new-instance v15, Ljava/lang/Exception;

    .line 285
    .line 286
    const-string v3, "Missing country code."

    .line 287
    .line 288
    invoke-direct {v15, v3}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 289
    .line 290
    .line 291
    const/16 v18, 0x0

    .line 292
    .line 293
    const/16 v19, 0x1e

    .line 294
    .line 295
    const/16 v16, 0x0

    .line 296
    .line 297
    const/16 v17, 0x0

    .line 298
    .line 299
    invoke-direct/range {v14 .. v19}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 300
    .line 301
    .line 302
    iput-object v11, v0, Lcb0/c;->m:Ljava/lang/Object;

    .line 303
    .line 304
    iput-object v11, v0, Lcb0/c;->d:Ljava/lang/String;

    .line 305
    .line 306
    iput-object v11, v0, Lcb0/c;->e:Lyr0/e;

    .line 307
    .line 308
    iput-object v11, v0, Lcb0/c;->f:Ljava/lang/String;

    .line 309
    .line 310
    const/4 v3, 0x6

    .line 311
    iput v3, v0, Lcb0/c;->l:I

    .line 312
    .line 313
    invoke-interface {v1, v14, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 314
    .line 315
    .line 316
    move-result-object v0

    .line 317
    if-ne v0, v2, :cond_15

    .line 318
    .line 319
    goto/16 :goto_16

    .line 320
    .line 321
    :cond_7
    iget-object v14, v10, Lcb0/d;->e:Lbq0/j;

    .line 322
    .line 323
    iget-object v15, v14, Lbq0/j;->a:Lbq0/h;

    .line 324
    .line 325
    iput-object v1, v0, Lcb0/c;->m:Ljava/lang/Object;

    .line 326
    .line 327
    iput-object v13, v0, Lcb0/c;->d:Ljava/lang/String;

    .line 328
    .line 329
    iput-object v12, v0, Lcb0/c;->e:Lyr0/e;

    .line 330
    .line 331
    iput-object v3, v0, Lcb0/c;->f:Ljava/lang/String;

    .line 332
    .line 333
    const/4 v5, 0x7

    .line 334
    iput v5, v0, Lcb0/c;->l:I

    .line 335
    .line 336
    move-object v5, v15

    .line 337
    check-cast v5, Lzp0/c;

    .line 338
    .line 339
    iget-object v6, v5, Lzp0/c;->o:Lyy0/l1;

    .line 340
    .line 341
    iget-object v5, v5, Lzp0/c;->d:Lez0/c;

    .line 342
    .line 343
    move-object/from16 v19, v15

    .line 344
    .line 345
    new-instance v15, La90/r;

    .line 346
    .line 347
    const/16 v16, 0x0

    .line 348
    .line 349
    const/16 v17, 0x2

    .line 350
    .line 351
    const-class v18, Lbq0/h;

    .line 352
    .line 353
    const-string v20, "isServiceDetailValid"

    .line 354
    .line 355
    const-string v21, "isServiceDetailValid()Z"

    .line 356
    .line 357
    invoke-direct/range {v15 .. v21}, La90/r;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 358
    .line 359
    .line 360
    new-instance v7, Lbq0/i;

    .line 361
    .line 362
    const/4 v4, 0x0

    .line 363
    invoke-direct {v7, v14, v11, v4}, Lbq0/i;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 364
    .line 365
    .line 366
    invoke-static {v6, v5, v15, v7}, Lbb/j0;->h(Lyy0/i;Lez0/a;Lay0/a;Lay0/k;)Lne0/n;

    .line 367
    .line 368
    .line 369
    move-result-object v4

    .line 370
    if-ne v4, v2, :cond_8

    .line 371
    .line 372
    goto/16 :goto_16

    .line 373
    .line 374
    :cond_8
    :goto_7
    check-cast v4, Lyy0/i;

    .line 375
    .line 376
    new-instance v5, La50/h;

    .line 377
    .line 378
    const/16 v6, 0x8

    .line 379
    .line 380
    invoke-direct {v5, v4, v6}, La50/h;-><init>(Lyy0/i;I)V

    .line 381
    .line 382
    .line 383
    invoke-static {v5, v8}, Lyy0/u;->G(Lyy0/i;I)Lyy0/d0;

    .line 384
    .line 385
    .line 386
    move-result-object v4

    .line 387
    iput-object v1, v0, Lcb0/c;->m:Ljava/lang/Object;

    .line 388
    .line 389
    iput-object v13, v0, Lcb0/c;->d:Ljava/lang/String;

    .line 390
    .line 391
    iput-object v12, v0, Lcb0/c;->e:Lyr0/e;

    .line 392
    .line 393
    iput-object v3, v0, Lcb0/c;->f:Ljava/lang/String;

    .line 394
    .line 395
    const/16 v5, 0x8

    .line 396
    .line 397
    iput v5, v0, Lcb0/c;->l:I

    .line 398
    .line 399
    invoke-static {v4, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 400
    .line 401
    .line 402
    move-result-object v4

    .line 403
    if-ne v4, v2, :cond_0

    .line 404
    .line 405
    goto/16 :goto_16

    .line 406
    .line 407
    :goto_8
    instance-of v3, v4, Lne0/e;

    .line 408
    .line 409
    if-eqz v3, :cond_9

    .line 410
    .line 411
    check-cast v4, Lne0/e;

    .line 412
    .line 413
    goto :goto_9

    .line 414
    :cond_9
    move-object v4, v11

    .line 415
    :goto_9
    if-eqz v4, :cond_a

    .line 416
    .line 417
    iget-object v3, v4, Lne0/e;->a:Ljava/lang/Object;

    .line 418
    .line 419
    check-cast v3, Lcq0/n;

    .line 420
    .line 421
    move-object v13, v3

    .line 422
    goto :goto_a

    .line 423
    :cond_a
    move-object v13, v11

    .line 424
    :goto_a
    iget-object v3, v10, Lcb0/d;->b:Lkc0/i;

    .line 425
    .line 426
    invoke-virtual {v3}, Lkc0/i;->invoke()Ljava/lang/Object;

    .line 427
    .line 428
    .line 429
    move-result-object v3

    .line 430
    check-cast v3, Ljava/lang/String;

    .line 431
    .line 432
    iget-object v4, v12, Lyr0/e;->a:Ljava/lang/String;

    .line 433
    .line 434
    iget-object v5, v10, Lcb0/d;->d:Lfj0/b;

    .line 435
    .line 436
    iput-object v1, v0, Lcb0/c;->m:Ljava/lang/Object;

    .line 437
    .line 438
    iput-object v15, v0, Lcb0/c;->d:Ljava/lang/String;

    .line 439
    .line 440
    iput-object v11, v0, Lcb0/c;->e:Lyr0/e;

    .line 441
    .line 442
    iput-object v14, v0, Lcb0/c;->f:Ljava/lang/String;

    .line 443
    .line 444
    iput-object v13, v0, Lcb0/c;->g:Lcq0/n;

    .line 445
    .line 446
    iput-object v3, v0, Lcb0/c;->h:Ljava/lang/String;

    .line 447
    .line 448
    iput-object v4, v0, Lcb0/c;->i:Ljava/lang/String;

    .line 449
    .line 450
    const/16 v6, 0x9

    .line 451
    .line 452
    iput v6, v0, Lcb0/c;->l:I

    .line 453
    .line 454
    iget-object v5, v5, Lfj0/b;->a:Lfj0/e;

    .line 455
    .line 456
    check-cast v5, Ldj0/b;

    .line 457
    .line 458
    iget-object v5, v5, Ldj0/b;->h:Lyy0/l1;

    .line 459
    .line 460
    iget-object v5, v5, Lyy0/l1;->d:Lyy0/a2;

    .line 461
    .line 462
    invoke-interface {v5}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 463
    .line 464
    .line 465
    move-result-object v5

    .line 466
    if-ne v5, v2, :cond_b

    .line 467
    .line 468
    goto/16 :goto_16

    .line 469
    .line 470
    :cond_b
    move-object/from16 v34, v3

    .line 471
    .line 472
    move-object/from16 v29, v4

    .line 473
    .line 474
    goto/16 :goto_1

    .line 475
    .line 476
    :goto_b
    check-cast v5, Ljava/util/Locale;

    .line 477
    .line 478
    invoke-virtual {v5}, Ljava/util/Locale;->getLanguage()Ljava/lang/String;

    .line 479
    .line 480
    .line 481
    move-result-object v27

    .line 482
    if-eqz v13, :cond_c

    .line 483
    .line 484
    new-instance v35, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;

    .line 485
    .line 486
    iget-object v3, v13, Lcq0/n;->h:Ljava/lang/String;

    .line 487
    .line 488
    iget-object v4, v13, Lcq0/n;->b:Ljava/lang/String;

    .line 489
    .line 490
    const/16 v39, 0x2

    .line 491
    .line 492
    const/16 v40, 0x0

    .line 493
    .line 494
    const/16 v37, 0x0

    .line 495
    .line 496
    move-object/from16 v36, v3

    .line 497
    .line 498
    move-object/from16 v38, v4

    .line 499
    .line 500
    invoke-direct/range {v35 .. v40}, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/g;)V

    .line 501
    .line 502
    .line 503
    move-object/from16 v30, v35

    .line 504
    .line 505
    goto :goto_c

    .line 506
    :cond_c
    move-object/from16 v30, v11

    .line 507
    .line 508
    :goto_c
    invoke-static/range {v27 .. v27}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 509
    .line 510
    .line 511
    iget-object v3, v0, Lcb0/c;->o:Ldb0/a;

    .line 512
    .line 513
    iget-object v3, v3, Ldb0/a;->d:Ljava/lang/String;

    .line 514
    .line 515
    new-instance v24, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPayload;

    .line 516
    .line 517
    const/16 v35, 0x182

    .line 518
    .line 519
    const/16 v36, 0x0

    .line 520
    .line 521
    const/16 v26, 0x0

    .line 522
    .line 523
    const/16 v32, 0x0

    .line 524
    .line 525
    const/16 v33, 0x0

    .line 526
    .line 527
    move-object/from16 v31, v3

    .line 528
    .line 529
    invoke-direct/range {v24 .. v36}, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPayload;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/g;)V

    .line 530
    .line 531
    .line 532
    move-object/from16 v12, v24

    .line 533
    .line 534
    iget-object v3, v10, Lcb0/d;->h:Lcb0/a;

    .line 535
    .line 536
    iget-object v4, v10, Lcb0/d;->g:Lam0/c;

    .line 537
    .line 538
    iput-object v1, v0, Lcb0/c;->m:Ljava/lang/Object;

    .line 539
    .line 540
    iput-object v11, v0, Lcb0/c;->d:Ljava/lang/String;

    .line 541
    .line 542
    iput-object v11, v0, Lcb0/c;->e:Lyr0/e;

    .line 543
    .line 544
    iput-object v11, v0, Lcb0/c;->f:Ljava/lang/String;

    .line 545
    .line 546
    iput-object v11, v0, Lcb0/c;->g:Lcq0/n;

    .line 547
    .line 548
    iput-object v11, v0, Lcb0/c;->h:Ljava/lang/String;

    .line 549
    .line 550
    iput-object v11, v0, Lcb0/c;->i:Ljava/lang/String;

    .line 551
    .line 552
    iput-object v12, v0, Lcb0/c;->j:Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPayload;

    .line 553
    .line 554
    iput-object v3, v0, Lcb0/c;->k:Lcb0/a;

    .line 555
    .line 556
    const/16 v5, 0xa

    .line 557
    .line 558
    iput v5, v0, Lcb0/c;->l:I

    .line 559
    .line 560
    invoke-virtual {v4, v9, v0}, Lam0/c;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 561
    .line 562
    .line 563
    move-result-object v4

    .line 564
    if-ne v4, v2, :cond_d

    .line 565
    .line 566
    goto/16 :goto_16

    .line 567
    .line 568
    :cond_d
    :goto_d
    check-cast v4, Lcm0/b;

    .line 569
    .line 570
    check-cast v3, Lab0/a;

    .line 571
    .line 572
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 573
    .line 574
    .line 575
    const-string v3, "env"

    .line 576
    .line 577
    invoke-static {v4, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 578
    .line 579
    .line 580
    const-string v3, "adm"

    .line 581
    .line 582
    invoke-static {v12, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 583
    .line 584
    .line 585
    new-instance v3, Lcom/squareup/moshi/Moshi$Builder;

    .line 586
    .line 587
    invoke-direct {v3}, Lcom/squareup/moshi/Moshi$Builder;-><init>()V

    .line 588
    .line 589
    .line 590
    new-instance v5, Lbx/d;

    .line 591
    .line 592
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 593
    .line 594
    .line 595
    invoke-virtual {v3, v5}, Lcom/squareup/moshi/Moshi$Builder;->a(Lcom/squareup/moshi/JsonAdapter$Factory;)V

    .line 596
    .line 597
    .line 598
    new-instance v5, Lcom/squareup/moshi/Moshi;

    .line 599
    .line 600
    invoke-direct {v5, v3}, Lcom/squareup/moshi/Moshi;-><init>(Lcom/squareup/moshi/Moshi$Builder;)V

    .line 601
    .line 602
    .line 603
    const-class v3, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPayload;

    .line 604
    .line 605
    sget-object v6, Lax/b;->a:Ljava/util/Set;

    .line 606
    .line 607
    invoke-virtual {v5, v3, v6, v11}, Lcom/squareup/moshi/Moshi;->a(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/String;)Lcom/squareup/moshi/JsonAdapter;

    .line 608
    .line 609
    .line 610
    move-result-object v3

    .line 611
    new-instance v5, Lu01/f;

    .line 612
    .line 613
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 614
    .line 615
    .line 616
    :try_start_0
    invoke-virtual {v3, v5, v12}, Lcom/squareup/moshi/JsonAdapter;->f(Lu01/g;Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 617
    .line 618
    .line 619
    invoke-virtual {v5}, Lu01/f;->T()Ljava/lang/String;

    .line 620
    .line 621
    .line 622
    move-result-object v3

    .line 623
    invoke-static {}, Ljava/util/Base64;->getUrlEncoder()Ljava/util/Base64$Encoder;

    .line 624
    .line 625
    .line 626
    move-result-object v5

    .line 627
    invoke-virtual {v5}, Ljava/util/Base64$Encoder;->withoutPadding()Ljava/util/Base64$Encoder;

    .line 628
    .line 629
    .line 630
    move-result-object v5

    .line 631
    sget-object v6, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 632
    .line 633
    invoke-virtual {v3, v6}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 634
    .line 635
    .line 636
    move-result-object v3

    .line 637
    const-string v6, "getBytes(...)"

    .line 638
    .line 639
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 640
    .line 641
    .line 642
    invoke-virtual {v5, v3}, Ljava/util/Base64$Encoder;->encodeToString([B)Ljava/lang/String;

    .line 643
    .line 644
    .line 645
    move-result-object v3

    .line 646
    const-string v5, "encodeToString(...)"

    .line 647
    .line 648
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 649
    .line 650
    .line 651
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 652
    .line 653
    .line 654
    move-result v4

    .line 655
    if-eqz v4, :cond_10

    .line 656
    .line 657
    if-eq v4, v8, :cond_10

    .line 658
    .line 659
    const/4 v5, 0x2

    .line 660
    if-eq v4, v5, :cond_f

    .line 661
    .line 662
    const/4 v5, 0x3

    .line 663
    if-eq v4, v5, :cond_f

    .line 664
    .line 665
    const/4 v5, 0x4

    .line 666
    if-ne v4, v5, :cond_e

    .line 667
    .line 668
    goto :goto_e

    .line 669
    :cond_e
    new-instance v0, La8/r0;

    .line 670
    .line 671
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 672
    .line 673
    .line 674
    throw v0

    .line 675
    :cond_f
    :goto_e
    const-string v4, "https://qa.acfspa.cariad.digital/acfspaf/"

    .line 676
    .line 677
    goto :goto_f

    .line 678
    :cond_10
    const-string v4, "https://live.acfspa.cariad.digital/acfspaf/"

    .line 679
    .line 680
    :goto_f
    const-string v5, "?adm-context="

    .line 681
    .line 682
    invoke-static {v4, v5, v3}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 683
    .line 684
    .line 685
    move-result-object v3

    .line 686
    iget-object v4, v10, Lcb0/d;->f:Lbd0/c;

    .line 687
    .line 688
    const/16 v5, 0x1e

    .line 689
    .line 690
    const/16 v16, 0x2

    .line 691
    .line 692
    and-int/lit8 v6, v5, 0x2

    .line 693
    .line 694
    const/4 v7, 0x0

    .line 695
    if-eqz v6, :cond_11

    .line 696
    .line 697
    move/from16 v25, v8

    .line 698
    .line 699
    :goto_10
    const/16 v22, 0x4

    .line 700
    .line 701
    goto :goto_11

    .line 702
    :cond_11
    move/from16 v25, v7

    .line 703
    .line 704
    goto :goto_10

    .line 705
    :goto_11
    and-int/lit8 v6, v5, 0x4

    .line 706
    .line 707
    if-eqz v6, :cond_12

    .line 708
    .line 709
    move/from16 v26, v8

    .line 710
    .line 711
    :goto_12
    const/16 v17, 0x8

    .line 712
    .line 713
    goto :goto_13

    .line 714
    :cond_12
    move/from16 v26, v7

    .line 715
    .line 716
    goto :goto_12

    .line 717
    :goto_13
    and-int/lit8 v6, v5, 0x8

    .line 718
    .line 719
    if-eqz v6, :cond_13

    .line 720
    .line 721
    move/from16 v27, v7

    .line 722
    .line 723
    goto :goto_14

    .line 724
    :cond_13
    move/from16 v27, v8

    .line 725
    .line 726
    :goto_14
    and-int/lit8 v5, v5, 0x10

    .line 727
    .line 728
    if-eqz v5, :cond_14

    .line 729
    .line 730
    move/from16 v28, v7

    .line 731
    .line 732
    goto :goto_15

    .line 733
    :cond_14
    move/from16 v28, v8

    .line 734
    .line 735
    :goto_15
    const-string v5, "url"

    .line 736
    .line 737
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 738
    .line 739
    .line 740
    iget-object v4, v4, Lbd0/c;->a:Lbd0/a;

    .line 741
    .line 742
    new-instance v5, Ljava/net/URL;

    .line 743
    .line 744
    invoke-direct {v5, v3}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 745
    .line 746
    .line 747
    move-object/from16 v23, v4

    .line 748
    .line 749
    check-cast v23, Lzc0/b;

    .line 750
    .line 751
    move-object/from16 v24, v5

    .line 752
    .line 753
    invoke-virtual/range {v23 .. v28}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 754
    .line 755
    .line 756
    new-instance v3, Lne0/e;

    .line 757
    .line 758
    invoke-direct {v3, v9}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 759
    .line 760
    .line 761
    iput-object v11, v0, Lcb0/c;->m:Ljava/lang/Object;

    .line 762
    .line 763
    iput-object v11, v0, Lcb0/c;->d:Ljava/lang/String;

    .line 764
    .line 765
    iput-object v11, v0, Lcb0/c;->e:Lyr0/e;

    .line 766
    .line 767
    iput-object v11, v0, Lcb0/c;->f:Ljava/lang/String;

    .line 768
    .line 769
    iput-object v11, v0, Lcb0/c;->g:Lcq0/n;

    .line 770
    .line 771
    iput-object v11, v0, Lcb0/c;->h:Ljava/lang/String;

    .line 772
    .line 773
    iput-object v11, v0, Lcb0/c;->i:Ljava/lang/String;

    .line 774
    .line 775
    iput-object v11, v0, Lcb0/c;->j:Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPayload;

    .line 776
    .line 777
    iput-object v11, v0, Lcb0/c;->k:Lcb0/a;

    .line 778
    .line 779
    const/16 v4, 0xb

    .line 780
    .line 781
    iput v4, v0, Lcb0/c;->l:I

    .line 782
    .line 783
    invoke-interface {v1, v3, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 784
    .line 785
    .line 786
    move-result-object v0

    .line 787
    if-ne v0, v2, :cond_15

    .line 788
    .line 789
    :goto_16
    return-object v2

    .line 790
    :cond_15
    return-object v9

    .line 791
    :catch_0
    move-exception v0

    .line 792
    new-instance v1, Ljava/lang/AssertionError;

    .line 793
    .line 794
    invoke-direct {v1, v0}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    .line 795
    .line 796
    .line 797
    throw v1

    .line 798
    nop

    .line 799
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_b
        :pswitch_a
        :pswitch_9
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
