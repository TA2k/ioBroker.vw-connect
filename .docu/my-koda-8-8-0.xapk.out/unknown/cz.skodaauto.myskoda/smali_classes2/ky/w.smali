.class public final Lky/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lky/j;

.field public final b:Lkc0/q;

.field public final c:Lci0/d;

.field public final d:Lgb0/c0;

.field public final e:Lgb0/j;

.field public final f:Lky/f0;

.field public final g:Lky/i;

.field public final h:Lky/c;

.field public final i:Lky/r;


# direct methods
.method public constructor <init>(Lam0/r;Lky/j;Lkc0/q;Lci0/d;Lgb0/c0;Lgb0/j;Lky/f0;Lky/i;Lky/c;Lam0/c;Lky/r;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lky/w;->a:Lky/j;

    .line 5
    .line 6
    iput-object p3, p0, Lky/w;->b:Lkc0/q;

    .line 7
    .line 8
    iput-object p4, p0, Lky/w;->c:Lci0/d;

    .line 9
    .line 10
    iput-object p5, p0, Lky/w;->d:Lgb0/c0;

    .line 11
    .line 12
    iput-object p6, p0, Lky/w;->e:Lgb0/j;

    .line 13
    .line 14
    iput-object p7, p0, Lky/w;->f:Lky/f0;

    .line 15
    .line 16
    iput-object p8, p0, Lky/w;->g:Lky/i;

    .line 17
    .line 18
    iput-object p9, p0, Lky/w;->h:Lky/c;

    .line 19
    .line 20
    iput-object p11, p0, Lky/w;->i:Lky/r;

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lky/u;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lky/w;->b(Lky/u;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lky/u;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p2

    .line 4
    .line 5
    instance-of v2, v0, Lky/v;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v0

    .line 10
    check-cast v2, Lky/v;

    .line 11
    .line 12
    iget v3, v2, Lky/v;->j:I

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
    iput v3, v2, Lky/v;->j:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lky/v;

    .line 25
    .line 26
    invoke-direct {v2, v1, v0}, Lky/v;-><init>(Lky/w;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v0, v2, Lky/v;->h:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lky/v;->j:I

    .line 34
    .line 35
    const/16 v5, 0x15

    .line 36
    .line 37
    const/4 v6, 0x2

    .line 38
    iget-object v7, v1, Lky/w;->i:Lky/r;

    .line 39
    .line 40
    const/4 v8, 0x0

    .line 41
    iget-object v9, v1, Lky/w;->a:Lky/j;

    .line 42
    .line 43
    sget-object v10, Llx0/b0;->a:Llx0/b0;

    .line 44
    .line 45
    const/4 v11, 0x1

    .line 46
    const/4 v12, 0x0

    .line 47
    packed-switch v4, :pswitch_data_0

    .line 48
    .line 49
    .line 50
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 53
    .line 54
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw v0

    .line 58
    :pswitch_0
    iget-object v3, v2, Lky/v;->f:Ljava/io/Serializable;

    .line 59
    .line 60
    check-cast v3, Lly/b;

    .line 61
    .line 62
    iget-object v2, v2, Lky/v;->d:Lky/u;

    .line 63
    .line 64
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    goto/16 :goto_c

    .line 68
    .line 69
    :pswitch_1
    iget-object v1, v2, Lky/v;->f:Ljava/io/Serializable;

    .line 70
    .line 71
    check-cast v1, Lly/b;

    .line 72
    .line 73
    iget-object v1, v2, Lky/v;->d:Lky/u;

    .line 74
    .line 75
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    goto/16 :goto_a

    .line 79
    .line 80
    :pswitch_2
    iget-object v4, v2, Lky/v;->f:Ljava/io/Serializable;

    .line 81
    .line 82
    check-cast v4, Lly/b;

    .line 83
    .line 84
    iget-object v5, v2, Lky/v;->e:Ljava/util/Map;

    .line 85
    .line 86
    iget-object v11, v2, Lky/v;->d:Lky/u;

    .line 87
    .line 88
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    move-object v6, v5

    .line 92
    move-object v5, v4

    .line 93
    move-object v4, v11

    .line 94
    goto/16 :goto_9

    .line 95
    .line 96
    :pswitch_3
    iget-object v4, v2, Lky/v;->f:Ljava/io/Serializable;

    .line 97
    .line 98
    check-cast v4, Lss0/d0;

    .line 99
    .line 100
    iget-object v4, v2, Lky/v;->e:Ljava/util/Map;

    .line 101
    .line 102
    iget-object v5, v2, Lky/v;->d:Lky/u;

    .line 103
    .line 104
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    goto/16 :goto_7

    .line 108
    .line 109
    :pswitch_4
    iget v4, v2, Lky/v;->g:I

    .line 110
    .line 111
    iget-object v13, v2, Lky/v;->f:Ljava/io/Serializable;

    .line 112
    .line 113
    check-cast v13, Lss0/d0;

    .line 114
    .line 115
    iget-object v14, v2, Lky/v;->e:Ljava/util/Map;

    .line 116
    .line 117
    iget-object v15, v2, Lky/v;->d:Lky/u;

    .line 118
    .line 119
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    move-object/from16 v16, v13

    .line 123
    .line 124
    move v13, v4

    .line 125
    move-object v4, v14

    .line 126
    move-object/from16 v14, v16

    .line 127
    .line 128
    goto/16 :goto_6

    .line 129
    .line 130
    :pswitch_5
    iget-object v4, v2, Lky/v;->d:Lky/u;

    .line 131
    .line 132
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    goto :goto_1

    .line 136
    :pswitch_6
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 137
    .line 138
    .line 139
    move-object/from16 v0, p1

    .line 140
    .line 141
    iput-object v0, v2, Lky/v;->d:Lky/u;

    .line 142
    .line 143
    iput v11, v2, Lky/v;->j:I

    .line 144
    .line 145
    iget-object v4, v1, Lky/w;->b:Lkc0/q;

    .line 146
    .line 147
    invoke-virtual {v4, v10, v2}, Lkc0/q;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v4

    .line 151
    if-ne v4, v3, :cond_1

    .line 152
    .line 153
    goto/16 :goto_b

    .line 154
    .line 155
    :cond_1
    move-object/from16 v16, v4

    .line 156
    .line 157
    move-object v4, v0

    .line 158
    move-object/from16 v0, v16

    .line 159
    .line 160
    :goto_1
    check-cast v0, Ljava/lang/Boolean;

    .line 161
    .line 162
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 163
    .line 164
    .line 165
    move-result v0

    .line 166
    if-nez v0, :cond_2

    .line 167
    .line 168
    new-instance v0, Ljv0/c;

    .line 169
    .line 170
    const/16 v13, 0x1a

    .line 171
    .line 172
    invoke-direct {v0, v13}, Ljv0/c;-><init>(I)V

    .line 173
    .line 174
    .line 175
    invoke-static {v12, v1, v0}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 176
    .line 177
    .line 178
    move-object v0, v9

    .line 179
    check-cast v0, Liy/b;

    .line 180
    .line 181
    invoke-virtual {v0, v11}, Liy/b;->g(Z)V

    .line 182
    .line 183
    .line 184
    iget-object v0, v4, Lky/u;->a:Ljava/lang/String;

    .line 185
    .line 186
    sget-object v13, Lhf0/d;->a:Ljava/util/List;

    .line 187
    .line 188
    const-string v13, "$v$c$cz-skodaauto-myskoda-library-deeplink-model-Link$-$this$shouldProcessWhenNotSignedIn$0"

    .line 189
    .line 190
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    sget-object v13, Lhf0/d;->a:Ljava/util/List;

    .line 194
    .line 195
    invoke-static {v0}, Lhf0/d;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 196
    .line 197
    .line 198
    move-result-object v0

    .line 199
    invoke-static {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->box-impl(Ljava/lang/String;)Lcz/skodaauto/myskoda/library/deeplink/model/Link;

    .line 200
    .line 201
    .line 202
    move-result-object v0

    .line 203
    invoke-interface {v13, v0}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 204
    .line 205
    .line 206
    move-result v0

    .line 207
    if-nez v0, :cond_2

    .line 208
    .line 209
    return-object v10

    .line 210
    :cond_2
    iget-object v0, v4, Lky/u;->a:Ljava/lang/String;

    .line 211
    .line 212
    sget-object v13, Lhf0/d;->a:Ljava/util/List;

    .line 213
    .line 214
    const-string v13, "$v$c$cz-skodaauto-myskoda-library-deeplink-model-Link$-$this$isValid$0"

    .line 215
    .line 216
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 217
    .line 218
    .line 219
    invoke-static {v0}, Lhf0/d;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 220
    .line 221
    .line 222
    move-result-object v0

    .line 223
    invoke-static {}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getEntries()Lsx0/a;

    .line 224
    .line 225
    .line 226
    move-result-object v13

    .line 227
    if-eqz v13, :cond_3

    .line 228
    .line 229
    invoke-interface {v13}, Ljava/util/Collection;->isEmpty()Z

    .line 230
    .line 231
    .line 232
    move-result v14

    .line 233
    if-eqz v14, :cond_3

    .line 234
    .line 235
    goto/16 :goto_d

    .line 236
    .line 237
    :cond_3
    invoke-interface {v13}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 238
    .line 239
    .line 240
    move-result-object v13

    .line 241
    :cond_4
    invoke-interface {v13}, Ljava/util/Iterator;->hasNext()Z

    .line 242
    .line 243
    .line 244
    move-result v14

    .line 245
    if-eqz v14, :cond_13

    .line 246
    .line 247
    invoke-interface {v13}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    move-result-object v14

    .line 251
    check-cast v14, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 252
    .line 253
    invoke-virtual {v14}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 254
    .line 255
    .line 256
    move-result-object v14

    .line 257
    invoke-static {v14, v0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->equals-impl0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 258
    .line 259
    .line 260
    move-result v14

    .line 261
    if-eqz v14, :cond_4

    .line 262
    .line 263
    iget-object v0, v4, Lky/u;->a:Ljava/lang/String;

    .line 264
    .line 265
    :try_start_0
    invoke-static {v0}, Ljava/net/URI;->create(Ljava/lang/String;)Ljava/net/URI;

    .line 266
    .line 267
    .line 268
    move-result-object v0

    .line 269
    const-string v13, "create(...)"

    .line 270
    .line 271
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 272
    .line 273
    .line 274
    invoke-static {v0}, Ljp/xa;->b(Ljava/net/URI;)Ljava/util/HashMap;

    .line 275
    .line 276
    .line 277
    move-result-object v0
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 278
    goto :goto_2

    .line 279
    :catch_0
    move-exception v0

    .line 280
    new-instance v13, Lgd0/b;

    .line 281
    .line 282
    invoke-direct {v13, v11, v0}, Lgd0/b;-><init>(ILjava/lang/IllegalArgumentException;)V

    .line 283
    .line 284
    .line 285
    invoke-static {v12, v1, v13}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 286
    .line 287
    .line 288
    sget-object v0, Lmx0/t;->d:Lmx0/t;

    .line 289
    .line 290
    :goto_2
    const-string v13, "vin"

    .line 291
    .line 292
    invoke-interface {v0, v13}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 293
    .line 294
    .line 295
    move-result-object v13

    .line 296
    check-cast v13, Ljava/lang/String;

    .line 297
    .line 298
    if-eqz v13, :cond_5

    .line 299
    .line 300
    goto :goto_3

    .line 301
    :cond_5
    move-object v13, v12

    .line 302
    :goto_3
    if-eqz v13, :cond_6

    .line 303
    .line 304
    new-instance v14, Lss0/j0;

    .line 305
    .line 306
    invoke-direct {v14, v13}, Lss0/j0;-><init>(Ljava/lang/String;)V

    .line 307
    .line 308
    .line 309
    goto :goto_5

    .line 310
    :cond_6
    const-string v13, "commissionId"

    .line 311
    .line 312
    invoke-interface {v0, v13}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 313
    .line 314
    .line 315
    move-result-object v13

    .line 316
    check-cast v13, Ljava/lang/String;

    .line 317
    .line 318
    if-eqz v13, :cond_7

    .line 319
    .line 320
    goto :goto_4

    .line 321
    :cond_7
    move-object v13, v12

    .line 322
    :goto_4
    if-eqz v13, :cond_8

    .line 323
    .line 324
    new-instance v14, Lss0/g;

    .line 325
    .line 326
    invoke-direct {v14, v13}, Lss0/g;-><init>(Ljava/lang/String;)V

    .line 327
    .line 328
    .line 329
    goto :goto_5

    .line 330
    :cond_8
    move-object v14, v12

    .line 331
    :goto_5
    move-object v13, v14

    .line 332
    check-cast v13, Lss0/d0;

    .line 333
    .line 334
    if-eqz v13, :cond_d

    .line 335
    .line 336
    iput-object v4, v2, Lky/v;->d:Lky/u;

    .line 337
    .line 338
    move-object v14, v0

    .line 339
    check-cast v14, Ljava/util/Map;

    .line 340
    .line 341
    iput-object v14, v2, Lky/v;->e:Ljava/util/Map;

    .line 342
    .line 343
    move-object v14, v13

    .line 344
    check-cast v14, Ljava/io/Serializable;

    .line 345
    .line 346
    iput-object v14, v2, Lky/v;->f:Ljava/io/Serializable;

    .line 347
    .line 348
    iput v8, v2, Lky/v;->g:I

    .line 349
    .line 350
    iput v6, v2, Lky/v;->j:I

    .line 351
    .line 352
    iget-object v14, v1, Lky/w;->e:Lgb0/j;

    .line 353
    .line 354
    invoke-virtual {v14, v2}, Lgb0/j;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 355
    .line 356
    .line 357
    move-result-object v14

    .line 358
    if-ne v14, v3, :cond_9

    .line 359
    .line 360
    goto/16 :goto_b

    .line 361
    .line 362
    :cond_9
    move-object v15, v4

    .line 363
    move-object v4, v0

    .line 364
    move-object v0, v14

    .line 365
    move-object v14, v13

    .line 366
    move v13, v8

    .line 367
    :goto_6
    check-cast v0, Lne0/t;

    .line 368
    .line 369
    new-instance v6, Li40/e1;

    .line 370
    .line 371
    invoke-direct {v6, v14, v5}, Li40/e1;-><init>(Ljava/lang/Object;I)V

    .line 372
    .line 373
    .line 374
    invoke-static {v0, v6}, Lbb/j0;->c(Lne0/t;Lay0/k;)Lne0/t;

    .line 375
    .line 376
    .line 377
    move-result-object v0

    .line 378
    instance-of v0, v0, Lne0/c;

    .line 379
    .line 380
    if-eqz v0, :cond_c

    .line 381
    .line 382
    new-instance v0, Lky/s;

    .line 383
    .line 384
    invoke-direct {v0, v14, v8}, Lky/s;-><init>(Lss0/d0;I)V

    .line 385
    .line 386
    .line 387
    invoke-static {v12, v1, v0}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 388
    .line 389
    .line 390
    iput-object v15, v2, Lky/v;->d:Lky/u;

    .line 391
    .line 392
    iput-object v4, v2, Lky/v;->e:Ljava/util/Map;

    .line 393
    .line 394
    iput-object v12, v2, Lky/v;->f:Ljava/io/Serializable;

    .line 395
    .line 396
    iput v13, v2, Lky/v;->g:I

    .line 397
    .line 398
    const/4 v0, 0x3

    .line 399
    iput v0, v2, Lky/v;->j:I

    .line 400
    .line 401
    sget-object v0, Lge0/b;->a:Lcz0/e;

    .line 402
    .line 403
    new-instance v5, Lk31/l;

    .line 404
    .line 405
    const/16 v6, 0x9

    .line 406
    .line 407
    invoke-direct {v5, v6, v1, v14, v12}, Lk31/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 408
    .line 409
    .line 410
    invoke-static {v0, v5, v2}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 411
    .line 412
    .line 413
    move-result-object v0

    .line 414
    if-ne v0, v3, :cond_a

    .line 415
    .line 416
    goto/16 :goto_b

    .line 417
    .line 418
    :cond_a
    move-object v5, v15

    .line 419
    :goto_7
    check-cast v0, Lne0/t;

    .line 420
    .line 421
    instance-of v6, v0, Lne0/c;

    .line 422
    .line 423
    if-eqz v6, :cond_b

    .line 424
    .line 425
    check-cast v0, Lne0/c;

    .line 426
    .line 427
    new-instance v2, La60/a;

    .line 428
    .line 429
    invoke-direct {v2, v0, v11}, La60/a;-><init>(Lne0/c;I)V

    .line 430
    .line 431
    .line 432
    invoke-static {v1, v2}, Llp/nd;->e(Ljava/lang/Object;Lay0/a;)V

    .line 433
    .line 434
    .line 435
    check-cast v9, Liy/b;

    .line 436
    .line 437
    invoke-virtual {v9, v11}, Liy/b;->g(Z)V

    .line 438
    .line 439
    .line 440
    return-object v10

    .line 441
    :cond_b
    move-object v0, v4

    .line 442
    move-object v4, v5

    .line 443
    goto :goto_8

    .line 444
    :cond_c
    move-object v0, v4

    .line 445
    move-object v4, v15

    .line 446
    :cond_d
    :goto_8
    move-object v5, v0

    .line 447
    iget-object v0, v4, Lky/u;->a:Ljava/lang/String;

    .line 448
    .line 449
    invoke-static {v0}, Lrp/d;->d(Ljava/lang/String;)Lly/b;

    .line 450
    .line 451
    .line 452
    move-result-object v0

    .line 453
    iput-object v4, v2, Lky/v;->d:Lky/u;

    .line 454
    .line 455
    iput-object v5, v2, Lky/v;->e:Ljava/util/Map;

    .line 456
    .line 457
    iput-object v0, v2, Lky/v;->f:Ljava/io/Serializable;

    .line 458
    .line 459
    const/4 v6, 0x4

    .line 460
    iput v6, v2, Lky/v;->j:I

    .line 461
    .line 462
    iget-object v6, v1, Lky/w;->g:Lky/i;

    .line 463
    .line 464
    invoke-virtual {v6, v0, v2}, Lky/i;->b(Lly/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 465
    .line 466
    .line 467
    move-result-object v6

    .line 468
    if-ne v6, v3, :cond_e

    .line 469
    .line 470
    goto :goto_b

    .line 471
    :cond_e
    move-object/from16 v16, v5

    .line 472
    .line 473
    move-object v5, v0

    .line 474
    move-object v0, v6

    .line 475
    move-object/from16 v6, v16

    .line 476
    .line 477
    :goto_9
    check-cast v0, Ljava/lang/Boolean;

    .line 478
    .line 479
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 480
    .line 481
    .line 482
    move-result v0

    .line 483
    if-nez v0, :cond_10

    .line 484
    .line 485
    new-instance v0, Lky/t;

    .line 486
    .line 487
    invoke-direct {v0, v5, v8}, Lky/t;-><init>(Lly/b;I)V

    .line 488
    .line 489
    .line 490
    invoke-static {v12, v1, v0}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 491
    .line 492
    .line 493
    iput-object v4, v2, Lky/v;->d:Lky/u;

    .line 494
    .line 495
    iput-object v12, v2, Lky/v;->e:Ljava/util/Map;

    .line 496
    .line 497
    iput-object v12, v2, Lky/v;->f:Ljava/io/Serializable;

    .line 498
    .line 499
    const/4 v0, 0x5

    .line 500
    iput v0, v2, Lky/v;->j:I

    .line 501
    .line 502
    iget-object v0, v1, Lky/w;->h:Lky/c;

    .line 503
    .line 504
    invoke-virtual {v0, v5, v2}, Lky/c;->c(Lly/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 505
    .line 506
    .line 507
    move-result-object v0

    .line 508
    if-ne v0, v3, :cond_f

    .line 509
    .line 510
    goto :goto_b

    .line 511
    :cond_f
    move-object v1, v4

    .line 512
    :goto_a
    check-cast v0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 513
    .line 514
    invoke-virtual {v0}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 515
    .line 516
    .line 517
    move-result-object v0

    .line 518
    iget-boolean v2, v1, Lky/u;->b:Z

    .line 519
    .line 520
    iget-boolean v1, v1, Lky/u;->c:Z

    .line 521
    .line 522
    check-cast v9, Liy/b;

    .line 523
    .line 524
    invoke-virtual {v9, v0, v2, v1}, Liy/b;->c(Ljava/lang/String;ZZ)V

    .line 525
    .line 526
    .line 527
    return-object v10

    .line 528
    :cond_10
    new-instance v0, Lky/c0;

    .line 529
    .line 530
    invoke-direct {v0, v5, v6}, Lky/c0;-><init>(Lly/b;Ljava/util/Map;)V

    .line 531
    .line 532
    .line 533
    iput-object v4, v2, Lky/v;->d:Lky/u;

    .line 534
    .line 535
    iput-object v12, v2, Lky/v;->e:Ljava/util/Map;

    .line 536
    .line 537
    iput-object v12, v2, Lky/v;->f:Ljava/io/Serializable;

    .line 538
    .line 539
    const/4 v5, 0x6

    .line 540
    iput v5, v2, Lky/v;->j:I

    .line 541
    .line 542
    iget-object v5, v1, Lky/w;->f:Lky/f0;

    .line 543
    .line 544
    invoke-virtual {v5, v0, v2}, Lky/f0;->b(Lky/c0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 545
    .line 546
    .line 547
    move-result-object v0

    .line 548
    if-ne v0, v3, :cond_11

    .line 549
    .line 550
    :goto_b
    return-object v3

    .line 551
    :cond_11
    move-object v2, v4

    .line 552
    :goto_c
    check-cast v0, Lne0/t;

    .line 553
    .line 554
    instance-of v3, v0, Lne0/c;

    .line 555
    .line 556
    if-eqz v3, :cond_12

    .line 557
    .line 558
    check-cast v0, Lne0/c;

    .line 559
    .line 560
    new-instance v2, La60/a;

    .line 561
    .line 562
    const/4 v6, 0x2

    .line 563
    invoke-direct {v2, v0, v6}, La60/a;-><init>(Lne0/c;I)V

    .line 564
    .line 565
    .line 566
    invoke-static {v12, v1, v2}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 567
    .line 568
    .line 569
    invoke-virtual {v7}, Lky/r;->invoke()Ljava/lang/Object;

    .line 570
    .line 571
    .line 572
    return-object v10

    .line 573
    :cond_12
    iget-object v0, v2, Lky/u;->a:Ljava/lang/String;

    .line 574
    .line 575
    iget-boolean v1, v2, Lky/u;->b:Z

    .line 576
    .line 577
    iget-boolean v2, v2, Lky/u;->c:Z

    .line 578
    .line 579
    check-cast v9, Liy/b;

    .line 580
    .line 581
    invoke-virtual {v9, v0, v1, v2}, Liy/b;->c(Ljava/lang/String;ZZ)V

    .line 582
    .line 583
    .line 584
    return-object v10

    .line 585
    :cond_13
    :goto_d
    new-instance v0, Lh50/q0;

    .line 586
    .line 587
    invoke-direct {v0, v4, v5}, Lh50/q0;-><init>(Ljava/lang/Object;I)V

    .line 588
    .line 589
    .line 590
    invoke-static {v12, v1, v0}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 591
    .line 592
    .line 593
    invoke-virtual {v7}, Lky/r;->invoke()Ljava/lang/Object;

    .line 594
    .line 595
    .line 596
    return-object v10

    .line 597
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
