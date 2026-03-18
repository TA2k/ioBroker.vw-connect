.class public final Lbz/w;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final r:Lhl0/b;


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lzy/z;

.field public final j:Lzy/u;

.field public final k:Lzy/i;

.field public final l:Lgl0/e;

.field public final m:Lzy/q;

.field public final n:Lzy/v;

.field public final o:Lij0/a;

.field public final p:Lzy/s;

.field public final q:Lzy/j;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    sget-object v0, Lhl0/a;->g:Lhl0/a;

    .line 2
    .line 3
    new-instance v1, Lhl0/b;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/16 v3, 0x79f

    .line 7
    .line 8
    invoke-direct {v1, v2, v0, v3}, Lhl0/b;-><init>(ZLhl0/a;I)V

    .line 9
    .line 10
    .line 11
    sput-object v1, Lbz/w;->r:Lhl0/b;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(Ltr0/b;Lzy/z;Lzy/u;Lzy/i;Lgl0/e;Lzy/q;Lzy/v;Lij0/a;Lzy/s;Lzy/j;)V
    .locals 4

    .line 1
    new-instance v0, Lbz/u;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 5
    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v0, v3, v3, v1, v2}, Lbz/u;-><init>(Laz/d;Laz/d;ZLjava/util/List;)V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lbz/w;->h:Ltr0/b;

    .line 14
    .line 15
    iput-object p2, p0, Lbz/w;->i:Lzy/z;

    .line 16
    .line 17
    iput-object p3, p0, Lbz/w;->j:Lzy/u;

    .line 18
    .line 19
    iput-object p4, p0, Lbz/w;->k:Lzy/i;

    .line 20
    .line 21
    iput-object p5, p0, Lbz/w;->l:Lgl0/e;

    .line 22
    .line 23
    iput-object p6, p0, Lbz/w;->m:Lzy/q;

    .line 24
    .line 25
    iput-object p7, p0, Lbz/w;->n:Lzy/v;

    .line 26
    .line 27
    iput-object p8, p0, Lbz/w;->o:Lij0/a;

    .line 28
    .line 29
    iput-object p9, p0, Lbz/w;->p:Lzy/s;

    .line 30
    .line 31
    iput-object p10, p0, Lbz/w;->q:Lzy/j;

    .line 32
    .line 33
    new-instance p1, Lbz/t;

    .line 34
    .line 35
    const/4 p2, 0x0

    .line 36
    invoke-direct {p1, p0, v3, p2}, Lbz/t;-><init>(Lbz/w;Lkotlin/coroutines/Continuation;I)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 40
    .line 41
    .line 42
    return-void
.end method

.method public static final h(Lbz/w;Lrx0/c;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    instance-of v2, v1, Lbz/v;

    .line 9
    .line 10
    if-eqz v2, :cond_0

    .line 11
    .line 12
    move-object v2, v1

    .line 13
    check-cast v2, Lbz/v;

    .line 14
    .line 15
    iget v3, v2, Lbz/v;->g:I

    .line 16
    .line 17
    const/high16 v4, -0x80000000

    .line 18
    .line 19
    and-int v5, v3, v4

    .line 20
    .line 21
    if-eqz v5, :cond_0

    .line 22
    .line 23
    sub-int/2addr v3, v4

    .line 24
    iput v3, v2, Lbz/v;->g:I

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    new-instance v2, Lbz/v;

    .line 28
    .line 29
    invoke-direct {v2, v0, v1}, Lbz/v;-><init>(Lbz/w;Lrx0/c;)V

    .line 30
    .line 31
    .line 32
    :goto_0
    iget-object v1, v2, Lbz/v;->e:Ljava/lang/Object;

    .line 33
    .line 34
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 35
    .line 36
    iget v4, v2, Lbz/v;->g:I

    .line 37
    .line 38
    const/4 v5, 0x2

    .line 39
    const/4 v6, 0x1

    .line 40
    if-eqz v4, :cond_3

    .line 41
    .line 42
    if-eq v4, v6, :cond_2

    .line 43
    .line 44
    if-ne v4, v5, :cond_1

    .line 45
    .line 46
    iget-boolean v2, v2, Lbz/v;->d:Z

    .line 47
    .line 48
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    goto :goto_3

    .line 52
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 55
    .line 56
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw v0

    .line 60
    :cond_2
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_3
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    iget-object v1, v0, Lbz/w;->p:Lzy/s;

    .line 68
    .line 69
    iput v6, v2, Lbz/v;->g:I

    .line 70
    .line 71
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 72
    .line 73
    .line 74
    invoke-virtual {v1, v2}, Lzy/s;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v1

    .line 78
    if-ne v1, v3, :cond_4

    .line 79
    .line 80
    goto :goto_2

    .line 81
    :cond_4
    :goto_1
    check-cast v1, Ljava/lang/Boolean;

    .line 82
    .line 83
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    if-eqz v1, :cond_c

    .line 88
    .line 89
    iget-object v4, v0, Lbz/w;->q:Lzy/j;

    .line 90
    .line 91
    iput-boolean v1, v2, Lbz/v;->d:Z

    .line 92
    .line 93
    iput v5, v2, Lbz/v;->g:I

    .line 94
    .line 95
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 96
    .line 97
    .line 98
    iget-object v2, v4, Lzy/j;->a:Lxy/e;

    .line 99
    .line 100
    new-instance v4, Laz/i;

    .line 101
    .line 102
    iget-object v5, v2, Lxy/e;->b:Laz/d;

    .line 103
    .line 104
    iget-object v6, v2, Lxy/e;->c:Laz/d;

    .line 105
    .line 106
    iget-object v7, v2, Lxy/e;->d:Ljava/util/ArrayList;

    .line 107
    .line 108
    iget v8, v2, Lxy/e;->h:I

    .line 109
    .line 110
    iget-object v9, v2, Lxy/e;->e:Ljava/util/ArrayList;

    .line 111
    .line 112
    iget-object v10, v2, Lxy/e;->f:Laz/h;

    .line 113
    .line 114
    iget-boolean v11, v2, Lxy/e;->g:Z

    .line 115
    .line 116
    iget-boolean v12, v2, Lxy/e;->i:Z

    .line 117
    .line 118
    invoke-direct/range {v4 .. v12}, Laz/i;-><init>(Laz/d;Laz/d;Ljava/util/List;ILjava/util/List;Laz/h;ZZ)V

    .line 119
    .line 120
    .line 121
    if-ne v4, v3, :cond_5

    .line 122
    .line 123
    :goto_2
    return-object v3

    .line 124
    :cond_5
    move v2, v1

    .line 125
    move-object v1, v4

    .line 126
    :goto_3
    check-cast v1, Laz/i;

    .line 127
    .line 128
    iget-object v3, v0, Lbz/w;->o:Lij0/a;

    .line 129
    .line 130
    const-string v4, "<this>"

    .line 131
    .line 132
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    iget-object v4, v1, Laz/i;->f:Laz/h;

    .line 136
    .line 137
    iget v5, v1, Laz/i;->d:I

    .line 138
    .line 139
    const-string v6, "stringResource"

    .line 140
    .line 141
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    new-instance v6, Ljava/util/ArrayList;

    .line 145
    .line 146
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 147
    .line 148
    .line 149
    iget-object v7, v1, Laz/i;->c:Ljava/util/List;

    .line 150
    .line 151
    iget-object v8, v1, Laz/i;->e:Ljava/util/List;

    .line 152
    .line 153
    check-cast v7, Ljava/lang/Iterable;

    .line 154
    .line 155
    new-instance v9, Ljava/util/ArrayList;

    .line 156
    .line 157
    const/16 v10, 0xa

    .line 158
    .line 159
    invoke-static {v7, v10}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 160
    .line 161
    .line 162
    move-result v11

    .line 163
    invoke-direct {v9, v11}, Ljava/util/ArrayList;-><init>(I)V

    .line 164
    .line 165
    .line 166
    invoke-interface {v7}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 167
    .line 168
    .line 169
    move-result-object v7

    .line 170
    :goto_4
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 171
    .line 172
    .line 173
    move-result v11

    .line 174
    if-eqz v11, :cond_9

    .line 175
    .line 176
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object v11

    .line 180
    check-cast v11, Laz/c;

    .line 181
    .line 182
    sget-object v13, Laz/c;->f:Laz/c;

    .line 183
    .line 184
    const-string v14, "interest_"

    .line 185
    .line 186
    if-ne v11, v13, :cond_8

    .line 187
    .line 188
    invoke-interface {v8}, Ljava/util/List;->isEmpty()Z

    .line 189
    .line 190
    .line 191
    move-result v11

    .line 192
    if-eqz v11, :cond_6

    .line 193
    .line 194
    new-instance v11, Laz/j;

    .line 195
    .line 196
    invoke-static {v13, v3}, Ljp/nb;->e(Laz/c;Lij0/a;)Ljava/lang/String;

    .line 197
    .line 198
    .line 199
    move-result-object v15

    .line 200
    invoke-static {v13}, Ljp/nb;->d(Laz/c;)I

    .line 201
    .line 202
    .line 203
    move-result v16

    .line 204
    invoke-static/range {v16 .. v16}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 205
    .line 206
    .line 207
    move-result-object v12

    .line 208
    iget-object v13, v13, Laz/c;->e:Ljava/lang/String;

    .line 209
    .line 210
    invoke-static {v14, v13}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 211
    .line 212
    .line 213
    move-result-object v13

    .line 214
    invoke-direct {v11, v15, v13, v12}, Laz/j;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;)V

    .line 215
    .line 216
    .line 217
    invoke-virtual {v6, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 218
    .line 219
    .line 220
    :cond_6
    move-object v11, v8

    .line 221
    check-cast v11, Ljava/lang/Iterable;

    .line 222
    .line 223
    new-instance v12, Ljava/util/ArrayList;

    .line 224
    .line 225
    invoke-static {v11, v10}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 226
    .line 227
    .line 228
    move-result v13

    .line 229
    invoke-direct {v12, v13}, Ljava/util/ArrayList;-><init>(I)V

    .line 230
    .line 231
    .line 232
    invoke-interface {v11}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 233
    .line 234
    .line 235
    move-result-object v11

    .line 236
    :goto_5
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    .line 237
    .line 238
    .line 239
    move-result v13

    .line 240
    if-eqz v13, :cond_7

    .line 241
    .line 242
    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 243
    .line 244
    .line 245
    move-result-object v13

    .line 246
    check-cast v13, Laz/a;

    .line 247
    .line 248
    new-instance v14, Laz/j;

    .line 249
    .line 250
    iget v15, v13, Laz/a;->d:I

    .line 251
    .line 252
    move/from16 v17, v2

    .line 253
    .line 254
    const/4 v10, 0x0

    .line 255
    new-array v2, v10, [Ljava/lang/Object;

    .line 256
    .line 257
    move-object v10, v3

    .line 258
    check-cast v10, Ljj0/f;

    .line 259
    .line 260
    invoke-virtual {v10, v15, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 261
    .line 262
    .line 263
    move-result-object v2

    .line 264
    sget-object v10, Laz/c;->f:Laz/c;

    .line 265
    .line 266
    invoke-static {v10}, Ljp/nb;->d(Laz/c;)I

    .line 267
    .line 268
    .line 269
    move-result v10

    .line 270
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 271
    .line 272
    .line 273
    move-result-object v10

    .line 274
    iget-object v13, v13, Laz/a;->e:Ljava/lang/String;

    .line 275
    .line 276
    const-string v15, "food_"

    .line 277
    .line 278
    invoke-virtual {v15, v13}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 279
    .line 280
    .line 281
    move-result-object v13

    .line 282
    invoke-direct {v14, v2, v13, v10}, Laz/j;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;)V

    .line 283
    .line 284
    .line 285
    invoke-virtual {v6, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 286
    .line 287
    .line 288
    move-result v2

    .line 289
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 290
    .line 291
    .line 292
    move-result-object v2

    .line 293
    invoke-virtual {v12, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 294
    .line 295
    .line 296
    move/from16 v2, v17

    .line 297
    .line 298
    const/16 v10, 0xa

    .line 299
    .line 300
    goto :goto_5

    .line 301
    :cond_7
    move/from16 v17, v2

    .line 302
    .line 303
    goto :goto_6

    .line 304
    :cond_8
    move/from16 v17, v2

    .line 305
    .line 306
    new-instance v2, Laz/j;

    .line 307
    .line 308
    invoke-static {v11, v3}, Ljp/nb;->e(Laz/c;Lij0/a;)Ljava/lang/String;

    .line 309
    .line 310
    .line 311
    move-result-object v10

    .line 312
    invoke-static {v11}, Ljp/nb;->d(Laz/c;)I

    .line 313
    .line 314
    .line 315
    move-result v12

    .line 316
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 317
    .line 318
    .line 319
    move-result-object v12

    .line 320
    iget-object v11, v11, Laz/c;->e:Ljava/lang/String;

    .line 321
    .line 322
    invoke-static {v14, v11}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 323
    .line 324
    .line 325
    move-result-object v11

    .line 326
    invoke-direct {v2, v10, v11, v12}, Laz/j;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;)V

    .line 327
    .line 328
    .line 329
    invoke-virtual {v6, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 330
    .line 331
    .line 332
    move-result v2

    .line 333
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 334
    .line 335
    .line 336
    move-result-object v12

    .line 337
    :goto_6
    invoke-virtual {v9, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 338
    .line 339
    .line 340
    move/from16 v2, v17

    .line 341
    .line 342
    const/16 v10, 0xa

    .line 343
    .line 344
    goto/16 :goto_4

    .line 345
    .line 346
    :cond_9
    move/from16 v17, v2

    .line 347
    .line 348
    new-instance v2, Laz/j;

    .line 349
    .line 350
    sget-object v7, Laz/g;->e:Lsx0/b;

    .line 351
    .line 352
    invoke-virtual {v7, v5}, Lsx0/b;->get(I)Ljava/lang/Object;

    .line 353
    .line 354
    .line 355
    move-result-object v7

    .line 356
    check-cast v7, Laz/g;

    .line 357
    .line 358
    invoke-static {v7}, Ljp/lb;->b(Laz/g;)I

    .line 359
    .line 360
    .line 361
    move-result v7

    .line 362
    const/4 v10, 0x0

    .line 363
    new-array v8, v10, [Ljava/lang/Object;

    .line 364
    .line 365
    check-cast v3, Ljj0/f;

    .line 366
    .line 367
    invoke-virtual {v3, v7, v8}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 368
    .line 369
    .line 370
    move-result-object v7

    .line 371
    const-string v8, "budget_"

    .line 372
    .line 373
    invoke-static {v5, v8}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 374
    .line 375
    .line 376
    move-result-object v5

    .line 377
    const/4 v8, 0x0

    .line 378
    invoke-direct {v2, v7, v5, v8}, Laz/j;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;)V

    .line 379
    .line 380
    .line 381
    invoke-virtual {v6, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 382
    .line 383
    .line 384
    new-instance v2, Laz/j;

    .line 385
    .line 386
    invoke-static {v4}, Ljp/mb;->c(Laz/h;)I

    .line 387
    .line 388
    .line 389
    move-result v5

    .line 390
    new-array v7, v10, [Ljava/lang/Object;

    .line 391
    .line 392
    invoke-virtual {v3, v5, v7}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 393
    .line 394
    .line 395
    move-result-object v5

    .line 396
    iget-object v4, v4, Laz/h;->d:Ljava/lang/String;

    .line 397
    .line 398
    const-string v7, "companion_"

    .line 399
    .line 400
    invoke-virtual {v7, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 401
    .line 402
    .line 403
    move-result-object v4

    .line 404
    invoke-direct {v2, v5, v4, v8}, Laz/j;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;)V

    .line 405
    .line 406
    .line 407
    invoke-virtual {v6, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 408
    .line 409
    .line 410
    iget-boolean v2, v1, Laz/i;->g:Z

    .line 411
    .line 412
    if-eqz v2, :cond_a

    .line 413
    .line 414
    new-instance v2, Laz/j;

    .line 415
    .line 416
    const v4, 0x7f120066

    .line 417
    .line 418
    .line 419
    new-array v5, v10, [Ljava/lang/Object;

    .line 420
    .line 421
    invoke-virtual {v3, v4, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 422
    .line 423
    .line 424
    move-result-object v4

    .line 425
    const v5, 0x7f080451

    .line 426
    .line 427
    .line 428
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 429
    .line 430
    .line 431
    move-result-object v5

    .line 432
    const-string v7, "with_pet"

    .line 433
    .line 434
    invoke-direct {v2, v4, v7, v5}, Laz/j;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;)V

    .line 435
    .line 436
    .line 437
    invoke-virtual {v6, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 438
    .line 439
    .line 440
    :cond_a
    iget-boolean v1, v1, Laz/i;->h:Z

    .line 441
    .line 442
    if-eqz v1, :cond_b

    .line 443
    .line 444
    new-instance v1, Laz/j;

    .line 445
    .line 446
    const v2, 0x7f120070

    .line 447
    .line 448
    .line 449
    const/4 v10, 0x0

    .line 450
    new-array v4, v10, [Ljava/lang/Object;

    .line 451
    .line 452
    invoke-virtual {v3, v2, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 453
    .line 454
    .line 455
    move-result-object v2

    .line 456
    const v3, 0x7f080522

    .line 457
    .line 458
    .line 459
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 460
    .line 461
    .line 462
    move-result-object v3

    .line 463
    const-string v4, "with_wheel_chair"

    .line 464
    .line 465
    invoke-direct {v1, v2, v4, v3}, Laz/j;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;)V

    .line 466
    .line 467
    .line 468
    invoke-virtual {v6, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 469
    .line 470
    .line 471
    :cond_b
    move/from16 v10, v17

    .line 472
    .line 473
    :goto_7
    move-object v11, v6

    .line 474
    goto :goto_8

    .line 475
    :cond_c
    sget-object v6, Lmx0/s;->d:Lmx0/s;

    .line 476
    .line 477
    move v10, v1

    .line 478
    goto :goto_7

    .line 479
    :goto_8
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 480
    .line 481
    .line 482
    move-result-object v1

    .line 483
    move-object v7, v1

    .line 484
    check-cast v7, Lbz/u;

    .line 485
    .line 486
    const/4 v9, 0x0

    .line 487
    const/4 v12, 0x3

    .line 488
    const/4 v8, 0x0

    .line 489
    invoke-static/range {v7 .. v12}, Lbz/u;->a(Lbz/u;Laz/d;Laz/d;ZLjava/util/List;I)Lbz/u;

    .line 490
    .line 491
    .line 492
    move-result-object v1

    .line 493
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 494
    .line 495
    .line 496
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 497
    .line 498
    return-object v0
.end method
