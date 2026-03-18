.class public final Lm70/m0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lk70/r;

.field public final j:Lcs0/l;

.field public final k:Lk70/k0;

.field public final l:Lk70/t0;

.field public final m:Lk70/u;

.field public final n:Lij0/a;


# direct methods
.method public constructor <init>(Ltr0/b;Lk70/r;Lcs0/l;Lk70/k0;Lk70/t0;Lk70/u;Lij0/a;)V
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    new-instance v1, Lm70/k0;

    .line 4
    .line 5
    const-string v3, ""

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v6, 0x0

    .line 9
    const/4 v8, 0x0

    .line 10
    const/4 v9, 0x0

    .line 11
    const/4 v10, 0x0

    .line 12
    const/4 v11, 0x0

    .line 13
    const/4 v12, 0x0

    .line 14
    const/4 v13, 0x0

    .line 15
    const/4 v14, 0x0

    .line 16
    const/4 v15, 0x0

    .line 17
    const/16 v16, 0x0

    .line 18
    .line 19
    const/16 v17, 0x0

    .line 20
    .line 21
    const/16 v18, 0x0

    .line 22
    .line 23
    const/16 v19, 0x0

    .line 24
    .line 25
    move-object v4, v3

    .line 26
    move-object v5, v3

    .line 27
    move-object v7, v3

    .line 28
    invoke-direct/range {v1 .. v19}, Lm70/k0;-><init>(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    invoke-direct {v0, v1}, Lql0/j;-><init>(Lql0/h;)V

    .line 32
    .line 33
    .line 34
    move-object/from16 v1, p1

    .line 35
    .line 36
    iput-object v1, v0, Lm70/m0;->h:Ltr0/b;

    .line 37
    .line 38
    move-object/from16 v1, p2

    .line 39
    .line 40
    iput-object v1, v0, Lm70/m0;->i:Lk70/r;

    .line 41
    .line 42
    move-object/from16 v1, p3

    .line 43
    .line 44
    iput-object v1, v0, Lm70/m0;->j:Lcs0/l;

    .line 45
    .line 46
    move-object/from16 v1, p4

    .line 47
    .line 48
    iput-object v1, v0, Lm70/m0;->k:Lk70/k0;

    .line 49
    .line 50
    move-object/from16 v1, p5

    .line 51
    .line 52
    iput-object v1, v0, Lm70/m0;->l:Lk70/t0;

    .line 53
    .line 54
    move-object/from16 v1, p6

    .line 55
    .line 56
    iput-object v1, v0, Lm70/m0;->m:Lk70/u;

    .line 57
    .line 58
    move-object/from16 v1, p7

    .line 59
    .line 60
    iput-object v1, v0, Lm70/m0;->n:Lij0/a;

    .line 61
    .line 62
    new-instance v1, Lk20/a;

    .line 63
    .line 64
    const/4 v2, 0x0

    .line 65
    const/16 v3, 0x12

    .line 66
    .line 67
    invoke-direct {v1, v0, v2, v3}, Lk20/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {v0, v1}, Lql0/j;->b(Lay0/n;)V

    .line 71
    .line 72
    .line 73
    return-void
.end method

.method public static final h(Lm70/m0;Ll70/i;Lrx0/c;)Ljava/lang/Object;
    .locals 29

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    iget-object v2, v0, Lm70/m0;->n:Lij0/a;

    .line 6
    .line 7
    instance-of v3, v1, Lm70/l0;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v1

    .line 12
    check-cast v3, Lm70/l0;

    .line 13
    .line 14
    iget v4, v3, Lm70/l0;->g:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Lm70/l0;->g:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lm70/l0;

    .line 27
    .line 28
    invoke-direct {v3, v0, v1}, Lm70/l0;-><init>(Lm70/m0;Lrx0/c;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v1, v3, Lm70/l0;->e:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lm70/l0;->g:I

    .line 36
    .line 37
    const/4 v6, 0x1

    .line 38
    if-eqz v5, :cond_2

    .line 39
    .line 40
    if-ne v5, v6, :cond_1

    .line 41
    .line 42
    iget-object v3, v3, Lm70/l0;->d:Ll70/i;

    .line 43
    .line 44
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw v0

    .line 56
    :cond_2
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    iget-object v1, v0, Lm70/m0;->j:Lcs0/l;

    .line 60
    .line 61
    move-object/from16 v5, p1

    .line 62
    .line 63
    iput-object v5, v3, Lm70/l0;->d:Ll70/i;

    .line 64
    .line 65
    iput v6, v3, Lm70/l0;->g:I

    .line 66
    .line 67
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 68
    .line 69
    .line 70
    invoke-virtual {v1, v3}, Lcs0/l;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    if-ne v1, v4, :cond_3

    .line 75
    .line 76
    return-object v4

    .line 77
    :cond_3
    move-object v3, v5

    .line 78
    :goto_1
    check-cast v1, Lqr0/s;

    .line 79
    .line 80
    iget-object v4, v0, Lm70/m0;->m:Lk70/u;

    .line 81
    .line 82
    invoke-static {v4}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v4

    .line 86
    check-cast v4, Ll70/a0;

    .line 87
    .line 88
    const/4 v5, 0x0

    .line 89
    new-array v6, v5, [Ljava/lang/Object;

    .line 90
    .line 91
    move-object v7, v2

    .line 92
    check-cast v7, Ljj0/f;

    .line 93
    .line 94
    const v8, 0x7f1201aa

    .line 95
    .line 96
    .line 97
    invoke-virtual {v7, v8, v6}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object v6

    .line 101
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 102
    .line 103
    .line 104
    move-result-object v7

    .line 105
    check-cast v7, Lm70/k0;

    .line 106
    .line 107
    iget-object v8, v3, Ll70/i;->b:Ljava/time/LocalDate;

    .line 108
    .line 109
    iget-object v9, v3, Ll70/i;->t:Ll70/u;

    .line 110
    .line 111
    invoke-static {v8}, Lu7/b;->d(Ljava/time/LocalDate;)Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object v12

    .line 115
    iget-object v8, v3, Ll70/i;->f:Ljava/time/LocalTime;

    .line 116
    .line 117
    invoke-static {v8}, Lua0/g;->b(Ljava/time/LocalTime;)Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object v13

    .line 121
    iget-wide v10, v3, Ll70/i;->j:J

    .line 122
    .line 123
    const/4 v8, 0x6

    .line 124
    invoke-static {v10, v11, v2, v5, v8}, Ljp/d1;->c(JLij0/a;ZI)Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object v14

    .line 128
    const/4 v2, 0x0

    .line 129
    if-eqz v9, :cond_4

    .line 130
    .line 131
    invoke-static {v9}, Ljp/p0;->d(Ll70/u;)Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object v5

    .line 135
    move-object v15, v5

    .line 136
    goto :goto_2

    .line 137
    :cond_4
    move-object v15, v2

    .line 138
    :goto_2
    iget-wide v10, v3, Ll70/i;->i:D

    .line 139
    .line 140
    sget-object v5, Lqr0/e;->e:Lqr0/e;

    .line 141
    .line 142
    invoke-static {v10, v11, v1, v5}, Lkp/f6;->a(DLqr0/s;Lqr0/e;)Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object v8

    .line 146
    iget-object v10, v3, Ll70/i;->m:Lqr0/p;

    .line 147
    .line 148
    if-eqz v10, :cond_5

    .line 149
    .line 150
    iget-wide v10, v10, Lqr0/p;->a:D

    .line 151
    .line 152
    invoke-static {v10, v11, v1}, Lkp/o6;->a(DLqr0/s;)Ljava/lang/String;

    .line 153
    .line 154
    .line 155
    move-result-object v10

    .line 156
    move-object/from16 v17, v10

    .line 157
    .line 158
    goto :goto_3

    .line 159
    :cond_5
    move-object/from16 v17, v2

    .line 160
    .line 161
    :goto_3
    iget-object v10, v3, Ll70/i;->n:Lqr0/i;

    .line 162
    .line 163
    if-eqz v10, :cond_6

    .line 164
    .line 165
    iget-wide v10, v10, Lqr0/i;->a:D

    .line 166
    .line 167
    invoke-static {v10, v11, v1}, Lkp/i6;->b(DLqr0/s;)Ljava/lang/String;

    .line 168
    .line 169
    .line 170
    move-result-object v10

    .line 171
    move-object/from16 v18, v10

    .line 172
    .line 173
    goto :goto_4

    .line 174
    :cond_6
    move-object/from16 v18, v2

    .line 175
    .line 176
    :goto_4
    iget-object v10, v3, Ll70/i;->q:Lqr0/j;

    .line 177
    .line 178
    if-eqz v10, :cond_7

    .line 179
    .line 180
    iget-wide v10, v10, Lqr0/j;->a:D

    .line 181
    .line 182
    invoke-static {v10, v11}, Lkp/j6;->b(D)Ljava/lang/String;

    .line 183
    .line 184
    .line 185
    move-result-object v10

    .line 186
    move-object/from16 v19, v10

    .line 187
    .line 188
    goto :goto_5

    .line 189
    :cond_7
    move-object/from16 v19, v2

    .line 190
    .line 191
    :goto_5
    iget-object v10, v3, Ll70/i;->p:Lqr0/g;

    .line 192
    .line 193
    if-eqz v10, :cond_8

    .line 194
    .line 195
    iget-wide v10, v10, Lqr0/g;->a:D

    .line 196
    .line 197
    invoke-static {v10, v11, v1}, Lkp/g6;->b(DLqr0/s;)Ljava/lang/String;

    .line 198
    .line 199
    .line 200
    move-result-object v10

    .line 201
    move-object/from16 v20, v10

    .line 202
    .line 203
    goto :goto_6

    .line 204
    :cond_8
    move-object/from16 v20, v2

    .line 205
    .line 206
    :goto_6
    iget-object v10, v3, Ll70/i;->g:Lqr0/d;

    .line 207
    .line 208
    if-eqz v10, :cond_9

    .line 209
    .line 210
    iget-wide v10, v10, Lqr0/d;->a:D

    .line 211
    .line 212
    invoke-static {v10, v11, v1, v5}, Lkp/f6;->a(DLqr0/s;Lqr0/e;)Ljava/lang/String;

    .line 213
    .line 214
    .line 215
    move-result-object v10

    .line 216
    move-object/from16 v21, v10

    .line 217
    .line 218
    goto :goto_7

    .line 219
    :cond_9
    move-object/from16 v21, v2

    .line 220
    .line 221
    :goto_7
    iget-object v3, v3, Ll70/i;->h:Lqr0/d;

    .line 222
    .line 223
    if-eqz v3, :cond_a

    .line 224
    .line 225
    iget-wide v10, v3, Lqr0/d;->a:D

    .line 226
    .line 227
    invoke-static {v10, v11, v1, v5}, Lkp/f6;->a(DLqr0/s;Lqr0/e;)Ljava/lang/String;

    .line 228
    .line 229
    .line 230
    move-result-object v3

    .line 231
    move-object/from16 v22, v3

    .line 232
    .line 233
    goto :goto_8

    .line 234
    :cond_a
    move-object/from16 v22, v2

    .line 235
    .line 236
    :goto_8
    sget-object v3, Ll70/a0;->e:Ll70/a0;

    .line 237
    .line 238
    if-eq v4, v3, :cond_c

    .line 239
    .line 240
    sget-object v3, Ll70/a0;->g:Ll70/a0;

    .line 241
    .line 242
    if-ne v4, v3, :cond_b

    .line 243
    .line 244
    goto :goto_9

    .line 245
    :cond_b
    move-object/from16 v23, v2

    .line 246
    .line 247
    goto :goto_b

    .line 248
    :cond_c
    :goto_9
    if-eqz v9, :cond_e

    .line 249
    .line 250
    iget-object v3, v9, Ll70/u;->c:Ll70/t;

    .line 251
    .line 252
    if-eqz v3, :cond_e

    .line 253
    .line 254
    invoke-static {v3}, Ljp/p0;->c(Ll70/t;)Ljava/lang/String;

    .line 255
    .line 256
    .line 257
    move-result-object v3

    .line 258
    if-nez v3, :cond_d

    .line 259
    .line 260
    goto :goto_a

    .line 261
    :cond_d
    move-object/from16 v23, v3

    .line 262
    .line 263
    goto :goto_b

    .line 264
    :cond_e
    :goto_a
    move-object/from16 v23, v6

    .line 265
    .line 266
    :goto_b
    if-eqz v9, :cond_f

    .line 267
    .line 268
    iget-object v3, v9, Ll70/u;->c:Ll70/t;

    .line 269
    .line 270
    if-eqz v3, :cond_f

    .line 271
    .line 272
    sget-object v5, Ll70/h;->d:Ll70/h;

    .line 273
    .line 274
    invoke-static {v3, v1, v5}, Ljp/p0;->g(Ll70/t;Lqr0/s;Ll70/h;)Ljava/lang/String;

    .line 275
    .line 276
    .line 277
    move-result-object v3

    .line 278
    move-object/from16 v24, v3

    .line 279
    .line 280
    goto :goto_c

    .line 281
    :cond_f
    move-object/from16 v24, v2

    .line 282
    .line 283
    :goto_c
    sget-object v3, Ll70/a0;->d:Ll70/a0;

    .line 284
    .line 285
    if-eq v4, v3, :cond_11

    .line 286
    .line 287
    sget-object v3, Ll70/a0;->g:Ll70/a0;

    .line 288
    .line 289
    if-ne v4, v3, :cond_10

    .line 290
    .line 291
    goto :goto_d

    .line 292
    :cond_10
    move-object/from16 v25, v2

    .line 293
    .line 294
    goto :goto_f

    .line 295
    :cond_11
    :goto_d
    if-eqz v9, :cond_13

    .line 296
    .line 297
    iget-object v3, v9, Ll70/u;->e:Ll70/t;

    .line 298
    .line 299
    if-eqz v3, :cond_13

    .line 300
    .line 301
    invoke-static {v3}, Ljp/p0;->c(Ll70/t;)Ljava/lang/String;

    .line 302
    .line 303
    .line 304
    move-result-object v3

    .line 305
    if-nez v3, :cond_12

    .line 306
    .line 307
    goto :goto_e

    .line 308
    :cond_12
    move-object/from16 v25, v3

    .line 309
    .line 310
    goto :goto_f

    .line 311
    :cond_13
    :goto_e
    move-object/from16 v25, v6

    .line 312
    .line 313
    :goto_f
    if-eqz v9, :cond_14

    .line 314
    .line 315
    iget-object v3, v9, Ll70/u;->e:Ll70/t;

    .line 316
    .line 317
    if-eqz v3, :cond_14

    .line 318
    .line 319
    sget-object v5, Ll70/h;->e:Ll70/h;

    .line 320
    .line 321
    invoke-static {v3, v1, v5}, Ljp/p0;->g(Ll70/t;Lqr0/s;Ll70/h;)Ljava/lang/String;

    .line 322
    .line 323
    .line 324
    move-result-object v3

    .line 325
    move-object/from16 v26, v3

    .line 326
    .line 327
    goto :goto_10

    .line 328
    :cond_14
    move-object/from16 v26, v2

    .line 329
    .line 330
    :goto_10
    sget-object v3, Ll70/a0;->f:Ll70/a0;

    .line 331
    .line 332
    if-ne v4, v3, :cond_17

    .line 333
    .line 334
    if-eqz v9, :cond_16

    .line 335
    .line 336
    iget-object v3, v9, Ll70/u;->d:Ll70/t;

    .line 337
    .line 338
    if-eqz v3, :cond_16

    .line 339
    .line 340
    invoke-static {v3}, Ljp/p0;->c(Ll70/t;)Ljava/lang/String;

    .line 341
    .line 342
    .line 343
    move-result-object v3

    .line 344
    if-nez v3, :cond_15

    .line 345
    .line 346
    goto :goto_11

    .line 347
    :cond_15
    move-object/from16 v27, v3

    .line 348
    .line 349
    goto :goto_12

    .line 350
    :cond_16
    :goto_11
    move-object/from16 v27, v6

    .line 351
    .line 352
    goto :goto_12

    .line 353
    :cond_17
    move-object/from16 v27, v2

    .line 354
    .line 355
    :goto_12
    if-eqz v9, :cond_18

    .line 356
    .line 357
    iget-object v3, v9, Ll70/u;->d:Ll70/t;

    .line 358
    .line 359
    if-eqz v3, :cond_18

    .line 360
    .line 361
    sget-object v2, Ll70/h;->f:Ll70/h;

    .line 362
    .line 363
    invoke-static {v3, v1, v2}, Ljp/p0;->g(Ll70/t;Lqr0/s;Ll70/h;)Ljava/lang/String;

    .line 364
    .line 365
    .line 366
    move-result-object v2

    .line 367
    :cond_18
    move-object/from16 v28, v2

    .line 368
    .line 369
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 370
    .line 371
    .line 372
    const-string v1, "duration"

    .line 373
    .line 374
    invoke-static {v14, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 375
    .line 376
    .line 377
    const-string v1, "distance"

    .line 378
    .line 379
    invoke-static {v8, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 380
    .line 381
    .line 382
    new-instance v10, Lm70/k0;

    .line 383
    .line 384
    const/4 v11, 0x0

    .line 385
    move-object/from16 v16, v8

    .line 386
    .line 387
    invoke-direct/range {v10 .. v28}, Lm70/k0;-><init>(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 388
    .line 389
    .line 390
    invoke-virtual {v0, v10}, Lql0/j;->g(Lql0/h;)V

    .line 391
    .line 392
    .line 393
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 394
    .line 395
    return-object v0
.end method
