.class public final Lh5/g;
.super Lh5/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public E0:I

.field public F0:I

.field public G0:I

.field public H0:I

.field public I0:I

.field public J0:I

.field public K0:F

.field public L0:F

.field public M0:F

.field public N0:F

.field public O0:F

.field public P0:F

.field public Q0:I

.field public R0:I

.field public S0:I

.field public T0:I

.field public U0:I

.field public V0:I

.field public W0:I

.field public final X0:Ljava/util/ArrayList;

.field public Y0:[Lh5/d;

.field public Z0:[Lh5/d;

.field public a1:[I

.field public b1:[Lh5/d;

.field public c1:I


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Lh5/k;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, -0x1

    .line 5
    iput v0, p0, Lh5/g;->E0:I

    .line 6
    .line 7
    iput v0, p0, Lh5/g;->F0:I

    .line 8
    .line 9
    iput v0, p0, Lh5/g;->G0:I

    .line 10
    .line 11
    iput v0, p0, Lh5/g;->H0:I

    .line 12
    .line 13
    iput v0, p0, Lh5/g;->I0:I

    .line 14
    .line 15
    iput v0, p0, Lh5/g;->J0:I

    .line 16
    .line 17
    const/high16 v1, 0x3f000000    # 0.5f

    .line 18
    .line 19
    iput v1, p0, Lh5/g;->K0:F

    .line 20
    .line 21
    iput v1, p0, Lh5/g;->L0:F

    .line 22
    .line 23
    iput v1, p0, Lh5/g;->M0:F

    .line 24
    .line 25
    iput v1, p0, Lh5/g;->N0:F

    .line 26
    .line 27
    iput v1, p0, Lh5/g;->O0:F

    .line 28
    .line 29
    iput v1, p0, Lh5/g;->P0:F

    .line 30
    .line 31
    const/4 v1, 0x0

    .line 32
    iput v1, p0, Lh5/g;->Q0:I

    .line 33
    .line 34
    iput v1, p0, Lh5/g;->R0:I

    .line 35
    .line 36
    const/4 v2, 0x2

    .line 37
    iput v2, p0, Lh5/g;->S0:I

    .line 38
    .line 39
    iput v2, p0, Lh5/g;->T0:I

    .line 40
    .line 41
    iput v1, p0, Lh5/g;->U0:I

    .line 42
    .line 43
    iput v0, p0, Lh5/g;->V0:I

    .line 44
    .line 45
    iput v1, p0, Lh5/g;->W0:I

    .line 46
    .line 47
    new-instance v0, Ljava/util/ArrayList;

    .line 48
    .line 49
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 50
    .line 51
    .line 52
    iput-object v0, p0, Lh5/g;->X0:Ljava/util/ArrayList;

    .line 53
    .line 54
    const/4 v0, 0x0

    .line 55
    iput-object v0, p0, Lh5/g;->Y0:[Lh5/d;

    .line 56
    .line 57
    iput-object v0, p0, Lh5/g;->Z0:[Lh5/d;

    .line 58
    .line 59
    iput-object v0, p0, Lh5/g;->a1:[I

    .line 60
    .line 61
    iput v1, p0, Lh5/g;->c1:I

    .line 62
    .line 63
    return-void
.end method


# virtual methods
.method public final Y(IIII)V
    .locals 37

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move/from16 v8, p1

    .line 4
    .line 5
    move/from16 v9, p2

    .line 6
    .line 7
    move/from16 v10, p3

    .line 8
    .line 9
    iget v0, v1, Lh5/i;->s0:I

    .line 10
    .line 11
    const/4 v12, 0x2

    .line 12
    const/4 v13, 0x3

    .line 13
    const/4 v14, 0x1

    .line 14
    const/4 v15, 0x0

    .line 15
    if-lez v0, :cond_7

    .line 16
    .line 17
    iget-object v0, v1, Lh5/d;->U:Lh5/e;

    .line 18
    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    iget-object v0, v0, Lh5/e;->v0:Li5/c;

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const/4 v0, 0x0

    .line 25
    :goto_0
    if-nez v0, :cond_1

    .line 26
    .line 27
    iput v15, v1, Lh5/k;->A0:I

    .line 28
    .line 29
    iput v15, v1, Lh5/k;->B0:I

    .line 30
    .line 31
    iput-boolean v15, v1, Lh5/k;->z0:Z

    .line 32
    .line 33
    return-void

    .line 34
    :cond_1
    move v3, v15

    .line 35
    :goto_1
    iget v4, v1, Lh5/i;->s0:I

    .line 36
    .line 37
    if-ge v3, v4, :cond_7

    .line 38
    .line 39
    iget-object v4, v1, Lh5/i;->r0:[Lh5/d;

    .line 40
    .line 41
    aget-object v4, v4, v3

    .line 42
    .line 43
    if-nez v4, :cond_2

    .line 44
    .line 45
    goto :goto_2

    .line 46
    :cond_2
    instance-of v5, v4, Lh5/h;

    .line 47
    .line 48
    if-eqz v5, :cond_3

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_3
    invoke-virtual {v4, v15}, Lh5/d;->k(I)I

    .line 52
    .line 53
    .line 54
    move-result v5

    .line 55
    invoke-virtual {v4, v14}, Lh5/d;->k(I)I

    .line 56
    .line 57
    .line 58
    move-result v6

    .line 59
    if-ne v5, v13, :cond_4

    .line 60
    .line 61
    iget v7, v4, Lh5/d;->s:I

    .line 62
    .line 63
    if-eq v7, v14, :cond_4

    .line 64
    .line 65
    if-ne v6, v13, :cond_4

    .line 66
    .line 67
    iget v7, v4, Lh5/d;->t:I

    .line 68
    .line 69
    if-eq v7, v14, :cond_4

    .line 70
    .line 71
    goto :goto_2

    .line 72
    :cond_4
    if-ne v5, v13, :cond_5

    .line 73
    .line 74
    move v5, v12

    .line 75
    :cond_5
    if-ne v6, v13, :cond_6

    .line 76
    .line 77
    move v6, v12

    .line 78
    :cond_6
    iget-object v7, v1, Lh5/k;->C0:Li5/b;

    .line 79
    .line 80
    iput v5, v7, Li5/b;->a:I

    .line 81
    .line 82
    iput v6, v7, Li5/b;->b:I

    .line 83
    .line 84
    invoke-virtual {v4}, Lh5/d;->r()I

    .line 85
    .line 86
    .line 87
    move-result v5

    .line 88
    iput v5, v7, Li5/b;->c:I

    .line 89
    .line 90
    invoke-virtual {v4}, Lh5/d;->l()I

    .line 91
    .line 92
    .line 93
    move-result v5

    .line 94
    iput v5, v7, Li5/b;->d:I

    .line 95
    .line 96
    invoke-interface {v0, v4, v7}, Li5/c;->b(Lh5/d;Li5/b;)V

    .line 97
    .line 98
    .line 99
    iget v5, v7, Li5/b;->e:I

    .line 100
    .line 101
    invoke-virtual {v4, v5}, Lh5/d;->S(I)V

    .line 102
    .line 103
    .line 104
    iget v5, v7, Li5/b;->f:I

    .line 105
    .line 106
    invoke-virtual {v4, v5}, Lh5/d;->N(I)V

    .line 107
    .line 108
    .line 109
    iget v5, v7, Li5/b;->g:I

    .line 110
    .line 111
    invoke-virtual {v4, v5}, Lh5/d;->J(I)V

    .line 112
    .line 113
    .line 114
    :goto_2
    add-int/lit8 v3, v3, 0x1

    .line 115
    .line 116
    goto :goto_1

    .line 117
    :cond_7
    iget v0, v1, Lh5/k;->x0:I

    .line 118
    .line 119
    iget v3, v1, Lh5/k;->y0:I

    .line 120
    .line 121
    iget v4, v1, Lh5/k;->t0:I

    .line 122
    .line 123
    iget v5, v1, Lh5/k;->u0:I

    .line 124
    .line 125
    new-array v6, v12, [I

    .line 126
    .line 127
    sub-int v7, v9, v0

    .line 128
    .line 129
    sub-int/2addr v7, v3

    .line 130
    iget v2, v1, Lh5/g;->W0:I

    .line 131
    .line 132
    if-ne v2, v14, :cond_8

    .line 133
    .line 134
    sub-int v7, p4, v4

    .line 135
    .line 136
    sub-int/2addr v7, v5

    .line 137
    :cond_8
    const/4 v13, -0x1

    .line 138
    if-nez v2, :cond_a

    .line 139
    .line 140
    iget v2, v1, Lh5/g;->E0:I

    .line 141
    .line 142
    if-ne v2, v13, :cond_9

    .line 143
    .line 144
    iput v15, v1, Lh5/g;->E0:I

    .line 145
    .line 146
    :cond_9
    iget v2, v1, Lh5/g;->F0:I

    .line 147
    .line 148
    if-ne v2, v13, :cond_c

    .line 149
    .line 150
    iput v15, v1, Lh5/g;->F0:I

    .line 151
    .line 152
    goto :goto_3

    .line 153
    :cond_a
    iget v2, v1, Lh5/g;->E0:I

    .line 154
    .line 155
    if-ne v2, v13, :cond_b

    .line 156
    .line 157
    iput v15, v1, Lh5/g;->E0:I

    .line 158
    .line 159
    :cond_b
    iget v2, v1, Lh5/g;->F0:I

    .line 160
    .line 161
    if-ne v2, v13, :cond_c

    .line 162
    .line 163
    iput v15, v1, Lh5/g;->F0:I

    .line 164
    .line 165
    :cond_c
    :goto_3
    iget-object v2, v1, Lh5/i;->r0:[Lh5/d;

    .line 166
    .line 167
    move v13, v15

    .line 168
    move/from16 v18, v13

    .line 169
    .line 170
    move/from16 v28, v18

    .line 171
    .line 172
    :goto_4
    iget v15, v1, Lh5/i;->s0:I

    .line 173
    .line 174
    const/16 v12, 0x8

    .line 175
    .line 176
    if-ge v13, v15, :cond_e

    .line 177
    .line 178
    iget-object v15, v1, Lh5/i;->r0:[Lh5/d;

    .line 179
    .line 180
    aget-object v15, v15, v13

    .line 181
    .line 182
    iget v15, v15, Lh5/d;->h0:I

    .line 183
    .line 184
    if-ne v15, v12, :cond_d

    .line 185
    .line 186
    add-int/lit8 v18, v18, 0x1

    .line 187
    .line 188
    :cond_d
    add-int/lit8 v13, v13, 0x1

    .line 189
    .line 190
    const/4 v12, 0x2

    .line 191
    goto :goto_4

    .line 192
    :cond_e
    if-lez v18, :cond_10

    .line 193
    .line 194
    sub-int v15, v15, v18

    .line 195
    .line 196
    new-array v2, v15, [Lh5/d;

    .line 197
    .line 198
    move/from16 v13, v28

    .line 199
    .line 200
    move v15, v13

    .line 201
    :goto_5
    iget v14, v1, Lh5/i;->s0:I

    .line 202
    .line 203
    if-ge v13, v14, :cond_10

    .line 204
    .line 205
    iget-object v14, v1, Lh5/i;->r0:[Lh5/d;

    .line 206
    .line 207
    aget-object v14, v14, v13

    .line 208
    .line 209
    move/from16 v18, v0

    .line 210
    .line 211
    iget v0, v14, Lh5/d;->h0:I

    .line 212
    .line 213
    if-eq v0, v12, :cond_f

    .line 214
    .line 215
    aput-object v14, v2, v15

    .line 216
    .line 217
    add-int/lit8 v15, v15, 0x1

    .line 218
    .line 219
    :cond_f
    add-int/lit8 v13, v13, 0x1

    .line 220
    .line 221
    move/from16 v0, v18

    .line 222
    .line 223
    goto :goto_5

    .line 224
    :cond_10
    move/from16 v18, v0

    .line 225
    .line 226
    move-object v12, v2

    .line 227
    iput-object v12, v1, Lh5/g;->b1:[Lh5/d;

    .line 228
    .line 229
    iput v15, v1, Lh5/g;->c1:I

    .line 230
    .line 231
    iget v0, v1, Lh5/g;->U0:I

    .line 232
    .line 233
    iget-object v13, v1, Lh5/g;->X0:Ljava/util/ArrayList;

    .line 234
    .line 235
    if-eqz v0, :cond_6d

    .line 236
    .line 237
    iget-object v14, v1, Lh5/d;->q0:[I

    .line 238
    .line 239
    iget-object v2, v1, Lh5/d;->K:Lh5/c;

    .line 240
    .line 241
    move-object/from16 v20, v14

    .line 242
    .line 243
    iget-object v14, v1, Lh5/d;->J:Lh5/c;

    .line 244
    .line 245
    move-object/from16 v21, v14

    .line 246
    .line 247
    iget-object v14, v1, Lh5/d;->L:Lh5/c;

    .line 248
    .line 249
    move-object/from16 v30, v14

    .line 250
    .line 251
    iget-object v14, v1, Lh5/d;->M:Lh5/c;

    .line 252
    .line 253
    move-object/from16 v22, v2

    .line 254
    .line 255
    const/4 v2, 0x1

    .line 256
    if-eq v0, v2, :cond_53

    .line 257
    .line 258
    const/4 v2, 0x2

    .line 259
    if-eq v0, v2, :cond_2c

    .line 260
    .line 261
    const/4 v2, 0x3

    .line 262
    if-eq v0, v2, :cond_11

    .line 263
    .line 264
    :goto_6
    move/from16 v32, v3

    .line 265
    .line 266
    move/from16 v33, v4

    .line 267
    .line 268
    move/from16 v34, v5

    .line 269
    .line 270
    move-object/from16 v35, v6

    .line 271
    .line 272
    move/from16 v31, v18

    .line 273
    .line 274
    :goto_7
    const/16 v29, 0x1

    .line 275
    .line 276
    goto/16 :goto_39

    .line 277
    .line 278
    :cond_11
    iget v2, v1, Lh5/g;->W0:I

    .line 279
    .line 280
    if-nez v15, :cond_12

    .line 281
    .line 282
    goto :goto_6

    .line 283
    :cond_12
    invoke-virtual {v13}, Ljava/util/ArrayList;->clear()V

    .line 284
    .line 285
    .line 286
    new-instance v0, Lh5/f;

    .line 287
    .line 288
    move/from16 v16, v5

    .line 289
    .line 290
    iget-object v5, v1, Lh5/d;->L:Lh5/c;

    .line 291
    .line 292
    move-object/from16 v23, v6

    .line 293
    .line 294
    iget-object v6, v1, Lh5/d;->M:Lh5/c;

    .line 295
    .line 296
    move/from16 v24, v3

    .line 297
    .line 298
    iget-object v3, v1, Lh5/d;->J:Lh5/c;

    .line 299
    .line 300
    move/from16 v25, v4

    .line 301
    .line 302
    iget-object v4, v1, Lh5/d;->K:Lh5/c;

    .line 303
    .line 304
    move/from16 v34, v16

    .line 305
    .line 306
    move/from16 v31, v18

    .line 307
    .line 308
    move-object/from16 v35, v23

    .line 309
    .line 310
    move/from16 v32, v24

    .line 311
    .line 312
    move/from16 v33, v25

    .line 313
    .line 314
    invoke-direct/range {v0 .. v7}, Lh5/f;-><init>(Lh5/g;ILh5/c;Lh5/c;Lh5/c;Lh5/c;I)V

    .line 315
    .line 316
    .line 317
    invoke-virtual {v13, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 318
    .line 319
    .line 320
    if-nez v2, :cond_1a

    .line 321
    .line 322
    move/from16 v3, v28

    .line 323
    .line 324
    move v4, v3

    .line 325
    move v5, v4

    .line 326
    move v6, v5

    .line 327
    :goto_8
    if-ge v3, v15, :cond_19

    .line 328
    .line 329
    const/16 v29, 0x1

    .line 330
    .line 331
    add-int/lit8 v4, v4, 0x1

    .line 332
    .line 333
    move-object/from16 v36, v14

    .line 334
    .line 335
    aget-object v14, v12, v3

    .line 336
    .line 337
    invoke-virtual {v1, v14, v7}, Lh5/g;->b0(Lh5/d;I)I

    .line 338
    .line 339
    .line 340
    move-result v16

    .line 341
    move/from16 v18, v2

    .line 342
    .line 343
    iget-object v2, v14, Lh5/d;->q0:[I

    .line 344
    .line 345
    aget v2, v2, v28

    .line 346
    .line 347
    move/from16 v23, v3

    .line 348
    .line 349
    const/4 v3, 0x3

    .line 350
    if-ne v2, v3, :cond_13

    .line 351
    .line 352
    add-int/lit8 v5, v5, 0x1

    .line 353
    .line 354
    :cond_13
    move/from16 v24, v5

    .line 355
    .line 356
    if-eq v6, v7, :cond_14

    .line 357
    .line 358
    iget v2, v1, Lh5/g;->Q0:I

    .line 359
    .line 360
    add-int/2addr v2, v6

    .line 361
    add-int v2, v2, v16

    .line 362
    .line 363
    if-le v2, v7, :cond_15

    .line 364
    .line 365
    :cond_14
    iget-object v2, v0, Lh5/f;->b:Lh5/d;

    .line 366
    .line 367
    if-eqz v2, :cond_15

    .line 368
    .line 369
    const/4 v2, 0x1

    .line 370
    goto :goto_9

    .line 371
    :cond_15
    move/from16 v2, v28

    .line 372
    .line 373
    :goto_9
    if-nez v2, :cond_16

    .line 374
    .line 375
    if-lez v23, :cond_16

    .line 376
    .line 377
    iget v3, v1, Lh5/g;->V0:I

    .line 378
    .line 379
    if-lez v3, :cond_16

    .line 380
    .line 381
    if-le v4, v3, :cond_16

    .line 382
    .line 383
    const/4 v2, 0x1

    .line 384
    :cond_16
    if-eqz v2, :cond_17

    .line 385
    .line 386
    new-instance v0, Lh5/f;

    .line 387
    .line 388
    iget-object v5, v1, Lh5/d;->L:Lh5/c;

    .line 389
    .line 390
    iget-object v6, v1, Lh5/d;->M:Lh5/c;

    .line 391
    .line 392
    iget-object v3, v1, Lh5/d;->J:Lh5/c;

    .line 393
    .line 394
    iget-object v4, v1, Lh5/d;->K:Lh5/c;

    .line 395
    .line 396
    move/from16 v2, v18

    .line 397
    .line 398
    move/from16 v11, v23

    .line 399
    .line 400
    invoke-direct/range {v0 .. v7}, Lh5/f;-><init>(Lh5/g;ILh5/c;Lh5/c;Lh5/c;Lh5/c;I)V

    .line 401
    .line 402
    .line 403
    iput v11, v0, Lh5/f;->n:I

    .line 404
    .line 405
    invoke-virtual {v13, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 406
    .line 407
    .line 408
    move/from16 v6, v16

    .line 409
    .line 410
    const/4 v4, 0x1

    .line 411
    goto :goto_a

    .line 412
    :cond_17
    move/from16 v2, v18

    .line 413
    .line 414
    move/from16 v11, v23

    .line 415
    .line 416
    if-lez v11, :cond_18

    .line 417
    .line 418
    iget v3, v1, Lh5/g;->Q0:I

    .line 419
    .line 420
    add-int v3, v3, v16

    .line 421
    .line 422
    add-int/2addr v3, v6

    .line 423
    move v6, v3

    .line 424
    goto :goto_a

    .line 425
    :cond_18
    move/from16 v6, v16

    .line 426
    .line 427
    :goto_a
    invoke-virtual {v0, v14}, Lh5/f;->a(Lh5/d;)V

    .line 428
    .line 429
    .line 430
    add-int/lit8 v3, v11, 0x1

    .line 431
    .line 432
    move/from16 v5, v24

    .line 433
    .line 434
    move-object/from16 v14, v36

    .line 435
    .line 436
    goto :goto_8

    .line 437
    :cond_19
    move-object/from16 v36, v14

    .line 438
    .line 439
    goto/16 :goto_e

    .line 440
    .line 441
    :cond_1a
    move-object/from16 v36, v14

    .line 442
    .line 443
    move/from16 v3, v28

    .line 444
    .line 445
    move v4, v3

    .line 446
    move v5, v4

    .line 447
    move v11, v5

    .line 448
    :goto_b
    if-ge v11, v15, :cond_21

    .line 449
    .line 450
    const/16 v29, 0x1

    .line 451
    .line 452
    add-int/lit8 v3, v3, 0x1

    .line 453
    .line 454
    aget-object v14, v12, v11

    .line 455
    .line 456
    invoke-virtual {v1, v14, v7}, Lh5/g;->a0(Lh5/d;I)I

    .line 457
    .line 458
    .line 459
    move-result v16

    .line 460
    iget-object v6, v14, Lh5/d;->q0:[I

    .line 461
    .line 462
    aget v6, v6, v29

    .line 463
    .line 464
    move/from16 v18, v2

    .line 465
    .line 466
    const/4 v2, 0x3

    .line 467
    if-ne v6, v2, :cond_1b

    .line 468
    .line 469
    add-int/lit8 v4, v4, 0x1

    .line 470
    .line 471
    :cond_1b
    move/from16 v23, v4

    .line 472
    .line 473
    if-eq v5, v7, :cond_1c

    .line 474
    .line 475
    iget v2, v1, Lh5/g;->R0:I

    .line 476
    .line 477
    add-int/2addr v2, v5

    .line 478
    add-int v2, v2, v16

    .line 479
    .line 480
    if-le v2, v7, :cond_1d

    .line 481
    .line 482
    :cond_1c
    iget-object v2, v0, Lh5/f;->b:Lh5/d;

    .line 483
    .line 484
    if-eqz v2, :cond_1d

    .line 485
    .line 486
    const/4 v2, 0x1

    .line 487
    goto :goto_c

    .line 488
    :cond_1d
    move/from16 v2, v28

    .line 489
    .line 490
    :goto_c
    if-nez v2, :cond_1e

    .line 491
    .line 492
    if-lez v11, :cond_1e

    .line 493
    .line 494
    iget v4, v1, Lh5/g;->V0:I

    .line 495
    .line 496
    if-lez v4, :cond_1e

    .line 497
    .line 498
    if-le v3, v4, :cond_1e

    .line 499
    .line 500
    const/4 v2, 0x1

    .line 501
    :cond_1e
    if-eqz v2, :cond_1f

    .line 502
    .line 503
    new-instance v0, Lh5/f;

    .line 504
    .line 505
    iget-object v5, v1, Lh5/d;->L:Lh5/c;

    .line 506
    .line 507
    iget-object v6, v1, Lh5/d;->M:Lh5/c;

    .line 508
    .line 509
    iget-object v3, v1, Lh5/d;->J:Lh5/c;

    .line 510
    .line 511
    iget-object v4, v1, Lh5/d;->K:Lh5/c;

    .line 512
    .line 513
    move/from16 v2, v18

    .line 514
    .line 515
    invoke-direct/range {v0 .. v7}, Lh5/f;-><init>(Lh5/g;ILh5/c;Lh5/c;Lh5/c;Lh5/c;I)V

    .line 516
    .line 517
    .line 518
    iput v11, v0, Lh5/f;->n:I

    .line 519
    .line 520
    invoke-virtual {v13, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 521
    .line 522
    .line 523
    move/from16 v5, v16

    .line 524
    .line 525
    const/4 v3, 0x1

    .line 526
    goto :goto_d

    .line 527
    :cond_1f
    move/from16 v2, v18

    .line 528
    .line 529
    if-lez v11, :cond_20

    .line 530
    .line 531
    iget v4, v1, Lh5/g;->R0:I

    .line 532
    .line 533
    add-int v4, v4, v16

    .line 534
    .line 535
    add-int/2addr v4, v5

    .line 536
    move v5, v4

    .line 537
    goto :goto_d

    .line 538
    :cond_20
    move/from16 v5, v16

    .line 539
    .line 540
    :goto_d
    invoke-virtual {v0, v14}, Lh5/f;->a(Lh5/d;)V

    .line 541
    .line 542
    .line 543
    add-int/lit8 v11, v11, 0x1

    .line 544
    .line 545
    move/from16 v4, v23

    .line 546
    .line 547
    goto :goto_b

    .line 548
    :cond_21
    move v5, v4

    .line 549
    :goto_e
    invoke-virtual {v13}, Ljava/util/ArrayList;->size()I

    .line 550
    .line 551
    .line 552
    move-result v0

    .line 553
    iget v3, v1, Lh5/k;->x0:I

    .line 554
    .line 555
    iget v4, v1, Lh5/k;->t0:I

    .line 556
    .line 557
    iget v6, v1, Lh5/k;->y0:I

    .line 558
    .line 559
    iget v11, v1, Lh5/k;->u0:I

    .line 560
    .line 561
    aget v12, v20, v28

    .line 562
    .line 563
    const/4 v14, 0x2

    .line 564
    if-eq v12, v14, :cond_23

    .line 565
    .line 566
    const/16 v29, 0x1

    .line 567
    .line 568
    aget v12, v20, v29

    .line 569
    .line 570
    if-ne v12, v14, :cond_22

    .line 571
    .line 572
    goto :goto_f

    .line 573
    :cond_22
    move/from16 v12, v28

    .line 574
    .line 575
    goto :goto_10

    .line 576
    :cond_23
    :goto_f
    const/4 v12, 0x1

    .line 577
    :goto_10
    if-lez v5, :cond_25

    .line 578
    .line 579
    if-eqz v12, :cond_25

    .line 580
    .line 581
    move/from16 v5, v28

    .line 582
    .line 583
    :goto_11
    if-ge v5, v0, :cond_25

    .line 584
    .line 585
    invoke-virtual {v13, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 586
    .line 587
    .line 588
    move-result-object v12

    .line 589
    check-cast v12, Lh5/f;

    .line 590
    .line 591
    if-nez v2, :cond_24

    .line 592
    .line 593
    invoke-virtual {v12}, Lh5/f;->d()I

    .line 594
    .line 595
    .line 596
    move-result v14

    .line 597
    sub-int v14, v7, v14

    .line 598
    .line 599
    invoke-virtual {v12, v14}, Lh5/f;->e(I)V

    .line 600
    .line 601
    .line 602
    goto :goto_12

    .line 603
    :cond_24
    invoke-virtual {v12}, Lh5/f;->c()I

    .line 604
    .line 605
    .line 606
    move-result v14

    .line 607
    sub-int v14, v7, v14

    .line 608
    .line 609
    invoke-virtual {v12, v14}, Lh5/f;->e(I)V

    .line 610
    .line 611
    .line 612
    :goto_12
    add-int/lit8 v5, v5, 0x1

    .line 613
    .line 614
    goto :goto_11

    .line 615
    :cond_25
    move/from16 v23, v3

    .line 616
    .line 617
    move/from16 v24, v4

    .line 618
    .line 619
    move/from16 v25, v6

    .line 620
    .line 621
    move/from16 v26, v11

    .line 622
    .line 623
    move-object/from16 v19, v21

    .line 624
    .line 625
    move-object/from16 v20, v22

    .line 626
    .line 627
    move/from16 v3, v28

    .line 628
    .line 629
    move v4, v3

    .line 630
    move v5, v4

    .line 631
    move-object/from16 v21, v30

    .line 632
    .line 633
    move-object/from16 v22, v36

    .line 634
    .line 635
    :goto_13
    if-ge v3, v0, :cond_2b

    .line 636
    .line 637
    invoke-virtual {v13, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 638
    .line 639
    .line 640
    move-result-object v6

    .line 641
    check-cast v6, Lh5/f;

    .line 642
    .line 643
    if-nez v2, :cond_28

    .line 644
    .line 645
    add-int/lit8 v11, v0, -0x1

    .line 646
    .line 647
    if-ge v3, v11, :cond_26

    .line 648
    .line 649
    add-int/lit8 v11, v3, 0x1

    .line 650
    .line 651
    invoke-virtual {v13, v11}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 652
    .line 653
    .line 654
    move-result-object v11

    .line 655
    check-cast v11, Lh5/f;

    .line 656
    .line 657
    iget-object v11, v11, Lh5/f;->b:Lh5/d;

    .line 658
    .line 659
    iget-object v11, v11, Lh5/d;->K:Lh5/c;

    .line 660
    .line 661
    move-object/from16 v22, v11

    .line 662
    .line 663
    move/from16 v26, v28

    .line 664
    .line 665
    goto :goto_14

    .line 666
    :cond_26
    iget v11, v1, Lh5/k;->u0:I

    .line 667
    .line 668
    move/from16 v26, v11

    .line 669
    .line 670
    move-object/from16 v22, v36

    .line 671
    .line 672
    :goto_14
    iget-object v11, v6, Lh5/f;->b:Lh5/d;

    .line 673
    .line 674
    iget-object v11, v11, Lh5/d;->M:Lh5/c;

    .line 675
    .line 676
    move/from16 v18, v2

    .line 677
    .line 678
    move-object/from16 v17, v6

    .line 679
    .line 680
    move/from16 v27, v7

    .line 681
    .line 682
    invoke-virtual/range {v17 .. v27}, Lh5/f;->f(ILh5/c;Lh5/c;Lh5/c;Lh5/c;IIIII)V

    .line 683
    .line 684
    .line 685
    invoke-virtual {v6}, Lh5/f;->d()I

    .line 686
    .line 687
    .line 688
    move-result v12

    .line 689
    invoke-static {v4, v12}, Ljava/lang/Math;->max(II)I

    .line 690
    .line 691
    .line 692
    move-result v4

    .line 693
    invoke-virtual {v6}, Lh5/f;->c()I

    .line 694
    .line 695
    .line 696
    move-result v6

    .line 697
    add-int/2addr v6, v5

    .line 698
    if-lez v3, :cond_27

    .line 699
    .line 700
    iget v5, v1, Lh5/g;->R0:I

    .line 701
    .line 702
    add-int/2addr v6, v5

    .line 703
    :cond_27
    move v5, v6

    .line 704
    move-object/from16 v20, v11

    .line 705
    .line 706
    move/from16 v24, v28

    .line 707
    .line 708
    goto :goto_16

    .line 709
    :cond_28
    add-int/lit8 v11, v0, -0x1

    .line 710
    .line 711
    if-ge v3, v11, :cond_29

    .line 712
    .line 713
    add-int/lit8 v11, v3, 0x1

    .line 714
    .line 715
    invoke-virtual {v13, v11}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 716
    .line 717
    .line 718
    move-result-object v11

    .line 719
    check-cast v11, Lh5/f;

    .line 720
    .line 721
    iget-object v11, v11, Lh5/f;->b:Lh5/d;

    .line 722
    .line 723
    iget-object v11, v11, Lh5/d;->J:Lh5/c;

    .line 724
    .line 725
    move-object/from16 v21, v11

    .line 726
    .line 727
    move/from16 v25, v28

    .line 728
    .line 729
    goto :goto_15

    .line 730
    :cond_29
    iget v11, v1, Lh5/k;->y0:I

    .line 731
    .line 732
    move/from16 v25, v11

    .line 733
    .line 734
    move-object/from16 v21, v30

    .line 735
    .line 736
    :goto_15
    iget-object v11, v6, Lh5/f;->b:Lh5/d;

    .line 737
    .line 738
    iget-object v11, v11, Lh5/d;->L:Lh5/c;

    .line 739
    .line 740
    move/from16 v18, v2

    .line 741
    .line 742
    move-object/from16 v17, v6

    .line 743
    .line 744
    move/from16 v27, v7

    .line 745
    .line 746
    invoke-virtual/range {v17 .. v27}, Lh5/f;->f(ILh5/c;Lh5/c;Lh5/c;Lh5/c;IIIII)V

    .line 747
    .line 748
    .line 749
    invoke-virtual/range {v17 .. v17}, Lh5/f;->d()I

    .line 750
    .line 751
    .line 752
    move-result v6

    .line 753
    add-int/2addr v6, v4

    .line 754
    invoke-virtual/range {v17 .. v17}, Lh5/f;->c()I

    .line 755
    .line 756
    .line 757
    move-result v4

    .line 758
    invoke-static {v5, v4}, Ljava/lang/Math;->max(II)I

    .line 759
    .line 760
    .line 761
    move-result v4

    .line 762
    if-lez v3, :cond_2a

    .line 763
    .line 764
    iget v5, v1, Lh5/g;->Q0:I

    .line 765
    .line 766
    add-int/2addr v6, v5

    .line 767
    :cond_2a
    move v5, v4

    .line 768
    move v4, v6

    .line 769
    move-object/from16 v19, v11

    .line 770
    .line 771
    move/from16 v23, v28

    .line 772
    .line 773
    :goto_16
    add-int/lit8 v3, v3, 0x1

    .line 774
    .line 775
    goto/16 :goto_13

    .line 776
    .line 777
    :cond_2b
    aput v4, v35, v28

    .line 778
    .line 779
    const/16 v29, 0x1

    .line 780
    .line 781
    aput v5, v35, v29

    .line 782
    .line 783
    goto/16 :goto_7

    .line 784
    .line 785
    :cond_2c
    move/from16 v32, v3

    .line 786
    .line 787
    move/from16 v33, v4

    .line 788
    .line 789
    move/from16 v34, v5

    .line 790
    .line 791
    move-object/from16 v35, v6

    .line 792
    .line 793
    move/from16 v31, v18

    .line 794
    .line 795
    iget v0, v1, Lh5/g;->W0:I

    .line 796
    .line 797
    if-nez v0, :cond_32

    .line 798
    .line 799
    iget v2, v1, Lh5/g;->V0:I

    .line 800
    .line 801
    if-gtz v2, :cond_31

    .line 802
    .line 803
    move/from16 v2, v28

    .line 804
    .line 805
    move v3, v2

    .line 806
    move v4, v3

    .line 807
    :goto_17
    if-ge v2, v15, :cond_30

    .line 808
    .line 809
    if-lez v2, :cond_2d

    .line 810
    .line 811
    iget v5, v1, Lh5/g;->Q0:I

    .line 812
    .line 813
    add-int/2addr v3, v5

    .line 814
    :cond_2d
    aget-object v5, v12, v2

    .line 815
    .line 816
    if-nez v5, :cond_2e

    .line 817
    .line 818
    goto :goto_18

    .line 819
    :cond_2e
    invoke-virtual {v1, v5, v7}, Lh5/g;->b0(Lh5/d;I)I

    .line 820
    .line 821
    .line 822
    move-result v5

    .line 823
    add-int/2addr v5, v3

    .line 824
    if-le v5, v7, :cond_2f

    .line 825
    .line 826
    goto :goto_19

    .line 827
    :cond_2f
    add-int/lit8 v4, v4, 0x1

    .line 828
    .line 829
    move v3, v5

    .line 830
    :goto_18
    add-int/lit8 v2, v2, 0x1

    .line 831
    .line 832
    goto :goto_17

    .line 833
    :cond_30
    :goto_19
    move/from16 v2, v28

    .line 834
    .line 835
    goto :goto_1d

    .line 836
    :cond_31
    move v4, v2

    .line 837
    goto :goto_19

    .line 838
    :cond_32
    iget v2, v1, Lh5/g;->V0:I

    .line 839
    .line 840
    if-gtz v2, :cond_37

    .line 841
    .line 842
    move/from16 v2, v28

    .line 843
    .line 844
    move v3, v2

    .line 845
    move v4, v3

    .line 846
    :goto_1a
    if-ge v2, v15, :cond_36

    .line 847
    .line 848
    if-lez v2, :cond_33

    .line 849
    .line 850
    iget v5, v1, Lh5/g;->R0:I

    .line 851
    .line 852
    add-int/2addr v3, v5

    .line 853
    :cond_33
    aget-object v5, v12, v2

    .line 854
    .line 855
    if-nez v5, :cond_34

    .line 856
    .line 857
    goto :goto_1b

    .line 858
    :cond_34
    invoke-virtual {v1, v5, v7}, Lh5/g;->a0(Lh5/d;I)I

    .line 859
    .line 860
    .line 861
    move-result v5

    .line 862
    add-int/2addr v5, v3

    .line 863
    if-le v5, v7, :cond_35

    .line 864
    .line 865
    goto :goto_1c

    .line 866
    :cond_35
    add-int/lit8 v4, v4, 0x1

    .line 867
    .line 868
    move v3, v5

    .line 869
    :goto_1b
    add-int/lit8 v2, v2, 0x1

    .line 870
    .line 871
    goto :goto_1a

    .line 872
    :cond_36
    :goto_1c
    move v2, v4

    .line 873
    :cond_37
    move/from16 v4, v28

    .line 874
    .line 875
    :goto_1d
    iget-object v3, v1, Lh5/g;->a1:[I

    .line 876
    .line 877
    if-nez v3, :cond_38

    .line 878
    .line 879
    const/4 v14, 0x2

    .line 880
    new-array v3, v14, [I

    .line 881
    .line 882
    iput-object v3, v1, Lh5/g;->a1:[I

    .line 883
    .line 884
    :cond_38
    if-nez v2, :cond_39

    .line 885
    .line 886
    const/4 v3, 0x1

    .line 887
    if-eq v0, v3, :cond_3a

    .line 888
    .line 889
    :cond_39
    if-nez v4, :cond_3b

    .line 890
    .line 891
    if-nez v0, :cond_3b

    .line 892
    .line 893
    :cond_3a
    const/4 v3, 0x1

    .line 894
    goto :goto_1e

    .line 895
    :cond_3b
    move/from16 v3, v28

    .line 896
    .line 897
    :goto_1e
    if-nez v3, :cond_52

    .line 898
    .line 899
    if-nez v0, :cond_3c

    .line 900
    .line 901
    int-to-float v2, v15

    .line 902
    int-to-float v5, v4

    .line 903
    div-float/2addr v2, v5

    .line 904
    float-to-double v5, v2

    .line 905
    invoke-static {v5, v6}, Ljava/lang/Math;->ceil(D)D

    .line 906
    .line 907
    .line 908
    move-result-wide v5

    .line 909
    double-to-int v2, v5

    .line 910
    goto :goto_1f

    .line 911
    :cond_3c
    int-to-float v4, v15

    .line 912
    int-to-float v5, v2

    .line 913
    div-float/2addr v4, v5

    .line 914
    float-to-double v4, v4

    .line 915
    invoke-static {v4, v5}, Ljava/lang/Math;->ceil(D)D

    .line 916
    .line 917
    .line 918
    move-result-wide v4

    .line 919
    double-to-int v4, v4

    .line 920
    :goto_1f
    iget-object v5, v1, Lh5/g;->Z0:[Lh5/d;

    .line 921
    .line 922
    if-eqz v5, :cond_3d

    .line 923
    .line 924
    array-length v6, v5

    .line 925
    if-ge v6, v4, :cond_3e

    .line 926
    .line 927
    :cond_3d
    const/4 v6, 0x0

    .line 928
    goto :goto_20

    .line 929
    :cond_3e
    const/4 v6, 0x0

    .line 930
    invoke-static {v5, v6}, Ljava/util/Arrays;->fill([Ljava/lang/Object;Ljava/lang/Object;)V

    .line 931
    .line 932
    .line 933
    goto :goto_21

    .line 934
    :goto_20
    new-array v5, v4, [Lh5/d;

    .line 935
    .line 936
    iput-object v5, v1, Lh5/g;->Z0:[Lh5/d;

    .line 937
    .line 938
    :goto_21
    iget-object v5, v1, Lh5/g;->Y0:[Lh5/d;

    .line 939
    .line 940
    if-eqz v5, :cond_40

    .line 941
    .line 942
    array-length v11, v5

    .line 943
    if-ge v11, v2, :cond_3f

    .line 944
    .line 945
    goto :goto_22

    .line 946
    :cond_3f
    invoke-static {v5, v6}, Ljava/util/Arrays;->fill([Ljava/lang/Object;Ljava/lang/Object;)V

    .line 947
    .line 948
    .line 949
    goto :goto_23

    .line 950
    :cond_40
    :goto_22
    new-array v5, v2, [Lh5/d;

    .line 951
    .line 952
    iput-object v5, v1, Lh5/g;->Y0:[Lh5/d;

    .line 953
    .line 954
    :goto_23
    move/from16 v5, v28

    .line 955
    .line 956
    :goto_24
    if-ge v5, v4, :cond_49

    .line 957
    .line 958
    move/from16 v6, v28

    .line 959
    .line 960
    :goto_25
    if-ge v6, v2, :cond_48

    .line 961
    .line 962
    mul-int v11, v6, v4

    .line 963
    .line 964
    add-int/2addr v11, v5

    .line 965
    const/4 v13, 0x1

    .line 966
    if-ne v0, v13, :cond_41

    .line 967
    .line 968
    mul-int v11, v5, v2

    .line 969
    .line 970
    add-int/2addr v11, v6

    .line 971
    :cond_41
    array-length v13, v12

    .line 972
    if-lt v11, v13, :cond_42

    .line 973
    .line 974
    goto :goto_26

    .line 975
    :cond_42
    aget-object v11, v12, v11

    .line 976
    .line 977
    if-nez v11, :cond_43

    .line 978
    .line 979
    goto :goto_26

    .line 980
    :cond_43
    invoke-virtual {v1, v11, v7}, Lh5/g;->b0(Lh5/d;I)I

    .line 981
    .line 982
    .line 983
    move-result v13

    .line 984
    iget-object v14, v1, Lh5/g;->Z0:[Lh5/d;

    .line 985
    .line 986
    aget-object v14, v14, v5

    .line 987
    .line 988
    if-eqz v14, :cond_44

    .line 989
    .line 990
    invoke-virtual {v14}, Lh5/d;->r()I

    .line 991
    .line 992
    .line 993
    move-result v14

    .line 994
    if-ge v14, v13, :cond_45

    .line 995
    .line 996
    :cond_44
    iget-object v13, v1, Lh5/g;->Z0:[Lh5/d;

    .line 997
    .line 998
    aput-object v11, v13, v5

    .line 999
    .line 1000
    :cond_45
    invoke-virtual {v1, v11, v7}, Lh5/g;->a0(Lh5/d;I)I

    .line 1001
    .line 1002
    .line 1003
    move-result v13

    .line 1004
    iget-object v14, v1, Lh5/g;->Y0:[Lh5/d;

    .line 1005
    .line 1006
    aget-object v14, v14, v6

    .line 1007
    .line 1008
    if-eqz v14, :cond_46

    .line 1009
    .line 1010
    invoke-virtual {v14}, Lh5/d;->l()I

    .line 1011
    .line 1012
    .line 1013
    move-result v14

    .line 1014
    if-ge v14, v13, :cond_47

    .line 1015
    .line 1016
    :cond_46
    iget-object v13, v1, Lh5/g;->Y0:[Lh5/d;

    .line 1017
    .line 1018
    aput-object v11, v13, v6

    .line 1019
    .line 1020
    :cond_47
    :goto_26
    add-int/lit8 v6, v6, 0x1

    .line 1021
    .line 1022
    goto :goto_25

    .line 1023
    :cond_48
    add-int/lit8 v5, v5, 0x1

    .line 1024
    .line 1025
    goto :goto_24

    .line 1026
    :cond_49
    move/from16 v5, v28

    .line 1027
    .line 1028
    move v6, v5

    .line 1029
    :goto_27
    if-ge v5, v4, :cond_4c

    .line 1030
    .line 1031
    iget-object v11, v1, Lh5/g;->Z0:[Lh5/d;

    .line 1032
    .line 1033
    aget-object v11, v11, v5

    .line 1034
    .line 1035
    if-eqz v11, :cond_4b

    .line 1036
    .line 1037
    if-lez v5, :cond_4a

    .line 1038
    .line 1039
    iget v13, v1, Lh5/g;->Q0:I

    .line 1040
    .line 1041
    add-int/2addr v6, v13

    .line 1042
    :cond_4a
    invoke-virtual {v1, v11, v7}, Lh5/g;->b0(Lh5/d;I)I

    .line 1043
    .line 1044
    .line 1045
    move-result v11

    .line 1046
    add-int/2addr v11, v6

    .line 1047
    move v6, v11

    .line 1048
    :cond_4b
    add-int/lit8 v5, v5, 0x1

    .line 1049
    .line 1050
    goto :goto_27

    .line 1051
    :cond_4c
    move/from16 v5, v28

    .line 1052
    .line 1053
    move v11, v5

    .line 1054
    :goto_28
    if-ge v5, v2, :cond_4f

    .line 1055
    .line 1056
    iget-object v13, v1, Lh5/g;->Y0:[Lh5/d;

    .line 1057
    .line 1058
    aget-object v13, v13, v5

    .line 1059
    .line 1060
    if-eqz v13, :cond_4e

    .line 1061
    .line 1062
    if-lez v5, :cond_4d

    .line 1063
    .line 1064
    iget v14, v1, Lh5/g;->R0:I

    .line 1065
    .line 1066
    add-int/2addr v11, v14

    .line 1067
    :cond_4d
    invoke-virtual {v1, v13, v7}, Lh5/g;->a0(Lh5/d;I)I

    .line 1068
    .line 1069
    .line 1070
    move-result v13

    .line 1071
    add-int/2addr v13, v11

    .line 1072
    move v11, v13

    .line 1073
    :cond_4e
    add-int/lit8 v5, v5, 0x1

    .line 1074
    .line 1075
    goto :goto_28

    .line 1076
    :cond_4f
    aput v6, v35, v28

    .line 1077
    .line 1078
    const/4 v13, 0x1

    .line 1079
    aput v11, v35, v13

    .line 1080
    .line 1081
    if-nez v0, :cond_51

    .line 1082
    .line 1083
    if-le v6, v7, :cond_50

    .line 1084
    .line 1085
    if-le v4, v13, :cond_50

    .line 1086
    .line 1087
    add-int/lit8 v4, v4, -0x1

    .line 1088
    .line 1089
    goto/16 :goto_1e

    .line 1090
    .line 1091
    :cond_50
    move v3, v13

    .line 1092
    goto/16 :goto_1e

    .line 1093
    .line 1094
    :cond_51
    if-le v11, v7, :cond_50

    .line 1095
    .line 1096
    if-le v2, v13, :cond_50

    .line 1097
    .line 1098
    add-int/lit8 v2, v2, -0x1

    .line 1099
    .line 1100
    goto/16 :goto_1e

    .line 1101
    .line 1102
    :cond_52
    const/4 v13, 0x1

    .line 1103
    iget-object v0, v1, Lh5/g;->a1:[I

    .line 1104
    .line 1105
    aput v4, v0, v28

    .line 1106
    .line 1107
    aput v2, v0, v13

    .line 1108
    .line 1109
    move/from16 v29, v13

    .line 1110
    .line 1111
    goto/16 :goto_39

    .line 1112
    .line 1113
    :cond_53
    move/from16 v32, v3

    .line 1114
    .line 1115
    move/from16 v33, v4

    .line 1116
    .line 1117
    move/from16 v34, v5

    .line 1118
    .line 1119
    move-object/from16 v35, v6

    .line 1120
    .line 1121
    move-object/from16 v36, v14

    .line 1122
    .line 1123
    move/from16 v31, v18

    .line 1124
    .line 1125
    iget v2, v1, Lh5/g;->W0:I

    .line 1126
    .line 1127
    if-nez v15, :cond_54

    .line 1128
    .line 1129
    goto/16 :goto_7

    .line 1130
    .line 1131
    :cond_54
    invoke-virtual {v13}, Ljava/util/ArrayList;->clear()V

    .line 1132
    .line 1133
    .line 1134
    new-instance v0, Lh5/f;

    .line 1135
    .line 1136
    iget-object v5, v1, Lh5/d;->L:Lh5/c;

    .line 1137
    .line 1138
    iget-object v6, v1, Lh5/d;->M:Lh5/c;

    .line 1139
    .line 1140
    iget-object v3, v1, Lh5/d;->J:Lh5/c;

    .line 1141
    .line 1142
    iget-object v4, v1, Lh5/d;->K:Lh5/c;

    .line 1143
    .line 1144
    invoke-direct/range {v0 .. v7}, Lh5/f;-><init>(Lh5/g;ILh5/c;Lh5/c;Lh5/c;Lh5/c;I)V

    .line 1145
    .line 1146
    .line 1147
    invoke-virtual {v13, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1148
    .line 1149
    .line 1150
    if-nez v2, :cond_5b

    .line 1151
    .line 1152
    move/from16 v3, v28

    .line 1153
    .line 1154
    move v4, v3

    .line 1155
    move v11, v4

    .line 1156
    :goto_29
    if-ge v11, v15, :cond_62

    .line 1157
    .line 1158
    aget-object v14, v12, v11

    .line 1159
    .line 1160
    invoke-virtual {v1, v14, v7}, Lh5/g;->b0(Lh5/d;I)I

    .line 1161
    .line 1162
    .line 1163
    move-result v16

    .line 1164
    iget-object v5, v14, Lh5/d;->q0:[I

    .line 1165
    .line 1166
    aget v5, v5, v28

    .line 1167
    .line 1168
    const/4 v6, 0x3

    .line 1169
    if-ne v5, v6, :cond_55

    .line 1170
    .line 1171
    add-int/lit8 v3, v3, 0x1

    .line 1172
    .line 1173
    :cond_55
    move/from16 v18, v3

    .line 1174
    .line 1175
    if-eq v4, v7, :cond_56

    .line 1176
    .line 1177
    iget v3, v1, Lh5/g;->Q0:I

    .line 1178
    .line 1179
    add-int/2addr v3, v4

    .line 1180
    add-int v3, v3, v16

    .line 1181
    .line 1182
    if-le v3, v7, :cond_57

    .line 1183
    .line 1184
    :cond_56
    iget-object v3, v0, Lh5/f;->b:Lh5/d;

    .line 1185
    .line 1186
    if-eqz v3, :cond_57

    .line 1187
    .line 1188
    const/4 v3, 0x1

    .line 1189
    goto :goto_2a

    .line 1190
    :cond_57
    move/from16 v3, v28

    .line 1191
    .line 1192
    :goto_2a
    if-nez v3, :cond_58

    .line 1193
    .line 1194
    if-lez v11, :cond_58

    .line 1195
    .line 1196
    iget v5, v1, Lh5/g;->V0:I

    .line 1197
    .line 1198
    if-lez v5, :cond_58

    .line 1199
    .line 1200
    rem-int v5, v11, v5

    .line 1201
    .line 1202
    if-nez v5, :cond_58

    .line 1203
    .line 1204
    const/4 v3, 0x1

    .line 1205
    :cond_58
    if-eqz v3, :cond_5a

    .line 1206
    .line 1207
    new-instance v0, Lh5/f;

    .line 1208
    .line 1209
    iget-object v5, v1, Lh5/d;->L:Lh5/c;

    .line 1210
    .line 1211
    iget-object v6, v1, Lh5/d;->M:Lh5/c;

    .line 1212
    .line 1213
    iget-object v3, v1, Lh5/d;->J:Lh5/c;

    .line 1214
    .line 1215
    iget-object v4, v1, Lh5/d;->K:Lh5/c;

    .line 1216
    .line 1217
    invoke-direct/range {v0 .. v7}, Lh5/f;-><init>(Lh5/g;ILh5/c;Lh5/c;Lh5/c;Lh5/c;I)V

    .line 1218
    .line 1219
    .line 1220
    iput v11, v0, Lh5/f;->n:I

    .line 1221
    .line 1222
    invoke-virtual {v13, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1223
    .line 1224
    .line 1225
    :cond_59
    move/from16 v4, v16

    .line 1226
    .line 1227
    goto :goto_2b

    .line 1228
    :cond_5a
    if-lez v11, :cond_59

    .line 1229
    .line 1230
    iget v3, v1, Lh5/g;->Q0:I

    .line 1231
    .line 1232
    add-int v3, v3, v16

    .line 1233
    .line 1234
    add-int/2addr v3, v4

    .line 1235
    move v4, v3

    .line 1236
    :goto_2b
    invoke-virtual {v0, v14}, Lh5/f;->a(Lh5/d;)V

    .line 1237
    .line 1238
    .line 1239
    add-int/lit8 v11, v11, 0x1

    .line 1240
    .line 1241
    move/from16 v3, v18

    .line 1242
    .line 1243
    goto :goto_29

    .line 1244
    :cond_5b
    move/from16 v3, v28

    .line 1245
    .line 1246
    move v4, v3

    .line 1247
    move v11, v4

    .line 1248
    :goto_2c
    if-ge v11, v15, :cond_62

    .line 1249
    .line 1250
    aget-object v14, v12, v11

    .line 1251
    .line 1252
    invoke-virtual {v1, v14, v7}, Lh5/g;->a0(Lh5/d;I)I

    .line 1253
    .line 1254
    .line 1255
    move-result v16

    .line 1256
    iget-object v5, v14, Lh5/d;->q0:[I

    .line 1257
    .line 1258
    const/16 v29, 0x1

    .line 1259
    .line 1260
    aget v5, v5, v29

    .line 1261
    .line 1262
    const/4 v6, 0x3

    .line 1263
    if-ne v5, v6, :cond_5c

    .line 1264
    .line 1265
    add-int/lit8 v3, v3, 0x1

    .line 1266
    .line 1267
    :cond_5c
    move/from16 v17, v3

    .line 1268
    .line 1269
    if-eq v4, v7, :cond_5d

    .line 1270
    .line 1271
    iget v3, v1, Lh5/g;->R0:I

    .line 1272
    .line 1273
    add-int/2addr v3, v4

    .line 1274
    add-int v3, v3, v16

    .line 1275
    .line 1276
    if-le v3, v7, :cond_5e

    .line 1277
    .line 1278
    :cond_5d
    iget-object v3, v0, Lh5/f;->b:Lh5/d;

    .line 1279
    .line 1280
    if-eqz v3, :cond_5e

    .line 1281
    .line 1282
    const/4 v3, 0x1

    .line 1283
    goto :goto_2d

    .line 1284
    :cond_5e
    move/from16 v3, v28

    .line 1285
    .line 1286
    :goto_2d
    if-nez v3, :cond_5f

    .line 1287
    .line 1288
    if-lez v11, :cond_5f

    .line 1289
    .line 1290
    iget v5, v1, Lh5/g;->V0:I

    .line 1291
    .line 1292
    if-lez v5, :cond_5f

    .line 1293
    .line 1294
    rem-int v5, v11, v5

    .line 1295
    .line 1296
    if-nez v5, :cond_5f

    .line 1297
    .line 1298
    const/4 v3, 0x1

    .line 1299
    :cond_5f
    if-eqz v3, :cond_61

    .line 1300
    .line 1301
    new-instance v0, Lh5/f;

    .line 1302
    .line 1303
    iget-object v5, v1, Lh5/d;->L:Lh5/c;

    .line 1304
    .line 1305
    move v3, v6

    .line 1306
    iget-object v6, v1, Lh5/d;->M:Lh5/c;

    .line 1307
    .line 1308
    move v4, v3

    .line 1309
    iget-object v3, v1, Lh5/d;->J:Lh5/c;

    .line 1310
    .line 1311
    move/from16 v18, v4

    .line 1312
    .line 1313
    iget-object v4, v1, Lh5/d;->K:Lh5/c;

    .line 1314
    .line 1315
    invoke-direct/range {v0 .. v7}, Lh5/f;-><init>(Lh5/g;ILh5/c;Lh5/c;Lh5/c;Lh5/c;I)V

    .line 1316
    .line 1317
    .line 1318
    iput v11, v0, Lh5/f;->n:I

    .line 1319
    .line 1320
    invoke-virtual {v13, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1321
    .line 1322
    .line 1323
    :cond_60
    move/from16 v4, v16

    .line 1324
    .line 1325
    goto :goto_2e

    .line 1326
    :cond_61
    move/from16 v18, v6

    .line 1327
    .line 1328
    if-lez v11, :cond_60

    .line 1329
    .line 1330
    iget v3, v1, Lh5/g;->R0:I

    .line 1331
    .line 1332
    add-int v3, v3, v16

    .line 1333
    .line 1334
    add-int/2addr v3, v4

    .line 1335
    move v4, v3

    .line 1336
    :goto_2e
    invoke-virtual {v0, v14}, Lh5/f;->a(Lh5/d;)V

    .line 1337
    .line 1338
    .line 1339
    add-int/lit8 v11, v11, 0x1

    .line 1340
    .line 1341
    move/from16 v3, v17

    .line 1342
    .line 1343
    goto :goto_2c

    .line 1344
    :cond_62
    invoke-virtual {v13}, Ljava/util/ArrayList;->size()I

    .line 1345
    .line 1346
    .line 1347
    move-result v0

    .line 1348
    iget v4, v1, Lh5/k;->x0:I

    .line 1349
    .line 1350
    iget v5, v1, Lh5/k;->t0:I

    .line 1351
    .line 1352
    iget v6, v1, Lh5/k;->y0:I

    .line 1353
    .line 1354
    iget v11, v1, Lh5/k;->u0:I

    .line 1355
    .line 1356
    aget v12, v20, v28

    .line 1357
    .line 1358
    const/4 v14, 0x2

    .line 1359
    if-eq v12, v14, :cond_64

    .line 1360
    .line 1361
    const/16 v29, 0x1

    .line 1362
    .line 1363
    aget v12, v20, v29

    .line 1364
    .line 1365
    if-ne v12, v14, :cond_63

    .line 1366
    .line 1367
    goto :goto_2f

    .line 1368
    :cond_63
    move/from16 v12, v28

    .line 1369
    .line 1370
    goto :goto_30

    .line 1371
    :cond_64
    :goto_2f
    const/4 v12, 0x1

    .line 1372
    :goto_30
    if-lez v3, :cond_66

    .line 1373
    .line 1374
    if-eqz v12, :cond_66

    .line 1375
    .line 1376
    move/from16 v3, v28

    .line 1377
    .line 1378
    :goto_31
    if-ge v3, v0, :cond_66

    .line 1379
    .line 1380
    invoke-virtual {v13, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1381
    .line 1382
    .line 1383
    move-result-object v12

    .line 1384
    check-cast v12, Lh5/f;

    .line 1385
    .line 1386
    if-nez v2, :cond_65

    .line 1387
    .line 1388
    invoke-virtual {v12}, Lh5/f;->d()I

    .line 1389
    .line 1390
    .line 1391
    move-result v14

    .line 1392
    sub-int v14, v7, v14

    .line 1393
    .line 1394
    invoke-virtual {v12, v14}, Lh5/f;->e(I)V

    .line 1395
    .line 1396
    .line 1397
    goto :goto_32

    .line 1398
    :cond_65
    invoke-virtual {v12}, Lh5/f;->c()I

    .line 1399
    .line 1400
    .line 1401
    move-result v14

    .line 1402
    sub-int v14, v7, v14

    .line 1403
    .line 1404
    invoke-virtual {v12, v14}, Lh5/f;->e(I)V

    .line 1405
    .line 1406
    .line 1407
    :goto_32
    add-int/lit8 v3, v3, 0x1

    .line 1408
    .line 1409
    goto :goto_31

    .line 1410
    :cond_66
    move/from16 v23, v4

    .line 1411
    .line 1412
    move/from16 v24, v5

    .line 1413
    .line 1414
    move/from16 v25, v6

    .line 1415
    .line 1416
    move/from16 v26, v11

    .line 1417
    .line 1418
    move-object/from16 v19, v21

    .line 1419
    .line 1420
    move-object/from16 v20, v22

    .line 1421
    .line 1422
    move/from16 v3, v28

    .line 1423
    .line 1424
    move v4, v3

    .line 1425
    move v5, v4

    .line 1426
    move-object/from16 v21, v30

    .line 1427
    .line 1428
    move-object/from16 v22, v36

    .line 1429
    .line 1430
    :goto_33
    if-ge v3, v0, :cond_6c

    .line 1431
    .line 1432
    invoke-virtual {v13, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1433
    .line 1434
    .line 1435
    move-result-object v6

    .line 1436
    check-cast v6, Lh5/f;

    .line 1437
    .line 1438
    if-nez v2, :cond_69

    .line 1439
    .line 1440
    add-int/lit8 v11, v0, -0x1

    .line 1441
    .line 1442
    if-ge v3, v11, :cond_67

    .line 1443
    .line 1444
    add-int/lit8 v11, v3, 0x1

    .line 1445
    .line 1446
    invoke-virtual {v13, v11}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1447
    .line 1448
    .line 1449
    move-result-object v11

    .line 1450
    check-cast v11, Lh5/f;

    .line 1451
    .line 1452
    iget-object v11, v11, Lh5/f;->b:Lh5/d;

    .line 1453
    .line 1454
    iget-object v11, v11, Lh5/d;->K:Lh5/c;

    .line 1455
    .line 1456
    move-object/from16 v22, v11

    .line 1457
    .line 1458
    move/from16 v26, v28

    .line 1459
    .line 1460
    goto :goto_34

    .line 1461
    :cond_67
    iget v11, v1, Lh5/k;->u0:I

    .line 1462
    .line 1463
    move/from16 v26, v11

    .line 1464
    .line 1465
    move-object/from16 v22, v36

    .line 1466
    .line 1467
    :goto_34
    iget-object v11, v6, Lh5/f;->b:Lh5/d;

    .line 1468
    .line 1469
    iget-object v11, v11, Lh5/d;->M:Lh5/c;

    .line 1470
    .line 1471
    move/from16 v18, v2

    .line 1472
    .line 1473
    move-object/from16 v17, v6

    .line 1474
    .line 1475
    move/from16 v27, v7

    .line 1476
    .line 1477
    invoke-virtual/range {v17 .. v27}, Lh5/f;->f(ILh5/c;Lh5/c;Lh5/c;Lh5/c;IIIII)V

    .line 1478
    .line 1479
    .line 1480
    invoke-virtual {v6}, Lh5/f;->d()I

    .line 1481
    .line 1482
    .line 1483
    move-result v12

    .line 1484
    invoke-static {v4, v12}, Ljava/lang/Math;->max(II)I

    .line 1485
    .line 1486
    .line 1487
    move-result v4

    .line 1488
    invoke-virtual {v6}, Lh5/f;->c()I

    .line 1489
    .line 1490
    .line 1491
    move-result v6

    .line 1492
    add-int/2addr v6, v5

    .line 1493
    if-lez v3, :cond_68

    .line 1494
    .line 1495
    iget v5, v1, Lh5/g;->R0:I

    .line 1496
    .line 1497
    add-int/2addr v6, v5

    .line 1498
    :cond_68
    move v5, v6

    .line 1499
    move-object/from16 v20, v11

    .line 1500
    .line 1501
    move/from16 v24, v28

    .line 1502
    .line 1503
    goto :goto_36

    .line 1504
    :cond_69
    add-int/lit8 v11, v0, -0x1

    .line 1505
    .line 1506
    if-ge v3, v11, :cond_6a

    .line 1507
    .line 1508
    add-int/lit8 v11, v3, 0x1

    .line 1509
    .line 1510
    invoke-virtual {v13, v11}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1511
    .line 1512
    .line 1513
    move-result-object v11

    .line 1514
    check-cast v11, Lh5/f;

    .line 1515
    .line 1516
    iget-object v11, v11, Lh5/f;->b:Lh5/d;

    .line 1517
    .line 1518
    iget-object v11, v11, Lh5/d;->J:Lh5/c;

    .line 1519
    .line 1520
    move-object/from16 v21, v11

    .line 1521
    .line 1522
    move/from16 v25, v28

    .line 1523
    .line 1524
    goto :goto_35

    .line 1525
    :cond_6a
    iget v11, v1, Lh5/k;->y0:I

    .line 1526
    .line 1527
    move/from16 v25, v11

    .line 1528
    .line 1529
    move-object/from16 v21, v30

    .line 1530
    .line 1531
    :goto_35
    iget-object v11, v6, Lh5/f;->b:Lh5/d;

    .line 1532
    .line 1533
    iget-object v11, v11, Lh5/d;->L:Lh5/c;

    .line 1534
    .line 1535
    move/from16 v18, v2

    .line 1536
    .line 1537
    move-object/from16 v17, v6

    .line 1538
    .line 1539
    move/from16 v27, v7

    .line 1540
    .line 1541
    invoke-virtual/range {v17 .. v27}, Lh5/f;->f(ILh5/c;Lh5/c;Lh5/c;Lh5/c;IIIII)V

    .line 1542
    .line 1543
    .line 1544
    invoke-virtual/range {v17 .. v17}, Lh5/f;->d()I

    .line 1545
    .line 1546
    .line 1547
    move-result v6

    .line 1548
    add-int/2addr v6, v4

    .line 1549
    invoke-virtual/range {v17 .. v17}, Lh5/f;->c()I

    .line 1550
    .line 1551
    .line 1552
    move-result v4

    .line 1553
    invoke-static {v5, v4}, Ljava/lang/Math;->max(II)I

    .line 1554
    .line 1555
    .line 1556
    move-result v4

    .line 1557
    if-lez v3, :cond_6b

    .line 1558
    .line 1559
    iget v5, v1, Lh5/g;->Q0:I

    .line 1560
    .line 1561
    add-int/2addr v6, v5

    .line 1562
    :cond_6b
    move v5, v4

    .line 1563
    move v4, v6

    .line 1564
    move-object/from16 v19, v11

    .line 1565
    .line 1566
    move/from16 v23, v28

    .line 1567
    .line 1568
    :goto_36
    add-int/lit8 v3, v3, 0x1

    .line 1569
    .line 1570
    goto/16 :goto_33

    .line 1571
    .line 1572
    :cond_6c
    aput v4, v35, v28

    .line 1573
    .line 1574
    const/16 v29, 0x1

    .line 1575
    .line 1576
    aput v5, v35, v29

    .line 1577
    .line 1578
    goto/16 :goto_7

    .line 1579
    .line 1580
    :cond_6d
    move/from16 v32, v3

    .line 1581
    .line 1582
    move/from16 v33, v4

    .line 1583
    .line 1584
    move/from16 v34, v5

    .line 1585
    .line 1586
    move-object/from16 v35, v6

    .line 1587
    .line 1588
    move/from16 v31, v18

    .line 1589
    .line 1590
    iget v2, v1, Lh5/g;->W0:I

    .line 1591
    .line 1592
    if-nez v15, :cond_6e

    .line 1593
    .line 1594
    goto/16 :goto_7

    .line 1595
    .line 1596
    :cond_6e
    invoke-virtual {v13}, Ljava/util/ArrayList;->size()I

    .line 1597
    .line 1598
    .line 1599
    move-result v0

    .line 1600
    if-nez v0, :cond_6f

    .line 1601
    .line 1602
    new-instance v0, Lh5/f;

    .line 1603
    .line 1604
    iget-object v5, v1, Lh5/d;->L:Lh5/c;

    .line 1605
    .line 1606
    iget-object v6, v1, Lh5/d;->M:Lh5/c;

    .line 1607
    .line 1608
    iget-object v3, v1, Lh5/d;->J:Lh5/c;

    .line 1609
    .line 1610
    iget-object v4, v1, Lh5/d;->K:Lh5/c;

    .line 1611
    .line 1612
    invoke-direct/range {v0 .. v7}, Lh5/f;-><init>(Lh5/g;ILh5/c;Lh5/c;Lh5/c;Lh5/c;I)V

    .line 1613
    .line 1614
    .line 1615
    invoke-virtual {v13, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1616
    .line 1617
    .line 1618
    goto :goto_37

    .line 1619
    :cond_6f
    move/from16 v0, v28

    .line 1620
    .line 1621
    invoke-virtual {v13, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1622
    .line 1623
    .line 1624
    move-result-object v3

    .line 1625
    check-cast v3, Lh5/f;

    .line 1626
    .line 1627
    iput v0, v3, Lh5/f;->c:I

    .line 1628
    .line 1629
    const/4 v6, 0x0

    .line 1630
    iput-object v6, v3, Lh5/f;->b:Lh5/d;

    .line 1631
    .line 1632
    iput v0, v3, Lh5/f;->l:I

    .line 1633
    .line 1634
    iput v0, v3, Lh5/f;->m:I

    .line 1635
    .line 1636
    iput v0, v3, Lh5/f;->n:I

    .line 1637
    .line 1638
    iput v0, v3, Lh5/f;->o:I

    .line 1639
    .line 1640
    iput v0, v3, Lh5/f;->p:I

    .line 1641
    .line 1642
    iget v0, v1, Lh5/k;->x0:I

    .line 1643
    .line 1644
    iget v4, v1, Lh5/k;->t0:I

    .line 1645
    .line 1646
    iget v5, v1, Lh5/k;->y0:I

    .line 1647
    .line 1648
    iget v6, v1, Lh5/k;->u0:I

    .line 1649
    .line 1650
    iget-object v11, v1, Lh5/d;->J:Lh5/c;

    .line 1651
    .line 1652
    iget-object v13, v1, Lh5/d;->K:Lh5/c;

    .line 1653
    .line 1654
    iget-object v14, v1, Lh5/d;->L:Lh5/c;

    .line 1655
    .line 1656
    move/from16 v23, v0

    .line 1657
    .line 1658
    iget-object v0, v1, Lh5/d;->M:Lh5/c;

    .line 1659
    .line 1660
    move-object/from16 v22, v0

    .line 1661
    .line 1662
    move/from16 v18, v2

    .line 1663
    .line 1664
    move-object/from16 v17, v3

    .line 1665
    .line 1666
    move/from16 v24, v4

    .line 1667
    .line 1668
    move/from16 v25, v5

    .line 1669
    .line 1670
    move/from16 v26, v6

    .line 1671
    .line 1672
    move/from16 v27, v7

    .line 1673
    .line 1674
    move-object/from16 v19, v11

    .line 1675
    .line 1676
    move-object/from16 v20, v13

    .line 1677
    .line 1678
    move-object/from16 v21, v14

    .line 1679
    .line 1680
    invoke-virtual/range {v17 .. v27}, Lh5/f;->f(ILh5/c;Lh5/c;Lh5/c;Lh5/c;IIIII)V

    .line 1681
    .line 1682
    .line 1683
    move-object/from16 v0, v17

    .line 1684
    .line 1685
    :goto_37
    const/4 v2, 0x0

    .line 1686
    :goto_38
    if-ge v2, v15, :cond_70

    .line 1687
    .line 1688
    aget-object v3, v12, v2

    .line 1689
    .line 1690
    invoke-virtual {v0, v3}, Lh5/f;->a(Lh5/d;)V

    .line 1691
    .line 1692
    .line 1693
    add-int/lit8 v2, v2, 0x1

    .line 1694
    .line 1695
    goto :goto_38

    .line 1696
    :cond_70
    invoke-virtual {v0}, Lh5/f;->d()I

    .line 1697
    .line 1698
    .line 1699
    move-result v2

    .line 1700
    const/16 v28, 0x0

    .line 1701
    .line 1702
    aput v2, v35, v28

    .line 1703
    .line 1704
    invoke-virtual {v0}, Lh5/f;->c()I

    .line 1705
    .line 1706
    .line 1707
    move-result v0

    .line 1708
    const/16 v29, 0x1

    .line 1709
    .line 1710
    aput v0, v35, v29

    .line 1711
    .line 1712
    :goto_39
    aget v0, v35, v28

    .line 1713
    .line 1714
    add-int v0, v0, v31

    .line 1715
    .line 1716
    add-int v0, v0, v32

    .line 1717
    .line 1718
    aget v2, v35, v29

    .line 1719
    .line 1720
    add-int v2, v2, v33

    .line 1721
    .line 1722
    add-int v2, v2, v34

    .line 1723
    .line 1724
    const/high16 v3, -0x80000000

    .line 1725
    .line 1726
    const/high16 v4, 0x40000000    # 2.0f

    .line 1727
    .line 1728
    if-ne v8, v4, :cond_71

    .line 1729
    .line 1730
    move v0, v9

    .line 1731
    goto :goto_3a

    .line 1732
    :cond_71
    if-ne v8, v3, :cond_72

    .line 1733
    .line 1734
    invoke-static {v0, v9}, Ljava/lang/Math;->min(II)I

    .line 1735
    .line 1736
    .line 1737
    move-result v0

    .line 1738
    goto :goto_3a

    .line 1739
    :cond_72
    if-nez v8, :cond_73

    .line 1740
    .line 1741
    goto :goto_3a

    .line 1742
    :cond_73
    move/from16 v0, v28

    .line 1743
    .line 1744
    :goto_3a
    if-ne v10, v4, :cond_74

    .line 1745
    .line 1746
    move/from16 v2, p4

    .line 1747
    .line 1748
    goto :goto_3b

    .line 1749
    :cond_74
    if-ne v10, v3, :cond_75

    .line 1750
    .line 1751
    move/from16 v11, p4

    .line 1752
    .line 1753
    invoke-static {v2, v11}, Ljava/lang/Math;->min(II)I

    .line 1754
    .line 1755
    .line 1756
    move-result v2

    .line 1757
    goto :goto_3b

    .line 1758
    :cond_75
    if-nez v10, :cond_76

    .line 1759
    .line 1760
    goto :goto_3b

    .line 1761
    :cond_76
    move/from16 v2, v28

    .line 1762
    .line 1763
    :goto_3b
    iput v0, v1, Lh5/k;->A0:I

    .line 1764
    .line 1765
    iput v2, v1, Lh5/k;->B0:I

    .line 1766
    .line 1767
    invoke-virtual {v1, v0}, Lh5/d;->S(I)V

    .line 1768
    .line 1769
    .line 1770
    invoke-virtual {v1, v2}, Lh5/d;->N(I)V

    .line 1771
    .line 1772
    .line 1773
    iget v0, v1, Lh5/i;->s0:I

    .line 1774
    .line 1775
    if-lez v0, :cond_77

    .line 1776
    .line 1777
    move/from16 v14, v29

    .line 1778
    .line 1779
    goto :goto_3c

    .line 1780
    :cond_77
    move/from16 v14, v28

    .line 1781
    .line 1782
    :goto_3c
    iput-boolean v14, v1, Lh5/k;->z0:Z

    .line 1783
    .line 1784
    return-void
.end method

.method public final a0(Lh5/d;I)I
    .locals 10

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p1, :cond_0

    .line 3
    .line 4
    goto :goto_0

    .line 5
    :cond_0
    iget-object v1, p1, Lh5/d;->q0:[I

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    aget v3, v1, v2

    .line 9
    .line 10
    const/4 v4, 0x3

    .line 11
    if-ne v3, v4, :cond_5

    .line 12
    .line 13
    iget v3, p1, Lh5/d;->t:I

    .line 14
    .line 15
    if-nez v3, :cond_1

    .line 16
    .line 17
    :goto_0
    return v0

    .line 18
    :cond_1
    const/4 v5, 0x2

    .line 19
    if-ne v3, v5, :cond_3

    .line 20
    .line 21
    iget v3, p1, Lh5/d;->A:F

    .line 22
    .line 23
    int-to-float p2, p2

    .line 24
    mul-float/2addr v3, p2

    .line 25
    float-to-int v8, v3

    .line 26
    invoke-virtual {p1}, Lh5/d;->l()I

    .line 27
    .line 28
    .line 29
    move-result p2

    .line 30
    if-eq v8, p2, :cond_2

    .line 31
    .line 32
    iput-boolean v2, p1, Lh5/d;->g:Z

    .line 33
    .line 34
    aget v5, v1, v0

    .line 35
    .line 36
    invoke-virtual {p1}, Lh5/d;->r()I

    .line 37
    .line 38
    .line 39
    move-result v6

    .line 40
    const/4 v7, 0x1

    .line 41
    move-object v4, p0

    .line 42
    move-object v9, p1

    .line 43
    invoke-virtual/range {v4 .. v9}, Lh5/k;->Z(IIIILh5/d;)V

    .line 44
    .line 45
    .line 46
    :cond_2
    return v8

    .line 47
    :cond_3
    move-object v9, p1

    .line 48
    if-ne v3, v2, :cond_4

    .line 49
    .line 50
    invoke-virtual {v9}, Lh5/d;->l()I

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    return p0

    .line 55
    :cond_4
    if-ne v3, v4, :cond_6

    .line 56
    .line 57
    invoke-virtual {v9}, Lh5/d;->r()I

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    int-to-float p0, p0

    .line 62
    iget p1, v9, Lh5/d;->X:F

    .line 63
    .line 64
    mul-float/2addr p0, p1

    .line 65
    const/high16 p1, 0x3f000000    # 0.5f

    .line 66
    .line 67
    add-float/2addr p0, p1

    .line 68
    float-to-int p0, p0

    .line 69
    return p0

    .line 70
    :cond_5
    move-object v9, p1

    .line 71
    :cond_6
    invoke-virtual {v9}, Lh5/d;->l()I

    .line 72
    .line 73
    .line 74
    move-result p0

    .line 75
    return p0
.end method

.method public final b0(Lh5/d;I)I
    .locals 11

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p1, :cond_0

    .line 3
    .line 4
    goto :goto_0

    .line 5
    :cond_0
    iget-object v1, p1, Lh5/d;->q0:[I

    .line 6
    .line 7
    aget v2, v1, v0

    .line 8
    .line 9
    const/4 v3, 0x3

    .line 10
    if-ne v2, v3, :cond_5

    .line 11
    .line 12
    iget v2, p1, Lh5/d;->s:I

    .line 13
    .line 14
    if-nez v2, :cond_1

    .line 15
    .line 16
    :goto_0
    return v0

    .line 17
    :cond_1
    const/4 v0, 0x2

    .line 18
    const/4 v4, 0x1

    .line 19
    if-ne v2, v0, :cond_3

    .line 20
    .line 21
    iget v0, p1, Lh5/d;->x:F

    .line 22
    .line 23
    int-to-float p2, p2

    .line 24
    mul-float/2addr v0, p2

    .line 25
    float-to-int v7, v0

    .line 26
    invoke-virtual {p1}, Lh5/d;->r()I

    .line 27
    .line 28
    .line 29
    move-result p2

    .line 30
    if-eq v7, p2, :cond_2

    .line 31
    .line 32
    iput-boolean v4, p1, Lh5/d;->g:Z

    .line 33
    .line 34
    aget v8, v1, v4

    .line 35
    .line 36
    invoke-virtual {p1}, Lh5/d;->l()I

    .line 37
    .line 38
    .line 39
    move-result v9

    .line 40
    const/4 v6, 0x1

    .line 41
    move-object v5, p0

    .line 42
    move-object v10, p1

    .line 43
    invoke-virtual/range {v5 .. v10}, Lh5/k;->Z(IIIILh5/d;)V

    .line 44
    .line 45
    .line 46
    :cond_2
    return v7

    .line 47
    :cond_3
    move-object v10, p1

    .line 48
    if-ne v2, v4, :cond_4

    .line 49
    .line 50
    invoke-virtual {v10}, Lh5/d;->r()I

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    return p0

    .line 55
    :cond_4
    if-ne v2, v3, :cond_6

    .line 56
    .line 57
    invoke-virtual {v10}, Lh5/d;->l()I

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    int-to-float p0, p0

    .line 62
    iget p1, v10, Lh5/d;->X:F

    .line 63
    .line 64
    mul-float/2addr p0, p1

    .line 65
    const/high16 p1, 0x3f000000    # 0.5f

    .line 66
    .line 67
    add-float/2addr p0, p1

    .line 68
    float-to-int p0, p0

    .line 69
    return p0

    .line 70
    :cond_5
    move-object v10, p1

    .line 71
    :cond_6
    invoke-virtual {v10}, Lh5/d;->r()I

    .line 72
    .line 73
    .line 74
    move-result p0

    .line 75
    return p0
.end method

.method public final c(La5/c;Z)V
    .locals 11

    .line 1
    invoke-super {p0, p1, p2}, Lh5/d;->c(La5/c;Z)V

    .line 2
    .line 3
    .line 4
    iget-object p1, p0, Lh5/d;->U:Lh5/e;

    .line 5
    .line 6
    const/4 p2, 0x0

    .line 7
    const/4 v0, 0x1

    .line 8
    if-eqz p1, :cond_0

    .line 9
    .line 10
    iget-boolean p1, p1, Lh5/e;->w0:Z

    .line 11
    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    move p1, v0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move p1, p2

    .line 17
    :goto_0
    iget v1, p0, Lh5/g;->U0:I

    .line 18
    .line 19
    iget-object v2, p0, Lh5/g;->X0:Ljava/util/ArrayList;

    .line 20
    .line 21
    if-eqz v1, :cond_1b

    .line 22
    .line 23
    if-eq v1, v0, :cond_19

    .line 24
    .line 25
    const/4 v3, 0x2

    .line 26
    if-eq v1, v3, :cond_3

    .line 27
    .line 28
    const/4 v3, 0x3

    .line 29
    if-eq v1, v3, :cond_1

    .line 30
    .line 31
    goto/16 :goto_e

    .line 32
    .line 33
    :cond_1
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    move v3, p2

    .line 38
    :goto_1
    if-ge v3, v1, :cond_1c

    .line 39
    .line 40
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v4

    .line 44
    check-cast v4, Lh5/f;

    .line 45
    .line 46
    add-int/lit8 v5, v1, -0x1

    .line 47
    .line 48
    if-ne v3, v5, :cond_2

    .line 49
    .line 50
    move v5, v0

    .line 51
    goto :goto_2

    .line 52
    :cond_2
    move v5, p2

    .line 53
    :goto_2
    invoke-virtual {v4, v3, p1, v5}, Lh5/f;->b(IZZ)V

    .line 54
    .line 55
    .line 56
    add-int/lit8 v3, v3, 0x1

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_3
    iget-object v1, p0, Lh5/g;->a1:[I

    .line 60
    .line 61
    if-eqz v1, :cond_1c

    .line 62
    .line 63
    iget-object v1, p0, Lh5/g;->Z0:[Lh5/d;

    .line 64
    .line 65
    if-eqz v1, :cond_1c

    .line 66
    .line 67
    iget-object v1, p0, Lh5/g;->Y0:[Lh5/d;

    .line 68
    .line 69
    if-nez v1, :cond_4

    .line 70
    .line 71
    goto/16 :goto_e

    .line 72
    .line 73
    :cond_4
    move v1, p2

    .line 74
    :goto_3
    iget v2, p0, Lh5/g;->c1:I

    .line 75
    .line 76
    if-ge v1, v2, :cond_5

    .line 77
    .line 78
    iget-object v2, p0, Lh5/g;->b1:[Lh5/d;

    .line 79
    .line 80
    aget-object v2, v2, v1

    .line 81
    .line 82
    invoke-virtual {v2}, Lh5/d;->E()V

    .line 83
    .line 84
    .line 85
    add-int/lit8 v1, v1, 0x1

    .line 86
    .line 87
    goto :goto_3

    .line 88
    :cond_5
    iget-object v1, p0, Lh5/g;->a1:[I

    .line 89
    .line 90
    aget v2, v1, p2

    .line 91
    .line 92
    aget v1, v1, v0

    .line 93
    .line 94
    iget v3, p0, Lh5/g;->K0:F

    .line 95
    .line 96
    const/4 v4, 0x0

    .line 97
    move v5, p2

    .line 98
    :goto_4
    const/16 v6, 0x8

    .line 99
    .line 100
    if-ge v5, v2, :cond_c

    .line 101
    .line 102
    if-eqz p1, :cond_6

    .line 103
    .line 104
    sub-int v3, v2, v5

    .line 105
    .line 106
    sub-int/2addr v3, v0

    .line 107
    const/high16 v7, 0x3f800000    # 1.0f

    .line 108
    .line 109
    iget v8, p0, Lh5/g;->K0:F

    .line 110
    .line 111
    sub-float/2addr v7, v8

    .line 112
    goto :goto_5

    .line 113
    :cond_6
    move v7, v3

    .line 114
    move v3, v5

    .line 115
    :goto_5
    iget-object v8, p0, Lh5/g;->Z0:[Lh5/d;

    .line 116
    .line 117
    aget-object v3, v8, v3

    .line 118
    .line 119
    if-eqz v3, :cond_b

    .line 120
    .line 121
    iget-object v8, v3, Lh5/d;->J:Lh5/c;

    .line 122
    .line 123
    iget v9, v3, Lh5/d;->h0:I

    .line 124
    .line 125
    if-ne v9, v6, :cond_7

    .line 126
    .line 127
    goto :goto_6

    .line 128
    :cond_7
    if-nez v5, :cond_8

    .line 129
    .line 130
    iget-object v6, p0, Lh5/d;->J:Lh5/c;

    .line 131
    .line 132
    iget v9, p0, Lh5/k;->x0:I

    .line 133
    .line 134
    invoke-virtual {v3, v8, v6, v9}, Lh5/d;->g(Lh5/c;Lh5/c;I)V

    .line 135
    .line 136
    .line 137
    iget v6, p0, Lh5/g;->E0:I

    .line 138
    .line 139
    iput v6, v3, Lh5/d;->j0:I

    .line 140
    .line 141
    iput v7, v3, Lh5/d;->e0:F

    .line 142
    .line 143
    :cond_8
    add-int/lit8 v6, v2, -0x1

    .line 144
    .line 145
    if-ne v5, v6, :cond_9

    .line 146
    .line 147
    iget-object v6, v3, Lh5/d;->L:Lh5/c;

    .line 148
    .line 149
    iget-object v9, p0, Lh5/d;->L:Lh5/c;

    .line 150
    .line 151
    iget v10, p0, Lh5/k;->y0:I

    .line 152
    .line 153
    invoke-virtual {v3, v6, v9, v10}, Lh5/d;->g(Lh5/c;Lh5/c;I)V

    .line 154
    .line 155
    .line 156
    :cond_9
    if-lez v5, :cond_a

    .line 157
    .line 158
    if-eqz v4, :cond_a

    .line 159
    .line 160
    iget-object v6, v4, Lh5/d;->L:Lh5/c;

    .line 161
    .line 162
    iget v9, p0, Lh5/g;->Q0:I

    .line 163
    .line 164
    invoke-virtual {v3, v8, v6, v9}, Lh5/d;->g(Lh5/c;Lh5/c;I)V

    .line 165
    .line 166
    .line 167
    invoke-virtual {v4, v6, v8, p2}, Lh5/d;->g(Lh5/c;Lh5/c;I)V

    .line 168
    .line 169
    .line 170
    :cond_a
    move-object v4, v3

    .line 171
    :cond_b
    :goto_6
    add-int/lit8 v5, v5, 0x1

    .line 172
    .line 173
    move v3, v7

    .line 174
    goto :goto_4

    .line 175
    :cond_c
    move p1, p2

    .line 176
    :goto_7
    if-ge p1, v1, :cond_12

    .line 177
    .line 178
    iget-object v3, p0, Lh5/g;->Y0:[Lh5/d;

    .line 179
    .line 180
    aget-object v3, v3, p1

    .line 181
    .line 182
    if-eqz v3, :cond_11

    .line 183
    .line 184
    iget-object v5, v3, Lh5/d;->K:Lh5/c;

    .line 185
    .line 186
    iget v7, v3, Lh5/d;->h0:I

    .line 187
    .line 188
    if-ne v7, v6, :cond_d

    .line 189
    .line 190
    goto :goto_8

    .line 191
    :cond_d
    if-nez p1, :cond_e

    .line 192
    .line 193
    iget-object v7, p0, Lh5/d;->K:Lh5/c;

    .line 194
    .line 195
    iget v8, p0, Lh5/k;->t0:I

    .line 196
    .line 197
    invoke-virtual {v3, v5, v7, v8}, Lh5/d;->g(Lh5/c;Lh5/c;I)V

    .line 198
    .line 199
    .line 200
    iget v7, p0, Lh5/g;->F0:I

    .line 201
    .line 202
    iput v7, v3, Lh5/d;->k0:I

    .line 203
    .line 204
    iget v7, p0, Lh5/g;->L0:F

    .line 205
    .line 206
    iput v7, v3, Lh5/d;->f0:F

    .line 207
    .line 208
    :cond_e
    add-int/lit8 v7, v1, -0x1

    .line 209
    .line 210
    if-ne p1, v7, :cond_f

    .line 211
    .line 212
    iget-object v7, v3, Lh5/d;->M:Lh5/c;

    .line 213
    .line 214
    iget-object v8, p0, Lh5/d;->M:Lh5/c;

    .line 215
    .line 216
    iget v9, p0, Lh5/k;->u0:I

    .line 217
    .line 218
    invoke-virtual {v3, v7, v8, v9}, Lh5/d;->g(Lh5/c;Lh5/c;I)V

    .line 219
    .line 220
    .line 221
    :cond_f
    if-lez p1, :cond_10

    .line 222
    .line 223
    if-eqz v4, :cond_10

    .line 224
    .line 225
    iget-object v7, v4, Lh5/d;->M:Lh5/c;

    .line 226
    .line 227
    iget v8, p0, Lh5/g;->R0:I

    .line 228
    .line 229
    invoke-virtual {v3, v5, v7, v8}, Lh5/d;->g(Lh5/c;Lh5/c;I)V

    .line 230
    .line 231
    .line 232
    invoke-virtual {v4, v7, v5, p2}, Lh5/d;->g(Lh5/c;Lh5/c;I)V

    .line 233
    .line 234
    .line 235
    :cond_10
    move-object v4, v3

    .line 236
    :cond_11
    :goto_8
    add-int/lit8 p1, p1, 0x1

    .line 237
    .line 238
    goto :goto_7

    .line 239
    :cond_12
    move p1, p2

    .line 240
    :goto_9
    if-ge p1, v2, :cond_1c

    .line 241
    .line 242
    move v3, p2

    .line 243
    :goto_a
    if-ge v3, v1, :cond_18

    .line 244
    .line 245
    mul-int v4, v3, v2

    .line 246
    .line 247
    add-int/2addr v4, p1

    .line 248
    iget v5, p0, Lh5/g;->W0:I

    .line 249
    .line 250
    if-ne v5, v0, :cond_13

    .line 251
    .line 252
    mul-int v4, p1, v1

    .line 253
    .line 254
    add-int/2addr v4, v3

    .line 255
    :cond_13
    iget-object v5, p0, Lh5/g;->b1:[Lh5/d;

    .line 256
    .line 257
    array-length v7, v5

    .line 258
    if-lt v4, v7, :cond_14

    .line 259
    .line 260
    goto :goto_b

    .line 261
    :cond_14
    aget-object v4, v5, v4

    .line 262
    .line 263
    if-eqz v4, :cond_17

    .line 264
    .line 265
    iget v5, v4, Lh5/d;->h0:I

    .line 266
    .line 267
    if-ne v5, v6, :cond_15

    .line 268
    .line 269
    goto :goto_b

    .line 270
    :cond_15
    iget-object v5, p0, Lh5/g;->Z0:[Lh5/d;

    .line 271
    .line 272
    aget-object v5, v5, p1

    .line 273
    .line 274
    iget-object v7, p0, Lh5/g;->Y0:[Lh5/d;

    .line 275
    .line 276
    aget-object v7, v7, v3

    .line 277
    .line 278
    if-eq v4, v5, :cond_16

    .line 279
    .line 280
    iget-object v8, v4, Lh5/d;->J:Lh5/c;

    .line 281
    .line 282
    iget-object v9, v5, Lh5/d;->J:Lh5/c;

    .line 283
    .line 284
    invoke-virtual {v4, v8, v9, p2}, Lh5/d;->g(Lh5/c;Lh5/c;I)V

    .line 285
    .line 286
    .line 287
    iget-object v8, v4, Lh5/d;->L:Lh5/c;

    .line 288
    .line 289
    iget-object v5, v5, Lh5/d;->L:Lh5/c;

    .line 290
    .line 291
    invoke-virtual {v4, v8, v5, p2}, Lh5/d;->g(Lh5/c;Lh5/c;I)V

    .line 292
    .line 293
    .line 294
    :cond_16
    if-eq v4, v7, :cond_17

    .line 295
    .line 296
    iget-object v5, v4, Lh5/d;->K:Lh5/c;

    .line 297
    .line 298
    iget-object v8, v7, Lh5/d;->K:Lh5/c;

    .line 299
    .line 300
    invoke-virtual {v4, v5, v8, p2}, Lh5/d;->g(Lh5/c;Lh5/c;I)V

    .line 301
    .line 302
    .line 303
    iget-object v5, v4, Lh5/d;->M:Lh5/c;

    .line 304
    .line 305
    iget-object v7, v7, Lh5/d;->M:Lh5/c;

    .line 306
    .line 307
    invoke-virtual {v4, v5, v7, p2}, Lh5/d;->g(Lh5/c;Lh5/c;I)V

    .line 308
    .line 309
    .line 310
    :cond_17
    :goto_b
    add-int/lit8 v3, v3, 0x1

    .line 311
    .line 312
    goto :goto_a

    .line 313
    :cond_18
    add-int/lit8 p1, p1, 0x1

    .line 314
    .line 315
    goto :goto_9

    .line 316
    :cond_19
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 317
    .line 318
    .line 319
    move-result v1

    .line 320
    move v3, p2

    .line 321
    :goto_c
    if-ge v3, v1, :cond_1c

    .line 322
    .line 323
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 324
    .line 325
    .line 326
    move-result-object v4

    .line 327
    check-cast v4, Lh5/f;

    .line 328
    .line 329
    add-int/lit8 v5, v1, -0x1

    .line 330
    .line 331
    if-ne v3, v5, :cond_1a

    .line 332
    .line 333
    move v5, v0

    .line 334
    goto :goto_d

    .line 335
    :cond_1a
    move v5, p2

    .line 336
    :goto_d
    invoke-virtual {v4, v3, p1, v5}, Lh5/f;->b(IZZ)V

    .line 337
    .line 338
    .line 339
    add-int/lit8 v3, v3, 0x1

    .line 340
    .line 341
    goto :goto_c

    .line 342
    :cond_1b
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 343
    .line 344
    .line 345
    move-result v1

    .line 346
    if-lez v1, :cond_1c

    .line 347
    .line 348
    invoke-virtual {v2, p2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 349
    .line 350
    .line 351
    move-result-object v1

    .line 352
    check-cast v1, Lh5/f;

    .line 353
    .line 354
    invoke-virtual {v1, p2, p1, v0}, Lh5/f;->b(IZZ)V

    .line 355
    .line 356
    .line 357
    :cond_1c
    :goto_e
    iput-boolean p2, p0, Lh5/k;->z0:Z

    .line 358
    .line 359
    return-void
.end method
