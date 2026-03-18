.class public final synthetic Lh2/d7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Lh2/e7;

.field public final synthetic e:I

.field public final synthetic f:I

.field public final synthetic g:Lt3/e1;

.field public final synthetic h:Lt3/e1;

.field public final synthetic i:Lt3/e1;

.field public final synthetic j:Lt3/e1;

.field public final synthetic k:Lt3/e1;

.field public final synthetic l:Lkotlin/jvm/internal/f0;

.field public final synthetic m:Lt3/e1;

.field public final synthetic n:Lt3/e1;

.field public final synthetic o:Lt3/e1;

.field public final synthetic p:Lt3/s0;

.field public final synthetic q:F


# direct methods
.method public synthetic constructor <init>(Lh2/e7;IILt3/e1;Lt3/e1;Lt3/e1;Lt3/e1;Lt3/e1;Lkotlin/jvm/internal/f0;Lt3/e1;Lt3/e1;Lt3/e1;Lt3/s0;F)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/d7;->d:Lh2/e7;

    .line 5
    .line 6
    iput p2, p0, Lh2/d7;->e:I

    .line 7
    .line 8
    iput p3, p0, Lh2/d7;->f:I

    .line 9
    .line 10
    iput-object p4, p0, Lh2/d7;->g:Lt3/e1;

    .line 11
    .line 12
    iput-object p5, p0, Lh2/d7;->h:Lt3/e1;

    .line 13
    .line 14
    iput-object p6, p0, Lh2/d7;->i:Lt3/e1;

    .line 15
    .line 16
    iput-object p7, p0, Lh2/d7;->j:Lt3/e1;

    .line 17
    .line 18
    iput-object p8, p0, Lh2/d7;->k:Lt3/e1;

    .line 19
    .line 20
    iput-object p9, p0, Lh2/d7;->l:Lkotlin/jvm/internal/f0;

    .line 21
    .line 22
    iput-object p10, p0, Lh2/d7;->m:Lt3/e1;

    .line 23
    .line 24
    iput-object p11, p0, Lh2/d7;->n:Lt3/e1;

    .line 25
    .line 26
    iput-object p12, p0, Lh2/d7;->o:Lt3/e1;

    .line 27
    .line 28
    iput-object p13, p0, Lh2/d7;->p:Lt3/s0;

    .line 29
    .line 30
    iput p14, p0, Lh2/d7;->q:F

    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lt3/d1;

    .line 6
    .line 7
    iget-object v2, v0, Lh2/d7;->l:Lkotlin/jvm/internal/f0;

    .line 8
    .line 9
    iget-object v2, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 10
    .line 11
    move-object v7, v2

    .line 12
    check-cast v7, Lt3/e1;

    .line 13
    .line 14
    iget-object v2, v0, Lh2/d7;->p:Lt3/s0;

    .line 15
    .line 16
    invoke-interface {v2}, Lt4/c;->a()F

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    invoke-interface {v2}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 21
    .line 22
    .line 23
    move-result-object v4

    .line 24
    iget-object v5, v0, Lh2/d7;->d:Lh2/e7;

    .line 25
    .line 26
    iget v6, v5, Lh2/e7;->f:F

    .line 27
    .line 28
    invoke-interface {v2, v6}, Lt4/c;->w0(F)F

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    iget-object v6, v5, Lh2/e7;->c:Lh2/nb;

    .line 33
    .line 34
    iget-object v8, v5, Lh2/e7;->e:Lk1/z0;

    .line 35
    .line 36
    iget-object v9, v0, Lh2/d7;->n:Lt3/e1;

    .line 37
    .line 38
    const/4 v10, 0x0

    .line 39
    move v11, v3

    .line 40
    const/4 v3, 0x0

    .line 41
    invoke-static {v1, v9, v10, v3}, Lt3/d1;->h(Lt3/d1;Lt3/e1;II)V

    .line 42
    .line 43
    .line 44
    iget-object v9, v0, Lh2/d7;->o:Lt3/e1;

    .line 45
    .line 46
    if-eqz v9, :cond_0

    .line 47
    .line 48
    iget v12, v9, Lt3/e1;->e:I

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_0
    move v12, v10

    .line 52
    :goto_0
    iget v13, v0, Lh2/d7;->e:I

    .line 53
    .line 54
    sub-int/2addr v13, v12

    .line 55
    invoke-interface {v8}, Lk1/z0;->d()F

    .line 56
    .line 57
    .line 58
    move-result v12

    .line 59
    mul-float/2addr v12, v11

    .line 60
    invoke-static {v12}, Lcy0/a;->i(F)I

    .line 61
    .line 62
    .line 63
    move-result v12

    .line 64
    iget-object v14, v0, Lh2/d7;->g:Lt3/e1;

    .line 65
    .line 66
    const/4 v15, 0x1

    .line 67
    const/high16 v16, 0x40000000    # 2.0f

    .line 68
    .line 69
    const/16 v17, 0x0

    .line 70
    .line 71
    if-eqz v14, :cond_1

    .line 72
    .line 73
    iget v3, v14, Lt3/e1;->e:I

    .line 74
    .line 75
    sub-int v3, v13, v3

    .line 76
    .line 77
    int-to-float v3, v3

    .line 78
    div-float v3, v3, v16

    .line 79
    .line 80
    int-to-float v10, v15

    .line 81
    add-float v10, v10, v17

    .line 82
    .line 83
    mul-float/2addr v10, v3

    .line 84
    invoke-static {v10}, Ljava/lang/Math;->round(F)I

    .line 85
    .line 86
    .line 87
    move-result v3

    .line 88
    const/4 v10, 0x0

    .line 89
    invoke-static {v1, v14, v10, v3}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 90
    .line 91
    .line 92
    :cond_1
    iget v10, v0, Lh2/d7;->f:I

    .line 93
    .line 94
    iget-object v3, v0, Lh2/d7;->h:Lt3/e1;

    .line 95
    .line 96
    if-eqz v7, :cond_9

    .line 97
    .line 98
    iget-boolean v15, v5, Lh2/e7;->b:Z

    .line 99
    .line 100
    if-eqz v15, :cond_2

    .line 101
    .line 102
    iget v15, v7, Lt3/e1;->e:I

    .line 103
    .line 104
    sub-int v15, v13, v15

    .line 105
    .line 106
    int-to-float v15, v15

    .line 107
    div-float v15, v15, v16

    .line 108
    .line 109
    move/from16 v18, v2

    .line 110
    .line 111
    move-object/from16 v19, v5

    .line 112
    .line 113
    const/4 v2, 0x1

    .line 114
    int-to-float v5, v2

    .line 115
    add-float v5, v5, v17

    .line 116
    .line 117
    mul-float/2addr v5, v15

    .line 118
    invoke-static {v5}, Ljava/lang/Math;->round(F)I

    .line 119
    .line 120
    .line 121
    move-result v2

    .line 122
    goto :goto_1

    .line 123
    :cond_2
    move/from16 v18, v2

    .line 124
    .line 125
    move-object/from16 v19, v5

    .line 126
    .line 127
    move v2, v12

    .line 128
    :goto_1
    iget v5, v7, Lt3/e1;->e:I

    .line 129
    .line 130
    div-int/lit8 v5, v5, 0x2

    .line 131
    .line 132
    neg-int v5, v5

    .line 133
    iget v15, v0, Lh2/d7;->q:F

    .line 134
    .line 135
    invoke-static {v15, v2, v5}, Llp/wa;->c(FII)I

    .line 136
    .line 137
    .line 138
    move-result v2

    .line 139
    invoke-static {v8, v4}, Landroidx/compose/foundation/layout/a;->f(Lk1/z0;Lt4/m;)F

    .line 140
    .line 141
    .line 142
    move-result v5

    .line 143
    mul-float/2addr v5, v11

    .line 144
    invoke-static {v8, v4}, Landroidx/compose/foundation/layout/a;->e(Lk1/z0;Lt4/m;)F

    .line 145
    .line 146
    .line 147
    move-result v8

    .line 148
    mul-float/2addr v8, v11

    .line 149
    if-nez v14, :cond_3

    .line 150
    .line 151
    move v11, v5

    .line 152
    goto :goto_2

    .line 153
    :cond_3
    iget v11, v14, Lt3/e1;->d:I

    .line 154
    .line 155
    int-to-float v11, v11

    .line 156
    sub-float v20, v5, v18

    .line 157
    .line 158
    cmpg-float v21, v20, v17

    .line 159
    .line 160
    if-gez v21, :cond_4

    .line 161
    .line 162
    move/from16 v20, v17

    .line 163
    .line 164
    :cond_4
    add-float v11, v11, v20

    .line 165
    .line 166
    :goto_2
    if-nez v3, :cond_5

    .line 167
    .line 168
    move/from16 v20, v5

    .line 169
    .line 170
    move v5, v8

    .line 171
    :goto_3
    move-object/from16 v18, v3

    .line 172
    .line 173
    goto :goto_4

    .line 174
    :cond_5
    move/from16 v20, v5

    .line 175
    .line 176
    iget v5, v3, Lt3/e1;->d:I

    .line 177
    .line 178
    int-to-float v5, v5

    .line 179
    sub-float v18, v8, v18

    .line 180
    .line 181
    cmpg-float v21, v18, v17

    .line 182
    .line 183
    if-gez v21, :cond_6

    .line 184
    .line 185
    move/from16 v18, v17

    .line 186
    .line 187
    :cond_6
    add-float v5, v5, v18

    .line 188
    .line 189
    goto :goto_3

    .line 190
    :goto_4
    sget-object v3, Lt4/m;->d:Lt4/m;

    .line 191
    .line 192
    if-ne v4, v3, :cond_7

    .line 193
    .line 194
    move/from16 v21, v20

    .line 195
    .line 196
    goto :goto_5

    .line 197
    :cond_7
    move/from16 v21, v8

    .line 198
    .line 199
    :goto_5
    if-ne v4, v3, :cond_8

    .line 200
    .line 201
    move v3, v11

    .line 202
    goto :goto_6

    .line 203
    :cond_8
    move v3, v5

    .line 204
    :goto_6
    sget v22, Li2/h1;->a:F

    .line 205
    .line 206
    move/from16 v22, v3

    .line 207
    .line 208
    iget-object v3, v6, Lh2/nb;->b:Lx2/h;

    .line 209
    .line 210
    move/from16 v23, v5

    .line 211
    .line 212
    iget v5, v7, Lt3/e1;->d:I

    .line 213
    .line 214
    add-float v11, v11, v23

    .line 215
    .line 216
    invoke-static {v11}, Lcy0/a;->i(F)I

    .line 217
    .line 218
    .line 219
    move-result v11

    .line 220
    sub-int v11, v10, v11

    .line 221
    .line 222
    invoke-virtual {v3, v5, v11, v4}, Lx2/h;->a(IILt4/m;)I

    .line 223
    .line 224
    .line 225
    move-result v3

    .line 226
    int-to-float v3, v3

    .line 227
    add-float v3, v3, v22

    .line 228
    .line 229
    invoke-static {v6}, Li2/h1;->c(Lh2/nb;)Lx2/d;

    .line 230
    .line 231
    .line 232
    move-result-object v5

    .line 233
    iget v6, v7, Lt3/e1;->d:I

    .line 234
    .line 235
    add-float v8, v20, v8

    .line 236
    .line 237
    invoke-static {v8}, Lcy0/a;->i(F)I

    .line 238
    .line 239
    .line 240
    move-result v8

    .line 241
    sub-int v8, v10, v8

    .line 242
    .line 243
    check-cast v5, Lx2/h;

    .line 244
    .line 245
    invoke-virtual {v5, v6, v8, v4}, Lx2/h;->a(IILt4/m;)I

    .line 246
    .line 247
    .line 248
    move-result v4

    .line 249
    int-to-float v4, v4

    .line 250
    add-float v4, v4, v21

    .line 251
    .line 252
    invoke-static {v3, v4, v15}, Llp/wa;->b(FFF)F

    .line 253
    .line 254
    .line 255
    move-result v3

    .line 256
    invoke-static {v3}, Lcy0/a;->i(F)I

    .line 257
    .line 258
    .line 259
    move-result v3

    .line 260
    move/from16 v4, v17

    .line 261
    .line 262
    invoke-virtual {v1, v7, v3, v2, v4}, Lt3/d1;->g(Lt3/e1;IIF)V

    .line 263
    .line 264
    .line 265
    goto :goto_7

    .line 266
    :cond_9
    move-object/from16 v18, v3

    .line 267
    .line 268
    move-object/from16 v19, v5

    .line 269
    .line 270
    move/from16 v4, v17

    .line 271
    .line 272
    :goto_7
    iget-object v8, v0, Lh2/d7;->i:Lt3/e1;

    .line 273
    .line 274
    if-eqz v8, :cond_b

    .line 275
    .line 276
    if-eqz v14, :cond_a

    .line 277
    .line 278
    iget v2, v14, Lt3/e1;->d:I

    .line 279
    .line 280
    :goto_8
    move/from16 v17, v4

    .line 281
    .line 282
    move v6, v12

    .line 283
    move v5, v13

    .line 284
    move-object/from16 v11, v18

    .line 285
    .line 286
    move-object/from16 v4, v19

    .line 287
    .line 288
    const/4 v3, 0x0

    .line 289
    goto :goto_9

    .line 290
    :cond_a
    const/4 v2, 0x0

    .line 291
    goto :goto_8

    .line 292
    :goto_9
    invoke-static/range {v3 .. v8}, Lh2/e7;->m(ILh2/e7;IILt3/e1;Lt3/e1;)I

    .line 293
    .line 294
    .line 295
    move-result v12

    .line 296
    invoke-static {v1, v8, v2, v12}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 297
    .line 298
    .line 299
    goto :goto_a

    .line 300
    :cond_b
    move/from16 v17, v4

    .line 301
    .line 302
    move v6, v12

    .line 303
    move v5, v13

    .line 304
    move-object/from16 v11, v18

    .line 305
    .line 306
    move-object/from16 v4, v19

    .line 307
    .line 308
    const/4 v3, 0x0

    .line 309
    :goto_a
    if-eqz v14, :cond_c

    .line 310
    .line 311
    iget v2, v14, Lt3/e1;->d:I

    .line 312
    .line 313
    goto :goto_b

    .line 314
    :cond_c
    const/4 v2, 0x0

    .line 315
    :goto_b
    if-eqz v8, :cond_d

    .line 316
    .line 317
    iget v8, v8, Lt3/e1;->d:I

    .line 318
    .line 319
    goto :goto_c

    .line 320
    :cond_d
    const/4 v8, 0x0

    .line 321
    :goto_c
    add-int/2addr v2, v8

    .line 322
    iget-object v8, v0, Lh2/d7;->k:Lt3/e1;

    .line 323
    .line 324
    invoke-static/range {v3 .. v8}, Lh2/e7;->m(ILh2/e7;IILt3/e1;Lt3/e1;)I

    .line 325
    .line 326
    .line 327
    move-result v12

    .line 328
    invoke-static {v1, v8, v2, v12}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 329
    .line 330
    .line 331
    iget-object v8, v0, Lh2/d7;->m:Lt3/e1;

    .line 332
    .line 333
    if-eqz v8, :cond_e

    .line 334
    .line 335
    invoke-static/range {v3 .. v8}, Lh2/e7;->m(ILh2/e7;IILt3/e1;Lt3/e1;)I

    .line 336
    .line 337
    .line 338
    move-result v12

    .line 339
    invoke-static {v1, v8, v2, v12}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 340
    .line 341
    .line 342
    :cond_e
    iget-object v8, v0, Lh2/d7;->j:Lt3/e1;

    .line 343
    .line 344
    if-eqz v8, :cond_10

    .line 345
    .line 346
    if-eqz v11, :cond_f

    .line 347
    .line 348
    iget v0, v11, Lt3/e1;->d:I

    .line 349
    .line 350
    goto :goto_d

    .line 351
    :cond_f
    const/4 v0, 0x0

    .line 352
    :goto_d
    sub-int v0, v10, v0

    .line 353
    .line 354
    iget v2, v8, Lt3/e1;->d:I

    .line 355
    .line 356
    sub-int/2addr v0, v2

    .line 357
    invoke-static/range {v3 .. v8}, Lh2/e7;->m(ILh2/e7;IILt3/e1;Lt3/e1;)I

    .line 358
    .line 359
    .line 360
    move-result v2

    .line 361
    invoke-static {v1, v8, v0, v2}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 362
    .line 363
    .line 364
    :cond_10
    if-eqz v11, :cond_11

    .line 365
    .line 366
    iget v0, v11, Lt3/e1;->d:I

    .line 367
    .line 368
    sub-int/2addr v10, v0

    .line 369
    iget v0, v11, Lt3/e1;->e:I

    .line 370
    .line 371
    sub-int v13, v5, v0

    .line 372
    .line 373
    int-to-float v0, v13

    .line 374
    div-float v0, v0, v16

    .line 375
    .line 376
    const/4 v2, 0x1

    .line 377
    int-to-float v2, v2

    .line 378
    add-float v2, v2, v17

    .line 379
    .line 380
    mul-float/2addr v2, v0

    .line 381
    invoke-static {v2}, Ljava/lang/Math;->round(F)I

    .line 382
    .line 383
    .line 384
    move-result v0

    .line 385
    invoke-static {v1, v11, v10, v0}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 386
    .line 387
    .line 388
    :cond_11
    if-eqz v9, :cond_12

    .line 389
    .line 390
    const/4 v10, 0x0

    .line 391
    invoke-static {v1, v9, v10, v5}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 392
    .line 393
    .line 394
    :cond_12
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 395
    .line 396
    return-object v0
.end method
