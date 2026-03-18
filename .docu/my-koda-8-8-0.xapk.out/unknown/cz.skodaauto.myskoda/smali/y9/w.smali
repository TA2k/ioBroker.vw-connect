.class public final Ly9/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public A:Z

.field public B:Z

.field public C:Z

.field public final a:Ly9/r;

.field public final b:Landroid/view/View;

.field public final c:Landroid/view/ViewGroup;

.field public final d:Landroid/view/ViewGroup;

.field public final e:Landroid/view/ViewGroup;

.field public final f:Landroid/view/ViewGroup;

.field public final g:Landroid/view/ViewGroup;

.field public final h:Landroid/view/ViewGroup;

.field public final i:Landroid/view/ViewGroup;

.field public final j:Landroid/view/View;

.field public final k:Landroid/view/View;

.field public final l:Landroid/animation/AnimatorSet;

.field public final m:Landroid/animation/AnimatorSet;

.field public final n:Landroid/animation/AnimatorSet;

.field public final o:Landroid/animation/AnimatorSet;

.field public final p:Landroid/animation/AnimatorSet;

.field public final q:Landroid/animation/ValueAnimator;

.field public final r:Landroid/animation/ValueAnimator;

.field public final s:Ly9/s;

.field public final t:Ly9/s;

.field public final u:Ly9/s;

.field public final v:Ly9/s;

.field public final w:Ly9/s;

.field public final x:Lkq/a;

.field public final y:Ljava/util/ArrayList;

.field public z:I


# direct methods
.method public constructor <init>(Ly9/r;)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    iput-object v1, v0, Ly9/w;->a:Ly9/r;

    .line 9
    .line 10
    new-instance v2, Ly9/s;

    .line 11
    .line 12
    const/4 v3, 0x0

    .line 13
    invoke-direct {v2, v0, v3}, Ly9/s;-><init>(Ly9/w;I)V

    .line 14
    .line 15
    .line 16
    iput-object v2, v0, Ly9/w;->s:Ly9/s;

    .line 17
    .line 18
    new-instance v2, Ly9/s;

    .line 19
    .line 20
    const/4 v4, 0x3

    .line 21
    invoke-direct {v2, v0, v4}, Ly9/s;-><init>(Ly9/w;I)V

    .line 22
    .line 23
    .line 24
    iput-object v2, v0, Ly9/w;->t:Ly9/s;

    .line 25
    .line 26
    new-instance v2, Ly9/s;

    .line 27
    .line 28
    const/4 v5, 0x4

    .line 29
    invoke-direct {v2, v0, v5}, Ly9/s;-><init>(Ly9/w;I)V

    .line 30
    .line 31
    .line 32
    iput-object v2, v0, Ly9/w;->u:Ly9/s;

    .line 33
    .line 34
    new-instance v2, Ly9/s;

    .line 35
    .line 36
    const/4 v6, 0x5

    .line 37
    invoke-direct {v2, v0, v6}, Ly9/s;-><init>(Ly9/w;I)V

    .line 38
    .line 39
    .line 40
    iput-object v2, v0, Ly9/w;->v:Ly9/s;

    .line 41
    .line 42
    new-instance v2, Ly9/s;

    .line 43
    .line 44
    const/4 v7, 0x6

    .line 45
    invoke-direct {v2, v0, v7}, Ly9/s;-><init>(Ly9/w;I)V

    .line 46
    .line 47
    .line 48
    iput-object v2, v0, Ly9/w;->w:Ly9/s;

    .line 49
    .line 50
    new-instance v2, Lkq/a;

    .line 51
    .line 52
    invoke-direct {v2, v0, v5}, Lkq/a;-><init>(Ljava/lang/Object;I)V

    .line 53
    .line 54
    .line 55
    iput-object v2, v0, Ly9/w;->x:Lkq/a;

    .line 56
    .line 57
    const/4 v2, 0x1

    .line 58
    iput-boolean v2, v0, Ly9/w;->C:Z

    .line 59
    .line 60
    iput v3, v0, Ly9/w;->z:I

    .line 61
    .line 62
    new-instance v7, Ljava/util/ArrayList;

    .line 63
    .line 64
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 65
    .line 66
    .line 67
    iput-object v7, v0, Ly9/w;->y:Ljava/util/ArrayList;

    .line 68
    .line 69
    const v7, 0x7f0a0138

    .line 70
    .line 71
    .line 72
    invoke-virtual {v1, v7}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 73
    .line 74
    .line 75
    move-result-object v7

    .line 76
    iput-object v7, v0, Ly9/w;->b:Landroid/view/View;

    .line 77
    .line 78
    const v7, 0x7f0a0133

    .line 79
    .line 80
    .line 81
    invoke-virtual {v1, v7}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 82
    .line 83
    .line 84
    move-result-object v7

    .line 85
    check-cast v7, Landroid/view/ViewGroup;

    .line 86
    .line 87
    iput-object v7, v0, Ly9/w;->c:Landroid/view/ViewGroup;

    .line 88
    .line 89
    const v7, 0x7f0a0143

    .line 90
    .line 91
    .line 92
    invoke-virtual {v1, v7}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 93
    .line 94
    .line 95
    move-result-object v7

    .line 96
    check-cast v7, Landroid/view/ViewGroup;

    .line 97
    .line 98
    iput-object v7, v0, Ly9/w;->e:Landroid/view/ViewGroup;

    .line 99
    .line 100
    const v7, 0x7f0a0131

    .line 101
    .line 102
    .line 103
    invoke-virtual {v1, v7}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 104
    .line 105
    .line 106
    move-result-object v7

    .line 107
    check-cast v7, Landroid/view/ViewGroup;

    .line 108
    .line 109
    iput-object v7, v0, Ly9/w;->d:Landroid/view/ViewGroup;

    .line 110
    .line 111
    const v8, 0x7f0a015c

    .line 112
    .line 113
    .line 114
    invoke-virtual {v1, v8}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 115
    .line 116
    .line 117
    move-result-object v8

    .line 118
    check-cast v8, Landroid/view/ViewGroup;

    .line 119
    .line 120
    iput-object v8, v0, Ly9/w;->i:Landroid/view/ViewGroup;

    .line 121
    .line 122
    const v8, 0x7f0a014f

    .line 123
    .line 124
    .line 125
    invoke-virtual {v1, v8}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 126
    .line 127
    .line 128
    move-result-object v8

    .line 129
    iput-object v8, v0, Ly9/w;->j:Landroid/view/View;

    .line 130
    .line 131
    const v9, 0x7f0a0130

    .line 132
    .line 133
    .line 134
    invoke-virtual {v1, v9}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 135
    .line 136
    .line 137
    move-result-object v9

    .line 138
    check-cast v9, Landroid/view/ViewGroup;

    .line 139
    .line 140
    iput-object v9, v0, Ly9/w;->f:Landroid/view/ViewGroup;

    .line 141
    .line 142
    const v9, 0x7f0a013b

    .line 143
    .line 144
    .line 145
    invoke-virtual {v1, v9}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 146
    .line 147
    .line 148
    move-result-object v9

    .line 149
    check-cast v9, Landroid/view/ViewGroup;

    .line 150
    .line 151
    iput-object v9, v0, Ly9/w;->g:Landroid/view/ViewGroup;

    .line 152
    .line 153
    const v9, 0x7f0a013c

    .line 154
    .line 155
    .line 156
    invoke-virtual {v1, v9}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 157
    .line 158
    .line 159
    move-result-object v9

    .line 160
    check-cast v9, Landroid/view/ViewGroup;

    .line 161
    .line 162
    iput-object v9, v0, Ly9/w;->h:Landroid/view/ViewGroup;

    .line 163
    .line 164
    const v9, 0x7f0a0147

    .line 165
    .line 166
    .line 167
    invoke-virtual {v1, v9}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 168
    .line 169
    .line 170
    move-result-object v9

    .line 171
    iput-object v9, v0, Ly9/w;->k:Landroid/view/View;

    .line 172
    .line 173
    const v10, 0x7f0a0146

    .line 174
    .line 175
    .line 176
    invoke-virtual {v1, v10}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 177
    .line 178
    .line 179
    move-result-object v10

    .line 180
    if-eqz v9, :cond_0

    .line 181
    .line 182
    if-eqz v10, :cond_0

    .line 183
    .line 184
    new-instance v11, Ly9/e;

    .line 185
    .line 186
    invoke-direct {v11, v0, v5}, Ly9/e;-><init>(Ljava/lang/Object;I)V

    .line 187
    .line 188
    .line 189
    invoke-virtual {v9, v11}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 190
    .line 191
    .line 192
    new-instance v9, Ly9/e;

    .line 193
    .line 194
    invoke-direct {v9, v0, v5}, Ly9/e;-><init>(Ljava/lang/Object;I)V

    .line 195
    .line 196
    .line 197
    invoke-virtual {v10, v9}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 198
    .line 199
    .line 200
    :cond_0
    const/4 v9, 0x2

    .line 201
    new-array v10, v9, [F

    .line 202
    .line 203
    fill-array-data v10, :array_0

    .line 204
    .line 205
    .line 206
    invoke-static {v10}, Landroid/animation/ValueAnimator;->ofFloat([F)Landroid/animation/ValueAnimator;

    .line 207
    .line 208
    .line 209
    move-result-object v10

    .line 210
    new-instance v11, Landroid/view/animation/LinearInterpolator;

    .line 211
    .line 212
    invoke-direct {v11}, Landroid/view/animation/LinearInterpolator;-><init>()V

    .line 213
    .line 214
    .line 215
    invoke-virtual {v10, v11}, Landroid/animation/ValueAnimator;->setInterpolator(Landroid/animation/TimeInterpolator;)V

    .line 216
    .line 217
    .line 218
    new-instance v11, Ly9/t;

    .line 219
    .line 220
    invoke-direct {v11, v0, v4}, Ly9/t;-><init>(Ly9/w;I)V

    .line 221
    .line 222
    .line 223
    invoke-virtual {v10, v11}, Landroid/animation/ValueAnimator;->addUpdateListener(Landroid/animation/ValueAnimator$AnimatorUpdateListener;)V

    .line 224
    .line 225
    .line 226
    new-instance v11, Ly9/u;

    .line 227
    .line 228
    invoke-direct {v11, v0, v3}, Ly9/u;-><init>(Ly9/w;I)V

    .line 229
    .line 230
    .line 231
    invoke-virtual {v10, v11}, Landroid/animation/Animator;->addListener(Landroid/animation/Animator$AnimatorListener;)V

    .line 232
    .line 233
    .line 234
    new-array v11, v9, [F

    .line 235
    .line 236
    fill-array-data v11, :array_1

    .line 237
    .line 238
    .line 239
    invoke-static {v11}, Landroid/animation/ValueAnimator;->ofFloat([F)Landroid/animation/ValueAnimator;

    .line 240
    .line 241
    .line 242
    move-result-object v11

    .line 243
    new-instance v12, Landroid/view/animation/LinearInterpolator;

    .line 244
    .line 245
    invoke-direct {v12}, Landroid/view/animation/LinearInterpolator;-><init>()V

    .line 246
    .line 247
    .line 248
    invoke-virtual {v11, v12}, Landroid/animation/ValueAnimator;->setInterpolator(Landroid/animation/TimeInterpolator;)V

    .line 249
    .line 250
    .line 251
    new-instance v12, Ly9/t;

    .line 252
    .line 253
    invoke-direct {v12, v0, v3}, Ly9/t;-><init>(Ly9/w;I)V

    .line 254
    .line 255
    .line 256
    invoke-virtual {v11, v12}, Landroid/animation/ValueAnimator;->addUpdateListener(Landroid/animation/ValueAnimator$AnimatorUpdateListener;)V

    .line 257
    .line 258
    .line 259
    new-instance v12, Ly9/u;

    .line 260
    .line 261
    invoke-direct {v12, v0, v2}, Ly9/u;-><init>(Ly9/w;I)V

    .line 262
    .line 263
    .line 264
    invoke-virtual {v11, v12}, Landroid/animation/Animator;->addListener(Landroid/animation/Animator$AnimatorListener;)V

    .line 265
    .line 266
    .line 267
    invoke-virtual {v1}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    .line 268
    .line 269
    .line 270
    move-result-object v12

    .line 271
    const v13, 0x7f0700ac

    .line 272
    .line 273
    .line 274
    invoke-virtual {v12, v13}, Landroid/content/res/Resources;->getDimension(I)F

    .line 275
    .line 276
    .line 277
    move-result v14

    .line 278
    const v15, 0x7f0700b1

    .line 279
    .line 280
    .line 281
    invoke-virtual {v12, v15}, Landroid/content/res/Resources;->getDimension(I)F

    .line 282
    .line 283
    .line 284
    move-result v15

    .line 285
    sub-float/2addr v14, v15

    .line 286
    invoke-virtual {v12, v13}, Landroid/content/res/Resources;->getDimension(I)F

    .line 287
    .line 288
    .line 289
    move-result v12

    .line 290
    new-instance v13, Landroid/animation/AnimatorSet;

    .line 291
    .line 292
    invoke-direct {v13}, Landroid/animation/AnimatorSet;-><init>()V

    .line 293
    .line 294
    .line 295
    iput-object v13, v0, Ly9/w;->l:Landroid/animation/AnimatorSet;

    .line 296
    .line 297
    const-wide/16 v5, 0xfa

    .line 298
    .line 299
    invoke-virtual {v13, v5, v6}, Landroid/animation/AnimatorSet;->setDuration(J)Landroid/animation/AnimatorSet;

    .line 300
    .line 301
    .line 302
    new-instance v15, Ly9/v;

    .line 303
    .line 304
    invoke-direct {v15, v0, v1, v3}, Ly9/v;-><init>(Ly9/w;Ly9/r;I)V

    .line 305
    .line 306
    .line 307
    invoke-virtual {v13, v15}, Landroid/animation/Animator;->addListener(Landroid/animation/Animator$AnimatorListener;)V

    .line 308
    .line 309
    .line 310
    invoke-virtual {v13, v10}, Landroid/animation/AnimatorSet;->play(Landroid/animation/Animator;)Landroid/animation/AnimatorSet$Builder;

    .line 311
    .line 312
    .line 313
    move-result-object v3

    .line 314
    const/4 v13, 0x0

    .line 315
    invoke-static {v8, v13, v14}, Ly9/w;->d(Landroid/view/View;FF)Landroid/animation/ObjectAnimator;

    .line 316
    .line 317
    .line 318
    move-result-object v15

    .line 319
    invoke-virtual {v3, v15}, Landroid/animation/AnimatorSet$Builder;->with(Landroid/animation/Animator;)Landroid/animation/AnimatorSet$Builder;

    .line 320
    .line 321
    .line 322
    move-result-object v3

    .line 323
    invoke-static {v7, v13, v14}, Ly9/w;->d(Landroid/view/View;FF)Landroid/animation/ObjectAnimator;

    .line 324
    .line 325
    .line 326
    move-result-object v15

    .line 327
    invoke-virtual {v3, v15}, Landroid/animation/AnimatorSet$Builder;->with(Landroid/animation/Animator;)Landroid/animation/AnimatorSet$Builder;

    .line 328
    .line 329
    .line 330
    new-instance v3, Landroid/animation/AnimatorSet;

    .line 331
    .line 332
    invoke-direct {v3}, Landroid/animation/AnimatorSet;-><init>()V

    .line 333
    .line 334
    .line 335
    iput-object v3, v0, Ly9/w;->m:Landroid/animation/AnimatorSet;

    .line 336
    .line 337
    invoke-virtual {v3, v5, v6}, Landroid/animation/AnimatorSet;->setDuration(J)Landroid/animation/AnimatorSet;

    .line 338
    .line 339
    .line 340
    new-instance v15, Ly9/v;

    .line 341
    .line 342
    invoke-direct {v15, v0, v1, v2}, Ly9/v;-><init>(Ly9/w;Ly9/r;I)V

    .line 343
    .line 344
    .line 345
    invoke-virtual {v3, v15}, Landroid/animation/Animator;->addListener(Landroid/animation/Animator$AnimatorListener;)V

    .line 346
    .line 347
    .line 348
    invoke-static {v8, v14, v12}, Ly9/w;->d(Landroid/view/View;FF)Landroid/animation/ObjectAnimator;

    .line 349
    .line 350
    .line 351
    move-result-object v15

    .line 352
    invoke-virtual {v3, v15}, Landroid/animation/AnimatorSet;->play(Landroid/animation/Animator;)Landroid/animation/AnimatorSet$Builder;

    .line 353
    .line 354
    .line 355
    move-result-object v3

    .line 356
    invoke-static {v7, v14, v12}, Ly9/w;->d(Landroid/view/View;FF)Landroid/animation/ObjectAnimator;

    .line 357
    .line 358
    .line 359
    move-result-object v15

    .line 360
    invoke-virtual {v3, v15}, Landroid/animation/AnimatorSet$Builder;->with(Landroid/animation/Animator;)Landroid/animation/AnimatorSet$Builder;

    .line 361
    .line 362
    .line 363
    new-instance v3, Landroid/animation/AnimatorSet;

    .line 364
    .line 365
    invoke-direct {v3}, Landroid/animation/AnimatorSet;-><init>()V

    .line 366
    .line 367
    .line 368
    iput-object v3, v0, Ly9/w;->n:Landroid/animation/AnimatorSet;

    .line 369
    .line 370
    invoke-virtual {v3, v5, v6}, Landroid/animation/AnimatorSet;->setDuration(J)Landroid/animation/AnimatorSet;

    .line 371
    .line 372
    .line 373
    new-instance v15, Ly9/v;

    .line 374
    .line 375
    invoke-direct {v15, v0, v1, v9}, Ly9/v;-><init>(Ly9/w;Ly9/r;I)V

    .line 376
    .line 377
    .line 378
    invoke-virtual {v3, v15}, Landroid/animation/Animator;->addListener(Landroid/animation/Animator$AnimatorListener;)V

    .line 379
    .line 380
    .line 381
    invoke-virtual {v3, v10}, Landroid/animation/AnimatorSet;->play(Landroid/animation/Animator;)Landroid/animation/AnimatorSet$Builder;

    .line 382
    .line 383
    .line 384
    move-result-object v1

    .line 385
    invoke-static {v8, v13, v12}, Ly9/w;->d(Landroid/view/View;FF)Landroid/animation/ObjectAnimator;

    .line 386
    .line 387
    .line 388
    move-result-object v3

    .line 389
    invoke-virtual {v1, v3}, Landroid/animation/AnimatorSet$Builder;->with(Landroid/animation/Animator;)Landroid/animation/AnimatorSet$Builder;

    .line 390
    .line 391
    .line 392
    move-result-object v1

    .line 393
    invoke-static {v7, v13, v12}, Ly9/w;->d(Landroid/view/View;FF)Landroid/animation/ObjectAnimator;

    .line 394
    .line 395
    .line 396
    move-result-object v3

    .line 397
    invoke-virtual {v1, v3}, Landroid/animation/AnimatorSet$Builder;->with(Landroid/animation/Animator;)Landroid/animation/AnimatorSet$Builder;

    .line 398
    .line 399
    .line 400
    new-instance v1, Landroid/animation/AnimatorSet;

    .line 401
    .line 402
    invoke-direct {v1}, Landroid/animation/AnimatorSet;-><init>()V

    .line 403
    .line 404
    .line 405
    iput-object v1, v0, Ly9/w;->o:Landroid/animation/AnimatorSet;

    .line 406
    .line 407
    invoke-virtual {v1, v5, v6}, Landroid/animation/AnimatorSet;->setDuration(J)Landroid/animation/AnimatorSet;

    .line 408
    .line 409
    .line 410
    new-instance v3, Ly9/u;

    .line 411
    .line 412
    invoke-direct {v3, v0, v9}, Ly9/u;-><init>(Ly9/w;I)V

    .line 413
    .line 414
    .line 415
    invoke-virtual {v1, v3}, Landroid/animation/Animator;->addListener(Landroid/animation/Animator$AnimatorListener;)V

    .line 416
    .line 417
    .line 418
    invoke-virtual {v1, v11}, Landroid/animation/AnimatorSet;->play(Landroid/animation/Animator;)Landroid/animation/AnimatorSet$Builder;

    .line 419
    .line 420
    .line 421
    move-result-object v1

    .line 422
    invoke-static {v8, v14, v13}, Ly9/w;->d(Landroid/view/View;FF)Landroid/animation/ObjectAnimator;

    .line 423
    .line 424
    .line 425
    move-result-object v3

    .line 426
    invoke-virtual {v1, v3}, Landroid/animation/AnimatorSet$Builder;->with(Landroid/animation/Animator;)Landroid/animation/AnimatorSet$Builder;

    .line 427
    .line 428
    .line 429
    move-result-object v1

    .line 430
    invoke-static {v7, v14, v13}, Ly9/w;->d(Landroid/view/View;FF)Landroid/animation/ObjectAnimator;

    .line 431
    .line 432
    .line 433
    move-result-object v3

    .line 434
    invoke-virtual {v1, v3}, Landroid/animation/AnimatorSet$Builder;->with(Landroid/animation/Animator;)Landroid/animation/AnimatorSet$Builder;

    .line 435
    .line 436
    .line 437
    new-instance v1, Landroid/animation/AnimatorSet;

    .line 438
    .line 439
    invoke-direct {v1}, Landroid/animation/AnimatorSet;-><init>()V

    .line 440
    .line 441
    .line 442
    iput-object v1, v0, Ly9/w;->p:Landroid/animation/AnimatorSet;

    .line 443
    .line 444
    invoke-virtual {v1, v5, v6}, Landroid/animation/AnimatorSet;->setDuration(J)Landroid/animation/AnimatorSet;

    .line 445
    .line 446
    .line 447
    new-instance v3, Ly9/u;

    .line 448
    .line 449
    invoke-direct {v3, v0, v4}, Ly9/u;-><init>(Ly9/w;I)V

    .line 450
    .line 451
    .line 452
    invoke-virtual {v1, v3}, Landroid/animation/Animator;->addListener(Landroid/animation/Animator$AnimatorListener;)V

    .line 453
    .line 454
    .line 455
    invoke-virtual {v1, v11}, Landroid/animation/AnimatorSet;->play(Landroid/animation/Animator;)Landroid/animation/AnimatorSet$Builder;

    .line 456
    .line 457
    .line 458
    move-result-object v1

    .line 459
    invoke-static {v8, v12, v13}, Ly9/w;->d(Landroid/view/View;FF)Landroid/animation/ObjectAnimator;

    .line 460
    .line 461
    .line 462
    move-result-object v3

    .line 463
    invoke-virtual {v1, v3}, Landroid/animation/AnimatorSet$Builder;->with(Landroid/animation/Animator;)Landroid/animation/AnimatorSet$Builder;

    .line 464
    .line 465
    .line 466
    move-result-object v1

    .line 467
    invoke-static {v7, v12, v13}, Ly9/w;->d(Landroid/view/View;FF)Landroid/animation/ObjectAnimator;

    .line 468
    .line 469
    .line 470
    move-result-object v3

    .line 471
    invoke-virtual {v1, v3}, Landroid/animation/AnimatorSet$Builder;->with(Landroid/animation/Animator;)Landroid/animation/AnimatorSet$Builder;

    .line 472
    .line 473
    .line 474
    new-array v1, v9, [F

    .line 475
    .line 476
    fill-array-data v1, :array_2

    .line 477
    .line 478
    .line 479
    invoke-static {v1}, Landroid/animation/ValueAnimator;->ofFloat([F)Landroid/animation/ValueAnimator;

    .line 480
    .line 481
    .line 482
    move-result-object v1

    .line 483
    iput-object v1, v0, Ly9/w;->q:Landroid/animation/ValueAnimator;

    .line 484
    .line 485
    invoke-virtual {v1, v5, v6}, Landroid/animation/ValueAnimator;->setDuration(J)Landroid/animation/ValueAnimator;

    .line 486
    .line 487
    .line 488
    new-instance v3, Ly9/t;

    .line 489
    .line 490
    invoke-direct {v3, v0, v2}, Ly9/t;-><init>(Ly9/w;I)V

    .line 491
    .line 492
    .line 493
    invoke-virtual {v1, v3}, Landroid/animation/ValueAnimator;->addUpdateListener(Landroid/animation/ValueAnimator$AnimatorUpdateListener;)V

    .line 494
    .line 495
    .line 496
    new-instance v2, Ly9/u;

    .line 497
    .line 498
    const/4 v15, 0x4

    .line 499
    invoke-direct {v2, v0, v15}, Ly9/u;-><init>(Ly9/w;I)V

    .line 500
    .line 501
    .line 502
    invoke-virtual {v1, v2}, Landroid/animation/Animator;->addListener(Landroid/animation/Animator$AnimatorListener;)V

    .line 503
    .line 504
    .line 505
    new-array v1, v9, [F

    .line 506
    .line 507
    fill-array-data v1, :array_3

    .line 508
    .line 509
    .line 510
    invoke-static {v1}, Landroid/animation/ValueAnimator;->ofFloat([F)Landroid/animation/ValueAnimator;

    .line 511
    .line 512
    .line 513
    move-result-object v1

    .line 514
    iput-object v1, v0, Ly9/w;->r:Landroid/animation/ValueAnimator;

    .line 515
    .line 516
    invoke-virtual {v1, v5, v6}, Landroid/animation/ValueAnimator;->setDuration(J)Landroid/animation/ValueAnimator;

    .line 517
    .line 518
    .line 519
    new-instance v2, Ly9/t;

    .line 520
    .line 521
    invoke-direct {v2, v0, v9}, Ly9/t;-><init>(Ly9/w;I)V

    .line 522
    .line 523
    .line 524
    invoke-virtual {v1, v2}, Landroid/animation/ValueAnimator;->addUpdateListener(Landroid/animation/ValueAnimator$AnimatorUpdateListener;)V

    .line 525
    .line 526
    .line 527
    new-instance v2, Ly9/u;

    .line 528
    .line 529
    const/4 v3, 0x5

    .line 530
    invoke-direct {v2, v0, v3}, Ly9/u;-><init>(Ly9/w;I)V

    .line 531
    .line 532
    .line 533
    invoke-virtual {v1, v2}, Landroid/animation/Animator;->addListener(Landroid/animation/Animator$AnimatorListener;)V

    .line 534
    .line 535
    .line 536
    return-void

    .line 537
    :array_0
    .array-data 4
        0x3f800000    # 1.0f
        0x0
    .end array-data

    .line 538
    .line 539
    .line 540
    .line 541
    .line 542
    .line 543
    .line 544
    .line 545
    :array_1
    .array-data 4
        0x0
        0x3f800000    # 1.0f
    .end array-data

    .line 546
    .line 547
    .line 548
    .line 549
    .line 550
    .line 551
    .line 552
    .line 553
    :array_2
    .array-data 4
        0x0
        0x3f800000    # 1.0f
    .end array-data

    .line 554
    .line 555
    .line 556
    .line 557
    .line 558
    .line 559
    .line 560
    .line 561
    :array_3
    .array-data 4
        0x3f800000    # 1.0f
        0x0
    .end array-data
.end method

.method public static c(Landroid/view/View;)I
    .locals 2

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return p0

    .line 5
    :cond_0
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    invoke-virtual {p0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    instance-of v1, p0, Landroid/view/ViewGroup$MarginLayoutParams;

    .line 14
    .line 15
    if-eqz v1, :cond_1

    .line 16
    .line 17
    check-cast p0, Landroid/view/ViewGroup$MarginLayoutParams;

    .line 18
    .line 19
    iget v1, p0, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    .line 20
    .line 21
    iget p0, p0, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    .line 22
    .line 23
    add-int/2addr v1, p0

    .line 24
    add-int/2addr v1, v0

    .line 25
    return v1

    .line 26
    :cond_1
    return v0
.end method

.method public static d(Landroid/view/View;FF)Landroid/animation/ObjectAnimator;
    .locals 2

    .line 1
    const/4 v0, 0x2

    .line 2
    new-array v0, v0, [F

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    aput p1, v0, v1

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    aput p2, v0, p1

    .line 9
    .line 10
    const-string p1, "translationY"

    .line 11
    .line 12
    invoke-static {p0, p1, v0}, Landroid/animation/ObjectAnimator;->ofFloat(Ljava/lang/Object;Ljava/lang/String;[F)Landroid/animation/ObjectAnimator;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method public static j(Landroid/view/View;)Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->getId()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    const v0, 0x7f0a0131

    .line 6
    .line 7
    .line 8
    if-eq p0, v0, :cond_1

    .line 9
    .line 10
    const v0, 0x7f0a014e

    .line 11
    .line 12
    .line 13
    if-eq p0, v0, :cond_1

    .line 14
    .line 15
    const v0, 0x7f0a0145

    .line 16
    .line 17
    .line 18
    if-eq p0, v0, :cond_1

    .line 19
    .line 20
    const v0, 0x7f0a0152

    .line 21
    .line 22
    .line 23
    if-eq p0, v0, :cond_1

    .line 24
    .line 25
    const v0, 0x7f0a0153

    .line 26
    .line 27
    .line 28
    if-eq p0, v0, :cond_1

    .line 29
    .line 30
    const v0, 0x7f0a013d

    .line 31
    .line 32
    .line 33
    if-eq p0, v0, :cond_1

    .line 34
    .line 35
    const v0, 0x7f0a013e

    .line 36
    .line 37
    .line 38
    if-ne p0, v0, :cond_0

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    const/4 p0, 0x0

    .line 42
    return p0

    .line 43
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 44
    return p0
.end method


# virtual methods
.method public final a(F)V
    .locals 4

    .line 1
    const/high16 v0, 0x3f800000    # 1.0f

    .line 2
    .line 3
    iget-object v1, p0, Ly9/w;->h:Landroid/view/ViewGroup;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    invoke-virtual {v1}, Landroid/view/View;->getWidth()I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    int-to-float v2, v2

    .line 12
    sub-float v3, v0, p1

    .line 13
    .line 14
    mul-float/2addr v3, v2

    .line 15
    float-to-int v2, v3

    .line 16
    int-to-float v2, v2

    .line 17
    invoke-virtual {v1, v2}, Landroid/view/View;->setTranslationX(F)V

    .line 18
    .line 19
    .line 20
    :cond_0
    iget-object v1, p0, Ly9/w;->i:Landroid/view/ViewGroup;

    .line 21
    .line 22
    if-eqz v1, :cond_1

    .line 23
    .line 24
    sub-float v2, v0, p1

    .line 25
    .line 26
    invoke-virtual {v1, v2}, Landroid/view/View;->setAlpha(F)V

    .line 27
    .line 28
    .line 29
    :cond_1
    iget-object p0, p0, Ly9/w;->f:Landroid/view/ViewGroup;

    .line 30
    .line 31
    if-eqz p0, :cond_2

    .line 32
    .line 33
    sub-float/2addr v0, p1

    .line 34
    invoke-virtual {p0, v0}, Landroid/view/View;->setAlpha(F)V

    .line 35
    .line 36
    .line 37
    :cond_2
    return-void
.end method

.method public final b(Landroid/view/View;)Z
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iget-object p0, p0, Ly9/w;->y:Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public final e(Ljava/lang/Runnable;J)V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v0, p2, v0

    .line 4
    .line 5
    if-ltz v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Ly9/w;->a:Ly9/r;

    .line 8
    .line 9
    invoke-virtual {p0, p1, p2, p3}, Landroid/view/View;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 10
    .line 11
    .line 12
    :cond_0
    return-void
.end method

.method public final f()V
    .locals 2

    .line 1
    iget-object v0, p0, Ly9/w;->w:Ly9/s;

    .line 2
    .line 3
    iget-object v1, p0, Ly9/w;->a:Ly9/r;

    .line 4
    .line 5
    invoke-virtual {v1, v0}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Ly9/w;->t:Ly9/s;

    .line 9
    .line 10
    invoke-virtual {v1, v0}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Ly9/w;->v:Ly9/s;

    .line 14
    .line 15
    invoke-virtual {v1, v0}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Ly9/w;->u:Ly9/s;

    .line 19
    .line 20
    invoke-virtual {v1, p0}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public final g()V
    .locals 4

    .line 1
    iget v0, p0, Ly9/w;->z:I

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    if-ne v0, v1, :cond_0

    .line 5
    .line 6
    goto :goto_0

    .line 7
    :cond_0
    invoke-virtual {p0}, Ly9/w;->f()V

    .line 8
    .line 9
    .line 10
    iget-object v0, p0, Ly9/w;->a:Ly9/r;

    .line 11
    .line 12
    invoke-virtual {v0}, Ly9/r;->getShowTimeoutMs()I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-lez v0, :cond_3

    .line 17
    .line 18
    iget-boolean v1, p0, Ly9/w;->C:Z

    .line 19
    .line 20
    if-nez v1, :cond_1

    .line 21
    .line 22
    iget-object v1, p0, Ly9/w;->w:Ly9/s;

    .line 23
    .line 24
    int-to-long v2, v0

    .line 25
    invoke-virtual {p0, v1, v2, v3}, Ly9/w;->e(Ljava/lang/Runnable;J)V

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :cond_1
    iget v1, p0, Ly9/w;->z:I

    .line 30
    .line 31
    const/4 v2, 0x1

    .line 32
    if-ne v1, v2, :cond_2

    .line 33
    .line 34
    iget-object v0, p0, Ly9/w;->u:Ly9/s;

    .line 35
    .line 36
    const-wide/16 v1, 0x7d0

    .line 37
    .line 38
    invoke-virtual {p0, v0, v1, v2}, Ly9/w;->e(Ljava/lang/Runnable;J)V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :cond_2
    iget-object v1, p0, Ly9/w;->v:Ly9/s;

    .line 43
    .line 44
    int-to-long v2, v0

    .line 45
    invoke-virtual {p0, v1, v2, v3}, Ly9/w;->e(Ljava/lang/Runnable;J)V

    .line 46
    .line 47
    .line 48
    :cond_3
    :goto_0
    return-void
.end method

.method public final h(Landroid/view/View;Z)V
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    iget-object v0, p0, Ly9/w;->y:Ljava/util/ArrayList;

    .line 5
    .line 6
    if-nez p2, :cond_1

    .line 7
    .line 8
    const/16 p0, 0x8

    .line 9
    .line 10
    invoke-virtual {p1, p0}, Landroid/view/View;->setVisibility(I)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :cond_1
    iget-boolean p0, p0, Ly9/w;->A:Z

    .line 18
    .line 19
    if-eqz p0, :cond_2

    .line 20
    .line 21
    invoke-static {p1}, Ly9/w;->j(Landroid/view/View;)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    if-eqz p0, :cond_2

    .line 26
    .line 27
    const/4 p0, 0x4

    .line 28
    invoke-virtual {p1, p0}, Landroid/view/View;->setVisibility(I)V

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_2
    const/4 p0, 0x0

    .line 33
    invoke-virtual {p1, p0}, Landroid/view/View;->setVisibility(I)V

    .line 34
    .line 35
    .line 36
    :goto_0
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    return-void
.end method

.method public final i(I)V
    .locals 2

    .line 1
    iget v0, p0, Ly9/w;->z:I

    .line 2
    .line 3
    iput p1, p0, Ly9/w;->z:I

    .line 4
    .line 5
    iget-object p0, p0, Ly9/w;->a:Ly9/r;

    .line 6
    .line 7
    const/4 v1, 0x2

    .line 8
    if-ne p1, v1, :cond_0

    .line 9
    .line 10
    const/16 v1, 0x8

    .line 11
    .line 12
    invoke-virtual {p0, v1}, Landroid/view/View;->setVisibility(I)V

    .line 13
    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    if-ne v0, v1, :cond_1

    .line 17
    .line 18
    const/4 v1, 0x0

    .line 19
    invoke-virtual {p0, v1}, Landroid/view/View;->setVisibility(I)V

    .line 20
    .line 21
    .line 22
    :cond_1
    :goto_0
    if-eq v0, p1, :cond_2

    .line 23
    .line 24
    iget-object p1, p0, Ly9/r;->m:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 25
    .line 26
    invoke-virtual {p1}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_2

    .line 35
    .line 36
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    check-cast v0, Ly9/q;

    .line 41
    .line 42
    invoke-virtual {p0}, Landroid/view/View;->getVisibility()I

    .line 43
    .line 44
    .line 45
    check-cast v0, Ly9/y;

    .line 46
    .line 47
    iget-object v0, v0, Ly9/y;->f:Landroidx/media3/ui/PlayerView;

    .line 48
    .line 49
    invoke-virtual {v0}, Landroidx/media3/ui/PlayerView;->m()V

    .line 50
    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_2
    return-void
.end method

.method public final k()V
    .locals 3

    .line 1
    iget-boolean v0, p0, Ly9/w;->C:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    invoke-virtual {p0, v0}, Ly9/w;->i(I)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, Ly9/w;->g()V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    iget v0, p0, Ly9/w;->z:I

    .line 14
    .line 15
    const/4 v1, 0x1

    .line 16
    if-eq v0, v1, :cond_4

    .line 17
    .line 18
    const/4 v2, 0x2

    .line 19
    if-eq v0, v2, :cond_3

    .line 20
    .line 21
    const/4 v2, 0x3

    .line 22
    if-eq v0, v2, :cond_2

    .line 23
    .line 24
    const/4 v1, 0x4

    .line 25
    if-eq v0, v1, :cond_1

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_1
    return-void

    .line 29
    :cond_2
    iput-boolean v1, p0, Ly9/w;->B:Z

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_3
    iget-object v0, p0, Ly9/w;->p:Landroid/animation/AnimatorSet;

    .line 33
    .line 34
    invoke-virtual {v0}, Landroid/animation/AnimatorSet;->start()V

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_4
    iget-object v0, p0, Ly9/w;->o:Landroid/animation/AnimatorSet;

    .line 39
    .line 40
    invoke-virtual {v0}, Landroid/animation/AnimatorSet;->start()V

    .line 41
    .line 42
    .line 43
    :goto_0
    invoke-virtual {p0}, Ly9/w;->g()V

    .line 44
    .line 45
    .line 46
    return-void
.end method
