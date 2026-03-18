.class public final Lu/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/r2;


# instance fields
.field public final b:Lu/q0;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lu/q0;->b(Landroid/content/Context;)Lu/q0;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    iput-object p1, p0, Lu/g0;->b:Lu/q0;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Lh0/q2;I)Lh0/q0;
    .locals 31

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p2

    .line 6
    .line 7
    invoke-static {}, Lh0/j1;->c()Lh0/j1;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    new-instance v4, Ljava/util/LinkedHashSet;

    .line 12
    .line 13
    invoke-direct {v4}, Ljava/util/LinkedHashSet;-><init>()V

    .line 14
    .line 15
    .line 16
    new-instance v5, Ljava/util/HashSet;

    .line 17
    .line 18
    invoke-direct {v5}, Ljava/util/HashSet;-><init>()V

    .line 19
    .line 20
    .line 21
    invoke-static {}, Lh0/j1;->c()Lh0/j1;

    .line 22
    .line 23
    .line 24
    move-result-object v6

    .line 25
    new-instance v7, Ljava/util/ArrayList;

    .line 26
    .line 27
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 28
    .line 29
    .line 30
    invoke-static {}, Lh0/k1;->a()Lh0/k1;

    .line 31
    .line 32
    .line 33
    move-result-object v8

    .line 34
    new-instance v9, Ljava/util/ArrayList;

    .line 35
    .line 36
    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    .line 37
    .line 38
    .line 39
    new-instance v10, Ljava/util/ArrayList;

    .line 40
    .line 41
    invoke-direct {v10}, Ljava/util/ArrayList;-><init>()V

    .line 42
    .line 43
    .line 44
    new-instance v11, Ljava/util/ArrayList;

    .line 45
    .line 46
    invoke-direct {v11}, Ljava/util/ArrayList;-><init>()V

    .line 47
    .line 48
    .line 49
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 50
    .line 51
    .line 52
    move-result v12

    .line 53
    const-class v15, Landroidx/camera/camera2/internal/compat/quirk/PreviewUnderExposureQuirk;

    .line 54
    .line 55
    const/4 v13, 0x3

    .line 56
    if-eqz v12, :cond_3

    .line 57
    .line 58
    if-eq v12, v13, :cond_1

    .line 59
    .line 60
    :cond_0
    :goto_0
    const/16 v20, 0x1

    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_1
    sget-object v12, Lx/a;->a:Ld01/x;

    .line 64
    .line 65
    invoke-virtual {v12, v15}, Ld01/x;->l(Ljava/lang/Class;)Lh0/p1;

    .line 66
    .line 67
    .line 68
    move-result-object v12

    .line 69
    if-eqz v12, :cond_2

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_2
    move/from16 v20, v13

    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_3
    const/4 v12, 0x2

    .line 76
    if-ne v2, v12, :cond_0

    .line 77
    .line 78
    const/16 v20, 0x5

    .line 79
    .line 80
    :goto_1
    sget-object v12, Lh0/o2;->P0:Lh0/g;

    .line 81
    .line 82
    new-instance v25, Lh0/z1;

    .line 83
    .line 84
    new-instance v14, Ljava/util/ArrayList;

    .line 85
    .line 86
    invoke-direct {v14, v4}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 87
    .line 88
    .line 89
    new-instance v4, Ljava/util/ArrayList;

    .line 90
    .line 91
    invoke-direct {v4, v9}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 92
    .line 93
    .line 94
    new-instance v9, Ljava/util/ArrayList;

    .line 95
    .line 96
    invoke-direct {v9, v10}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 97
    .line 98
    .line 99
    new-instance v10, Ljava/util/ArrayList;

    .line 100
    .line 101
    invoke-direct {v10, v11}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 102
    .line 103
    .line 104
    new-instance v17, Lh0/o0;

    .line 105
    .line 106
    new-instance v11, Ljava/util/ArrayList;

    .line 107
    .line 108
    invoke-direct {v11, v5}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 109
    .line 110
    .line 111
    invoke-static {v6}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 112
    .line 113
    .line 114
    move-result-object v19

    .line 115
    new-instance v5, Ljava/util/ArrayList;

    .line 116
    .line 117
    invoke-direct {v5, v7}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 118
    .line 119
    .line 120
    sget-object v6, Lh0/j2;->b:Lh0/j2;

    .line 121
    .line 122
    new-instance v6, Landroid/util/ArrayMap;

    .line 123
    .line 124
    invoke-direct {v6}, Landroid/util/ArrayMap;-><init>()V

    .line 125
    .line 126
    .line 127
    iget-object v7, v8, Lh0/j2;->a:Landroid/util/ArrayMap;

    .line 128
    .line 129
    invoke-virtual {v7}, Landroid/util/ArrayMap;->keySet()Ljava/util/Set;

    .line 130
    .line 131
    .line 132
    move-result-object v7

    .line 133
    invoke-interface {v7}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 134
    .line 135
    .line 136
    move-result-object v7

    .line 137
    :goto_2
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 138
    .line 139
    .line 140
    move-result v18

    .line 141
    if-eqz v18, :cond_4

    .line 142
    .line 143
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object v18

    .line 147
    move-object/from16 v13, v18

    .line 148
    .line 149
    check-cast v13, Ljava/lang/String;

    .line 150
    .line 151
    move-object/from16 v26, v4

    .line 152
    .line 153
    iget-object v4, v8, Lh0/j2;->a:Landroid/util/ArrayMap;

    .line 154
    .line 155
    invoke-virtual {v4, v13}, Landroid/util/ArrayMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v4

    .line 159
    invoke-virtual {v6, v13, v4}, Landroid/util/ArrayMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-object/from16 v4, v26

    .line 163
    .line 164
    const/4 v13, 0x3

    .line 165
    goto :goto_2

    .line 166
    :cond_4
    move-object/from16 v26, v4

    .line 167
    .line 168
    new-instance v4, Lh0/j2;

    .line 169
    .line 170
    invoke-direct {v4, v6}, Lh0/j2;-><init>(Landroid/util/ArrayMap;)V

    .line 171
    .line 172
    .line 173
    const/16 v22, 0x0

    .line 174
    .line 175
    const/16 v24, 0x0

    .line 176
    .line 177
    move-object/from16 v23, v4

    .line 178
    .line 179
    move-object/from16 v21, v5

    .line 180
    .line 181
    move-object/from16 v18, v11

    .line 182
    .line 183
    invoke-direct/range {v17 .. v24}, Lh0/o0;-><init>(Ljava/util/ArrayList;Lh0/n1;ILjava/util/ArrayList;ZLh0/j2;Lh0/s;)V

    .line 184
    .line 185
    .line 186
    const/16 v27, 0x0

    .line 187
    .line 188
    const/16 v28, 0x0

    .line 189
    .line 190
    const/16 v29, 0x0

    .line 191
    .line 192
    const/16 v30, 0x0

    .line 193
    .line 194
    move-object/from16 v24, v9

    .line 195
    .line 196
    move-object/from16 v22, v14

    .line 197
    .line 198
    move-object/from16 v21, v25

    .line 199
    .line 200
    move-object/from16 v23, v26

    .line 201
    .line 202
    move-object/from16 v25, v10

    .line 203
    .line 204
    move-object/from16 v26, v17

    .line 205
    .line 206
    invoke-direct/range {v21 .. v30}, Lh0/z1;-><init>(Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Lh0/o0;Lh0/x1;Landroid/hardware/camera2/params/InputConfiguration;ILh0/i;)V

    .line 207
    .line 208
    .line 209
    move-object/from16 v4, v21

    .line 210
    .line 211
    invoke-virtual {v3, v12, v4}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 212
    .line 213
    .line 214
    sget-object v4, Lh0/o2;->R0:Lh0/g;

    .line 215
    .line 216
    sget-object v5, Lu/f0;->a:Lu/f0;

    .line 217
    .line 218
    invoke-virtual {v3, v4, v5}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 219
    .line 220
    .line 221
    new-instance v4, Ljava/util/HashSet;

    .line 222
    .line 223
    invoke-direct {v4}, Ljava/util/HashSet;-><init>()V

    .line 224
    .line 225
    .line 226
    invoke-static {}, Lh0/j1;->c()Lh0/j1;

    .line 227
    .line 228
    .line 229
    move-result-object v5

    .line 230
    new-instance v6, Ljava/util/ArrayList;

    .line 231
    .line 232
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 233
    .line 234
    .line 235
    invoke-static {}, Lh0/k1;->a()Lh0/k1;

    .line 236
    .line 237
    .line 238
    move-result-object v7

    .line 239
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 240
    .line 241
    .line 242
    move-result v8

    .line 243
    if-eqz v8, :cond_7

    .line 244
    .line 245
    const/4 v9, 0x3

    .line 246
    if-eq v8, v9, :cond_5

    .line 247
    .line 248
    :goto_3
    const/16 v19, 0x1

    .line 249
    .line 250
    goto :goto_4

    .line 251
    :cond_5
    sget-object v2, Lx/a;->a:Ld01/x;

    .line 252
    .line 253
    invoke-virtual {v2, v15}, Ld01/x;->l(Ljava/lang/Class;)Lh0/p1;

    .line 254
    .line 255
    .line 256
    move-result-object v2

    .line 257
    if-eqz v2, :cond_6

    .line 258
    .line 259
    goto :goto_3

    .line 260
    :cond_6
    move/from16 v19, v9

    .line 261
    .line 262
    goto :goto_4

    .line 263
    :cond_7
    const/4 v12, 0x2

    .line 264
    if-ne v2, v12, :cond_8

    .line 265
    .line 266
    const/16 v19, 0x5

    .line 267
    .line 268
    goto :goto_4

    .line 269
    :cond_8
    move/from16 v19, v12

    .line 270
    .line 271
    :goto_4
    sget-object v2, Lh0/o2;->Q0:Lh0/g;

    .line 272
    .line 273
    new-instance v16, Lh0/o0;

    .line 274
    .line 275
    new-instance v8, Ljava/util/ArrayList;

    .line 276
    .line 277
    invoke-direct {v8, v4}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 278
    .line 279
    .line 280
    invoke-static {v5}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 281
    .line 282
    .line 283
    move-result-object v18

    .line 284
    new-instance v4, Ljava/util/ArrayList;

    .line 285
    .line 286
    invoke-direct {v4, v6}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 287
    .line 288
    .line 289
    sget-object v5, Lh0/j2;->b:Lh0/j2;

    .line 290
    .line 291
    new-instance v5, Landroid/util/ArrayMap;

    .line 292
    .line 293
    invoke-direct {v5}, Landroid/util/ArrayMap;-><init>()V

    .line 294
    .line 295
    .line 296
    iget-object v6, v7, Lh0/j2;->a:Landroid/util/ArrayMap;

    .line 297
    .line 298
    invoke-virtual {v6}, Landroid/util/ArrayMap;->keySet()Ljava/util/Set;

    .line 299
    .line 300
    .line 301
    move-result-object v6

    .line 302
    invoke-interface {v6}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 303
    .line 304
    .line 305
    move-result-object v6

    .line 306
    :goto_5
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 307
    .line 308
    .line 309
    move-result v9

    .line 310
    if-eqz v9, :cond_9

    .line 311
    .line 312
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 313
    .line 314
    .line 315
    move-result-object v9

    .line 316
    check-cast v9, Ljava/lang/String;

    .line 317
    .line 318
    iget-object v10, v7, Lh0/j2;->a:Landroid/util/ArrayMap;

    .line 319
    .line 320
    invoke-virtual {v10, v9}, Landroid/util/ArrayMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 321
    .line 322
    .line 323
    move-result-object v10

    .line 324
    invoke-virtual {v5, v9, v10}, Landroid/util/ArrayMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 325
    .line 326
    .line 327
    goto :goto_5

    .line 328
    :cond_9
    new-instance v6, Lh0/j2;

    .line 329
    .line 330
    invoke-direct {v6, v5}, Lh0/j2;-><init>(Landroid/util/ArrayMap;)V

    .line 331
    .line 332
    .line 333
    const/16 v21, 0x0

    .line 334
    .line 335
    const/16 v23, 0x0

    .line 336
    .line 337
    move-object/from16 v20, v4

    .line 338
    .line 339
    move-object/from16 v22, v6

    .line 340
    .line 341
    move-object/from16 v17, v8

    .line 342
    .line 343
    invoke-direct/range {v16 .. v23}, Lh0/o0;-><init>(Ljava/util/ArrayList;Lh0/n1;ILjava/util/ArrayList;ZLh0/j2;Lh0/s;)V

    .line 344
    .line 345
    .line 346
    move-object/from16 v4, v16

    .line 347
    .line 348
    invoke-virtual {v3, v2, v4}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 349
    .line 350
    .line 351
    sget-object v2, Lh0/o2;->S0:Lh0/g;

    .line 352
    .line 353
    sget-object v4, Lh0/q2;->d:Lh0/q2;

    .line 354
    .line 355
    if-ne v1, v4, :cond_a

    .line 356
    .line 357
    sget-object v4, Lu/u0;->b:Lu/u0;

    .line 358
    .line 359
    goto :goto_6

    .line 360
    :cond_a
    sget-object v4, Lu/c0;->a:Lu/c0;

    .line 361
    .line 362
    :goto_6
    invoke-virtual {v3, v2, v4}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 363
    .line 364
    .line 365
    sget-object v2, Lh0/q2;->e:Lh0/q2;

    .line 366
    .line 367
    if-ne v1, v2, :cond_b

    .line 368
    .line 369
    iget-object v2, v0, Lu/g0;->b:Lu/q0;

    .line 370
    .line 371
    invoke-virtual {v2}, Lu/q0;->e()Landroid/util/Size;

    .line 372
    .line 373
    .line 374
    move-result-object v2

    .line 375
    sget-object v4, Lh0/a1;->L0:Lh0/g;

    .line 376
    .line 377
    invoke-virtual {v3, v4, v2}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 378
    .line 379
    .line 380
    :cond_b
    iget-object v0, v0, Lu/g0;->b:Lu/q0;

    .line 381
    .line 382
    const/4 v2, 0x1

    .line 383
    invoke-virtual {v0, v2}, Lu/q0;->c(Z)Landroid/view/Display;

    .line 384
    .line 385
    .line 386
    move-result-object v0

    .line 387
    invoke-virtual {v0}, Landroid/view/Display;->getRotation()I

    .line 388
    .line 389
    .line 390
    move-result v0

    .line 391
    sget-object v2, Lh0/a1;->G0:Lh0/g;

    .line 392
    .line 393
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 394
    .line 395
    .line 396
    move-result-object v0

    .line 397
    invoke-virtual {v3, v2, v0}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 398
    .line 399
    .line 400
    sget-object v0, Lh0/q2;->g:Lh0/q2;

    .line 401
    .line 402
    if-eq v1, v0, :cond_c

    .line 403
    .line 404
    sget-object v0, Lh0/q2;->h:Lh0/q2;

    .line 405
    .line 406
    if-ne v1, v0, :cond_d

    .line 407
    .line 408
    :cond_c
    sget-object v0, Lh0/o2;->X0:Lh0/g;

    .line 409
    .line 410
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 411
    .line 412
    invoke-virtual {v3, v0, v1}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 413
    .line 414
    .line 415
    :cond_d
    invoke-static {v3}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 416
    .line 417
    .line 418
    move-result-object v0

    .line 419
    return-object v0
.end method
