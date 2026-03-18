.class public final Lf5/h;
.super Lf5/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final apply()V
    .locals 13

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 3
    .line 4
    .line 5
    move-result-object v1

    .line 6
    iget-object v2, p0, Le5/h;->m0:Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object v3

    .line 12
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v4

    .line 16
    iget-object v5, p0, Le5/h;->k0:Lz4/q;

    .line 17
    .line 18
    if-eqz v4, :cond_0

    .line 19
    .line 20
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v4

    .line 24
    invoke-virtual {v5, v4}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 25
    .line 26
    .line 27
    move-result-object v4

    .line 28
    invoke-virtual {v4}, Le5/b;->g()V

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    const/4 v3, 0x0

    .line 37
    move-object v4, v3

    .line 38
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 39
    .line 40
    .line 41
    move-result v6

    .line 42
    const/4 v7, 0x7

    .line 43
    if-eqz v6, :cond_9

    .line 44
    .line 45
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v6

    .line 49
    invoke-virtual {v5, v6}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 50
    .line 51
    .line 52
    move-result-object v8

    .line 53
    const/4 v9, 0x6

    .line 54
    if-nez v4, :cond_5

    .line 55
    .line 56
    iget-object v4, p0, Le5/b;->N:Ljava/lang/Object;

    .line 57
    .line 58
    if-eqz v4, :cond_1

    .line 59
    .line 60
    invoke-virtual {v8, v4}, Le5/b;->o(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    iget v4, p0, Le5/b;->l:I

    .line 64
    .line 65
    invoke-virtual {v8, v4}, Le5/b;->k(I)Le5/b;

    .line 66
    .line 67
    .line 68
    move-result-object v4

    .line 69
    iget v10, p0, Le5/b;->r:I

    .line 70
    .line 71
    invoke-virtual {v4, v10}, Le5/b;->m(I)V

    .line 72
    .line 73
    .line 74
    goto :goto_2

    .line 75
    :cond_1
    iget-object v4, p0, Le5/b;->O:Ljava/lang/Object;

    .line 76
    .line 77
    if-eqz v4, :cond_2

    .line 78
    .line 79
    iput v9, v8, Le5/b;->j0:I

    .line 80
    .line 81
    iput-object v4, v8, Le5/b;->O:Ljava/lang/Object;

    .line 82
    .line 83
    iget v4, p0, Le5/b;->l:I

    .line 84
    .line 85
    invoke-virtual {v8, v4}, Le5/b;->k(I)Le5/b;

    .line 86
    .line 87
    .line 88
    move-result-object v4

    .line 89
    iget v10, p0, Le5/b;->r:I

    .line 90
    .line 91
    invoke-virtual {v4, v10}, Le5/b;->m(I)V

    .line 92
    .line 93
    .line 94
    goto :goto_2

    .line 95
    :cond_2
    iget-object v4, p0, Le5/b;->J:Ljava/lang/Object;

    .line 96
    .line 97
    if-eqz v4, :cond_3

    .line 98
    .line 99
    invoke-virtual {v8, v4}, Le5/b;->o(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    iget v4, p0, Le5/b;->j:I

    .line 103
    .line 104
    invoke-virtual {v8, v4}, Le5/b;->k(I)Le5/b;

    .line 105
    .line 106
    .line 107
    move-result-object v4

    .line 108
    iget v10, p0, Le5/b;->p:I

    .line 109
    .line 110
    invoke-virtual {v4, v10}, Le5/b;->m(I)V

    .line 111
    .line 112
    .line 113
    goto :goto_2

    .line 114
    :cond_3
    iget-object v4, p0, Le5/b;->K:Ljava/lang/Object;

    .line 115
    .line 116
    if-eqz v4, :cond_4

    .line 117
    .line 118
    iput v9, v8, Le5/b;->j0:I

    .line 119
    .line 120
    iput-object v4, v8, Le5/b;->O:Ljava/lang/Object;

    .line 121
    .line 122
    iget v4, p0, Le5/b;->j:I

    .line 123
    .line 124
    invoke-virtual {v8, v4}, Le5/b;->k(I)Le5/b;

    .line 125
    .line 126
    .line 127
    move-result-object v4

    .line 128
    iget v10, p0, Le5/b;->p:I

    .line 129
    .line 130
    invoke-virtual {v4, v10}, Le5/b;->m(I)V

    .line 131
    .line 132
    .line 133
    goto :goto_2

    .line 134
    :cond_4
    iget-object v4, v8, Le5/b;->a:Ljava/lang/Object;

    .line 135
    .line 136
    invoke-virtual {v4}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object v4

    .line 140
    invoke-virtual {v8, v1}, Le5/b;->o(Ljava/lang/Object;)V

    .line 141
    .line 142
    .line 143
    invoke-virtual {p0, v4}, Lf5/c;->w(Ljava/lang/String;)F

    .line 144
    .line 145
    .line 146
    move-result v10

    .line 147
    invoke-static {v10}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 148
    .line 149
    .line 150
    move-result-object v10

    .line 151
    invoke-virtual {v8, v10}, Le5/b;->l(Ljava/lang/Float;)Le5/b;

    .line 152
    .line 153
    .line 154
    move-result-object v10

    .line 155
    invoke-virtual {p0, v4}, Lf5/c;->v(Ljava/lang/String;)F

    .line 156
    .line 157
    .line 158
    move-result v4

    .line 159
    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 160
    .line 161
    .line 162
    move-result-object v4

    .line 163
    invoke-virtual {v10, v4}, Le5/b;->n(Ljava/lang/Float;)V

    .line 164
    .line 165
    .line 166
    :goto_2
    move-object v4, v8

    .line 167
    :cond_5
    if-eqz v3, :cond_6

    .line 168
    .line 169
    iget-object v10, v3, Le5/b;->a:Ljava/lang/Object;

    .line 170
    .line 171
    invoke-virtual {v10}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object v10

    .line 175
    iget-object v11, v8, Le5/b;->a:Ljava/lang/Object;

    .line 176
    .line 177
    invoke-virtual {v11}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object v11

    .line 181
    iget-object v12, v8, Le5/b;->a:Ljava/lang/Object;

    .line 182
    .line 183
    iput v7, v3, Le5/b;->j0:I

    .line 184
    .line 185
    iput-object v12, v3, Le5/b;->P:Ljava/lang/Object;

    .line 186
    .line 187
    invoke-virtual {p0, v10}, Lf5/c;->u(Ljava/lang/String;)F

    .line 188
    .line 189
    .line 190
    move-result v7

    .line 191
    invoke-static {v7}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 192
    .line 193
    .line 194
    move-result-object v7

    .line 195
    invoke-virtual {v3, v7}, Le5/b;->l(Ljava/lang/Float;)Le5/b;

    .line 196
    .line 197
    .line 198
    move-result-object v7

    .line 199
    invoke-virtual {p0, v10}, Lf5/c;->t(Ljava/lang/String;)F

    .line 200
    .line 201
    .line 202
    move-result v10

    .line 203
    invoke-static {v10}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 204
    .line 205
    .line 206
    move-result-object v10

    .line 207
    invoke-virtual {v7, v10}, Le5/b;->n(Ljava/lang/Float;)V

    .line 208
    .line 209
    .line 210
    iget-object v3, v3, Le5/b;->a:Ljava/lang/Object;

    .line 211
    .line 212
    iput v9, v8, Le5/b;->j0:I

    .line 213
    .line 214
    iput-object v3, v8, Le5/b;->O:Ljava/lang/Object;

    .line 215
    .line 216
    invoke-virtual {p0, v11}, Lf5/c;->w(Ljava/lang/String;)F

    .line 217
    .line 218
    .line 219
    move-result v3

    .line 220
    invoke-static {v3}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 221
    .line 222
    .line 223
    move-result-object v3

    .line 224
    invoke-virtual {v8, v3}, Le5/b;->l(Ljava/lang/Float;)Le5/b;

    .line 225
    .line 226
    .line 227
    move-result-object v3

    .line 228
    invoke-virtual {p0, v11}, Lf5/c;->v(Ljava/lang/String;)F

    .line 229
    .line 230
    .line 231
    move-result v7

    .line 232
    invoke-static {v7}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 233
    .line 234
    .line 235
    move-result-object v7

    .line 236
    invoke-virtual {v3, v7}, Le5/b;->n(Ljava/lang/Float;)V

    .line 237
    .line 238
    .line 239
    :cond_6
    invoke-virtual {v6}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 240
    .line 241
    .line 242
    move-result-object v3

    .line 243
    iget-object v6, p0, Lf5/c;->o0:Ljava/util/HashMap;

    .line 244
    .line 245
    invoke-virtual {v6, v3}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 246
    .line 247
    .line 248
    move-result v7

    .line 249
    const/high16 v9, -0x40800000    # -1.0f

    .line 250
    .line 251
    if-eqz v7, :cond_7

    .line 252
    .line 253
    invoke-virtual {v6, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 254
    .line 255
    .line 256
    move-result-object v3

    .line 257
    check-cast v3, Ljava/lang/Float;

    .line 258
    .line 259
    invoke-virtual {v3}, Ljava/lang/Float;->floatValue()F

    .line 260
    .line 261
    .line 262
    move-result v3

    .line 263
    goto :goto_3

    .line 264
    :cond_7
    move v3, v9

    .line 265
    :goto_3
    cmpl-float v6, v3, v9

    .line 266
    .line 267
    if-eqz v6, :cond_8

    .line 268
    .line 269
    iput v3, v8, Le5/b;->f:F

    .line 270
    .line 271
    :cond_8
    move-object v3, v8

    .line 272
    goto/16 :goto_1

    .line 273
    .line 274
    :cond_9
    if-eqz v3, :cond_e

    .line 275
    .line 276
    iget-object v2, p0, Le5/b;->P:Ljava/lang/Object;

    .line 277
    .line 278
    if-eqz v2, :cond_a

    .line 279
    .line 280
    iput v7, v3, Le5/b;->j0:I

    .line 281
    .line 282
    iput-object v2, v3, Le5/b;->P:Ljava/lang/Object;

    .line 283
    .line 284
    iget v1, p0, Le5/b;->m:I

    .line 285
    .line 286
    invoke-virtual {v3, v1}, Le5/b;->k(I)Le5/b;

    .line 287
    .line 288
    .line 289
    move-result-object v1

    .line 290
    iget v2, p0, Le5/b;->s:I

    .line 291
    .line 292
    invoke-virtual {v1, v2}, Le5/b;->m(I)V

    .line 293
    .line 294
    .line 295
    goto :goto_4

    .line 296
    :cond_a
    iget-object v2, p0, Le5/b;->Q:Ljava/lang/Object;

    .line 297
    .line 298
    if-eqz v2, :cond_b

    .line 299
    .line 300
    invoke-virtual {v3, v2}, Le5/b;->i(Ljava/lang/Object;)V

    .line 301
    .line 302
    .line 303
    iget v1, p0, Le5/b;->m:I

    .line 304
    .line 305
    invoke-virtual {v3, v1}, Le5/b;->k(I)Le5/b;

    .line 306
    .line 307
    .line 308
    move-result-object v1

    .line 309
    iget v2, p0, Le5/b;->s:I

    .line 310
    .line 311
    invoke-virtual {v1, v2}, Le5/b;->m(I)V

    .line 312
    .line 313
    .line 314
    goto :goto_4

    .line 315
    :cond_b
    iget-object v2, p0, Le5/b;->L:Ljava/lang/Object;

    .line 316
    .line 317
    if-eqz v2, :cond_c

    .line 318
    .line 319
    iput v7, v3, Le5/b;->j0:I

    .line 320
    .line 321
    iput-object v2, v3, Le5/b;->P:Ljava/lang/Object;

    .line 322
    .line 323
    iget v1, p0, Le5/b;->k:I

    .line 324
    .line 325
    invoke-virtual {v3, v1}, Le5/b;->k(I)Le5/b;

    .line 326
    .line 327
    .line 328
    move-result-object v1

    .line 329
    iget v2, p0, Le5/b;->q:I

    .line 330
    .line 331
    invoke-virtual {v1, v2}, Le5/b;->m(I)V

    .line 332
    .line 333
    .line 334
    goto :goto_4

    .line 335
    :cond_c
    iget-object v2, p0, Le5/b;->M:Ljava/lang/Object;

    .line 336
    .line 337
    if-eqz v2, :cond_d

    .line 338
    .line 339
    invoke-virtual {v3, v2}, Le5/b;->i(Ljava/lang/Object;)V

    .line 340
    .line 341
    .line 342
    iget v1, p0, Le5/b;->k:I

    .line 343
    .line 344
    invoke-virtual {v3, v1}, Le5/b;->k(I)Le5/b;

    .line 345
    .line 346
    .line 347
    move-result-object v1

    .line 348
    iget v2, p0, Le5/b;->q:I

    .line 349
    .line 350
    invoke-virtual {v1, v2}, Le5/b;->m(I)V

    .line 351
    .line 352
    .line 353
    goto :goto_4

    .line 354
    :cond_d
    iget-object v2, v3, Le5/b;->a:Ljava/lang/Object;

    .line 355
    .line 356
    invoke-virtual {v2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 357
    .line 358
    .line 359
    move-result-object v2

    .line 360
    invoke-virtual {v3, v1}, Le5/b;->i(Ljava/lang/Object;)V

    .line 361
    .line 362
    .line 363
    invoke-virtual {p0, v2}, Lf5/c;->u(Ljava/lang/String;)F

    .line 364
    .line 365
    .line 366
    move-result v1

    .line 367
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 368
    .line 369
    .line 370
    move-result-object v1

    .line 371
    invoke-virtual {v3, v1}, Le5/b;->l(Ljava/lang/Float;)Le5/b;

    .line 372
    .line 373
    .line 374
    move-result-object v1

    .line 375
    invoke-virtual {p0, v2}, Lf5/c;->t(Ljava/lang/String;)F

    .line 376
    .line 377
    .line 378
    move-result v2

    .line 379
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 380
    .line 381
    .line 382
    move-result-object v2

    .line 383
    invoke-virtual {v1, v2}, Le5/b;->n(Ljava/lang/Float;)V

    .line 384
    .line 385
    .line 386
    :cond_e
    :goto_4
    if-nez v4, :cond_f

    .line 387
    .line 388
    goto :goto_5

    .line 389
    :cond_f
    iget v1, p0, Lf5/c;->n0:F

    .line 390
    .line 391
    const/high16 v2, 0x3f000000    # 0.5f

    .line 392
    .line 393
    cmpl-float v2, v1, v2

    .line 394
    .line 395
    if-eqz v2, :cond_10

    .line 396
    .line 397
    iput v1, v4, Le5/b;->h:F

    .line 398
    .line 399
    :cond_10
    iget-object p0, p0, Lf5/c;->t0:Le5/j;

    .line 400
    .line 401
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 402
    .line 403
    .line 404
    move-result p0

    .line 405
    if-eqz p0, :cond_13

    .line 406
    .line 407
    const/4 v0, 0x1

    .line 408
    if-eq p0, v0, :cond_12

    .line 409
    .line 410
    const/4 v0, 0x2

    .line 411
    if-eq p0, v0, :cond_11

    .line 412
    .line 413
    :goto_5
    return-void

    .line 414
    :cond_11
    iput v0, v4, Le5/b;->d:I

    .line 415
    .line 416
    return-void

    .line 417
    :cond_12
    iput v0, v4, Le5/b;->d:I

    .line 418
    .line 419
    return-void

    .line 420
    :cond_13
    iput v0, v4, Le5/b;->d:I

    .line 421
    .line 422
    return-void
.end method
