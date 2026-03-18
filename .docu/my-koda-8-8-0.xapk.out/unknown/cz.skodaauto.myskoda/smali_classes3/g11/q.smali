.class public final Lg11/q;
.super Ll11/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lj11/u;

.field public final b:Lg11/m;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lj11/u;

    .line 5
    .line 6
    invoke-direct {v0}, Lj11/s;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lg11/q;->a:Lj11/u;

    .line 10
    .line 11
    new-instance v0, Lg11/m;

    .line 12
    .line 13
    invoke-direct {v0}, Lg11/m;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lg11/q;->b:Lg11/m;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final a(Lk11/b;)V
    .locals 8

    .line 1
    iget-object p0, p0, Lg11/q;->b:Lg11/m;

    .line 2
    .line 3
    iget-object v0, p0, Lg11/m;->b:Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lg11/m;->a:I

    .line 9
    .line 10
    const/4 v2, 0x6

    .line 11
    if-ne v1, v2, :cond_0

    .line 12
    .line 13
    goto/16 :goto_5

    .line 14
    .line 15
    :cond_0
    new-instance v1, Ljava/util/ArrayList;

    .line 16
    .line 17
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    new-instance p1, Lh11/h;

    .line 24
    .line 25
    invoke-direct {p1, v1}, Lh11/h;-><init>(Ljava/util/List;)V

    .line 26
    .line 27
    .line 28
    :cond_1
    :goto_0
    invoke-virtual {p1}, Lh11/h;->f()Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-eqz v1, :cond_19

    .line 33
    .line 34
    iget v1, p0, Lg11/m;->a:I

    .line 35
    .line 36
    invoke-static {v1}, Lu/w;->o(I)I

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    const/4 v3, 0x2

    .line 41
    const/16 v4, 0xa

    .line 42
    .line 43
    if-eqz v1, :cond_16

    .line 44
    .line 45
    const/4 v5, 0x3

    .line 46
    const/4 v6, 0x1

    .line 47
    if-eq v1, v6, :cond_10

    .line 48
    .line 49
    const/4 v7, 0x4

    .line 50
    if-eq v1, v3, :cond_b

    .line 51
    .line 52
    if-eq v1, v5, :cond_6

    .line 53
    .line 54
    if-ne v1, v7, :cond_5

    .line 55
    .line 56
    invoke-virtual {p1}, Lh11/h;->n()Lb8/i;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    iget-char v3, p0, Lg11/m;->g:C

    .line 61
    .line 62
    invoke-static {p1, v3}, Llp/o1;->c(Lh11/h;C)Z

    .line 63
    .line 64
    .line 65
    move-result v3

    .line 66
    if-nez v3, :cond_2

    .line 67
    .line 68
    goto/16 :goto_4

    .line 69
    .line 70
    :cond_2
    iget-object v3, p0, Lg11/m;->h:Ljava/lang/StringBuilder;

    .line 71
    .line 72
    invoke-virtual {p1}, Lh11/h;->n()Lb8/i;

    .line 73
    .line 74
    .line 75
    move-result-object v5

    .line 76
    invoke-virtual {p1, v1, v5}, Lh11/h;->e(Lb8/i;Lb8/i;)Lbn/c;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    invoke-virtual {v1}, Lbn/c;->i()Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v1

    .line 84
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    invoke-virtual {p1}, Lh11/h;->f()Z

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    if-nez v1, :cond_3

    .line 92
    .line 93
    iget-object v1, p0, Lg11/m;->h:Ljava/lang/StringBuilder;

    .line 94
    .line 95
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    goto :goto_0

    .line 99
    :cond_3
    invoke-virtual {p1}, Lh11/h;->j()V

    .line 100
    .line 101
    .line 102
    invoke-virtual {p1}, Lh11/h;->p()I

    .line 103
    .line 104
    .line 105
    invoke-virtual {p1}, Lh11/h;->f()Z

    .line 106
    .line 107
    .line 108
    move-result v1

    .line 109
    if-eqz v1, :cond_4

    .line 110
    .line 111
    goto/16 :goto_4

    .line 112
    .line 113
    :cond_4
    iput-boolean v6, p0, Lg11/m;->i:Z

    .line 114
    .line 115
    invoke-virtual {p0}, Lg11/m;->a()V

    .line 116
    .line 117
    .line 118
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 119
    .line 120
    .line 121
    iput v6, p0, Lg11/m;->a:I

    .line 122
    .line 123
    goto :goto_0

    .line 124
    :cond_5
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 125
    .line 126
    iget p0, p0, Lg11/m;->a:I

    .line 127
    .line 128
    packed-switch p0, :pswitch_data_0

    .line 129
    .line 130
    .line 131
    const-string p0, "null"

    .line 132
    .line 133
    goto :goto_1

    .line 134
    :pswitch_0
    const-string p0, "PARAGRAPH"

    .line 135
    .line 136
    goto :goto_1

    .line 137
    :pswitch_1
    const-string p0, "TITLE"

    .line 138
    .line 139
    goto :goto_1

    .line 140
    :pswitch_2
    const-string p0, "START_TITLE"

    .line 141
    .line 142
    goto :goto_1

    .line 143
    :pswitch_3
    const-string p0, "DESTINATION"

    .line 144
    .line 145
    goto :goto_1

    .line 146
    :pswitch_4
    const-string p0, "LABEL"

    .line 147
    .line 148
    goto :goto_1

    .line 149
    :pswitch_5
    const-string p0, "START_DEFINITION"

    .line 150
    .line 151
    :goto_1
    const-string v0, "Unknown parsing state: "

    .line 152
    .line 153
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object p0

    .line 157
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    throw p1

    .line 161
    :cond_6
    invoke-virtual {p1}, Lh11/h;->p()I

    .line 162
    .line 163
    .line 164
    invoke-virtual {p1}, Lh11/h;->f()Z

    .line 165
    .line 166
    .line 167
    move-result v1

    .line 168
    if-nez v1, :cond_7

    .line 169
    .line 170
    iput v6, p0, Lg11/m;->a:I

    .line 171
    .line 172
    goto/16 :goto_0

    .line 173
    .line 174
    :cond_7
    const/4 v1, 0x0

    .line 175
    iput-char v1, p0, Lg11/m;->g:C

    .line 176
    .line 177
    invoke-virtual {p1}, Lh11/h;->m()C

    .line 178
    .line 179
    .line 180
    move-result v1

    .line 181
    const/16 v3, 0x22

    .line 182
    .line 183
    if-eq v1, v3, :cond_9

    .line 184
    .line 185
    const/16 v3, 0x27

    .line 186
    .line 187
    if-eq v1, v3, :cond_9

    .line 188
    .line 189
    const/16 v3, 0x28

    .line 190
    .line 191
    if-eq v1, v3, :cond_8

    .line 192
    .line 193
    goto :goto_2

    .line 194
    :cond_8
    const/16 v1, 0x29

    .line 195
    .line 196
    iput-char v1, p0, Lg11/m;->g:C

    .line 197
    .line 198
    goto :goto_2

    .line 199
    :cond_9
    iput-char v1, p0, Lg11/m;->g:C

    .line 200
    .line 201
    :goto_2
    iget-char v1, p0, Lg11/m;->g:C

    .line 202
    .line 203
    if-eqz v1, :cond_a

    .line 204
    .line 205
    const/4 v1, 0x5

    .line 206
    iput v1, p0, Lg11/m;->a:I

    .line 207
    .line 208
    new-instance v1, Ljava/lang/StringBuilder;

    .line 209
    .line 210
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 211
    .line 212
    .line 213
    iput-object v1, p0, Lg11/m;->h:Ljava/lang/StringBuilder;

    .line 214
    .line 215
    invoke-virtual {p1}, Lh11/h;->j()V

    .line 216
    .line 217
    .line 218
    invoke-virtual {p1}, Lh11/h;->f()Z

    .line 219
    .line 220
    .line 221
    move-result v1

    .line 222
    if-nez v1, :cond_1

    .line 223
    .line 224
    iget-object v1, p0, Lg11/m;->h:Ljava/lang/StringBuilder;

    .line 225
    .line 226
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 227
    .line 228
    .line 229
    goto/16 :goto_0

    .line 230
    .line 231
    :cond_a
    invoke-virtual {p0}, Lg11/m;->a()V

    .line 232
    .line 233
    .line 234
    iput v6, p0, Lg11/m;->a:I

    .line 235
    .line 236
    goto/16 :goto_0

    .line 237
    .line 238
    :cond_b
    invoke-virtual {p1}, Lh11/h;->p()I

    .line 239
    .line 240
    .line 241
    invoke-virtual {p1}, Lh11/h;->n()Lb8/i;

    .line 242
    .line 243
    .line 244
    move-result-object v1

    .line 245
    invoke-static {p1}, Llp/o1;->a(Lh11/h;)Z

    .line 246
    .line 247
    .line 248
    move-result v3

    .line 249
    if-nez v3, :cond_c

    .line 250
    .line 251
    goto/16 :goto_4

    .line 252
    .line 253
    :cond_c
    invoke-virtual {p1}, Lh11/h;->n()Lb8/i;

    .line 254
    .line 255
    .line 256
    move-result-object v3

    .line 257
    invoke-virtual {p1, v1, v3}, Lh11/h;->e(Lb8/i;Lb8/i;)Lbn/c;

    .line 258
    .line 259
    .line 260
    move-result-object v1

    .line 261
    invoke-virtual {v1}, Lbn/c;->i()Ljava/lang/String;

    .line 262
    .line 263
    .line 264
    move-result-object v1

    .line 265
    const-string v3, "<"

    .line 266
    .line 267
    invoke-virtual {v1, v3}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 268
    .line 269
    .line 270
    move-result v3

    .line 271
    if-eqz v3, :cond_d

    .line 272
    .line 273
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 274
    .line 275
    .line 276
    move-result v3

    .line 277
    sub-int/2addr v3, v6

    .line 278
    invoke-virtual {v1, v6, v3}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 279
    .line 280
    .line 281
    move-result-object v1

    .line 282
    :cond_d
    iput-object v1, p0, Lg11/m;->f:Ljava/lang/String;

    .line 283
    .line 284
    invoke-virtual {p1}, Lh11/h;->p()I

    .line 285
    .line 286
    .line 287
    move-result v1

    .line 288
    invoke-virtual {p1}, Lh11/h;->f()Z

    .line 289
    .line 290
    .line 291
    move-result v3

    .line 292
    if-nez v3, :cond_e

    .line 293
    .line 294
    iput-boolean v6, p0, Lg11/m;->i:Z

    .line 295
    .line 296
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 297
    .line 298
    .line 299
    goto :goto_3

    .line 300
    :cond_e
    if-nez v1, :cond_f

    .line 301
    .line 302
    goto/16 :goto_4

    .line 303
    .line 304
    :cond_f
    :goto_3
    iput v7, p0, Lg11/m;->a:I

    .line 305
    .line 306
    goto/16 :goto_0

    .line 307
    .line 308
    :cond_10
    invoke-virtual {p1}, Lh11/h;->n()Lb8/i;

    .line 309
    .line 310
    .line 311
    move-result-object v1

    .line 312
    invoke-static {p1}, Llp/o1;->b(Lh11/h;)Z

    .line 313
    .line 314
    .line 315
    move-result v3

    .line 316
    if-nez v3, :cond_11

    .line 317
    .line 318
    goto :goto_4

    .line 319
    :cond_11
    iget-object v3, p0, Lg11/m;->e:Ljava/lang/StringBuilder;

    .line 320
    .line 321
    invoke-virtual {p1}, Lh11/h;->n()Lb8/i;

    .line 322
    .line 323
    .line 324
    move-result-object v6

    .line 325
    invoke-virtual {p1, v1, v6}, Lh11/h;->e(Lb8/i;Lb8/i;)Lbn/c;

    .line 326
    .line 327
    .line 328
    move-result-object v1

    .line 329
    invoke-virtual {v1}, Lbn/c;->i()Ljava/lang/String;

    .line 330
    .line 331
    .line 332
    move-result-object v1

    .line 333
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 334
    .line 335
    .line 336
    invoke-virtual {p1}, Lh11/h;->f()Z

    .line 337
    .line 338
    .line 339
    move-result v1

    .line 340
    if-nez v1, :cond_12

    .line 341
    .line 342
    iget-object v1, p0, Lg11/m;->e:Ljava/lang/StringBuilder;

    .line 343
    .line 344
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 345
    .line 346
    .line 347
    goto/16 :goto_0

    .line 348
    .line 349
    :cond_12
    const/16 v1, 0x5d

    .line 350
    .line 351
    invoke-virtual {p1, v1}, Lh11/h;->k(C)Z

    .line 352
    .line 353
    .line 354
    move-result v1

    .line 355
    if-eqz v1, :cond_17

    .line 356
    .line 357
    const/16 v1, 0x3a

    .line 358
    .line 359
    invoke-virtual {p1, v1}, Lh11/h;->k(C)Z

    .line 360
    .line 361
    .line 362
    move-result v1

    .line 363
    if-nez v1, :cond_13

    .line 364
    .line 365
    goto :goto_4

    .line 366
    :cond_13
    iget-object v1, p0, Lg11/m;->e:Ljava/lang/StringBuilder;

    .line 367
    .line 368
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->length()I

    .line 369
    .line 370
    .line 371
    move-result v1

    .line 372
    const/16 v3, 0x3e7

    .line 373
    .line 374
    if-le v1, v3, :cond_14

    .line 375
    .line 376
    goto :goto_4

    .line 377
    :cond_14
    iget-object v1, p0, Lg11/m;->e:Ljava/lang/StringBuilder;

    .line 378
    .line 379
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 380
    .line 381
    .line 382
    move-result-object v1

    .line 383
    invoke-static {v1}, Li11/a;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 384
    .line 385
    .line 386
    move-result-object v1

    .line 387
    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    .line 388
    .line 389
    .line 390
    move-result v1

    .line 391
    if-eqz v1, :cond_15

    .line 392
    .line 393
    goto :goto_4

    .line 394
    :cond_15
    iput v5, p0, Lg11/m;->a:I

    .line 395
    .line 396
    invoke-virtual {p1}, Lh11/h;->p()I

    .line 397
    .line 398
    .line 399
    goto/16 :goto_0

    .line 400
    .line 401
    :cond_16
    invoke-virtual {p1}, Lh11/h;->p()I

    .line 402
    .line 403
    .line 404
    const/16 v1, 0x5b

    .line 405
    .line 406
    invoke-virtual {p1, v1}, Lh11/h;->k(C)Z

    .line 407
    .line 408
    .line 409
    move-result v1

    .line 410
    if-nez v1, :cond_18

    .line 411
    .line 412
    :cond_17
    :goto_4
    iput v2, p0, Lg11/m;->a:I

    .line 413
    .line 414
    return-void

    .line 415
    :cond_18
    iput v3, p0, Lg11/m;->a:I

    .line 416
    .line 417
    new-instance v1, Ljava/lang/StringBuilder;

    .line 418
    .line 419
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 420
    .line 421
    .line 422
    iput-object v1, p0, Lg11/m;->e:Ljava/lang/StringBuilder;

    .line 423
    .line 424
    invoke-virtual {p1}, Lh11/h;->f()Z

    .line 425
    .line 426
    .line 427
    move-result v1

    .line 428
    if-nez v1, :cond_1

    .line 429
    .line 430
    iget-object v1, p0, Lg11/m;->e:Ljava/lang/StringBuilder;

    .line 431
    .line 432
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 433
    .line 434
    .line 435
    goto/16 :goto_0

    .line 436
    .line 437
    :cond_19
    :goto_5
    return-void

    .line 438
    nop

    .line 439
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final b(Lj11/w;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lg11/q;->b:Lg11/m;

    .line 2
    .line 3
    iget-object p0, p0, Lg11/m;->d:Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final e()V
    .locals 3

    .line 1
    iget-object v0, p0, Lg11/q;->b:Lg11/m;

    .line 2
    .line 3
    iget-object v1, v0, Lg11/m;->b:Ljava/util/ArrayList;

    .line 4
    .line 5
    new-instance v2, Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 11
    .line 12
    .line 13
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    iget-object p0, p0, Lg11/q;->a:Lj11/u;

    .line 18
    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    invoke-virtual {p0}, Lj11/s;->i()V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    iget-object v0, v0, Lg11/m;->d:Ljava/util/ArrayList;

    .line 26
    .line 27
    invoke-virtual {p0, v0}, Lj11/s;->g(Ljava/util/List;)V

    .line 28
    .line 29
    .line 30
    return-void
.end method

.method public final f()Lj11/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lg11/q;->a:Lj11/u;

    .line 2
    .line 3
    return-object p0
.end method

.method public final h(Lg11/l;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lg11/q;->b:Lg11/m;

    .line 2
    .line 3
    iget-object v0, v0, Lg11/m;->b:Ljava/util/ArrayList;

    .line 4
    .line 5
    new-instance v1, Lbn/c;

    .line 6
    .line 7
    const/4 v2, 0x4

    .line 8
    invoke-direct {v1, v2}, Lbn/c;-><init>(I)V

    .line 9
    .line 10
    .line 11
    iget-object v2, v1, Lbn/c;->d:Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-virtual {v2, v0}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 14
    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-nez v0, :cond_0

    .line 21
    .line 22
    iget-object p0, p0, Lg11/q;->a:Lj11/u;

    .line 23
    .line 24
    invoke-virtual {p1, v1, p0}, Lg11/l;->e(Lbn/c;Lj11/s;)V

    .line 25
    .line 26
    .line 27
    :cond_0
    return-void
.end method

.method public final i(Lg11/g;)Lc9/h;
    .locals 0

    .line 1
    iget-boolean p0, p1, Lg11/g;->i:Z

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    iget p0, p1, Lg11/g;->c:I

    .line 6
    .line 7
    invoke-static {p0}, Lc9/h;->a(I)Lc9/h;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return-object p0
.end method
