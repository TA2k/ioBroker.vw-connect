.class public final Lal0/n0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Ljava/util/List;

.field public synthetic f:Ljava/util/List;

.field public synthetic g:Lxj0/r;


# direct methods
.method public synthetic constructor <init>(ILkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lal0/n0;->d:I

    .line 2
    .line 3
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget p0, p0, Lal0/n0;->d:I

    .line 2
    .line 3
    check-cast p1, Ljava/util/List;

    .line 4
    .line 5
    check-cast p2, Ljava/util/List;

    .line 6
    .line 7
    check-cast p3, Lxj0/r;

    .line 8
    .line 9
    check-cast p4, Lkotlin/coroutines/Continuation;

    .line 10
    .line 11
    packed-switch p0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    new-instance p0, Lal0/n0;

    .line 15
    .line 16
    const/4 v0, 0x4

    .line 17
    const/4 v1, 0x1

    .line 18
    invoke-direct {p0, v0, p4, v1}, Lal0/n0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 19
    .line 20
    .line 21
    check-cast p1, Ljava/util/List;

    .line 22
    .line 23
    iput-object p1, p0, Lal0/n0;->e:Ljava/util/List;

    .line 24
    .line 25
    check-cast p2, Ljava/util/List;

    .line 26
    .line 27
    iput-object p2, p0, Lal0/n0;->f:Ljava/util/List;

    .line 28
    .line 29
    iput-object p3, p0, Lal0/n0;->g:Lxj0/r;

    .line 30
    .line 31
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    invoke-virtual {p0, p1}, Lal0/n0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0

    .line 38
    :pswitch_0
    new-instance p0, Lal0/n0;

    .line 39
    .line 40
    const/4 v0, 0x4

    .line 41
    const/4 v1, 0x0

    .line 42
    invoke-direct {p0, v0, p4, v1}, Lal0/n0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 43
    .line 44
    .line 45
    check-cast p1, Ljava/util/List;

    .line 46
    .line 47
    iput-object p1, p0, Lal0/n0;->e:Ljava/util/List;

    .line 48
    .line 49
    check-cast p2, Ljava/util/List;

    .line 50
    .line 51
    iput-object p2, p0, Lal0/n0;->f:Ljava/util/List;

    .line 52
    .line 53
    iput-object p3, p0, Lal0/n0;->g:Lxj0/r;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lal0/n0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    nop

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lal0/n0;->d:I

    .line 4
    .line 5
    const/16 v2, 0x10

    .line 6
    .line 7
    const/16 v3, 0xa

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    packed-switch v1, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    iget-object v1, v0, Lal0/n0;->e:Ljava/util/List;

    .line 14
    .line 15
    check-cast v1, Ljava/util/List;

    .line 16
    .line 17
    iget-object v5, v0, Lal0/n0;->f:Ljava/util/List;

    .line 18
    .line 19
    check-cast v5, Ljava/util/List;

    .line 20
    .line 21
    iget-object v0, v0, Lal0/n0;->g:Lxj0/r;

    .line 22
    .line 23
    sget-object v6, Lqx0/a;->d:Lqx0/a;

    .line 24
    .line 25
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    check-cast v5, Ljava/lang/Iterable;

    .line 29
    .line 30
    invoke-static {v5, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 31
    .line 32
    .line 33
    move-result v6

    .line 34
    invoke-static {v6}, Lmx0/x;->k(I)I

    .line 35
    .line 36
    .line 37
    move-result v6

    .line 38
    if-ge v6, v2, :cond_0

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    move v2, v6

    .line 42
    :goto_0
    new-instance v6, Ljava/util/LinkedHashMap;

    .line 43
    .line 44
    invoke-direct {v6, v2}, Ljava/util/LinkedHashMap;-><init>(I)V

    .line 45
    .line 46
    .line 47
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 52
    .line 53
    .line 54
    move-result v5

    .line 55
    if-eqz v5, :cond_1

    .line 56
    .line 57
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v5

    .line 61
    move-object v7, v5

    .line 62
    check-cast v7, Lbl0/w;

    .line 63
    .line 64
    iget-object v7, v7, Lbl0/w;->a:Ljava/lang/String;

    .line 65
    .line 66
    invoke-interface {v6, v7, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_1
    if-eqz v1, :cond_14

    .line 71
    .line 72
    check-cast v1, Ljava/lang/Iterable;

    .line 73
    .line 74
    new-instance v2, Ljava/util/ArrayList;

    .line 75
    .line 76
    invoke-static {v1, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 77
    .line 78
    .line 79
    move-result v3

    .line 80
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 81
    .line 82
    .line 83
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 88
    .line 89
    .line 90
    move-result v3

    .line 91
    if-eqz v3, :cond_13

    .line 92
    .line 93
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v3

    .line 97
    check-cast v3, Lbl0/g0;

    .line 98
    .line 99
    invoke-interface {v3}, Lbl0/g0;->getId()Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v5

    .line 103
    if-eqz v0, :cond_2

    .line 104
    .line 105
    invoke-virtual {v0}, Lxj0/r;->b()Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object v7

    .line 109
    goto :goto_3

    .line 110
    :cond_2
    move-object v7, v4

    .line 111
    :goto_3
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result v13

    .line 115
    invoke-interface {v3}, Lbl0/g0;->getId()Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object v5

    .line 119
    invoke-virtual {v6, v5}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v5

    .line 123
    check-cast v5, Lbl0/w;

    .line 124
    .line 125
    instance-of v7, v3, Lbl0/r;

    .line 126
    .line 127
    const v8, 0x7f0802dc

    .line 128
    .line 129
    .line 130
    if-eqz v7, :cond_9

    .line 131
    .line 132
    check-cast v3, Lbl0/r;

    .line 133
    .line 134
    iget-object v9, v3, Lbl0/r;->a:Ljava/lang/String;

    .line 135
    .line 136
    iget-object v10, v3, Lbl0/r;->e:Lxj0/f;

    .line 137
    .line 138
    iget-object v7, v3, Lbl0/r;->j:Lbl0/q;

    .line 139
    .line 140
    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    .line 141
    .line 142
    .line 143
    move-result v7

    .line 144
    if-eqz v7, :cond_5

    .line 145
    .line 146
    const/4 v8, 0x1

    .line 147
    if-eq v7, v8, :cond_4

    .line 148
    .line 149
    const/4 v8, 0x2

    .line 150
    if-ne v7, v8, :cond_3

    .line 151
    .line 152
    goto :goto_4

    .line 153
    :cond_3
    new-instance v0, La8/r0;

    .line 154
    .line 155
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 156
    .line 157
    .line 158
    throw v0

    .line 159
    :cond_4
    :goto_4
    const v8, 0x7f0802d9

    .line 160
    .line 161
    .line 162
    :cond_5
    move v12, v8

    .line 163
    xor-int/lit8 v11, v13, 0x1

    .line 164
    .line 165
    iget-object v7, v3, Lbl0/r;->h:Ljava/lang/Integer;

    .line 166
    .line 167
    if-eqz v7, :cond_6

    .line 168
    .line 169
    invoke-virtual {v7}, Ljava/lang/Number;->intValue()I

    .line 170
    .line 171
    .line 172
    move-result v7

    .line 173
    iget v3, v3, Lbl0/r;->i:I

    .line 174
    .line 175
    new-instance v8, Ljava/lang/StringBuilder;

    .line 176
    .line 177
    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    .line 178
    .line 179
    .line 180
    invoke-virtual {v8, v7}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 181
    .line 182
    .line 183
    const-string v7, "/"

    .line 184
    .line 185
    invoke-virtual {v8, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 186
    .line 187
    .line 188
    invoke-virtual {v8, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 189
    .line 190
    .line 191
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 192
    .line 193
    .line 194
    move-result-object v3

    .line 195
    move-object v14, v3

    .line 196
    goto :goto_5

    .line 197
    :cond_6
    move-object v14, v4

    .line 198
    :goto_5
    if-eqz v5, :cond_7

    .line 199
    .line 200
    iget-object v3, v5, Lbl0/w;->d:Ljava/net/URL;

    .line 201
    .line 202
    move-object v15, v3

    .line 203
    goto :goto_6

    .line 204
    :cond_7
    move-object v15, v4

    .line 205
    :goto_6
    if-eqz v5, :cond_8

    .line 206
    .line 207
    iget-object v3, v5, Lbl0/w;->c:Ljava/lang/String;

    .line 208
    .line 209
    move-object/from16 v16, v3

    .line 210
    .line 211
    goto :goto_7

    .line 212
    :cond_8
    move-object/from16 v16, v4

    .line 213
    .line 214
    :goto_7
    new-instance v8, Lxj0/k;

    .line 215
    .line 216
    invoke-direct/range {v8 .. v16}, Lxj0/k;-><init>(Ljava/lang/String;Lxj0/f;ZIZLjava/lang/String;Ljava/net/URL;Ljava/lang/String;)V

    .line 217
    .line 218
    .line 219
    goto :goto_c

    .line 220
    :cond_9
    invoke-interface {v3}, Lbl0/g0;->getId()Ljava/lang/String;

    .line 221
    .line 222
    .line 223
    move-result-object v9

    .line 224
    invoke-interface {v3}, Lbl0/g0;->getLocation()Lxj0/f;

    .line 225
    .line 226
    .line 227
    move-result-object v10

    .line 228
    if-eqz v7, :cond_a

    .line 229
    .line 230
    :goto_8
    move v12, v8

    .line 231
    goto :goto_9

    .line 232
    :cond_a
    instance-of v7, v3, Lbl0/u;

    .line 233
    .line 234
    if-eqz v7, :cond_b

    .line 235
    .line 236
    const v8, 0x7f08047b

    .line 237
    .line 238
    .line 239
    goto :goto_8

    .line 240
    :cond_b
    instance-of v7, v3, Lbl0/d0;

    .line 241
    .line 242
    if-eqz v7, :cond_c

    .line 243
    .line 244
    const v8, 0x7f08044b

    .line 245
    .line 246
    .line 247
    goto :goto_8

    .line 248
    :cond_c
    instance-of v7, v3, Lbl0/e0;

    .line 249
    .line 250
    if-eqz v7, :cond_d

    .line 251
    .line 252
    const v8, 0x7f0803c6

    .line 253
    .line 254
    .line 255
    goto :goto_8

    .line 256
    :cond_d
    instance-of v7, v3, Lbl0/v;

    .line 257
    .line 258
    if-eqz v7, :cond_e

    .line 259
    .line 260
    const v8, 0x7f0803e8

    .line 261
    .line 262
    .line 263
    goto :goto_8

    .line 264
    :cond_e
    instance-of v7, v3, Lbl0/f0;

    .line 265
    .line 266
    if-eqz v7, :cond_f

    .line 267
    .line 268
    const v8, 0x7f080408

    .line 269
    .line 270
    .line 271
    goto :goto_8

    .line 272
    :cond_f
    instance-of v3, v3, Lbl0/w;

    .line 273
    .line 274
    if-eqz v3, :cond_12

    .line 275
    .line 276
    const v8, 0x7f080416

    .line 277
    .line 278
    .line 279
    goto :goto_8

    .line 280
    :goto_9
    xor-int/lit8 v11, v13, 0x1

    .line 281
    .line 282
    if-eqz v5, :cond_10

    .line 283
    .line 284
    iget-object v3, v5, Lbl0/w;->d:Ljava/net/URL;

    .line 285
    .line 286
    move-object v14, v3

    .line 287
    goto :goto_a

    .line 288
    :cond_10
    move-object v14, v4

    .line 289
    :goto_a
    if-eqz v5, :cond_11

    .line 290
    .line 291
    iget-object v3, v5, Lbl0/w;->c:Ljava/lang/String;

    .line 292
    .line 293
    move-object v15, v3

    .line 294
    goto :goto_b

    .line 295
    :cond_11
    move-object v15, v4

    .line 296
    :goto_b
    new-instance v8, Lxj0/p;

    .line 297
    .line 298
    invoke-direct/range {v8 .. v15}, Lxj0/p;-><init>(Ljava/lang/String;Lxj0/f;ZIZLjava/net/URL;Ljava/lang/String;)V

    .line 299
    .line 300
    .line 301
    :goto_c
    invoke-virtual {v2, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 302
    .line 303
    .line 304
    goto/16 :goto_2

    .line 305
    .line 306
    :cond_12
    new-instance v0, La8/r0;

    .line 307
    .line 308
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 309
    .line 310
    .line 311
    throw v0

    .line 312
    :cond_13
    move-object v4, v2

    .line 313
    :cond_14
    if-nez v4, :cond_15

    .line 314
    .line 315
    sget-object v4, Lmx0/s;->d:Lmx0/s;

    .line 316
    .line 317
    :cond_15
    return-object v4

    .line 318
    :pswitch_0
    iget-object v1, v0, Lal0/n0;->e:Ljava/util/List;

    .line 319
    .line 320
    check-cast v1, Ljava/util/List;

    .line 321
    .line 322
    iget-object v5, v0, Lal0/n0;->f:Ljava/util/List;

    .line 323
    .line 324
    check-cast v5, Ljava/util/List;

    .line 325
    .line 326
    iget-object v0, v0, Lal0/n0;->g:Lxj0/r;

    .line 327
    .line 328
    sget-object v6, Lqx0/a;->d:Lqx0/a;

    .line 329
    .line 330
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 331
    .line 332
    .line 333
    if-eqz v5, :cond_17

    .line 334
    .line 335
    check-cast v5, Ljava/lang/Iterable;

    .line 336
    .line 337
    invoke-static {v5, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 338
    .line 339
    .line 340
    move-result v3

    .line 341
    invoke-static {v3}, Lmx0/x;->k(I)I

    .line 342
    .line 343
    .line 344
    move-result v3

    .line 345
    if-ge v3, v2, :cond_16

    .line 346
    .line 347
    goto :goto_d

    .line 348
    :cond_16
    move v2, v3

    .line 349
    :goto_d
    new-instance v3, Ljava/util/LinkedHashMap;

    .line 350
    .line 351
    invoke-direct {v3, v2}, Ljava/util/LinkedHashMap;-><init>(I)V

    .line 352
    .line 353
    .line 354
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 355
    .line 356
    .line 357
    move-result-object v2

    .line 358
    :goto_e
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 359
    .line 360
    .line 361
    move-result v5

    .line 362
    if-eqz v5, :cond_18

    .line 363
    .line 364
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 365
    .line 366
    .line 367
    move-result-object v5

    .line 368
    move-object v6, v5

    .line 369
    check-cast v6, Lbl0/g0;

    .line 370
    .line 371
    invoke-interface {v6}, Lbl0/g0;->getId()Ljava/lang/String;

    .line 372
    .line 373
    .line 374
    move-result-object v6

    .line 375
    invoke-interface {v3, v6, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 376
    .line 377
    .line 378
    goto :goto_e

    .line 379
    :cond_17
    sget-object v3, Lmx0/t;->d:Lmx0/t;

    .line 380
    .line 381
    :cond_18
    check-cast v1, Ljava/lang/Iterable;

    .line 382
    .line 383
    new-instance v2, Ljava/util/ArrayList;

    .line 384
    .line 385
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 386
    .line 387
    .line 388
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 389
    .line 390
    .line 391
    move-result-object v1

    .line 392
    :cond_19
    :goto_f
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 393
    .line 394
    .line 395
    move-result v5

    .line 396
    if-eqz v5, :cond_1c

    .line 397
    .line 398
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 399
    .line 400
    .line 401
    move-result-object v5

    .line 402
    check-cast v5, Lbl0/w;

    .line 403
    .line 404
    iget-object v6, v5, Lbl0/w;->a:Ljava/lang/String;

    .line 405
    .line 406
    if-eqz v0, :cond_1a

    .line 407
    .line 408
    invoke-virtual {v0}, Lxj0/r;->b()Ljava/lang/String;

    .line 409
    .line 410
    .line 411
    move-result-object v7

    .line 412
    goto :goto_10

    .line 413
    :cond_1a
    move-object v7, v4

    .line 414
    :goto_10
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 415
    .line 416
    .line 417
    move-result v13

    .line 418
    new-instance v8, Lxj0/m;

    .line 419
    .line 420
    iget-object v9, v5, Lbl0/w;->a:Ljava/lang/String;

    .line 421
    .line 422
    iget-object v10, v5, Lbl0/w;->b:Lxj0/f;

    .line 423
    .line 424
    xor-int/lit8 v11, v13, 0x1

    .line 425
    .line 426
    iget-object v12, v5, Lbl0/w;->d:Ljava/net/URL;

    .line 427
    .line 428
    iget-object v14, v5, Lbl0/w;->c:Ljava/lang/String;

    .line 429
    .line 430
    invoke-direct/range {v8 .. v14}, Lxj0/m;-><init>(Ljava/lang/String;Lxj0/f;ZLjava/net/URL;ZLjava/lang/String;)V

    .line 431
    .line 432
    .line 433
    iget-object v5, v5, Lbl0/w;->a:Ljava/lang/String;

    .line 434
    .line 435
    invoke-interface {v3, v5}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 436
    .line 437
    .line 438
    move-result-object v5

    .line 439
    if-nez v5, :cond_1b

    .line 440
    .line 441
    goto :goto_11

    .line 442
    :cond_1b
    move-object v8, v4

    .line 443
    :goto_11
    if-eqz v8, :cond_19

    .line 444
    .line 445
    invoke-virtual {v2, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 446
    .line 447
    .line 448
    goto :goto_f

    .line 449
    :cond_1c
    return-object v2

    .line 450
    nop

    .line 451
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
