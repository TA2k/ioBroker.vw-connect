.class public final synthetic Le2/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lic/q;Ldc/t;Lac/a0;Z)V
    .locals 1

    .line 1
    const/4 v0, 0x4

    iput v0, p0, Le2/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Le2/g;->f:Ljava/lang/Object;

    iput-object p2, p0, Le2/g;->g:Ljava/lang/Object;

    iput-object p3, p0, Le2/g;->h:Ljava/lang/Object;

    iput-boolean p4, p0, Le2/g;->e:Z

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;ZLjava/lang/Object;I)V
    .locals 0

    .line 2
    iput p5, p0, Le2/g;->d:I

    iput-object p1, p0, Le2/g;->f:Ljava/lang/Object;

    iput-object p2, p0, Le2/g;->g:Ljava/lang/Object;

    iput-boolean p3, p0, Le2/g;->e:Z

    iput-object p4, p0, Le2/g;->h:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;ZLjava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 3
    iput p5, p0, Le2/g;->d:I

    iput-object p1, p0, Le2/g;->f:Ljava/lang/Object;

    iput-boolean p2, p0, Le2/g;->e:Z

    iput-object p3, p0, Le2/g;->g:Ljava/lang/Object;

    iput-object p4, p0, Le2/g;->h:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lz21/b;Lz21/c;Lz21/e;Z)V
    .locals 1

    .line 4
    const/4 v0, 0x3

    iput v0, p0, Le2/g;->d:I

    sget-object v0, Li31/g;->d:Li31/g;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Le2/g;->f:Ljava/lang/Object;

    iput-object p2, p0, Le2/g;->g:Ljava/lang/Object;

    iput-object p3, p0, Le2/g;->h:Ljava/lang/Object;

    iput-boolean p4, p0, Le2/g;->e:Z

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Le2/g;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    iget-object v4, v0, Le2/g;->h:Ljava/lang/Object;

    .line 9
    .line 10
    iget-boolean v5, v0, Le2/g;->e:Z

    .line 11
    .line 12
    iget-object v6, v0, Le2/g;->g:Ljava/lang/Object;

    .line 13
    .line 14
    iget-object v0, v0, Le2/g;->f:Ljava/lang/Object;

    .line 15
    .line 16
    packed-switch v1, :pswitch_data_0

    .line 17
    .line 18
    .line 19
    check-cast v0, Lac/e;

    .line 20
    .line 21
    check-cast v6, Lac/a0;

    .line 22
    .line 23
    check-cast v4, Lxh/e;

    .line 24
    .line 25
    move-object/from16 v1, p1

    .line 26
    .line 27
    check-cast v1, Lhi/a;

    .line 28
    .line 29
    const-string v2, "$this$sdkViewModel"

    .line 30
    .line 31
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    const-string v1, "userLegalCountry"

    .line 35
    .line 36
    invoke-static {v6, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    new-instance v1, Lng/g;

    .line 40
    .line 41
    invoke-direct {v1, v0, v6, v5, v4}, Lng/g;-><init>(Lac/e;Lac/a0;ZLxh/e;)V

    .line 42
    .line 43
    .line 44
    return-object v1

    .line 45
    :pswitch_0
    check-cast v0, Lic/q;

    .line 46
    .line 47
    check-cast v6, Ldc/t;

    .line 48
    .line 49
    check-cast v4, Lac/a0;

    .line 50
    .line 51
    move-object/from16 v1, p1

    .line 52
    .line 53
    check-cast v1, Llx0/b0;

    .line 54
    .line 55
    iget-object v0, v0, Lic/q;->j:Lic/s;

    .line 56
    .line 57
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 58
    .line 59
    .line 60
    const-string v0, "response"

    .line 61
    .line 62
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    iget-object v0, v6, Ldc/t;->b:Ljava/util/List;

    .line 66
    .line 67
    move-object v1, v0

    .line 68
    check-cast v1, Ljava/util/Collection;

    .line 69
    .line 70
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 71
    .line 72
    .line 73
    move-result v1

    .line 74
    if-nez v1, :cond_4

    .line 75
    .line 76
    iget-object v1, v6, Ldc/t;->c:Ljava/lang/String;

    .line 77
    .line 78
    if-eqz v1, :cond_4

    .line 79
    .line 80
    move-object v2, v0

    .line 81
    check-cast v2, Ljava/lang/Iterable;

    .line 82
    .line 83
    new-instance v3, Ljava/util/ArrayList;

    .line 84
    .line 85
    const/16 v6, 0xa

    .line 86
    .line 87
    invoke-static {v2, v6}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 88
    .line 89
    .line 90
    move-result v6

    .line 91
    invoke-direct {v3, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 92
    .line 93
    .line 94
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 95
    .line 96
    .line 97
    move-result-object v6

    .line 98
    :goto_0
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 99
    .line 100
    .line 101
    move-result v7

    .line 102
    if-eqz v7, :cond_0

    .line 103
    .line 104
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v7

    .line 108
    check-cast v7, Lac/a0;

    .line 109
    .line 110
    new-instance v8, Lac/a0;

    .line 111
    .line 112
    iget-object v9, v7, Lac/a0;->d:Ljava/lang/String;

    .line 113
    .line 114
    iget-object v7, v7, Lac/a0;->e:Ljava/lang/String;

    .line 115
    .line 116
    invoke-direct {v8, v9, v7}, Lac/a0;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    invoke-virtual {v3, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    goto :goto_0

    .line 123
    :cond_0
    if-nez v4, :cond_3

    .line 124
    .line 125
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 126
    .line 127
    .line 128
    move-result-object v2

    .line 129
    :cond_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 130
    .line 131
    .line 132
    move-result v4

    .line 133
    if-eqz v4, :cond_2

    .line 134
    .line 135
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v4

    .line 139
    move-object v6, v4

    .line 140
    check-cast v6, Lac/a0;

    .line 141
    .line 142
    iget-object v6, v6, Lac/a0;->e:Ljava/lang/String;

    .line 143
    .line 144
    invoke-static {v6, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 145
    .line 146
    .line 147
    move-result v6

    .line 148
    if-eqz v6, :cond_1

    .line 149
    .line 150
    goto :goto_1

    .line 151
    :cond_2
    const/4 v4, 0x0

    .line 152
    :goto_1
    check-cast v4, Lac/a0;

    .line 153
    .line 154
    if-nez v4, :cond_3

    .line 155
    .line 156
    invoke-static {v0}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v0

    .line 160
    move-object v4, v0

    .line 161
    check-cast v4, Lac/a0;

    .line 162
    .line 163
    :cond_3
    iget-object v0, v4, Lac/a0;->d:Ljava/lang/String;

    .line 164
    .line 165
    new-instance v1, Lic/k;

    .line 166
    .line 167
    invoke-direct {v1, v0, v3, v5}, Lic/k;-><init>(Ljava/lang/String;Ljava/util/ArrayList;Z)V

    .line 168
    .line 169
    .line 170
    goto :goto_3

    .line 171
    :cond_4
    iget-object v0, v6, Ldc/t;->a:Ljava/util/List;

    .line 172
    .line 173
    invoke-static {v0}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object v0

    .line 177
    check-cast v0, Ldc/n;

    .line 178
    .line 179
    new-instance v1, Lic/m;

    .line 180
    .line 181
    iget-object v2, v0, Ldc/n;->g:Ljava/lang/String;

    .line 182
    .line 183
    iget-object v4, v0, Ldc/n;->d:Ljava/lang/String;

    .line 184
    .line 185
    iget-object v5, v0, Ldc/n;->e:Ljava/lang/String;

    .line 186
    .line 187
    iget-object v0, v0, Ldc/n;->f:Ldc/m;

    .line 188
    .line 189
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 190
    .line 191
    .line 192
    move-result v0

    .line 193
    if-eqz v0, :cond_6

    .line 194
    .line 195
    if-ne v0, v3, :cond_5

    .line 196
    .line 197
    sget-object v0, Lic/l;->e:Lic/l;

    .line 198
    .line 199
    goto :goto_2

    .line 200
    :cond_5
    new-instance v0, La8/r0;

    .line 201
    .line 202
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 203
    .line 204
    .line 205
    throw v0

    .line 206
    :cond_6
    sget-object v0, Lic/l;->f:Lic/l;

    .line 207
    .line 208
    :goto_2
    invoke-direct {v1, v2, v4, v5, v0}, Lic/m;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lic/l;)V

    .line 209
    .line 210
    .line 211
    :goto_3
    return-object v1

    .line 212
    :pswitch_1
    check-cast v0, Lz21/b;

    .line 213
    .line 214
    check-cast v6, Lz21/c;

    .line 215
    .line 216
    check-cast v4, Lz21/e;

    .line 217
    .line 218
    sget-object v1, Li31/g;->d:Li31/g;

    .line 219
    .line 220
    move-object/from16 v1, p1

    .line 221
    .line 222
    check-cast v1, Le21/a;

    .line 223
    .line 224
    const-string v7, "$this$module"

    .line 225
    .line 226
    invoke-static {v1, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 227
    .line 228
    .line 229
    iget-object v7, v0, Lz21/b;->c:Lzv0/c;

    .line 230
    .line 231
    sget-object v8, Lhw0/h;->d:Lgw0/c;

    .line 232
    .line 233
    invoke-static {v7, v8}, Lfw0/u;->a(Lzv0/c;Lfw0/t;)Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    move-result-object v9

    .line 237
    if-nez v9, :cond_7

    .line 238
    .line 239
    iget-object v9, v7, Lzv0/c;->d:Lcw0/c;

    .line 240
    .line 241
    new-instance v10, Lzv0/e;

    .line 242
    .line 243
    invoke-direct {v10}, Lzv0/e;-><init>()V

    .line 244
    .line 245
    .line 246
    iget-object v11, v7, Lzv0/c;->e:Lzv0/e;

    .line 247
    .line 248
    invoke-virtual {v10, v11}, Lzv0/e;->b(Lzv0/e;)V

    .line 249
    .line 250
    .line 251
    new-instance v11, Lh10/d;

    .line 252
    .line 253
    const/16 v12, 0x16

    .line 254
    .line 255
    invoke-direct {v11, v12}, Lh10/d;-><init>(I)V

    .line 256
    .line 257
    .line 258
    invoke-virtual {v10, v8, v11}, Lzv0/e;->a(Lfw0/t;Lay0/k;)V

    .line 259
    .line 260
    .line 261
    iget-boolean v7, v7, Lzv0/c;->f:Z

    .line 262
    .line 263
    new-instance v8, Lzv0/c;

    .line 264
    .line 265
    invoke-direct {v8, v9, v10, v7}, Lzv0/c;-><init>(Lcw0/c;Lzv0/e;Z)V

    .line 266
    .line 267
    .line 268
    move-object v7, v8

    .line 269
    :cond_7
    iget-object v8, v0, Lz21/b;->b:Ljava/lang/String;

    .line 270
    .line 271
    const-string v9, "/"

    .line 272
    .line 273
    const/4 v10, 0x0

    .line 274
    invoke-static {v8, v9, v10}, Lly0/w;->o(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 275
    .line 276
    .line 277
    move-result v11

    .line 278
    if-eqz v11, :cond_8

    .line 279
    .line 280
    goto :goto_4

    .line 281
    :cond_8
    invoke-virtual {v8, v9}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 282
    .line 283
    .line 284
    move-result-object v8

    .line 285
    :goto_4
    new-instance v15, Lh31/a;

    .line 286
    .line 287
    invoke-direct {v15, v0, v8, v7, v10}, Lh31/a;-><init>(Lz21/b;Ljava/lang/String;Lzv0/c;I)V

    .line 288
    .line 289
    .line 290
    sget-object v17, Li21/b;->e:Lh21/b;

    .line 291
    .line 292
    sget-object v21, La21/c;->d:La21/c;

    .line 293
    .line 294
    new-instance v11, La21/a;

    .line 295
    .line 296
    sget-object v9, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 297
    .line 298
    const-class v12, Lc31/j;

    .line 299
    .line 300
    invoke-virtual {v9, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 301
    .line 302
    .line 303
    move-result-object v13

    .line 304
    const/4 v14, 0x0

    .line 305
    move-object/from16 v12, v17

    .line 306
    .line 307
    move-object/from16 v16, v21

    .line 308
    .line 309
    invoke-direct/range {v11 .. v16}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 310
    .line 311
    .line 312
    new-instance v12, Lc21/d;

    .line 313
    .line 314
    invoke-direct {v12, v11}, Lc21/b;-><init>(La21/a;)V

    .line 315
    .line 316
    .line 317
    invoke-virtual {v1, v12}, Le21/a;->a(Lc21/b;)V

    .line 318
    .line 319
    .line 320
    new-instance v11, Lh31/a;

    .line 321
    .line 322
    invoke-direct {v11, v0, v8, v7, v3}, Lh31/a;-><init>(Lz21/b;Ljava/lang/String;Lzv0/c;I)V

    .line 323
    .line 324
    .line 325
    new-instance v16, La21/a;

    .line 326
    .line 327
    const-class v3, Lc31/n;

    .line 328
    .line 329
    invoke-virtual {v9, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 330
    .line 331
    .line 332
    move-result-object v18

    .line 333
    const/16 v19, 0x0

    .line 334
    .line 335
    move-object/from16 v20, v11

    .line 336
    .line 337
    invoke-direct/range {v16 .. v21}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 338
    .line 339
    .line 340
    move-object/from16 v3, v16

    .line 341
    .line 342
    new-instance v11, Lc21/d;

    .line 343
    .line 344
    invoke-direct {v11, v3}, Lc21/b;-><init>(La21/a;)V

    .line 345
    .line 346
    .line 347
    invoke-virtual {v1, v11}, Le21/a;->a(Lc21/b;)V

    .line 348
    .line 349
    .line 350
    new-instance v3, Lh31/a;

    .line 351
    .line 352
    const/4 v11, 0x2

    .line 353
    invoke-direct {v3, v0, v8, v7, v11}, Lh31/a;-><init>(Lz21/b;Ljava/lang/String;Lzv0/c;I)V

    .line 354
    .line 355
    .line 356
    new-instance v16, La21/a;

    .line 357
    .line 358
    const-class v11, Lc31/l;

    .line 359
    .line 360
    invoke-virtual {v9, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 361
    .line 362
    .line 363
    move-result-object v18

    .line 364
    move-object/from16 v20, v3

    .line 365
    .line 366
    invoke-direct/range {v16 .. v21}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 367
    .line 368
    .line 369
    move-object/from16 v3, v16

    .line 370
    .line 371
    new-instance v11, Lc21/d;

    .line 372
    .line 373
    invoke-direct {v11, v3}, Lc21/b;-><init>(La21/a;)V

    .line 374
    .line 375
    .line 376
    invoke-virtual {v1, v11}, Le21/a;->a(Lc21/b;)V

    .line 377
    .line 378
    .line 379
    new-instance v3, Lh31/a;

    .line 380
    .line 381
    const/4 v11, 0x3

    .line 382
    invoke-direct {v3, v0, v8, v7, v11}, Lh31/a;-><init>(Lz21/b;Ljava/lang/String;Lzv0/c;I)V

    .line 383
    .line 384
    .line 385
    new-instance v16, La21/a;

    .line 386
    .line 387
    const-class v11, Lc31/d;

    .line 388
    .line 389
    invoke-virtual {v9, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 390
    .line 391
    .line 392
    move-result-object v18

    .line 393
    move-object/from16 v20, v3

    .line 394
    .line 395
    invoke-direct/range {v16 .. v21}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 396
    .line 397
    .line 398
    move-object/from16 v3, v16

    .line 399
    .line 400
    new-instance v11, Lc21/d;

    .line 401
    .line 402
    invoke-direct {v11, v3}, Lc21/b;-><init>(La21/a;)V

    .line 403
    .line 404
    .line 405
    invoke-virtual {v1, v11}, Le21/a;->a(Lc21/b;)V

    .line 406
    .line 407
    .line 408
    new-instance v3, Lh31/a;

    .line 409
    .line 410
    const/4 v11, 0x4

    .line 411
    invoke-direct {v3, v0, v8, v7, v11}, Lh31/a;-><init>(Lz21/b;Ljava/lang/String;Lzv0/c;I)V

    .line 412
    .line 413
    .line 414
    new-instance v16, La21/a;

    .line 415
    .line 416
    const-class v11, Lc31/b;

    .line 417
    .line 418
    invoke-virtual {v9, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 419
    .line 420
    .line 421
    move-result-object v18

    .line 422
    move-object/from16 v20, v3

    .line 423
    .line 424
    invoke-direct/range {v16 .. v21}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 425
    .line 426
    .line 427
    move-object/from16 v3, v16

    .line 428
    .line 429
    new-instance v11, Lc21/d;

    .line 430
    .line 431
    invoke-direct {v11, v3}, Lc21/b;-><init>(La21/a;)V

    .line 432
    .line 433
    .line 434
    invoke-virtual {v1, v11}, Le21/a;->a(Lc21/b;)V

    .line 435
    .line 436
    .line 437
    new-instance v3, Lh31/a;

    .line 438
    .line 439
    const/4 v11, 0x5

    .line 440
    invoke-direct {v3, v0, v8, v7, v11}, Lh31/a;-><init>(Lz21/b;Ljava/lang/String;Lzv0/c;I)V

    .line 441
    .line 442
    .line 443
    new-instance v16, La21/a;

    .line 444
    .line 445
    const-class v11, Lc31/f;

    .line 446
    .line 447
    invoke-virtual {v9, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 448
    .line 449
    .line 450
    move-result-object v18

    .line 451
    move-object/from16 v20, v3

    .line 452
    .line 453
    invoke-direct/range {v16 .. v21}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 454
    .line 455
    .line 456
    move-object/from16 v3, v16

    .line 457
    .line 458
    new-instance v11, Lc21/d;

    .line 459
    .line 460
    invoke-direct {v11, v3}, Lc21/b;-><init>(La21/a;)V

    .line 461
    .line 462
    .line 463
    invoke-virtual {v1, v11}, Le21/a;->a(Lc21/b;)V

    .line 464
    .line 465
    .line 466
    new-instance v3, Lh31/a;

    .line 467
    .line 468
    const/4 v11, 0x6

    .line 469
    invoke-direct {v3, v0, v8, v7, v11}, Lh31/a;-><init>(Lz21/b;Ljava/lang/String;Lzv0/c;I)V

    .line 470
    .line 471
    .line 472
    new-instance v16, La21/a;

    .line 473
    .line 474
    const-class v0, Lc31/h;

    .line 475
    .line 476
    invoke-virtual {v9, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 477
    .line 478
    .line 479
    move-result-object v18

    .line 480
    move-object/from16 v20, v3

    .line 481
    .line 482
    invoke-direct/range {v16 .. v21}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 483
    .line 484
    .line 485
    move-object/from16 v0, v16

    .line 486
    .line 487
    new-instance v3, Lc21/d;

    .line 488
    .line 489
    invoke-direct {v3, v0}, Lc21/b;-><init>(La21/a;)V

    .line 490
    .line 491
    .line 492
    invoke-virtual {v1, v3}, Le21/a;->a(Lc21/b;)V

    .line 493
    .line 494
    .line 495
    const-string v0, "CONFIG_IN_MEMORY_DATA_SOURCE"

    .line 496
    .line 497
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 498
    .line 499
    .line 500
    move-result-object v19

    .line 501
    new-instance v0, La71/l0;

    .line 502
    .line 503
    invoke-direct {v0, v6, v4, v5}, La71/l0;-><init>(Lz21/c;Lz21/e;Z)V

    .line 504
    .line 505
    .line 506
    new-instance v16, La21/a;

    .line 507
    .line 508
    const-class v3, Lb31/a;

    .line 509
    .line 510
    invoke-virtual {v9, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 511
    .line 512
    .line 513
    move-result-object v18

    .line 514
    move-object/from16 v20, v0

    .line 515
    .line 516
    invoke-direct/range {v16 .. v21}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 517
    .line 518
    .line 519
    move-object/from16 v0, v16

    .line 520
    .line 521
    new-instance v4, Lc21/d;

    .line 522
    .line 523
    invoke-direct {v4, v0}, Lc21/b;-><init>(La21/a;)V

    .line 524
    .line 525
    .line 526
    invoke-virtual {v1, v4}, Le21/a;->a(Lc21/b;)V

    .line 527
    .line 528
    .line 529
    const-string v0, "APPOINTMENT_IN_MEMORY_DATA_SOURCE"

    .line 530
    .line 531
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 532
    .line 533
    .line 534
    move-result-object v19

    .line 535
    new-instance v0, Lgv0/a;

    .line 536
    .line 537
    const/16 v4, 0x15

    .line 538
    .line 539
    invoke-direct {v0, v10, v4}, Lgv0/a;-><init>(BI)V

    .line 540
    .line 541
    .line 542
    new-instance v16, La21/a;

    .line 543
    .line 544
    invoke-virtual {v9, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 545
    .line 546
    .line 547
    move-result-object v18

    .line 548
    move-object/from16 v20, v0

    .line 549
    .line 550
    invoke-direct/range {v16 .. v21}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 551
    .line 552
    .line 553
    move-object/from16 v0, v16

    .line 554
    .line 555
    new-instance v4, Lc21/d;

    .line 556
    .line 557
    invoke-direct {v4, v0}, Lc21/b;-><init>(La21/a;)V

    .line 558
    .line 559
    .line 560
    invoke-virtual {v1, v4}, Le21/a;->a(Lc21/b;)V

    .line 561
    .line 562
    .line 563
    const-string v0, "FAVOURITE_SERVICE_PARTNER_DATA_SOURCE"

    .line 564
    .line 565
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 566
    .line 567
    .line 568
    move-result-object v19

    .line 569
    new-instance v0, Lgv0/a;

    .line 570
    .line 571
    const/16 v4, 0x14

    .line 572
    .line 573
    invoke-direct {v0, v10, v4}, Lgv0/a;-><init>(BI)V

    .line 574
    .line 575
    .line 576
    new-instance v16, La21/a;

    .line 577
    .line 578
    invoke-virtual {v9, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 579
    .line 580
    .line 581
    move-result-object v18

    .line 582
    move-object/from16 v20, v0

    .line 583
    .line 584
    invoke-direct/range {v16 .. v21}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 585
    .line 586
    .line 587
    move-object/from16 v0, v16

    .line 588
    .line 589
    invoke-static {v0, v1}, Lf2/m0;->t(La21/a;Le21/a;)V

    .line 590
    .line 591
    .line 592
    return-object v2

    .line 593
    :pswitch_2
    check-cast v0, Ly1/i;

    .line 594
    .line 595
    check-cast v6, Lxh/e;

    .line 596
    .line 597
    check-cast v4, Ll2/b1;

    .line 598
    .line 599
    move-object/from16 v7, p1

    .line 600
    .line 601
    check-cast v7, Lz9/w;

    .line 602
    .line 603
    const-string v1, "$this$NavHost"

    .line 604
    .line 605
    invoke-static {v7, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 606
    .line 607
    .line 608
    new-instance v1, La71/m0;

    .line 609
    .line 610
    invoke-direct {v1, v0, v6, v5, v3}, La71/m0;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 611
    .line 612
    .line 613
    new-instance v14, Lt2/b;

    .line 614
    .line 615
    const v0, 0x72c39cda

    .line 616
    .line 617
    .line 618
    invoke-direct {v14, v1, v3, v0}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 619
    .line 620
    .line 621
    const/16 v15, 0xfe

    .line 622
    .line 623
    const-string v8, "/form"

    .line 624
    .line 625
    const/4 v9, 0x0

    .line 626
    const/4 v10, 0x0

    .line 627
    const/4 v11, 0x0

    .line 628
    const/4 v12, 0x0

    .line 629
    const/4 v13, 0x0

    .line 630
    invoke-static/range {v7 .. v15}, Ljp/r0;->b(Lz9/w;Ljava/lang/String;Ljava/util/List;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lt2/b;I)V

    .line 631
    .line 632
    .line 633
    new-instance v0, Leh/f;

    .line 634
    .line 635
    invoke-direct {v0, v4, v3}, Leh/f;-><init>(Ll2/b1;I)V

    .line 636
    .line 637
    .line 638
    new-instance v14, Lt2/b;

    .line 639
    .line 640
    const v1, 0x440bf491

    .line 641
    .line 642
    .line 643
    invoke-direct {v14, v0, v3, v1}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 644
    .line 645
    .line 646
    const-string v8, "/document"

    .line 647
    .line 648
    invoke-static/range {v7 .. v15}, Ljp/r0;->b(Lz9/w;Ljava/lang/String;Ljava/util/List;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lt2/b;I)V

    .line 649
    .line 650
    .line 651
    return-object v2

    .line 652
    :pswitch_3
    check-cast v0, Leb/v;

    .line 653
    .line 654
    check-cast v6, Ljava/lang/String;

    .line 655
    .line 656
    check-cast v4, Lfb/f0;

    .line 657
    .line 658
    move-object/from16 v1, p1

    .line 659
    .line 660
    check-cast v1, Ljava/lang/Throwable;

    .line 661
    .line 662
    instance-of v3, v1, Lfb/x;

    .line 663
    .line 664
    if-eqz v3, :cond_9

    .line 665
    .line 666
    check-cast v1, Lfb/x;

    .line 667
    .line 668
    iget v1, v1, Lfb/x;->d:I

    .line 669
    .line 670
    iget-object v0, v0, Leb/v;->f:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 671
    .line 672
    const/16 v3, -0x100

    .line 673
    .line 674
    invoke-virtual {v0, v3, v1}, Ljava/util/concurrent/atomic/AtomicInteger;->compareAndSet(II)Z

    .line 675
    .line 676
    .line 677
    :cond_9
    if-eqz v5, :cond_a

    .line 678
    .line 679
    if-eqz v6, :cond_a

    .line 680
    .line 681
    iget-object v0, v4, Lfb/f0;->e:Leb/b;

    .line 682
    .line 683
    iget-object v0, v0, Leb/b;->m:Leb/j;

    .line 684
    .line 685
    iget-object v1, v4, Lfb/f0;->a:Lmb/o;

    .line 686
    .line 687
    invoke-virtual {v1}, Lmb/o;->hashCode()I

    .line 688
    .line 689
    .line 690
    move-result v1

    .line 691
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 692
    .line 693
    .line 694
    invoke-static {v6}, Ljp/x0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 695
    .line 696
    .line 697
    move-result-object v0

    .line 698
    invoke-static {v0, v1}, Landroid/os/Trace;->endAsyncSection(Ljava/lang/String;I)V

    .line 699
    .line 700
    .line 701
    :cond_a
    return-object v2

    .line 702
    :pswitch_4
    check-cast v0, Lay0/a;

    .line 703
    .line 704
    move-object v8, v6

    .line 705
    check-cast v8, Le3/f;

    .line 706
    .line 707
    move-object v12, v4

    .line 708
    check-cast v12, Le3/m;

    .line 709
    .line 710
    move-object/from16 v7, p1

    .line 711
    .line 712
    check-cast v7, Lv3/j0;

    .line 713
    .line 714
    invoke-virtual {v7}, Lv3/j0;->b()V

    .line 715
    .line 716
    .line 717
    iget-object v1, v7, Lv3/j0;->d:Lg3/b;

    .line 718
    .line 719
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 720
    .line 721
    .line 722
    move-result-object v0

    .line 723
    check-cast v0, Ljava/lang/Boolean;

    .line 724
    .line 725
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 726
    .line 727
    .line 728
    move-result v0

    .line 729
    if-nez v0, :cond_b

    .line 730
    .line 731
    goto :goto_5

    .line 732
    :cond_b
    if-eqz v5, :cond_c

    .line 733
    .line 734
    invoke-interface {v1}, Lg3/d;->D0()J

    .line 735
    .line 736
    .line 737
    move-result-wide v3

    .line 738
    iget-object v1, v1, Lg3/b;->e:Lgw0/c;

    .line 739
    .line 740
    invoke-virtual {v1}, Lgw0/c;->o()J

    .line 741
    .line 742
    .line 743
    move-result-wide v5

    .line 744
    invoke-virtual {v1}, Lgw0/c;->h()Le3/r;

    .line 745
    .line 746
    .line 747
    move-result-object v0

    .line 748
    invoke-interface {v0}, Le3/r;->o()V

    .line 749
    .line 750
    .line 751
    :try_start_0
    iget-object v0, v1, Lgw0/c;->e:Ljava/lang/Object;

    .line 752
    .line 753
    check-cast v0, Lbu/c;

    .line 754
    .line 755
    const/high16 v9, -0x40800000    # -1.0f

    .line 756
    .line 757
    const/high16 v10, 0x3f800000    # 1.0f

    .line 758
    .line 759
    invoke-virtual {v0, v3, v4, v9, v10}, Lbu/c;->A(JFF)V

    .line 760
    .line 761
    .line 762
    const/4 v11, 0x0

    .line 763
    const/16 v13, 0x2e

    .line 764
    .line 765
    const-wide/16 v9, 0x0

    .line 766
    .line 767
    invoke-static/range {v7 .. v13}, Lg3/d;->v(Lg3/d;Le3/f;JFLe3/m;I)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 768
    .line 769
    .line 770
    invoke-static {v1, v5, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 771
    .line 772
    .line 773
    goto :goto_5

    .line 774
    :catchall_0
    move-exception v0

    .line 775
    invoke-static {v1, v5, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 776
    .line 777
    .line 778
    throw v0

    .line 779
    :cond_c
    const/4 v11, 0x0

    .line 780
    const/16 v13, 0x2e

    .line 781
    .line 782
    const-wide/16 v9, 0x0

    .line 783
    .line 784
    invoke-static/range {v7 .. v13}, Lg3/d;->v(Lg3/d;Le3/f;JFLe3/m;I)V

    .line 785
    .line 786
    .line 787
    :goto_5
    return-object v2

    .line 788
    nop

    .line 789
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
