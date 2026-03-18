.class public final Lm70/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lm70/n;


# direct methods
.method public synthetic constructor <init>(Lm70/n;I)V
    .locals 0

    .line 1
    iput p2, p0, Lm70/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lm70/f;->e:Lm70/n;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lm70/f;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Lne0/s;

    .line 11
    .line 12
    iget-object v0, v0, Lm70/f;->e:Lm70/n;

    .line 13
    .line 14
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    move-object v3, v2

    .line 19
    check-cast v3, Lm70/l;

    .line 20
    .line 21
    sget-object v2, Lne0/d;->a:Lne0/d;

    .line 22
    .line 23
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v5

    .line 27
    const/16 v20, 0x0

    .line 28
    .line 29
    const v21, 0x1fffd

    .line 30
    .line 31
    .line 32
    const/4 v4, 0x0

    .line 33
    const/4 v6, 0x0

    .line 34
    const/4 v7, 0x0

    .line 35
    const/4 v8, 0x0

    .line 36
    const/4 v9, 0x0

    .line 37
    const/4 v10, 0x0

    .line 38
    const/4 v11, 0x0

    .line 39
    const/4 v12, 0x0

    .line 40
    const/4 v13, 0x0

    .line 41
    const/4 v14, 0x0

    .line 42
    const/4 v15, 0x0

    .line 43
    const/16 v16, 0x0

    .line 44
    .line 45
    const/16 v17, 0x0

    .line 46
    .line 47
    const/16 v18, 0x0

    .line 48
    .line 49
    const/16 v19, 0x0

    .line 50
    .line 51
    invoke-static/range {v3 .. v21}, Lm70/l;->a(Lm70/l;ZZZLqr0/s;Ljava/util/List;ZLl70/h;Ljava/lang/String;Ljava/util/List;Ll70/d;ZLjava/lang/String;ZLjava/util/Map;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lm70/l;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 56
    .line 57
    .line 58
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 59
    .line 60
    return-object v0

    .line 61
    :pswitch_0
    move-object/from16 v1, p1

    .line 62
    .line 63
    check-cast v1, Lne0/s;

    .line 64
    .line 65
    instance-of v2, v1, Lne0/c;

    .line 66
    .line 67
    iget-object v0, v0, Lm70/f;->e:Lm70/n;

    .line 68
    .line 69
    if-eqz v2, :cond_0

    .line 70
    .line 71
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 72
    .line 73
    .line 74
    move-result-object v1

    .line 75
    move-object v2, v1

    .line 76
    check-cast v2, Lm70/l;

    .line 77
    .line 78
    const/16 v19, 0x0

    .line 79
    .line 80
    const v20, 0x1cfff

    .line 81
    .line 82
    .line 83
    const/4 v3, 0x0

    .line 84
    const/4 v4, 0x0

    .line 85
    const/4 v5, 0x0

    .line 86
    const/4 v6, 0x0

    .line 87
    const/4 v7, 0x0

    .line 88
    const/4 v8, 0x0

    .line 89
    const/4 v9, 0x0

    .line 90
    const/4 v10, 0x0

    .line 91
    const/4 v11, 0x0

    .line 92
    const/4 v12, 0x0

    .line 93
    const/4 v13, 0x0

    .line 94
    const/4 v14, 0x0

    .line 95
    const/4 v15, 0x0

    .line 96
    sget-object v16, Lmx0/t;->d:Lmx0/t;

    .line 97
    .line 98
    const/16 v17, 0x0

    .line 99
    .line 100
    const/16 v18, 0x0

    .line 101
    .line 102
    invoke-static/range {v2 .. v20}, Lm70/l;->a(Lm70/l;ZZZLqr0/s;Ljava/util/List;ZLl70/h;Ljava/lang/String;Ljava/util/List;Ll70/d;ZLjava/lang/String;ZLjava/util/Map;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lm70/l;

    .line 103
    .line 104
    .line 105
    move-result-object v1

    .line 106
    goto/16 :goto_5

    .line 107
    .line 108
    :cond_0
    sget-object v2, Lne0/d;->a:Lne0/d;

    .line 109
    .line 110
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    move-result v2

    .line 114
    if-eqz v2, :cond_1

    .line 115
    .line 116
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 117
    .line 118
    .line 119
    move-result-object v1

    .line 120
    move-object v2, v1

    .line 121
    check-cast v2, Lm70/l;

    .line 122
    .line 123
    const/16 v19, 0x0

    .line 124
    .line 125
    const v20, 0x1efff

    .line 126
    .line 127
    .line 128
    const/4 v3, 0x0

    .line 129
    const/4 v4, 0x0

    .line 130
    const/4 v5, 0x0

    .line 131
    const/4 v6, 0x0

    .line 132
    const/4 v7, 0x0

    .line 133
    const/4 v8, 0x0

    .line 134
    const/4 v9, 0x0

    .line 135
    const/4 v10, 0x0

    .line 136
    const/4 v11, 0x0

    .line 137
    const/4 v12, 0x0

    .line 138
    const/4 v13, 0x0

    .line 139
    const/4 v14, 0x0

    .line 140
    const/4 v15, 0x1

    .line 141
    const/16 v16, 0x0

    .line 142
    .line 143
    const/16 v17, 0x0

    .line 144
    .line 145
    const/16 v18, 0x0

    .line 146
    .line 147
    invoke-static/range {v2 .. v20}, Lm70/l;->a(Lm70/l;ZZZLqr0/s;Ljava/util/List;ZLl70/h;Ljava/lang/String;Ljava/util/List;Ll70/d;ZLjava/lang/String;ZLjava/util/Map;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lm70/l;

    .line 148
    .line 149
    .line 150
    move-result-object v1

    .line 151
    goto/16 :goto_5

    .line 152
    .line 153
    :cond_1
    instance-of v2, v1, Lne0/e;

    .line 154
    .line 155
    if-eqz v2, :cond_7

    .line 156
    .line 157
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 158
    .line 159
    .line 160
    move-result-object v2

    .line 161
    move-object v3, v2

    .line 162
    check-cast v3, Lm70/l;

    .line 163
    .line 164
    check-cast v1, Lne0/e;

    .line 165
    .line 166
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 167
    .line 168
    check-cast v1, Ll70/u;

    .line 169
    .line 170
    sget-object v2, Ll70/h;->d:Ll70/h;

    .line 171
    .line 172
    const/4 v4, 0x0

    .line 173
    if-eqz v1, :cond_2

    .line 174
    .line 175
    iget-object v5, v1, Ll70/u;->c:Ll70/t;

    .line 176
    .line 177
    goto :goto_0

    .line 178
    :cond_2
    move-object v5, v4

    .line 179
    :goto_0
    new-instance v6, Llx0/l;

    .line 180
    .line 181
    invoke-direct {v6, v2, v5}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 182
    .line 183
    .line 184
    sget-object v2, Ll70/h;->e:Ll70/h;

    .line 185
    .line 186
    if-eqz v1, :cond_3

    .line 187
    .line 188
    iget-object v5, v1, Ll70/u;->e:Ll70/t;

    .line 189
    .line 190
    goto :goto_1

    .line 191
    :cond_3
    move-object v5, v4

    .line 192
    :goto_1
    new-instance v7, Llx0/l;

    .line 193
    .line 194
    invoke-direct {v7, v2, v5}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 195
    .line 196
    .line 197
    sget-object v2, Ll70/h;->f:Ll70/h;

    .line 198
    .line 199
    if-eqz v1, :cond_4

    .line 200
    .line 201
    iget-object v1, v1, Ll70/u;->d:Ll70/t;

    .line 202
    .line 203
    goto :goto_2

    .line 204
    :cond_4
    move-object v1, v4

    .line 205
    :goto_2
    new-instance v5, Llx0/l;

    .line 206
    .line 207
    invoke-direct {v5, v2, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 208
    .line 209
    .line 210
    filled-new-array {v6, v7, v5}, [Llx0/l;

    .line 211
    .line 212
    .line 213
    move-result-object v1

    .line 214
    invoke-static {v1}, Lmx0/x;->m([Llx0/l;)Ljava/util/Map;

    .line 215
    .line 216
    .line 217
    move-result-object v1

    .line 218
    new-instance v2, Ljava/util/LinkedHashMap;

    .line 219
    .line 220
    invoke-interface {v1}, Ljava/util/Map;->size()I

    .line 221
    .line 222
    .line 223
    move-result v5

    .line 224
    invoke-static {v5}, Lmx0/x;->k(I)I

    .line 225
    .line 226
    .line 227
    move-result v5

    .line 228
    invoke-direct {v2, v5}, Ljava/util/LinkedHashMap;-><init>(I)V

    .line 229
    .line 230
    .line 231
    invoke-interface {v1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 232
    .line 233
    .line 234
    move-result-object v1

    .line 235
    check-cast v1, Ljava/lang/Iterable;

    .line 236
    .line 237
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 238
    .line 239
    .line 240
    move-result-object v1

    .line 241
    :goto_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 242
    .line 243
    .line 244
    move-result v5

    .line 245
    if-eqz v5, :cond_6

    .line 246
    .line 247
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    move-result-object v5

    .line 251
    check-cast v5, Ljava/util/Map$Entry;

    .line 252
    .line 253
    invoke-interface {v5}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 254
    .line 255
    .line 256
    move-result-object v6

    .line 257
    invoke-interface {v5}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 258
    .line 259
    .line 260
    move-result-object v5

    .line 261
    check-cast v5, Ll70/t;

    .line 262
    .line 263
    if-eqz v5, :cond_5

    .line 264
    .line 265
    invoke-static {v5}, Ljp/p0;->c(Ll70/t;)Ljava/lang/String;

    .line 266
    .line 267
    .line 268
    move-result-object v5

    .line 269
    goto :goto_4

    .line 270
    :cond_5
    move-object v5, v4

    .line 271
    :goto_4
    invoke-interface {v2, v6, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    goto :goto_3

    .line 275
    :cond_6
    const/16 v20, 0x0

    .line 276
    .line 277
    const v21, 0x1cfff

    .line 278
    .line 279
    .line 280
    const/4 v4, 0x0

    .line 281
    const/4 v5, 0x0

    .line 282
    const/4 v6, 0x0

    .line 283
    const/4 v7, 0x0

    .line 284
    const/4 v8, 0x0

    .line 285
    const/4 v9, 0x0

    .line 286
    const/4 v10, 0x0

    .line 287
    const/4 v11, 0x0

    .line 288
    const/4 v12, 0x0

    .line 289
    const/4 v13, 0x0

    .line 290
    const/4 v14, 0x0

    .line 291
    const/4 v15, 0x0

    .line 292
    const/16 v16, 0x0

    .line 293
    .line 294
    const/16 v18, 0x0

    .line 295
    .line 296
    const/16 v19, 0x0

    .line 297
    .line 298
    move-object/from16 v17, v2

    .line 299
    .line 300
    invoke-static/range {v3 .. v21}, Lm70/l;->a(Lm70/l;ZZZLqr0/s;Ljava/util/List;ZLl70/h;Ljava/lang/String;Ljava/util/List;Ll70/d;ZLjava/lang/String;ZLjava/util/Map;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lm70/l;

    .line 301
    .line 302
    .line 303
    move-result-object v1

    .line 304
    :goto_5
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 305
    .line 306
    .line 307
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 308
    .line 309
    return-object v0

    .line 310
    :cond_7
    new-instance v0, La8/r0;

    .line 311
    .line 312
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 313
    .line 314
    .line 315
    throw v0

    .line 316
    :pswitch_1
    move-object/from16 v1, p1

    .line 317
    .line 318
    check-cast v1, Ll70/c;

    .line 319
    .line 320
    if-eqz v1, :cond_9

    .line 321
    .line 322
    iget-object v0, v0, Lm70/f;->e:Lm70/n;

    .line 323
    .line 324
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 325
    .line 326
    .line 327
    move-result-object v2

    .line 328
    move-object v3, v2

    .line 329
    check-cast v3, Lm70/l;

    .line 330
    .line 331
    iget-object v2, v1, Ll70/c;->a:Ll70/w;

    .line 332
    .line 333
    iget-object v4, v1, Ll70/c;->b:Ljava/time/LocalDate;

    .line 334
    .line 335
    iget-object v1, v1, Ll70/c;->c:Ljava/lang/Integer;

    .line 336
    .line 337
    if-nez v1, :cond_8

    .line 338
    .line 339
    invoke-static {v4, v2}, Lim/g;->g(Ljava/time/LocalDate;Ll70/w;)Ljava/lang/String;

    .line 340
    .line 341
    .line 342
    move-result-object v1

    .line 343
    :goto_6
    move-object v15, v1

    .line 344
    goto :goto_7

    .line 345
    :cond_8
    invoke-static {v4, v2}, Lim/g;->f(Ljava/time/LocalDate;Ll70/w;)Ljava/lang/String;

    .line 346
    .line 347
    .line 348
    move-result-object v1

    .line 349
    goto :goto_6

    .line 350
    :goto_7
    const/16 v20, 0x0

    .line 351
    .line 352
    const v21, 0x1f7ff

    .line 353
    .line 354
    .line 355
    const/4 v4, 0x0

    .line 356
    const/4 v5, 0x0

    .line 357
    const/4 v6, 0x0

    .line 358
    const/4 v7, 0x0

    .line 359
    const/4 v8, 0x0

    .line 360
    const/4 v9, 0x0

    .line 361
    const/4 v10, 0x0

    .line 362
    const/4 v11, 0x0

    .line 363
    const/4 v12, 0x0

    .line 364
    const/4 v13, 0x0

    .line 365
    const/4 v14, 0x0

    .line 366
    const/16 v16, 0x0

    .line 367
    .line 368
    const/16 v17, 0x0

    .line 369
    .line 370
    const/16 v18, 0x0

    .line 371
    .line 372
    const/16 v19, 0x0

    .line 373
    .line 374
    invoke-static/range {v3 .. v21}, Lm70/l;->a(Lm70/l;ZZZLqr0/s;Ljava/util/List;ZLl70/h;Ljava/lang/String;Ljava/util/List;Ll70/d;ZLjava/lang/String;ZLjava/util/Map;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lm70/l;

    .line 375
    .line 376
    .line 377
    move-result-object v1

    .line 378
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 379
    .line 380
    .line 381
    :cond_9
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 382
    .line 383
    return-object v0

    .line 384
    nop

    .line 385
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
