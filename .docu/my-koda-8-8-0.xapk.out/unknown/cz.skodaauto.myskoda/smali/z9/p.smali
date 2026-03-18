.class public final synthetic Lz9/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lz9/r;


# direct methods
.method public synthetic constructor <init>(Lz9/r;I)V
    .locals 0

    .line 1
    iput p2, p0, Lz9/p;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lz9/p;->e:Lz9/r;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lz9/p;->d:I

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    const-string v3, "parse(...)"

    .line 7
    .line 8
    const/4 v4, 0x0

    .line 9
    const/4 v5, 0x0

    .line 10
    iget-object v0, v0, Lz9/p;->e:Lz9/r;

    .line 11
    .line 12
    packed-switch v1, :pswitch_data_0

    .line 13
    .line 14
    .line 15
    return-object v5

    .line 16
    :pswitch_0
    iget-object v0, v0, Lz9/r;->j:Ljava/lang/Object;

    .line 17
    .line 18
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    check-cast v0, Ljava/lang/String;

    .line 23
    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    new-instance v5, Lly0/n;

    .line 27
    .line 28
    sget-object v1, Lly0/o;->d:[Lly0/o;

    .line 29
    .line 30
    invoke-direct {v5, v0, v4}, Lly0/n;-><init>(Ljava/lang/String;I)V

    .line 31
    .line 32
    .line 33
    :cond_0
    return-object v5

    .line 34
    :pswitch_1
    iget-object v0, v0, Lz9/r;->h:Ljava/lang/Object;

    .line 35
    .line 36
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    check-cast v0, Llx0/l;

    .line 41
    .line 42
    if-eqz v0, :cond_1

    .line 43
    .line 44
    iget-object v0, v0, Llx0/l;->e:Ljava/lang/Object;

    .line 45
    .line 46
    move-object v5, v0

    .line 47
    check-cast v5, Ljava/lang/String;

    .line 48
    .line 49
    :cond_1
    return-object v5

    .line 50
    :pswitch_2
    iget-object v0, v0, Lz9/r;->h:Ljava/lang/Object;

    .line 51
    .line 52
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    check-cast v0, Llx0/l;

    .line 57
    .line 58
    if-eqz v0, :cond_2

    .line 59
    .line 60
    iget-object v0, v0, Llx0/l;->d:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v0, Ljava/util/List;

    .line 63
    .line 64
    if-nez v0, :cond_3

    .line 65
    .line 66
    :cond_2
    new-instance v0, Ljava/util/ArrayList;

    .line 67
    .line 68
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 69
    .line 70
    .line 71
    :cond_3
    return-object v0

    .line 72
    :pswitch_3
    iget-object v0, v0, Lz9/r;->a:Ljava/lang/String;

    .line 73
    .line 74
    invoke-static {v0}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 75
    .line 76
    .line 77
    move-result-object v1

    .line 78
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {v1}, Landroid/net/Uri;->getFragment()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    if-nez v1, :cond_4

    .line 86
    .line 87
    goto :goto_0

    .line 88
    :cond_4
    new-instance v1, Ljava/util/ArrayList;

    .line 89
    .line 90
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 91
    .line 92
    .line 93
    invoke-static {v0}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {v0}, Landroid/net/Uri;->getFragment()Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object v0

    .line 104
    new-instance v2, Ljava/lang/StringBuilder;

    .line 105
    .line 106
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 107
    .line 108
    .line 109
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    invoke-static {v0, v1, v2}, Lz9/r;->a(Ljava/lang/String;Ljava/util/ArrayList;Ljava/lang/StringBuilder;)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object v0

    .line 119
    new-instance v5, Llx0/l;

    .line 120
    .line 121
    invoke-direct {v5, v1, v0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    :goto_0
    return-object v5

    .line 125
    :pswitch_4
    iget-object v1, v0, Lz9/r;->a:Ljava/lang/String;

    .line 126
    .line 127
    new-instance v5, Ljava/util/LinkedHashMap;

    .line 128
    .line 129
    invoke-direct {v5}, Ljava/util/LinkedHashMap;-><init>()V

    .line 130
    .line 131
    .line 132
    iget-object v6, v0, Lz9/r;->e:Llx0/q;

    .line 133
    .line 134
    invoke-virtual {v6}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v6

    .line 138
    check-cast v6, Ljava/lang/Boolean;

    .line 139
    .line 140
    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    .line 141
    .line 142
    .line 143
    move-result v6

    .line 144
    if-nez v6, :cond_5

    .line 145
    .line 146
    goto/16 :goto_3

    .line 147
    .line 148
    :cond_5
    invoke-static {v1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 149
    .line 150
    .line 151
    move-result-object v6

    .line 152
    invoke-static {v6, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {v6}, Landroid/net/Uri;->getQueryParameterNames()Ljava/util/Set;

    .line 156
    .line 157
    .line 158
    move-result-object v3

    .line 159
    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 160
    .line 161
    .line 162
    move-result-object v3

    .line 163
    :goto_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 164
    .line 165
    .line 166
    move-result v7

    .line 167
    if-eqz v7, :cond_b

    .line 168
    .line 169
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v7

    .line 173
    check-cast v7, Ljava/lang/String;

    .line 174
    .line 175
    new-instance v8, Ljava/lang/StringBuilder;

    .line 176
    .line 177
    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    .line 178
    .line 179
    .line 180
    invoke-virtual {v6, v7}, Landroid/net/Uri;->getQueryParameters(Ljava/lang/String;)Ljava/util/List;

    .line 181
    .line 182
    .line 183
    move-result-object v9

    .line 184
    invoke-interface {v9}, Ljava/util/List;->size()I

    .line 185
    .line 186
    .line 187
    move-result v10

    .line 188
    if-gt v10, v2, :cond_a

    .line 189
    .line 190
    invoke-static {v9}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move-result-object v9

    .line 194
    check-cast v9, Ljava/lang/String;

    .line 195
    .line 196
    if-nez v9, :cond_6

    .line 197
    .line 198
    iput-boolean v2, v0, Lz9/r;->g:Z

    .line 199
    .line 200
    move-object v9, v7

    .line 201
    :cond_6
    sget-object v10, Lz9/r;->n:Lly0/n;

    .line 202
    .line 203
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 204
    .line 205
    .line 206
    const-string v11, "input"

    .line 207
    .line 208
    invoke-static {v9, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 209
    .line 210
    .line 211
    iget-object v10, v10, Lly0/n;->d:Ljava/util/regex/Pattern;

    .line 212
    .line 213
    invoke-virtual {v10, v9}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 214
    .line 215
    .line 216
    move-result-object v10

    .line 217
    const-string v11, "matcher(...)"

    .line 218
    .line 219
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 220
    .line 221
    .line 222
    invoke-static {v10, v4, v9}, Ltm0/d;->c(Ljava/util/regex/Matcher;ILjava/lang/CharSequence;)Lly0/l;

    .line 223
    .line 224
    .line 225
    move-result-object v10

    .line 226
    new-instance v11, Lz9/q;

    .line 227
    .line 228
    invoke-direct {v11}, Lz9/q;-><init>()V

    .line 229
    .line 230
    .line 231
    move v12, v4

    .line 232
    :goto_2
    const-string v13, "quote(...)"

    .line 233
    .line 234
    const-string v14, "substring(...)"

    .line 235
    .line 236
    if-eqz v10, :cond_8

    .line 237
    .line 238
    iget-object v15, v10, Lly0/l;->c:Lly0/k;

    .line 239
    .line 240
    invoke-virtual {v15, v2}, Lly0/k;->e(I)Lly0/i;

    .line 241
    .line 242
    .line 243
    move-result-object v15

    .line 244
    invoke-static {v15}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 245
    .line 246
    .line 247
    iget-object v15, v15, Lly0/i;->a:Ljava/lang/String;

    .line 248
    .line 249
    move/from16 v16, v2

    .line 250
    .line 251
    iget-object v2, v11, Lz9/q;->b:Ljava/util/ArrayList;

    .line 252
    .line 253
    invoke-virtual {v2, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 254
    .line 255
    .line 256
    invoke-virtual {v10}, Lly0/l;->b()Lgy0/j;

    .line 257
    .line 258
    .line 259
    move-result-object v2

    .line 260
    iget v2, v2, Lgy0/h;->d:I

    .line 261
    .line 262
    if-le v2, v12, :cond_7

    .line 263
    .line 264
    invoke-virtual {v10}, Lly0/l;->b()Lgy0/j;

    .line 265
    .line 266
    .line 267
    move-result-object v2

    .line 268
    iget v2, v2, Lgy0/h;->d:I

    .line 269
    .line 270
    invoke-virtual {v9, v12, v2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 271
    .line 272
    .line 273
    move-result-object v2

    .line 274
    invoke-static {v2, v14}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 275
    .line 276
    .line 277
    invoke-static {v2}, Ljava/util/regex/Pattern;->quote(Ljava/lang/String;)Ljava/lang/String;

    .line 278
    .line 279
    .line 280
    move-result-object v2

    .line 281
    invoke-static {v2, v13}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 282
    .line 283
    .line 284
    invoke-virtual {v8, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 285
    .line 286
    .line 287
    :cond_7
    const-string v2, "([\\s\\S]+?)?"

    .line 288
    .line 289
    invoke-virtual {v8, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 290
    .line 291
    .line 292
    invoke-virtual {v10}, Lly0/l;->b()Lgy0/j;

    .line 293
    .line 294
    .line 295
    move-result-object v2

    .line 296
    iget v2, v2, Lgy0/h;->e:I

    .line 297
    .line 298
    add-int/lit8 v12, v2, 0x1

    .line 299
    .line 300
    invoke-virtual {v10}, Lly0/l;->d()Lly0/l;

    .line 301
    .line 302
    .line 303
    move-result-object v10

    .line 304
    move/from16 v2, v16

    .line 305
    .line 306
    goto :goto_2

    .line 307
    :cond_8
    move/from16 v16, v2

    .line 308
    .line 309
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    .line 310
    .line 311
    .line 312
    move-result v2

    .line 313
    if-ge v12, v2, :cond_9

    .line 314
    .line 315
    invoke-virtual {v9, v12}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 316
    .line 317
    .line 318
    move-result-object v2

    .line 319
    invoke-static {v2, v14}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 320
    .line 321
    .line 322
    invoke-static {v2}, Ljava/util/regex/Pattern;->quote(Ljava/lang/String;)Ljava/lang/String;

    .line 323
    .line 324
    .line 325
    move-result-object v2

    .line 326
    invoke-static {v2, v13}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 327
    .line 328
    .line 329
    invoke-virtual {v8, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 330
    .line 331
    .line 332
    :cond_9
    const-string v2, "$"

    .line 333
    .line 334
    invoke-virtual {v8, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 335
    .line 336
    .line 337
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 338
    .line 339
    .line 340
    move-result-object v2

    .line 341
    const-string v8, "toString(...)"

    .line 342
    .line 343
    invoke-static {v2, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 344
    .line 345
    .line 346
    invoke-static {v2}, Lz9/r;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 347
    .line 348
    .line 349
    move-result-object v2

    .line 350
    iput-object v2, v11, Lz9/q;->a:Ljava/lang/String;

    .line 351
    .line 352
    invoke-interface {v5, v7, v11}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 353
    .line 354
    .line 355
    move/from16 v2, v16

    .line 356
    .line 357
    goto/16 :goto_1

    .line 358
    .line 359
    :cond_a
    const-string v0, " must only be present once in "

    .line 360
    .line 361
    const-string v2, ". To support repeated query parameters, use an array type for your argument and the pattern provided in your URI will be used to parse each query parameter instance."

    .line 362
    .line 363
    const-string v3, "Query parameter "

    .line 364
    .line 365
    invoke-static {v3, v7, v0, v1, v2}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 366
    .line 367
    .line 368
    move-result-object v0

    .line 369
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 370
    .line 371
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 372
    .line 373
    .line 374
    move-result-object v0

    .line 375
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 376
    .line 377
    .line 378
    throw v1

    .line 379
    :cond_b
    :goto_3
    return-object v5

    .line 380
    :pswitch_5
    move/from16 v16, v2

    .line 381
    .line 382
    iget-object v0, v0, Lz9/r;->a:Ljava/lang/String;

    .line 383
    .line 384
    if-eqz v0, :cond_c

    .line 385
    .line 386
    sget-object v1, Lz9/r;->r:Lly0/n;

    .line 387
    .line 388
    invoke-virtual {v1, v0}, Lly0/n;->d(Ljava/lang/CharSequence;)Z

    .line 389
    .line 390
    .line 391
    move-result v0

    .line 392
    if-eqz v0, :cond_c

    .line 393
    .line 394
    move/from16 v2, v16

    .line 395
    .line 396
    goto :goto_4

    .line 397
    :cond_c
    move v2, v4

    .line 398
    :goto_4
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 399
    .line 400
    .line 401
    move-result-object v0

    .line 402
    return-object v0

    .line 403
    :pswitch_6
    iget-object v0, v0, Lz9/r;->c:Ljava/lang/String;

    .line 404
    .line 405
    if-eqz v0, :cond_d

    .line 406
    .line 407
    new-instance v5, Lly0/n;

    .line 408
    .line 409
    sget-object v1, Lly0/o;->d:[Lly0/o;

    .line 410
    .line 411
    invoke-direct {v5, v0, v4}, Lly0/n;-><init>(Ljava/lang/String;I)V

    .line 412
    .line 413
    .line 414
    :cond_d
    return-object v5

    .line 415
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
