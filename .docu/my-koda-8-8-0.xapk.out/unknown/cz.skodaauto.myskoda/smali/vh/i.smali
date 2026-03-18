.class public final Lvh/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/e1;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;

.field public final synthetic c:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lvh/i;->a:I

    .line 2
    .line 3
    iput-object p2, p0, Lvh/i;->b:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Lvh/i;->c:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final b(Ljava/lang/Class;)Landroidx/lifecycle/b1;
    .locals 9

    .line 1
    iget v0, p0, Lvh/i;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lce/u;

    .line 7
    .line 8
    iget-object v0, p0, Lvh/i;->b:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Ljava/lang/String;

    .line 11
    .line 12
    new-instance v1, Lag/c;

    .line 13
    .line 14
    iget-object p0, p0, Lvh/i;->c:Ljava/lang/Object;

    .line 15
    .line 16
    move-object v3, p0

    .line 17
    check-cast v3, Lbe/b;

    .line 18
    .line 19
    const/4 v7, 0x0

    .line 20
    const/4 v8, 0x5

    .line 21
    const/4 v2, 0x2

    .line 22
    const-class v4, Lbe/b;

    .line 23
    .line 24
    const-string v5, "getCpoiDetails"

    .line 25
    .line 26
    const-string v6, "getCpoiDetails-gIAlu-s(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 27
    .line 28
    invoke-direct/range {v1 .. v8}, Lag/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 29
    .line 30
    .line 31
    invoke-direct {p1, v0, v1}, Lce/u;-><init>(Ljava/lang/String;Lag/c;)V

    .line 32
    .line 33
    .line 34
    return-object p1

    .line 35
    :pswitch_0
    iget-object v0, p0, Lvh/i;->b:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v0, Lhi/a;

    .line 38
    .line 39
    if-eqz v0, :cond_0

    .line 40
    .line 41
    iget-object p0, p0, Lvh/i;->c:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast p0, Lay0/k;

    .line 44
    .line 45
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 50
    .line 51
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    check-cast p0, Landroidx/lifecycle/b1;

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_0
    const/4 p0, 0x0

    .line 58
    :try_start_0
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 67
    .line 68
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    :goto_0
    return-object p0

    .line 72
    :catch_0
    move-exception v0

    .line 73
    move-object p0, v0

    .line 74
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 75
    .line 76
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 81
    .line 82
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    throw p1

    .line 90
    :pswitch_1
    iget-object v0, p0, Lvh/i;->b:Ljava/lang/Object;

    .line 91
    .line 92
    check-cast v0, Lhi/a;

    .line 93
    .line 94
    if-eqz v0, :cond_1

    .line 95
    .line 96
    iget-object p0, p0, Lvh/i;->c:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast p0, Lay0/k;

    .line 99
    .line 100
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 105
    .line 106
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    check-cast p0, Landroidx/lifecycle/b1;

    .line 110
    .line 111
    goto :goto_1

    .line 112
    :cond_1
    const/4 p0, 0x0

    .line 113
    :try_start_1
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 114
    .line 115
    .line 116
    move-result-object p1

    .line 117
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 122
    .line 123
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    :goto_1
    return-object p0

    .line 127
    :catch_1
    move-exception v0

    .line 128
    move-object p0, v0

    .line 129
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 130
    .line 131
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 136
    .line 137
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 138
    .line 139
    .line 140
    move-result-object p0

    .line 141
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    throw p1

    .line 145
    :pswitch_2
    iget-object v0, p0, Lvh/i;->b:Ljava/lang/Object;

    .line 146
    .line 147
    check-cast v0, Lhi/a;

    .line 148
    .line 149
    if-eqz v0, :cond_2

    .line 150
    .line 151
    iget-object p0, p0, Lvh/i;->c:Ljava/lang/Object;

    .line 152
    .line 153
    check-cast p0, Lay0/k;

    .line 154
    .line 155
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 160
    .line 161
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    check-cast p0, Landroidx/lifecycle/b1;

    .line 165
    .line 166
    goto :goto_2

    .line 167
    :cond_2
    const/4 p0, 0x0

    .line 168
    :try_start_2
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 169
    .line 170
    .line 171
    move-result-object p1

    .line 172
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2

    .line 177
    .line 178
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 179
    .line 180
    .line 181
    :goto_2
    return-object p0

    .line 182
    :catch_2
    move-exception v0

    .line 183
    move-object p0, v0

    .line 184
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 185
    .line 186
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 187
    .line 188
    .line 189
    move-result-object p0

    .line 190
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 191
    .line 192
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 193
    .line 194
    .line 195
    move-result-object p0

    .line 196
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 197
    .line 198
    .line 199
    throw p1

    .line 200
    :pswitch_3
    iget-object v0, p0, Lvh/i;->b:Ljava/lang/Object;

    .line 201
    .line 202
    check-cast v0, Lhi/a;

    .line 203
    .line 204
    if-eqz v0, :cond_3

    .line 205
    .line 206
    iget-object p0, p0, Lvh/i;->c:Ljava/lang/Object;

    .line 207
    .line 208
    check-cast p0, Lay0/k;

    .line 209
    .line 210
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object p0

    .line 214
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 215
    .line 216
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 217
    .line 218
    .line 219
    check-cast p0, Landroidx/lifecycle/b1;

    .line 220
    .line 221
    goto :goto_3

    .line 222
    :cond_3
    const/4 p0, 0x0

    .line 223
    :try_start_3
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 224
    .line 225
    .line 226
    move-result-object p1

    .line 227
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 228
    .line 229
    .line 230
    move-result-object p0

    .line 231
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_3

    .line 232
    .line 233
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 234
    .line 235
    .line 236
    :goto_3
    return-object p0

    .line 237
    :catch_3
    move-exception v0

    .line 238
    move-object p0, v0

    .line 239
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 240
    .line 241
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 242
    .line 243
    .line 244
    move-result-object p0

    .line 245
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 246
    .line 247
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 248
    .line 249
    .line 250
    move-result-object p0

    .line 251
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 252
    .line 253
    .line 254
    throw p1

    .line 255
    :pswitch_4
    iget-object v0, p0, Lvh/i;->b:Ljava/lang/Object;

    .line 256
    .line 257
    check-cast v0, Lhi/a;

    .line 258
    .line 259
    if-eqz v0, :cond_4

    .line 260
    .line 261
    iget-object p0, p0, Lvh/i;->c:Ljava/lang/Object;

    .line 262
    .line 263
    check-cast p0, Lay0/k;

    .line 264
    .line 265
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 266
    .line 267
    .line 268
    move-result-object p0

    .line 269
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 270
    .line 271
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 272
    .line 273
    .line 274
    check-cast p0, Landroidx/lifecycle/b1;

    .line 275
    .line 276
    goto :goto_4

    .line 277
    :cond_4
    const/4 p0, 0x0

    .line 278
    :try_start_4
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 279
    .line 280
    .line 281
    move-result-object p1

    .line 282
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 283
    .line 284
    .line 285
    move-result-object p0

    .line 286
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_4

    .line 287
    .line 288
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 289
    .line 290
    .line 291
    :goto_4
    return-object p0

    .line 292
    :catch_4
    move-exception v0

    .line 293
    move-object p0, v0

    .line 294
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 295
    .line 296
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 297
    .line 298
    .line 299
    move-result-object p0

    .line 300
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 301
    .line 302
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 303
    .line 304
    .line 305
    move-result-object p0

    .line 306
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 307
    .line 308
    .line 309
    throw p1

    .line 310
    :pswitch_5
    iget-object v0, p0, Lvh/i;->b:Ljava/lang/Object;

    .line 311
    .line 312
    check-cast v0, Lhi/a;

    .line 313
    .line 314
    if-eqz v0, :cond_5

    .line 315
    .line 316
    iget-object p0, p0, Lvh/i;->c:Ljava/lang/Object;

    .line 317
    .line 318
    check-cast p0, Lay0/k;

    .line 319
    .line 320
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 321
    .line 322
    .line 323
    move-result-object p0

    .line 324
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 325
    .line 326
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 327
    .line 328
    .line 329
    check-cast p0, Landroidx/lifecycle/b1;

    .line 330
    .line 331
    goto :goto_5

    .line 332
    :cond_5
    const/4 p0, 0x0

    .line 333
    :try_start_5
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 334
    .line 335
    .line 336
    move-result-object p1

    .line 337
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 338
    .line 339
    .line 340
    move-result-object p0

    .line 341
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_5
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_5

    .line 342
    .line 343
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 344
    .line 345
    .line 346
    :goto_5
    return-object p0

    .line 347
    :catch_5
    move-exception v0

    .line 348
    move-object p0, v0

    .line 349
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 350
    .line 351
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 352
    .line 353
    .line 354
    move-result-object p0

    .line 355
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 356
    .line 357
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 358
    .line 359
    .line 360
    move-result-object p0

    .line 361
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 362
    .line 363
    .line 364
    throw p1

    .line 365
    :pswitch_6
    iget-object v0, p0, Lvh/i;->b:Ljava/lang/Object;

    .line 366
    .line 367
    check-cast v0, Lhi/a;

    .line 368
    .line 369
    if-eqz v0, :cond_6

    .line 370
    .line 371
    iget-object p0, p0, Lvh/i;->c:Ljava/lang/Object;

    .line 372
    .line 373
    check-cast p0, Lay0/k;

    .line 374
    .line 375
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 376
    .line 377
    .line 378
    move-result-object p0

    .line 379
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 380
    .line 381
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 382
    .line 383
    .line 384
    check-cast p0, Landroidx/lifecycle/b1;

    .line 385
    .line 386
    goto :goto_6

    .line 387
    :cond_6
    const/4 p0, 0x0

    .line 388
    :try_start_6
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 389
    .line 390
    .line 391
    move-result-object p1

    .line 392
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 393
    .line 394
    .line 395
    move-result-object p0

    .line 396
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_6
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_6

    .line 397
    .line 398
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 399
    .line 400
    .line 401
    :goto_6
    return-object p0

    .line 402
    :catch_6
    move-exception v0

    .line 403
    move-object p0, v0

    .line 404
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 405
    .line 406
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 407
    .line 408
    .line 409
    move-result-object p0

    .line 410
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 411
    .line 412
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 413
    .line 414
    .line 415
    move-result-object p0

    .line 416
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 417
    .line 418
    .line 419
    throw p1

    .line 420
    :pswitch_7
    iget-object v0, p0, Lvh/i;->b:Ljava/lang/Object;

    .line 421
    .line 422
    check-cast v0, Lhi/a;

    .line 423
    .line 424
    if-eqz v0, :cond_7

    .line 425
    .line 426
    iget-object p0, p0, Lvh/i;->c:Ljava/lang/Object;

    .line 427
    .line 428
    check-cast p0, Lay0/k;

    .line 429
    .line 430
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 431
    .line 432
    .line 433
    move-result-object p0

    .line 434
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 435
    .line 436
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 437
    .line 438
    .line 439
    check-cast p0, Landroidx/lifecycle/b1;

    .line 440
    .line 441
    goto :goto_7

    .line 442
    :cond_7
    const/4 p0, 0x0

    .line 443
    :try_start_7
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 444
    .line 445
    .line 446
    move-result-object p1

    .line 447
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 448
    .line 449
    .line 450
    move-result-object p0

    .line 451
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_7
    .catch Ljava/lang/Exception; {:try_start_7 .. :try_end_7} :catch_7

    .line 452
    .line 453
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 454
    .line 455
    .line 456
    :goto_7
    return-object p0

    .line 457
    :catch_7
    move-exception v0

    .line 458
    move-object p0, v0

    .line 459
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 460
    .line 461
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 462
    .line 463
    .line 464
    move-result-object p0

    .line 465
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 466
    .line 467
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 468
    .line 469
    .line 470
    move-result-object p0

    .line 471
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 472
    .line 473
    .line 474
    throw p1

    .line 475
    :pswitch_8
    iget-object v0, p0, Lvh/i;->b:Ljava/lang/Object;

    .line 476
    .line 477
    check-cast v0, Lhi/a;

    .line 478
    .line 479
    if-eqz v0, :cond_8

    .line 480
    .line 481
    iget-object p0, p0, Lvh/i;->c:Ljava/lang/Object;

    .line 482
    .line 483
    check-cast p0, Lay0/k;

    .line 484
    .line 485
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 486
    .line 487
    .line 488
    move-result-object p0

    .line 489
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 490
    .line 491
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 492
    .line 493
    .line 494
    check-cast p0, Landroidx/lifecycle/b1;

    .line 495
    .line 496
    goto :goto_8

    .line 497
    :cond_8
    const/4 p0, 0x0

    .line 498
    :try_start_8
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 499
    .line 500
    .line 501
    move-result-object p1

    .line 502
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 503
    .line 504
    .line 505
    move-result-object p0

    .line 506
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_8
    .catch Ljava/lang/Exception; {:try_start_8 .. :try_end_8} :catch_8

    .line 507
    .line 508
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 509
    .line 510
    .line 511
    :goto_8
    return-object p0

    .line 512
    :catch_8
    move-exception v0

    .line 513
    move-object p0, v0

    .line 514
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 515
    .line 516
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 517
    .line 518
    .line 519
    move-result-object p0

    .line 520
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 521
    .line 522
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 523
    .line 524
    .line 525
    move-result-object p0

    .line 526
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 527
    .line 528
    .line 529
    throw p1

    .line 530
    :pswitch_9
    iget-object v0, p0, Lvh/i;->b:Ljava/lang/Object;

    .line 531
    .line 532
    check-cast v0, Lhi/a;

    .line 533
    .line 534
    if-eqz v0, :cond_9

    .line 535
    .line 536
    iget-object p0, p0, Lvh/i;->c:Ljava/lang/Object;

    .line 537
    .line 538
    check-cast p0, Lay0/k;

    .line 539
    .line 540
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 541
    .line 542
    .line 543
    move-result-object p0

    .line 544
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 545
    .line 546
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 547
    .line 548
    .line 549
    check-cast p0, Landroidx/lifecycle/b1;

    .line 550
    .line 551
    goto :goto_9

    .line 552
    :cond_9
    const/4 p0, 0x0

    .line 553
    :try_start_9
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 554
    .line 555
    .line 556
    move-result-object p1

    .line 557
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 558
    .line 559
    .line 560
    move-result-object p0

    .line 561
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_9
    .catch Ljava/lang/Exception; {:try_start_9 .. :try_end_9} :catch_9

    .line 562
    .line 563
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 564
    .line 565
    .line 566
    :goto_9
    return-object p0

    .line 567
    :catch_9
    move-exception v0

    .line 568
    move-object p0, v0

    .line 569
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 570
    .line 571
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 572
    .line 573
    .line 574
    move-result-object p0

    .line 575
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 576
    .line 577
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 578
    .line 579
    .line 580
    move-result-object p0

    .line 581
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 582
    .line 583
    .line 584
    throw p1

    .line 585
    :pswitch_a
    iget-object v0, p0, Lvh/i;->b:Ljava/lang/Object;

    .line 586
    .line 587
    check-cast v0, Lhi/a;

    .line 588
    .line 589
    if-eqz v0, :cond_a

    .line 590
    .line 591
    iget-object p0, p0, Lvh/i;->c:Ljava/lang/Object;

    .line 592
    .line 593
    check-cast p0, Lay0/k;

    .line 594
    .line 595
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 596
    .line 597
    .line 598
    move-result-object p0

    .line 599
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 600
    .line 601
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 602
    .line 603
    .line 604
    check-cast p0, Landroidx/lifecycle/b1;

    .line 605
    .line 606
    goto :goto_a

    .line 607
    :cond_a
    const/4 p0, 0x0

    .line 608
    :try_start_a
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 609
    .line 610
    .line 611
    move-result-object p1

    .line 612
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 613
    .line 614
    .line 615
    move-result-object p0

    .line 616
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_a
    .catch Ljava/lang/Exception; {:try_start_a .. :try_end_a} :catch_a

    .line 617
    .line 618
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 619
    .line 620
    .line 621
    :goto_a
    return-object p0

    .line 622
    :catch_a
    move-exception v0

    .line 623
    move-object p0, v0

    .line 624
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 625
    .line 626
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 627
    .line 628
    .line 629
    move-result-object p0

    .line 630
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 631
    .line 632
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 633
    .line 634
    .line 635
    move-result-object p0

    .line 636
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 637
    .line 638
    .line 639
    throw p1

    .line 640
    :pswitch_b
    iget-object v0, p0, Lvh/i;->b:Ljava/lang/Object;

    .line 641
    .line 642
    check-cast v0, Lhi/a;

    .line 643
    .line 644
    if-eqz v0, :cond_b

    .line 645
    .line 646
    iget-object p0, p0, Lvh/i;->c:Ljava/lang/Object;

    .line 647
    .line 648
    check-cast p0, Lay0/k;

    .line 649
    .line 650
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 651
    .line 652
    .line 653
    move-result-object p0

    .line 654
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 655
    .line 656
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 657
    .line 658
    .line 659
    check-cast p0, Landroidx/lifecycle/b1;

    .line 660
    .line 661
    goto :goto_b

    .line 662
    :cond_b
    const/4 p0, 0x0

    .line 663
    :try_start_b
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 664
    .line 665
    .line 666
    move-result-object p1

    .line 667
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 668
    .line 669
    .line 670
    move-result-object p0

    .line 671
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_b
    .catch Ljava/lang/Exception; {:try_start_b .. :try_end_b} :catch_b

    .line 672
    .line 673
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 674
    .line 675
    .line 676
    :goto_b
    return-object p0

    .line 677
    :catch_b
    move-exception v0

    .line 678
    move-object p0, v0

    .line 679
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 680
    .line 681
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 682
    .line 683
    .line 684
    move-result-object p0

    .line 685
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 686
    .line 687
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 688
    .line 689
    .line 690
    move-result-object p0

    .line 691
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 692
    .line 693
    .line 694
    throw p1

    .line 695
    :pswitch_c
    iget-object v0, p0, Lvh/i;->b:Ljava/lang/Object;

    .line 696
    .line 697
    check-cast v0, Lhi/a;

    .line 698
    .line 699
    if-eqz v0, :cond_c

    .line 700
    .line 701
    iget-object p0, p0, Lvh/i;->c:Ljava/lang/Object;

    .line 702
    .line 703
    check-cast p0, Lay0/k;

    .line 704
    .line 705
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 706
    .line 707
    .line 708
    move-result-object p0

    .line 709
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 710
    .line 711
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 712
    .line 713
    .line 714
    check-cast p0, Landroidx/lifecycle/b1;

    .line 715
    .line 716
    goto :goto_c

    .line 717
    :cond_c
    const/4 p0, 0x0

    .line 718
    :try_start_c
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 719
    .line 720
    .line 721
    move-result-object p1

    .line 722
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 723
    .line 724
    .line 725
    move-result-object p0

    .line 726
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_c
    .catch Ljava/lang/Exception; {:try_start_c .. :try_end_c} :catch_c

    .line 727
    .line 728
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 729
    .line 730
    .line 731
    :goto_c
    return-object p0

    .line 732
    :catch_c
    move-exception v0

    .line 733
    move-object p0, v0

    .line 734
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 735
    .line 736
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 737
    .line 738
    .line 739
    move-result-object p0

    .line 740
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 741
    .line 742
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 743
    .line 744
    .line 745
    move-result-object p0

    .line 746
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 747
    .line 748
    .line 749
    throw p1

    .line 750
    nop

    .line 751
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
