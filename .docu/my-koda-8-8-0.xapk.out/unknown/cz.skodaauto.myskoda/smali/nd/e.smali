.class public final Lnd/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/e1;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Lhi/a;

.field public final synthetic c:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lhi/a;Lay0/k;I)V
    .locals 0

    .line 1
    iput p3, p0, Lnd/e;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lnd/e;->b:Lhi/a;

    .line 4
    .line 5
    iput-object p2, p0, Lnd/e;->c:Lay0/k;

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
    .locals 1

    .line 1
    iget v0, p0, Lnd/e;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 11
    .line 12
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 17
    .line 18
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    check-cast p0, Landroidx/lifecycle/b1;

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const/4 p0, 0x0

    .line 25
    :try_start_0
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 34
    .line 35
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    :goto_0
    return-object p0

    .line 39
    :catch_0
    move-exception p0

    .line 40
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 47
    .line 48
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p1

    .line 56
    :pswitch_0
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 57
    .line 58
    if-eqz v0, :cond_1

    .line 59
    .line 60
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 61
    .line 62
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 67
    .line 68
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    check-cast p0, Landroidx/lifecycle/b1;

    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_1
    const/4 p0, 0x0

    .line 75
    :try_start_1
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 84
    .line 85
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    :goto_1
    return-object p0

    .line 89
    :catch_1
    move-exception p0

    .line 90
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 91
    .line 92
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 97
    .line 98
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    throw p1

    .line 106
    :pswitch_1
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 107
    .line 108
    if-eqz v0, :cond_2

    .line 109
    .line 110
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 111
    .line 112
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 117
    .line 118
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    check-cast p0, Landroidx/lifecycle/b1;

    .line 122
    .line 123
    goto :goto_2

    .line 124
    :cond_2
    const/4 p0, 0x0

    .line 125
    :try_start_2
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 126
    .line 127
    .line 128
    move-result-object p1

    .line 129
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object p0

    .line 133
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2

    .line 134
    .line 135
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    :goto_2
    return-object p0

    .line 139
    :catch_2
    move-exception p0

    .line 140
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 141
    .line 142
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object p0

    .line 146
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 147
    .line 148
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    throw p1

    .line 156
    :pswitch_2
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 157
    .line 158
    if-eqz v0, :cond_3

    .line 159
    .line 160
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 161
    .line 162
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object p0

    .line 166
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 167
    .line 168
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    check-cast p0, Landroidx/lifecycle/b1;

    .line 172
    .line 173
    goto :goto_3

    .line 174
    :cond_3
    const/4 p0, 0x0

    .line 175
    :try_start_3
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 176
    .line 177
    .line 178
    move-result-object p1

    .line 179
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object p0

    .line 183
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_3

    .line 184
    .line 185
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 186
    .line 187
    .line 188
    :goto_3
    return-object p0

    .line 189
    :catch_3
    move-exception p0

    .line 190
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 191
    .line 192
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 193
    .line 194
    .line 195
    move-result-object p0

    .line 196
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 197
    .line 198
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 199
    .line 200
    .line 201
    move-result-object p0

    .line 202
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 203
    .line 204
    .line 205
    throw p1

    .line 206
    :pswitch_3
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 207
    .line 208
    if-eqz v0, :cond_4

    .line 209
    .line 210
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 211
    .line 212
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object p0

    .line 216
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 217
    .line 218
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 219
    .line 220
    .line 221
    check-cast p0, Landroidx/lifecycle/b1;

    .line 222
    .line 223
    goto :goto_4

    .line 224
    :cond_4
    const/4 p0, 0x0

    .line 225
    :try_start_4
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 226
    .line 227
    .line 228
    move-result-object p1

    .line 229
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 230
    .line 231
    .line 232
    move-result-object p0

    .line 233
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_4

    .line 234
    .line 235
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 236
    .line 237
    .line 238
    :goto_4
    return-object p0

    .line 239
    :catch_4
    move-exception p0

    .line 240
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 241
    .line 242
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 243
    .line 244
    .line 245
    move-result-object p0

    .line 246
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 247
    .line 248
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 249
    .line 250
    .line 251
    move-result-object p0

    .line 252
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 253
    .line 254
    .line 255
    throw p1

    .line 256
    :pswitch_4
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 257
    .line 258
    if-eqz v0, :cond_5

    .line 259
    .line 260
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 261
    .line 262
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 263
    .line 264
    .line 265
    move-result-object p0

    .line 266
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 267
    .line 268
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 269
    .line 270
    .line 271
    check-cast p0, Landroidx/lifecycle/b1;

    .line 272
    .line 273
    goto :goto_5

    .line 274
    :cond_5
    const/4 p0, 0x0

    .line 275
    :try_start_5
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 276
    .line 277
    .line 278
    move-result-object p1

    .line 279
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 280
    .line 281
    .line 282
    move-result-object p0

    .line 283
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_5
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_5

    .line 284
    .line 285
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 286
    .line 287
    .line 288
    :goto_5
    return-object p0

    .line 289
    :catch_5
    move-exception p0

    .line 290
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 291
    .line 292
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 293
    .line 294
    .line 295
    move-result-object p0

    .line 296
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 297
    .line 298
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 299
    .line 300
    .line 301
    move-result-object p0

    .line 302
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 303
    .line 304
    .line 305
    throw p1

    .line 306
    :pswitch_5
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 307
    .line 308
    if-eqz v0, :cond_6

    .line 309
    .line 310
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 311
    .line 312
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 313
    .line 314
    .line 315
    move-result-object p0

    .line 316
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 317
    .line 318
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 319
    .line 320
    .line 321
    check-cast p0, Landroidx/lifecycle/b1;

    .line 322
    .line 323
    goto :goto_6

    .line 324
    :cond_6
    const/4 p0, 0x0

    .line 325
    :try_start_6
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 326
    .line 327
    .line 328
    move-result-object p1

    .line 329
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 330
    .line 331
    .line 332
    move-result-object p0

    .line 333
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_6
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_6

    .line 334
    .line 335
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 336
    .line 337
    .line 338
    :goto_6
    return-object p0

    .line 339
    :catch_6
    move-exception p0

    .line 340
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 341
    .line 342
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 343
    .line 344
    .line 345
    move-result-object p0

    .line 346
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 347
    .line 348
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 349
    .line 350
    .line 351
    move-result-object p0

    .line 352
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 353
    .line 354
    .line 355
    throw p1

    .line 356
    :pswitch_6
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 357
    .line 358
    if-eqz v0, :cond_7

    .line 359
    .line 360
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 361
    .line 362
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 363
    .line 364
    .line 365
    move-result-object p0

    .line 366
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 367
    .line 368
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 369
    .line 370
    .line 371
    check-cast p0, Landroidx/lifecycle/b1;

    .line 372
    .line 373
    goto :goto_7

    .line 374
    :cond_7
    const/4 p0, 0x0

    .line 375
    :try_start_7
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 376
    .line 377
    .line 378
    move-result-object p1

    .line 379
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 380
    .line 381
    .line 382
    move-result-object p0

    .line 383
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_7
    .catch Ljava/lang/Exception; {:try_start_7 .. :try_end_7} :catch_7

    .line 384
    .line 385
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 386
    .line 387
    .line 388
    :goto_7
    return-object p0

    .line 389
    :catch_7
    move-exception p0

    .line 390
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 391
    .line 392
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 393
    .line 394
    .line 395
    move-result-object p0

    .line 396
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 397
    .line 398
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 399
    .line 400
    .line 401
    move-result-object p0

    .line 402
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 403
    .line 404
    .line 405
    throw p1

    .line 406
    :pswitch_7
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 407
    .line 408
    if-eqz v0, :cond_8

    .line 409
    .line 410
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 411
    .line 412
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 413
    .line 414
    .line 415
    move-result-object p0

    .line 416
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 417
    .line 418
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 419
    .line 420
    .line 421
    check-cast p0, Landroidx/lifecycle/b1;

    .line 422
    .line 423
    goto :goto_8

    .line 424
    :cond_8
    const/4 p0, 0x0

    .line 425
    :try_start_8
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 426
    .line 427
    .line 428
    move-result-object p1

    .line 429
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 430
    .line 431
    .line 432
    move-result-object p0

    .line 433
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_8
    .catch Ljava/lang/Exception; {:try_start_8 .. :try_end_8} :catch_8

    .line 434
    .line 435
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 436
    .line 437
    .line 438
    :goto_8
    return-object p0

    .line 439
    :catch_8
    move-exception p0

    .line 440
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 441
    .line 442
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 443
    .line 444
    .line 445
    move-result-object p0

    .line 446
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 447
    .line 448
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 449
    .line 450
    .line 451
    move-result-object p0

    .line 452
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 453
    .line 454
    .line 455
    throw p1

    .line 456
    :pswitch_8
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 457
    .line 458
    if-eqz v0, :cond_9

    .line 459
    .line 460
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 461
    .line 462
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 463
    .line 464
    .line 465
    move-result-object p0

    .line 466
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 467
    .line 468
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 469
    .line 470
    .line 471
    check-cast p0, Landroidx/lifecycle/b1;

    .line 472
    .line 473
    goto :goto_9

    .line 474
    :cond_9
    const/4 p0, 0x0

    .line 475
    :try_start_9
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 476
    .line 477
    .line 478
    move-result-object p1

    .line 479
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 480
    .line 481
    .line 482
    move-result-object p0

    .line 483
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_9
    .catch Ljava/lang/Exception; {:try_start_9 .. :try_end_9} :catch_9

    .line 484
    .line 485
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 486
    .line 487
    .line 488
    :goto_9
    return-object p0

    .line 489
    :catch_9
    move-exception p0

    .line 490
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 491
    .line 492
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 493
    .line 494
    .line 495
    move-result-object p0

    .line 496
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 497
    .line 498
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 499
    .line 500
    .line 501
    move-result-object p0

    .line 502
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 503
    .line 504
    .line 505
    throw p1

    .line 506
    :pswitch_9
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 507
    .line 508
    if-eqz v0, :cond_a

    .line 509
    .line 510
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 511
    .line 512
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 513
    .line 514
    .line 515
    move-result-object p0

    .line 516
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 517
    .line 518
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 519
    .line 520
    .line 521
    check-cast p0, Landroidx/lifecycle/b1;

    .line 522
    .line 523
    goto :goto_a

    .line 524
    :cond_a
    const/4 p0, 0x0

    .line 525
    :try_start_a
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 526
    .line 527
    .line 528
    move-result-object p1

    .line 529
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 530
    .line 531
    .line 532
    move-result-object p0

    .line 533
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_a
    .catch Ljava/lang/Exception; {:try_start_a .. :try_end_a} :catch_a

    .line 534
    .line 535
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 536
    .line 537
    .line 538
    :goto_a
    return-object p0

    .line 539
    :catch_a
    move-exception p0

    .line 540
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 541
    .line 542
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 543
    .line 544
    .line 545
    move-result-object p0

    .line 546
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 547
    .line 548
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 549
    .line 550
    .line 551
    move-result-object p0

    .line 552
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 553
    .line 554
    .line 555
    throw p1

    .line 556
    :pswitch_a
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 557
    .line 558
    if-eqz v0, :cond_b

    .line 559
    .line 560
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 561
    .line 562
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 563
    .line 564
    .line 565
    move-result-object p0

    .line 566
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 567
    .line 568
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 569
    .line 570
    .line 571
    check-cast p0, Landroidx/lifecycle/b1;

    .line 572
    .line 573
    goto :goto_b

    .line 574
    :cond_b
    const/4 p0, 0x0

    .line 575
    :try_start_b
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 576
    .line 577
    .line 578
    move-result-object p1

    .line 579
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 580
    .line 581
    .line 582
    move-result-object p0

    .line 583
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_b
    .catch Ljava/lang/Exception; {:try_start_b .. :try_end_b} :catch_b

    .line 584
    .line 585
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 586
    .line 587
    .line 588
    :goto_b
    return-object p0

    .line 589
    :catch_b
    move-exception p0

    .line 590
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 591
    .line 592
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 593
    .line 594
    .line 595
    move-result-object p0

    .line 596
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 597
    .line 598
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 599
    .line 600
    .line 601
    move-result-object p0

    .line 602
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 603
    .line 604
    .line 605
    throw p1

    .line 606
    :pswitch_b
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 607
    .line 608
    if-eqz v0, :cond_c

    .line 609
    .line 610
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 611
    .line 612
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 613
    .line 614
    .line 615
    move-result-object p0

    .line 616
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 617
    .line 618
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 619
    .line 620
    .line 621
    check-cast p0, Landroidx/lifecycle/b1;

    .line 622
    .line 623
    goto :goto_c

    .line 624
    :cond_c
    const/4 p0, 0x0

    .line 625
    :try_start_c
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 626
    .line 627
    .line 628
    move-result-object p1

    .line 629
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 630
    .line 631
    .line 632
    move-result-object p0

    .line 633
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_c
    .catch Ljava/lang/Exception; {:try_start_c .. :try_end_c} :catch_c

    .line 634
    .line 635
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 636
    .line 637
    .line 638
    :goto_c
    return-object p0

    .line 639
    :catch_c
    move-exception p0

    .line 640
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 641
    .line 642
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 643
    .line 644
    .line 645
    move-result-object p0

    .line 646
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 647
    .line 648
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 649
    .line 650
    .line 651
    move-result-object p0

    .line 652
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 653
    .line 654
    .line 655
    throw p1

    .line 656
    :pswitch_c
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 657
    .line 658
    if-eqz v0, :cond_d

    .line 659
    .line 660
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 661
    .line 662
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 663
    .line 664
    .line 665
    move-result-object p0

    .line 666
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 667
    .line 668
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 669
    .line 670
    .line 671
    check-cast p0, Landroidx/lifecycle/b1;

    .line 672
    .line 673
    goto :goto_d

    .line 674
    :cond_d
    const/4 p0, 0x0

    .line 675
    :try_start_d
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 676
    .line 677
    .line 678
    move-result-object p1

    .line 679
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 680
    .line 681
    .line 682
    move-result-object p0

    .line 683
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_d
    .catch Ljava/lang/Exception; {:try_start_d .. :try_end_d} :catch_d

    .line 684
    .line 685
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 686
    .line 687
    .line 688
    :goto_d
    return-object p0

    .line 689
    :catch_d
    move-exception p0

    .line 690
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 691
    .line 692
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 693
    .line 694
    .line 695
    move-result-object p0

    .line 696
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 697
    .line 698
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 699
    .line 700
    .line 701
    move-result-object p0

    .line 702
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 703
    .line 704
    .line 705
    throw p1

    .line 706
    :pswitch_d
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 707
    .line 708
    if-eqz v0, :cond_e

    .line 709
    .line 710
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 711
    .line 712
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 713
    .line 714
    .line 715
    move-result-object p0

    .line 716
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 717
    .line 718
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 719
    .line 720
    .line 721
    check-cast p0, Landroidx/lifecycle/b1;

    .line 722
    .line 723
    goto :goto_e

    .line 724
    :cond_e
    const/4 p0, 0x0

    .line 725
    :try_start_e
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 726
    .line 727
    .line 728
    move-result-object p1

    .line 729
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 730
    .line 731
    .line 732
    move-result-object p0

    .line 733
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_e
    .catch Ljava/lang/Exception; {:try_start_e .. :try_end_e} :catch_e

    .line 734
    .line 735
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 736
    .line 737
    .line 738
    :goto_e
    return-object p0

    .line 739
    :catch_e
    move-exception p0

    .line 740
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 741
    .line 742
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 743
    .line 744
    .line 745
    move-result-object p0

    .line 746
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 747
    .line 748
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 749
    .line 750
    .line 751
    move-result-object p0

    .line 752
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 753
    .line 754
    .line 755
    throw p1

    .line 756
    :pswitch_e
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 757
    .line 758
    if-eqz v0, :cond_f

    .line 759
    .line 760
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 761
    .line 762
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 763
    .line 764
    .line 765
    move-result-object p0

    .line 766
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 767
    .line 768
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 769
    .line 770
    .line 771
    check-cast p0, Landroidx/lifecycle/b1;

    .line 772
    .line 773
    goto :goto_f

    .line 774
    :cond_f
    const/4 p0, 0x0

    .line 775
    :try_start_f
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 776
    .line 777
    .line 778
    move-result-object p1

    .line 779
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 780
    .line 781
    .line 782
    move-result-object p0

    .line 783
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_f
    .catch Ljava/lang/Exception; {:try_start_f .. :try_end_f} :catch_f

    .line 784
    .line 785
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 786
    .line 787
    .line 788
    :goto_f
    return-object p0

    .line 789
    :catch_f
    move-exception p0

    .line 790
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 791
    .line 792
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 793
    .line 794
    .line 795
    move-result-object p0

    .line 796
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 797
    .line 798
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 799
    .line 800
    .line 801
    move-result-object p0

    .line 802
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 803
    .line 804
    .line 805
    throw p1

    .line 806
    :pswitch_f
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 807
    .line 808
    if-eqz v0, :cond_10

    .line 809
    .line 810
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 811
    .line 812
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 813
    .line 814
    .line 815
    move-result-object p0

    .line 816
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 817
    .line 818
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 819
    .line 820
    .line 821
    check-cast p0, Landroidx/lifecycle/b1;

    .line 822
    .line 823
    goto :goto_10

    .line 824
    :cond_10
    const/4 p0, 0x0

    .line 825
    :try_start_10
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 826
    .line 827
    .line 828
    move-result-object p1

    .line 829
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 830
    .line 831
    .line 832
    move-result-object p0

    .line 833
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_10
    .catch Ljava/lang/Exception; {:try_start_10 .. :try_end_10} :catch_10

    .line 834
    .line 835
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 836
    .line 837
    .line 838
    :goto_10
    return-object p0

    .line 839
    :catch_10
    move-exception p0

    .line 840
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 841
    .line 842
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 843
    .line 844
    .line 845
    move-result-object p0

    .line 846
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 847
    .line 848
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 849
    .line 850
    .line 851
    move-result-object p0

    .line 852
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 853
    .line 854
    .line 855
    throw p1

    .line 856
    :pswitch_10
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 857
    .line 858
    if-eqz v0, :cond_11

    .line 859
    .line 860
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 861
    .line 862
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 863
    .line 864
    .line 865
    move-result-object p0

    .line 866
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 867
    .line 868
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 869
    .line 870
    .line 871
    check-cast p0, Landroidx/lifecycle/b1;

    .line 872
    .line 873
    goto :goto_11

    .line 874
    :cond_11
    const/4 p0, 0x0

    .line 875
    :try_start_11
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 876
    .line 877
    .line 878
    move-result-object p1

    .line 879
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 880
    .line 881
    .line 882
    move-result-object p0

    .line 883
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_11
    .catch Ljava/lang/Exception; {:try_start_11 .. :try_end_11} :catch_11

    .line 884
    .line 885
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 886
    .line 887
    .line 888
    :goto_11
    return-object p0

    .line 889
    :catch_11
    move-exception p0

    .line 890
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 891
    .line 892
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 893
    .line 894
    .line 895
    move-result-object p0

    .line 896
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 897
    .line 898
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 899
    .line 900
    .line 901
    move-result-object p0

    .line 902
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 903
    .line 904
    .line 905
    throw p1

    .line 906
    :pswitch_11
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 907
    .line 908
    if-eqz v0, :cond_12

    .line 909
    .line 910
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 911
    .line 912
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 913
    .line 914
    .line 915
    move-result-object p0

    .line 916
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 917
    .line 918
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 919
    .line 920
    .line 921
    check-cast p0, Landroidx/lifecycle/b1;

    .line 922
    .line 923
    goto :goto_12

    .line 924
    :cond_12
    const/4 p0, 0x0

    .line 925
    :try_start_12
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 926
    .line 927
    .line 928
    move-result-object p1

    .line 929
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 930
    .line 931
    .line 932
    move-result-object p0

    .line 933
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_12
    .catch Ljava/lang/Exception; {:try_start_12 .. :try_end_12} :catch_12

    .line 934
    .line 935
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 936
    .line 937
    .line 938
    :goto_12
    return-object p0

    .line 939
    :catch_12
    move-exception p0

    .line 940
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 941
    .line 942
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 943
    .line 944
    .line 945
    move-result-object p0

    .line 946
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 947
    .line 948
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 949
    .line 950
    .line 951
    move-result-object p0

    .line 952
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 953
    .line 954
    .line 955
    throw p1

    .line 956
    :pswitch_12
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 957
    .line 958
    if-eqz v0, :cond_13

    .line 959
    .line 960
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 961
    .line 962
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 963
    .line 964
    .line 965
    move-result-object p0

    .line 966
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 967
    .line 968
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 969
    .line 970
    .line 971
    check-cast p0, Landroidx/lifecycle/b1;

    .line 972
    .line 973
    goto :goto_13

    .line 974
    :cond_13
    const/4 p0, 0x0

    .line 975
    :try_start_13
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 976
    .line 977
    .line 978
    move-result-object p1

    .line 979
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 980
    .line 981
    .line 982
    move-result-object p0

    .line 983
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_13
    .catch Ljava/lang/Exception; {:try_start_13 .. :try_end_13} :catch_13

    .line 984
    .line 985
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 986
    .line 987
    .line 988
    :goto_13
    return-object p0

    .line 989
    :catch_13
    move-exception p0

    .line 990
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 991
    .line 992
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 993
    .line 994
    .line 995
    move-result-object p0

    .line 996
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 997
    .line 998
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 999
    .line 1000
    .line 1001
    move-result-object p0

    .line 1002
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1003
    .line 1004
    .line 1005
    throw p1

    .line 1006
    :pswitch_13
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 1007
    .line 1008
    if-eqz v0, :cond_14

    .line 1009
    .line 1010
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 1011
    .line 1012
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1013
    .line 1014
    .line 1015
    move-result-object p0

    .line 1016
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 1017
    .line 1018
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1019
    .line 1020
    .line 1021
    check-cast p0, Landroidx/lifecycle/b1;

    .line 1022
    .line 1023
    goto :goto_14

    .line 1024
    :cond_14
    const/4 p0, 0x0

    .line 1025
    :try_start_14
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 1026
    .line 1027
    .line 1028
    move-result-object p1

    .line 1029
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 1030
    .line 1031
    .line 1032
    move-result-object p0

    .line 1033
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_14
    .catch Ljava/lang/Exception; {:try_start_14 .. :try_end_14} :catch_14

    .line 1034
    .line 1035
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 1036
    .line 1037
    .line 1038
    :goto_14
    return-object p0

    .line 1039
    :catch_14
    move-exception p0

    .line 1040
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 1041
    .line 1042
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 1043
    .line 1044
    .line 1045
    move-result-object p0

    .line 1046
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 1047
    .line 1048
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1049
    .line 1050
    .line 1051
    move-result-object p0

    .line 1052
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1053
    .line 1054
    .line 1055
    throw p1

    .line 1056
    :pswitch_14
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 1057
    .line 1058
    if-eqz v0, :cond_15

    .line 1059
    .line 1060
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 1061
    .line 1062
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1063
    .line 1064
    .line 1065
    move-result-object p0

    .line 1066
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 1067
    .line 1068
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1069
    .line 1070
    .line 1071
    check-cast p0, Landroidx/lifecycle/b1;

    .line 1072
    .line 1073
    goto :goto_15

    .line 1074
    :cond_15
    const/4 p0, 0x0

    .line 1075
    :try_start_15
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 1076
    .line 1077
    .line 1078
    move-result-object p1

    .line 1079
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 1080
    .line 1081
    .line 1082
    move-result-object p0

    .line 1083
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_15
    .catch Ljava/lang/Exception; {:try_start_15 .. :try_end_15} :catch_15

    .line 1084
    .line 1085
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 1086
    .line 1087
    .line 1088
    :goto_15
    return-object p0

    .line 1089
    :catch_15
    move-exception p0

    .line 1090
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 1091
    .line 1092
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 1093
    .line 1094
    .line 1095
    move-result-object p0

    .line 1096
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 1097
    .line 1098
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1099
    .line 1100
    .line 1101
    move-result-object p0

    .line 1102
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1103
    .line 1104
    .line 1105
    throw p1

    .line 1106
    :pswitch_15
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 1107
    .line 1108
    if-eqz v0, :cond_16

    .line 1109
    .line 1110
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 1111
    .line 1112
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1113
    .line 1114
    .line 1115
    move-result-object p0

    .line 1116
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 1117
    .line 1118
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1119
    .line 1120
    .line 1121
    check-cast p0, Landroidx/lifecycle/b1;

    .line 1122
    .line 1123
    goto :goto_16

    .line 1124
    :cond_16
    const/4 p0, 0x0

    .line 1125
    :try_start_16
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 1126
    .line 1127
    .line 1128
    move-result-object p1

    .line 1129
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 1130
    .line 1131
    .line 1132
    move-result-object p0

    .line 1133
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_16
    .catch Ljava/lang/Exception; {:try_start_16 .. :try_end_16} :catch_16

    .line 1134
    .line 1135
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 1136
    .line 1137
    .line 1138
    :goto_16
    return-object p0

    .line 1139
    :catch_16
    move-exception p0

    .line 1140
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 1141
    .line 1142
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 1143
    .line 1144
    .line 1145
    move-result-object p0

    .line 1146
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 1147
    .line 1148
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1149
    .line 1150
    .line 1151
    move-result-object p0

    .line 1152
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1153
    .line 1154
    .line 1155
    throw p1

    .line 1156
    :pswitch_16
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 1157
    .line 1158
    if-eqz v0, :cond_17

    .line 1159
    .line 1160
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 1161
    .line 1162
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1163
    .line 1164
    .line 1165
    move-result-object p0

    .line 1166
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 1167
    .line 1168
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1169
    .line 1170
    .line 1171
    check-cast p0, Landroidx/lifecycle/b1;

    .line 1172
    .line 1173
    goto :goto_17

    .line 1174
    :cond_17
    const/4 p0, 0x0

    .line 1175
    :try_start_17
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 1176
    .line 1177
    .line 1178
    move-result-object p1

    .line 1179
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 1180
    .line 1181
    .line 1182
    move-result-object p0

    .line 1183
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_17
    .catch Ljava/lang/Exception; {:try_start_17 .. :try_end_17} :catch_17

    .line 1184
    .line 1185
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 1186
    .line 1187
    .line 1188
    :goto_17
    return-object p0

    .line 1189
    :catch_17
    move-exception p0

    .line 1190
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 1191
    .line 1192
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 1193
    .line 1194
    .line 1195
    move-result-object p0

    .line 1196
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 1197
    .line 1198
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1199
    .line 1200
    .line 1201
    move-result-object p0

    .line 1202
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1203
    .line 1204
    .line 1205
    throw p1

    .line 1206
    :pswitch_17
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 1207
    .line 1208
    if-eqz v0, :cond_18

    .line 1209
    .line 1210
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 1211
    .line 1212
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1213
    .line 1214
    .line 1215
    move-result-object p0

    .line 1216
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 1217
    .line 1218
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1219
    .line 1220
    .line 1221
    check-cast p0, Landroidx/lifecycle/b1;

    .line 1222
    .line 1223
    goto :goto_18

    .line 1224
    :cond_18
    const/4 p0, 0x0

    .line 1225
    :try_start_18
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 1226
    .line 1227
    .line 1228
    move-result-object p1

    .line 1229
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 1230
    .line 1231
    .line 1232
    move-result-object p0

    .line 1233
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_18
    .catch Ljava/lang/Exception; {:try_start_18 .. :try_end_18} :catch_18

    .line 1234
    .line 1235
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 1236
    .line 1237
    .line 1238
    :goto_18
    return-object p0

    .line 1239
    :catch_18
    move-exception p0

    .line 1240
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 1241
    .line 1242
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 1243
    .line 1244
    .line 1245
    move-result-object p0

    .line 1246
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 1247
    .line 1248
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1249
    .line 1250
    .line 1251
    move-result-object p0

    .line 1252
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1253
    .line 1254
    .line 1255
    throw p1

    .line 1256
    :pswitch_18
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 1257
    .line 1258
    if-eqz v0, :cond_19

    .line 1259
    .line 1260
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 1261
    .line 1262
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1263
    .line 1264
    .line 1265
    move-result-object p0

    .line 1266
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 1267
    .line 1268
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1269
    .line 1270
    .line 1271
    check-cast p0, Landroidx/lifecycle/b1;

    .line 1272
    .line 1273
    goto :goto_19

    .line 1274
    :cond_19
    const/4 p0, 0x0

    .line 1275
    :try_start_19
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 1276
    .line 1277
    .line 1278
    move-result-object p1

    .line 1279
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 1280
    .line 1281
    .line 1282
    move-result-object p0

    .line 1283
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_19
    .catch Ljava/lang/Exception; {:try_start_19 .. :try_end_19} :catch_19

    .line 1284
    .line 1285
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 1286
    .line 1287
    .line 1288
    :goto_19
    return-object p0

    .line 1289
    :catch_19
    move-exception p0

    .line 1290
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 1291
    .line 1292
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 1293
    .line 1294
    .line 1295
    move-result-object p0

    .line 1296
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 1297
    .line 1298
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1299
    .line 1300
    .line 1301
    move-result-object p0

    .line 1302
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1303
    .line 1304
    .line 1305
    throw p1

    .line 1306
    :pswitch_19
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 1307
    .line 1308
    if-eqz v0, :cond_1a

    .line 1309
    .line 1310
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 1311
    .line 1312
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1313
    .line 1314
    .line 1315
    move-result-object p0

    .line 1316
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 1317
    .line 1318
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1319
    .line 1320
    .line 1321
    check-cast p0, Landroidx/lifecycle/b1;

    .line 1322
    .line 1323
    goto :goto_1a

    .line 1324
    :cond_1a
    const/4 p0, 0x0

    .line 1325
    :try_start_1a
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 1326
    .line 1327
    .line 1328
    move-result-object p1

    .line 1329
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 1330
    .line 1331
    .line 1332
    move-result-object p0

    .line 1333
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_1a
    .catch Ljava/lang/Exception; {:try_start_1a .. :try_end_1a} :catch_1a

    .line 1334
    .line 1335
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 1336
    .line 1337
    .line 1338
    :goto_1a
    return-object p0

    .line 1339
    :catch_1a
    move-exception p0

    .line 1340
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 1341
    .line 1342
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 1343
    .line 1344
    .line 1345
    move-result-object p0

    .line 1346
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 1347
    .line 1348
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1349
    .line 1350
    .line 1351
    move-result-object p0

    .line 1352
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1353
    .line 1354
    .line 1355
    throw p1

    .line 1356
    :pswitch_1a
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 1357
    .line 1358
    if-eqz v0, :cond_1b

    .line 1359
    .line 1360
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 1361
    .line 1362
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1363
    .line 1364
    .line 1365
    move-result-object p0

    .line 1366
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 1367
    .line 1368
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1369
    .line 1370
    .line 1371
    check-cast p0, Landroidx/lifecycle/b1;

    .line 1372
    .line 1373
    goto :goto_1b

    .line 1374
    :cond_1b
    const/4 p0, 0x0

    .line 1375
    :try_start_1b
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 1376
    .line 1377
    .line 1378
    move-result-object p1

    .line 1379
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 1380
    .line 1381
    .line 1382
    move-result-object p0

    .line 1383
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_1b
    .catch Ljava/lang/Exception; {:try_start_1b .. :try_end_1b} :catch_1b

    .line 1384
    .line 1385
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 1386
    .line 1387
    .line 1388
    :goto_1b
    return-object p0

    .line 1389
    :catch_1b
    move-exception p0

    .line 1390
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 1391
    .line 1392
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 1393
    .line 1394
    .line 1395
    move-result-object p0

    .line 1396
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 1397
    .line 1398
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1399
    .line 1400
    .line 1401
    move-result-object p0

    .line 1402
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1403
    .line 1404
    .line 1405
    throw p1

    .line 1406
    :pswitch_1b
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 1407
    .line 1408
    if-eqz v0, :cond_1c

    .line 1409
    .line 1410
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 1411
    .line 1412
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1413
    .line 1414
    .line 1415
    move-result-object p0

    .line 1416
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 1417
    .line 1418
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1419
    .line 1420
    .line 1421
    check-cast p0, Landroidx/lifecycle/b1;

    .line 1422
    .line 1423
    goto :goto_1c

    .line 1424
    :cond_1c
    const/4 p0, 0x0

    .line 1425
    :try_start_1c
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 1426
    .line 1427
    .line 1428
    move-result-object p1

    .line 1429
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 1430
    .line 1431
    .line 1432
    move-result-object p0

    .line 1433
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_1c
    .catch Ljava/lang/Exception; {:try_start_1c .. :try_end_1c} :catch_1c

    .line 1434
    .line 1435
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 1436
    .line 1437
    .line 1438
    :goto_1c
    return-object p0

    .line 1439
    :catch_1c
    move-exception p0

    .line 1440
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 1441
    .line 1442
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 1443
    .line 1444
    .line 1445
    move-result-object p0

    .line 1446
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 1447
    .line 1448
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1449
    .line 1450
    .line 1451
    move-result-object p0

    .line 1452
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1453
    .line 1454
    .line 1455
    throw p1

    .line 1456
    :pswitch_1c
    iget-object v0, p0, Lnd/e;->b:Lhi/a;

    .line 1457
    .line 1458
    if-eqz v0, :cond_1d

    .line 1459
    .line 1460
    iget-object p0, p0, Lnd/e;->c:Lay0/k;

    .line 1461
    .line 1462
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1463
    .line 1464
    .line 1465
    move-result-object p0

    .line 1466
    const-string p1, "null cannot be cast to non-null type VM of cariad.charging.multicharge.common.presentation.KoinInjectionKt.sdkViewModel.<no name provided>.create"

    .line 1467
    .line 1468
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1469
    .line 1470
    .line 1471
    check-cast p0, Landroidx/lifecycle/b1;

    .line 1472
    .line 1473
    goto :goto_1d

    .line 1474
    :cond_1d
    const/4 p0, 0x0

    .line 1475
    :try_start_1d
    invoke-virtual {p1, p0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 1476
    .line 1477
    .line 1478
    move-result-object p1

    .line 1479
    invoke-virtual {p1, p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 1480
    .line 1481
    .line 1482
    move-result-object p0

    .line 1483
    check-cast p0, Landroidx/lifecycle/b1;
    :try_end_1d
    .catch Ljava/lang/Exception; {:try_start_1d .. :try_end_1d} :catch_1d

    .line 1484
    .line 1485
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 1486
    .line 1487
    .line 1488
    :goto_1d
    return-object p0

    .line 1489
    :catch_1d
    move-exception p0

    .line 1490
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 1491
    .line 1492
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 1493
    .line 1494
    .line 1495
    move-result-object p0

    .line 1496
    const-string v0, "Cannot create ViewModel in preview mode: "

    .line 1497
    .line 1498
    invoke-static {v0, p0}, Lz9/c;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1499
    .line 1500
    .line 1501
    move-result-object p0

    .line 1502
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1503
    .line 1504
    .line 1505
    throw p1

    .line 1506
    nop

    .line 1507
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
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
