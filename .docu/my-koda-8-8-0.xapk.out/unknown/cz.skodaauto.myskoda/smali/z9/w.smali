.class public final Lz9/w;
.super Lvp/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final g:Lz9/k0;

.field public final h:Ljava/lang/String;

.field public final i:Lhy0/d;

.field public final j:Ll31/q;

.field public final k:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(Lz9/k0;Lhy0/d;Ljava/util/Map;)V
    .locals 2

    const-string v0, "provider"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "startDestination"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "typeMap"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    const-class v0, Lz9/x;

    .line 9
    invoke-static {v0}, Ljp/s0;->a(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object v0

    .line 10
    invoke-virtual {p1, v0}, Lz9/k0;->b(Ljava/lang/String;)Lz9/j0;

    move-result-object v0

    const/4 v1, 0x0

    .line 11
    invoke-direct {p0, v0, v1, p3}, Lvp/c;-><init>(Lz9/j0;Lhy0/d;Ljava/util/Map;)V

    .line 12
    new-instance p3, Ljava/util/ArrayList;

    invoke-direct {p3}, Ljava/util/ArrayList;-><init>()V

    iput-object p3, p0, Lz9/w;->k:Ljava/util/ArrayList;

    .line 13
    iput-object p1, p0, Lz9/w;->g:Lz9/k0;

    .line 14
    iput-object p2, p0, Lz9/w;->i:Lhy0/d;

    return-void
.end method

.method public constructor <init>(Lz9/k0;Ljava/lang/String;Ljava/lang/String;)V
    .locals 2

    const-string v0, "provider"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "startDestination"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    const-class v0, Lz9/x;

    .line 2
    invoke-static {v0}, Ljp/s0;->a(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object v0

    .line 3
    invoke-virtual {p1, v0}, Lz9/k0;->b(Ljava/lang/String;)Lz9/j0;

    move-result-object v0

    const/4 v1, -0x1

    .line 4
    invoke-direct {p0, v0, v1, p3}, Lvp/c;-><init>(Lz9/j0;ILjava/lang/String;)V

    .line 5
    new-instance p3, Ljava/util/ArrayList;

    invoke-direct {p3}, Ljava/util/ArrayList;-><init>()V

    iput-object p3, p0, Lz9/w;->k:Ljava/util/ArrayList;

    .line 6
    iput-object p1, p0, Lz9/w;->g:Lz9/k0;

    .line 7
    iput-object p2, p0, Lz9/w;->h:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(Lz9/k0;Ll31/q;Lhy0/d;)V
    .locals 2

    const-string v0, "provider"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    const-class v0, Lz9/x;

    .line 16
    invoke-static {v0}, Ljp/s0;->a(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object v0

    .line 17
    invoke-virtual {p1, v0}, Lz9/k0;->b(Ljava/lang/String;)Lz9/j0;

    move-result-object v0

    .line 18
    sget-object v1, Lmx0/t;->d:Lmx0/t;

    invoke-direct {p0, v0, p3, v1}, Lvp/c;-><init>(Lz9/j0;Lhy0/d;Ljava/util/Map;)V

    .line 19
    new-instance p3, Ljava/util/ArrayList;

    invoke-direct {p3}, Ljava/util/ArrayList;-><init>()V

    iput-object p3, p0, Lz9/w;->k:Ljava/util/ArrayList;

    .line 20
    iput-object p1, p0, Lz9/w;->g:Lz9/k0;

    .line 21
    iput-object p2, p0, Lz9/w;->j:Ll31/q;

    return-void
.end method


# virtual methods
.method public final bridge synthetic a()Lz9/u;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lz9/w;->i()Lz9/v;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final i()Lz9/v;
    .locals 13

    .line 1
    invoke-super {p0}, Lvp/c;->a()Lz9/u;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Lz9/v;

    .line 6
    .line 7
    const-string v1, "nodes"

    .line 8
    .line 9
    iget-object v2, p0, Lz9/w;->k:Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    iget-object v1, v0, Lz9/v;->i:Lca/m;

    .line 15
    .line 16
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    iget-object v3, v1, Lca/m;->e:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v3, Lz9/v;

    .line 22
    .line 23
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    const/4 v5, 0x0

    .line 32
    if-eqz v4, :cond_9

    .line 33
    .line 34
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v4

    .line 38
    check-cast v4, Lz9/u;

    .line 39
    .line 40
    if-nez v4, :cond_0

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    iget-object v6, v1, Lca/m;->f:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v6, Landroidx/collection/b1;

    .line 46
    .line 47
    iget-object v7, v3, Lz9/u;->e:Lca/j;

    .line 48
    .line 49
    iget-object v8, v4, Lz9/u;->e:Lca/j;

    .line 50
    .line 51
    iget v9, v8, Lca/j;->a:I

    .line 52
    .line 53
    iget-object v10, v8, Lca/j;->e:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast v10, Ljava/lang/String;

    .line 56
    .line 57
    if-nez v9, :cond_2

    .line 58
    .line 59
    if-eqz v10, :cond_1

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 63
    .line 64
    const-string v0, "Destinations must have an id or route. Call setId(), setRoute(), or include an android:id or app:route in your navigation XML."

    .line 65
    .line 66
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    throw p0

    .line 70
    :cond_2
    :goto_1
    iget-object v11, v7, Lca/j;->e:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast v11, Ljava/lang/String;

    .line 73
    .line 74
    const-string v12, "Destination "

    .line 75
    .line 76
    if-eqz v11, :cond_4

    .line 77
    .line 78
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v10

    .line 82
    if-nez v10, :cond_3

    .line 83
    .line 84
    goto :goto_2

    .line 85
    :cond_3
    new-instance p0, Ljava/lang/StringBuilder;

    .line 86
    .line 87
    invoke-direct {p0, v12}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {p0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string v0, " cannot have the same route as graph "

    .line 94
    .line 95
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    invoke-virtual {p0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 106
    .line 107
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    throw v0

    .line 115
    :cond_4
    :goto_2
    iget v7, v7, Lca/j;->a:I

    .line 116
    .line 117
    if-eq v9, v7, :cond_8

    .line 118
    .line 119
    invoke-virtual {v6, v9}, Landroidx/collection/b1;->c(I)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v7

    .line 123
    check-cast v7, Lz9/u;

    .line 124
    .line 125
    if-ne v7, v4, :cond_5

    .line 126
    .line 127
    goto :goto_0

    .line 128
    :cond_5
    iget-object v9, v4, Lz9/u;->f:Lz9/v;

    .line 129
    .line 130
    if-nez v9, :cond_7

    .line 131
    .line 132
    if-eqz v7, :cond_6

    .line 133
    .line 134
    iput-object v5, v7, Lz9/u;->f:Lz9/v;

    .line 135
    .line 136
    :cond_6
    iput-object v3, v4, Lz9/u;->f:Lz9/v;

    .line 137
    .line 138
    iget v5, v8, Lca/j;->a:I

    .line 139
    .line 140
    invoke-virtual {v6, v5, v4}, Landroidx/collection/b1;->e(ILjava/lang/Object;)V

    .line 141
    .line 142
    .line 143
    goto :goto_0

    .line 144
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 145
    .line 146
    const-string v0, "Destination already has a parent set. Call NavGraph.remove() to remove the previous parent."

    .line 147
    .line 148
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    throw p0

    .line 152
    :cond_8
    new-instance p0, Ljava/lang/StringBuilder;

    .line 153
    .line 154
    invoke-direct {p0, v12}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {p0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 158
    .line 159
    .line 160
    const-string v0, " cannot have the same id as graph "

    .line 161
    .line 162
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 163
    .line 164
    .line 165
    invoke-virtual {p0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 166
    .line 167
    .line 168
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object p0

    .line 172
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 173
    .line 174
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 175
    .line 176
    .line 177
    move-result-object p0

    .line 178
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 179
    .line 180
    .line 181
    throw v0

    .line 182
    :cond_9
    iget-object v2, p0, Lz9/w;->j:Ll31/q;

    .line 183
    .line 184
    iget-object v4, p0, Lz9/w;->i:Lhy0/d;

    .line 185
    .line 186
    iget-object v6, p0, Lz9/w;->h:Ljava/lang/String;

    .line 187
    .line 188
    if-nez v6, :cond_b

    .line 189
    .line 190
    if-nez v4, :cond_b

    .line 191
    .line 192
    if-nez v2, :cond_b

    .line 193
    .line 194
    iget-object p0, p0, Lvp/c;->b:Ljava/lang/String;

    .line 195
    .line 196
    if-eqz p0, :cond_a

    .line 197
    .line 198
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 199
    .line 200
    const-string v0, "You must set a start destination route"

    .line 201
    .line 202
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 203
    .line 204
    .line 205
    throw p0

    .line 206
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 207
    .line 208
    const-string v0, "You must set a start destination id"

    .line 209
    .line 210
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    throw p0

    .line 214
    :cond_b
    if-eqz v6, :cond_c

    .line 215
    .line 216
    invoke-virtual {v1, v6}, Lca/m;->l(Ljava/lang/String;)V

    .line 217
    .line 218
    .line 219
    return-object v0

    .line 220
    :cond_c
    if-eqz v4, :cond_e

    .line 221
    .line 222
    invoke-static {v4}, Ljp/mg;->c(Lhy0/d;)Lqz0/a;

    .line 223
    .line 224
    .line 225
    move-result-object p0

    .line 226
    invoke-static {p0}, Lda/d;->b(Lqz0/a;)I

    .line 227
    .line 228
    .line 229
    move-result v2

    .line 230
    invoke-virtual {v1, v2}, Lca/m;->d(I)Lz9/u;

    .line 231
    .line 232
    .line 233
    move-result-object v3

    .line 234
    if-eqz v3, :cond_d

    .line 235
    .line 236
    iget-object p0, v3, Lz9/u;->e:Lca/j;

    .line 237
    .line 238
    iget-object p0, p0, Lca/j;->e:Ljava/lang/Object;

    .line 239
    .line 240
    check-cast p0, Ljava/lang/String;

    .line 241
    .line 242
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 243
    .line 244
    .line 245
    invoke-virtual {v1, p0}, Lca/m;->l(Ljava/lang/String;)V

    .line 246
    .line 247
    .line 248
    iput v2, v1, Lca/m;->d:I

    .line 249
    .line 250
    return-object v0

    .line 251
    :cond_d
    new-instance v0, Ljava/lang/StringBuilder;

    .line 252
    .line 253
    const-string v1, "Cannot find startDestination "

    .line 254
    .line 255
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 256
    .line 257
    .line 258
    invoke-interface {p0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 259
    .line 260
    .line 261
    move-result-object p0

    .line 262
    invoke-interface {p0}, Lsz0/g;->h()Ljava/lang/String;

    .line 263
    .line 264
    .line 265
    move-result-object p0

    .line 266
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 267
    .line 268
    .line 269
    const-string p0, " from NavGraph. Ensure the starting NavDestination was added with route from KClass."

    .line 270
    .line 271
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 272
    .line 273
    .line 274
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 275
    .line 276
    .line 277
    move-result-object p0

    .line 278
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 279
    .line 280
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 281
    .line 282
    .line 283
    move-result-object p0

    .line 284
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 285
    .line 286
    .line 287
    throw v0

    .line 288
    :cond_e
    if-eqz v2, :cond_10

    .line 289
    .line 290
    const-class p0, Ll31/q;

    .line 291
    .line 292
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 293
    .line 294
    invoke-virtual {v3, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 295
    .line 296
    .line 297
    move-result-object p0

    .line 298
    invoke-static {p0}, Ljp/mg;->c(Lhy0/d;)Lqz0/a;

    .line 299
    .line 300
    .line 301
    move-result-object p0

    .line 302
    new-instance v3, Lca/k;

    .line 303
    .line 304
    const/4 v4, 0x0

    .line 305
    invoke-direct {v3, v2, v4}, Lca/k;-><init>(Ljava/lang/Object;I)V

    .line 306
    .line 307
    .line 308
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 309
    .line 310
    .line 311
    invoke-static {p0}, Lda/d;->b(Lqz0/a;)I

    .line 312
    .line 313
    .line 314
    move-result v2

    .line 315
    invoke-virtual {v1, v2}, Lca/m;->d(I)Lz9/u;

    .line 316
    .line 317
    .line 318
    move-result-object v4

    .line 319
    if-eqz v4, :cond_f

    .line 320
    .line 321
    invoke-interface {v3, v4}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 322
    .line 323
    .line 324
    move-result-object p0

    .line 325
    check-cast p0, Ljava/lang/String;

    .line 326
    .line 327
    invoke-virtual {v1, p0}, Lca/m;->l(Ljava/lang/String;)V

    .line 328
    .line 329
    .line 330
    iput v2, v1, Lca/m;->d:I

    .line 331
    .line 332
    return-object v0

    .line 333
    :cond_f
    new-instance v0, Ljava/lang/StringBuilder;

    .line 334
    .line 335
    const-string v1, "Cannot find startDestination "

    .line 336
    .line 337
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 338
    .line 339
    .line 340
    invoke-interface {p0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 341
    .line 342
    .line 343
    move-result-object p0

    .line 344
    invoke-interface {p0}, Lsz0/g;->h()Ljava/lang/String;

    .line 345
    .line 346
    .line 347
    move-result-object p0

    .line 348
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 349
    .line 350
    .line 351
    const-string p0, " from NavGraph. Ensure the starting NavDestination was added with route from KClass."

    .line 352
    .line 353
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 354
    .line 355
    .line 356
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 357
    .line 358
    .line 359
    move-result-object p0

    .line 360
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 361
    .line 362
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 363
    .line 364
    .line 365
    move-result-object p0

    .line 366
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 367
    .line 368
    .line 369
    throw v0

    .line 370
    :cond_10
    iget-object p0, v3, Lz9/u;->e:Lca/j;

    .line 371
    .line 372
    iget p0, p0, Lca/j;->a:I

    .line 373
    .line 374
    if-eqz p0, :cond_12

    .line 375
    .line 376
    iget-object p0, v1, Lca/m;->h:Ljava/lang/Object;

    .line 377
    .line 378
    check-cast p0, Ljava/lang/String;

    .line 379
    .line 380
    if-eqz p0, :cond_11

    .line 381
    .line 382
    invoke-virtual {v1, v5}, Lca/m;->l(Ljava/lang/String;)V

    .line 383
    .line 384
    .line 385
    :cond_11
    const/4 p0, 0x0

    .line 386
    iput p0, v1, Lca/m;->d:I

    .line 387
    .line 388
    iput-object v5, v1, Lca/m;->g:Ljava/lang/Object;

    .line 389
    .line 390
    return-object v0

    .line 391
    :cond_12
    new-instance p0, Ljava/lang/StringBuilder;

    .line 392
    .line 393
    const-string v0, "Start destination 0 cannot use the same id as the graph "

    .line 394
    .line 395
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 396
    .line 397
    .line 398
    invoke-virtual {p0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 399
    .line 400
    .line 401
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 402
    .line 403
    .line 404
    move-result-object p0

    .line 405
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 406
    .line 407
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 408
    .line 409
    .line 410
    move-result-object p0

    .line 411
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 412
    .line 413
    .line 414
    throw v0
.end method
