.class public final Lkc0/m0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lic0/a;

.field public final b:Lwr0/e;

.field public final c:Lam0/c;


# direct methods
.method public constructor <init>(Lic0/a;Lwr0/e;Lam0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkc0/m0;->a:Lic0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lkc0/m0;->b:Lwr0/e;

    .line 7
    .line 8
    iput-object p3, p0, Lkc0/m0;->c:Lam0/c;

    .line 9
    .line 10
    return-void
.end method

.method public static c(Ljava/lang/String;)Ljava/util/HashMap;
    .locals 5

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    if-eqz p0, :cond_0

    .line 7
    .line 8
    const-string v1, "&"

    .line 9
    .line 10
    filled-new-array {v1}, [Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    const/4 v2, 0x6

    .line 15
    invoke-static {p0, v1, v2}, Lly0/p;->Y(Ljava/lang/CharSequence;[Ljava/lang/String;I)Ljava/util/List;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Ljava/lang/Iterable;

    .line 20
    .line 21
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-eqz v1, :cond_0

    .line 30
    .line 31
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    check-cast v1, Ljava/lang/String;

    .line 36
    .line 37
    const-string v3, "="

    .line 38
    .line 39
    filled-new-array {v3}, [Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    invoke-static {v1, v3, v2}, Lly0/p;->Y(Ljava/lang/CharSequence;[Ljava/lang/String;I)Ljava/util/List;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    const/4 v3, 0x0

    .line 48
    invoke-interface {v1, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    const/4 v4, 0x1

    .line 53
    invoke-static {v4, v1}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-virtual {v0, v3, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_0
    return-object v0
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lkc0/k0;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lkc0/m0;->b(Lkc0/k0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkc0/k0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 12

    .line 1
    instance-of v0, p2, Lkc0/l0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lkc0/l0;

    .line 7
    .line 8
    iget v1, v0, Lkc0/l0;->l:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lkc0/l0;->l:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lkc0/l0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lkc0/l0;-><init>(Lkc0/m0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lkc0/l0;->j:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lkc0/l0;->l:I

    .line 30
    .line 31
    const/4 v3, 0x3

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x1

    .line 34
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    const/4 v7, 0x0

    .line 37
    if-eqz v2, :cond_4

    .line 38
    .line 39
    if-eq v2, v5, :cond_3

    .line 40
    .line 41
    if-eq v2, v4, :cond_2

    .line 42
    .line 43
    if-ne v2, v3, :cond_1

    .line 44
    .line 45
    iget-object p1, v0, Lkc0/l0;->g:Ljava/lang/String;

    .line 46
    .line 47
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 48
    .line 49
    .line 50
    goto/16 :goto_8

    .line 51
    .line 52
    :catchall_0
    move-exception v0

    .line 53
    move-object p1, v0

    .line 54
    goto/16 :goto_a

    .line 55
    .line 56
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 57
    .line 58
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 59
    .line 60
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    throw p0

    .line 64
    :cond_2
    iget p1, v0, Lkc0/l0;->i:I

    .line 65
    .line 66
    iget v2, v0, Lkc0/l0;->h:I

    .line 67
    .line 68
    iget-object v4, v0, Lkc0/l0;->g:Ljava/lang/String;

    .line 69
    .line 70
    iget-object v5, v0, Lkc0/l0;->e:Lkc0/m0;

    .line 71
    .line 72
    iget-object v8, v0, Lkc0/l0;->d:Lkc0/k0;

    .line 73
    .line 74
    :try_start_1
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 75
    .line 76
    .line 77
    move p2, v2

    .line 78
    move v2, p1

    .line 79
    move-object p1, v4

    .line 80
    goto/16 :goto_5

    .line 81
    .line 82
    :cond_3
    iget p1, v0, Lkc0/l0;->i:I

    .line 83
    .line 84
    iget v2, v0, Lkc0/l0;->h:I

    .line 85
    .line 86
    iget-object v5, v0, Lkc0/l0;->f:Ljava/util/HashMap;

    .line 87
    .line 88
    iget-object v8, v0, Lkc0/l0;->e:Lkc0/m0;

    .line 89
    .line 90
    iget-object v9, v0, Lkc0/l0;->d:Lkc0/k0;

    .line 91
    .line 92
    :try_start_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 93
    .line 94
    .line 95
    move p2, v2

    .line 96
    move v2, p1

    .line 97
    move-object p1, v9

    .line 98
    goto/16 :goto_3

    .line 99
    .line 100
    :cond_4
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    iget-object p2, p1, Lkc0/k0;->a:Ljava/lang/String;

    .line 104
    .line 105
    if-eqz p2, :cond_11

    .line 106
    .line 107
    new-instance v2, Lac0/a;

    .line 108
    .line 109
    const/16 v8, 0x19

    .line 110
    .line 111
    invoke-direct {v2, p2, v8}, Lac0/a;-><init>(Ljava/lang/String;I)V

    .line 112
    .line 113
    .line 114
    const-string v8, "Authentication"

    .line 115
    .line 116
    invoke-static {v8, p0, v2}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 117
    .line 118
    .line 119
    :try_start_3
    invoke-static {p2}, Ljava/net/URI;->create(Ljava/lang/String;)Ljava/net/URI;

    .line 120
    .line 121
    .line 122
    move-result-object p2

    .line 123
    invoke-virtual {p2}, Ljava/net/URI;->getScheme()Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object v2

    .line 127
    const-string v8, "myskoda"

    .line 128
    .line 129
    invoke-static {v2, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    move-result v2

    .line 133
    if-eqz v2, :cond_f

    .line 134
    .line 135
    invoke-virtual {p2}, Ljava/net/URI;->getHost()Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object v2

    .line 139
    const-string v8, "redirect"

    .line 140
    .line 141
    invoke-static {v2, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 142
    .line 143
    .line 144
    move-result v2

    .line 145
    if-eqz v2, :cond_f

    .line 146
    .line 147
    invoke-virtual {p2}, Ljava/net/URI;->getPath()Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object v2

    .line 151
    const-string v8, "/login/"

    .line 152
    .line 153
    invoke-static {v2, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 154
    .line 155
    .line 156
    move-result v2

    .line 157
    if-nez v2, :cond_5

    .line 158
    .line 159
    goto/16 :goto_9

    .line 160
    .line 161
    :cond_5
    invoke-virtual {p2}, Ljava/net/URI;->getQuery()Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object p2

    .line 165
    invoke-static {p2}, Lkc0/m0;->c(Ljava/lang/String;)Ljava/util/HashMap;

    .line 166
    .line 167
    .line 168
    move-result-object p2

    .line 169
    const-string v2, "error"

    .line 170
    .line 171
    invoke-virtual {p2, v2}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 172
    .line 173
    .line 174
    move-result v2

    .line 175
    if-eqz v2, :cond_7

    .line 176
    .line 177
    const-string v2, "login_required"

    .line 178
    .line 179
    invoke-virtual {p2, v2}, Ljava/util/HashMap;->containsValue(Ljava/lang/Object;)Z

    .line 180
    .line 181
    .line 182
    move-result v2

    .line 183
    if-nez v2, :cond_6

    .line 184
    .line 185
    goto :goto_1

    .line 186
    :cond_6
    new-instance p1, Llc0/e;

    .line 187
    .line 188
    const-string p2, "Login is required"

    .line 189
    .line 190
    invoke-direct {p1, p2}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    throw p1

    .line 194
    :cond_7
    :goto_1
    iput-object p1, v0, Lkc0/l0;->d:Lkc0/k0;

    .line 195
    .line 196
    iput-object p0, v0, Lkc0/l0;->e:Lkc0/m0;

    .line 197
    .line 198
    iput-object p2, v0, Lkc0/l0;->f:Ljava/util/HashMap;

    .line 199
    .line 200
    const/4 v2, 0x0

    .line 201
    iput v2, v0, Lkc0/l0;->h:I

    .line 202
    .line 203
    iput v2, v0, Lkc0/l0;->i:I

    .line 204
    .line 205
    iput v5, v0, Lkc0/l0;->l:I

    .line 206
    .line 207
    sget-object v5, Lge0/b;->a:Lcz0/e;

    .line 208
    .line 209
    new-instance v8, Li50/p;

    .line 210
    .line 211
    const/16 v9, 0xd

    .line 212
    .line 213
    invoke-direct {v8, v9, p2, p0, v7}, Li50/p;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 214
    .line 215
    .line 216
    invoke-static {v5, v8, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 217
    .line 218
    .line 219
    move-result-object v5

    .line 220
    if-ne v5, v1, :cond_8

    .line 221
    .line 222
    goto :goto_2

    .line 223
    :cond_8
    move-object v5, v6

    .line 224
    :goto_2
    if-ne v5, v1, :cond_9

    .line 225
    .line 226
    goto :goto_7

    .line 227
    :cond_9
    move-object v8, p0

    .line 228
    move-object v5, p2

    .line 229
    move p2, v2

    .line 230
    :goto_3
    const-string v9, "code"

    .line 231
    .line 232
    invoke-interface {v5, v9}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object v5

    .line 236
    check-cast v5, Ljava/lang/String;

    .line 237
    .line 238
    if-eqz v5, :cond_e

    .line 239
    .line 240
    iput-object p1, v0, Lkc0/l0;->d:Lkc0/k0;

    .line 241
    .line 242
    iput-object v8, v0, Lkc0/l0;->e:Lkc0/m0;

    .line 243
    .line 244
    iput-object v7, v0, Lkc0/l0;->f:Ljava/util/HashMap;

    .line 245
    .line 246
    iput-object v5, v0, Lkc0/l0;->g:Ljava/lang/String;

    .line 247
    .line 248
    iput p2, v0, Lkc0/l0;->h:I

    .line 249
    .line 250
    iput v2, v0, Lkc0/l0;->i:I

    .line 251
    .line 252
    iput v4, v0, Lkc0/l0;->l:I

    .line 253
    .line 254
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 255
    .line 256
    .line 257
    sget-object v4, Lge0/b;->a:Lcz0/e;

    .line 258
    .line 259
    new-instance v9, Li50/p;

    .line 260
    .line 261
    const/16 v10, 0xc

    .line 262
    .line 263
    invoke-direct {v9, v10, v8, v5, v7}, Li50/p;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 264
    .line 265
    .line 266
    invoke-static {v4, v9, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    move-result-object v4

    .line 270
    if-ne v4, v1, :cond_a

    .line 271
    .line 272
    goto :goto_4

    .line 273
    :cond_a
    move-object v4, v6

    .line 274
    :goto_4
    if-ne v4, v1, :cond_b

    .line 275
    .line 276
    goto :goto_7

    .line 277
    :cond_b
    move-object v11, v8

    .line 278
    move-object v8, p1

    .line 279
    move-object p1, v5

    .line 280
    move-object v5, v11

    .line 281
    :goto_5
    iget-boolean v4, v8, Lkc0/k0;->b:Z

    .line 282
    .line 283
    iput-object v7, v0, Lkc0/l0;->d:Lkc0/k0;

    .line 284
    .line 285
    iput-object v7, v0, Lkc0/l0;->e:Lkc0/m0;

    .line 286
    .line 287
    iput-object v7, v0, Lkc0/l0;->f:Ljava/util/HashMap;

    .line 288
    .line 289
    iput-object p1, v0, Lkc0/l0;->g:Ljava/lang/String;

    .line 290
    .line 291
    iput p2, v0, Lkc0/l0;->h:I

    .line 292
    .line 293
    iput v2, v0, Lkc0/l0;->i:I

    .line 294
    .line 295
    iput v3, v0, Lkc0/l0;->l:I

    .line 296
    .line 297
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 298
    .line 299
    .line 300
    sget-object p2, Lge0/b;->a:Lcz0/e;

    .line 301
    .line 302
    new-instance v2, Lau0/b;

    .line 303
    .line 304
    invoke-direct {v2, v5, p1, v4, v7}, Lau0/b;-><init>(Lkc0/m0;Ljava/lang/String;ZLkotlin/coroutines/Continuation;)V

    .line 305
    .line 306
    .line 307
    invoke-static {p2, v2, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 308
    .line 309
    .line 310
    move-result-object p2

    .line 311
    if-ne p2, v1, :cond_c

    .line 312
    .line 313
    goto :goto_6

    .line 314
    :cond_c
    move-object p2, v6

    .line 315
    :goto_6
    if-ne p2, v1, :cond_d

    .line 316
    .line 317
    :goto_7
    return-object v1

    .line 318
    :cond_d
    :goto_8
    new-instance p2, Llc0/b;

    .line 319
    .line 320
    invoke-direct {p2, p1}, Llc0/b;-><init>(Ljava/lang/String;)V

    .line 321
    .line 322
    .line 323
    goto :goto_b

    .line 324
    :cond_e
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 325
    .line 326
    const-string p2, "Auth code value is null"

    .line 327
    .line 328
    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 329
    .line 330
    .line 331
    throw p1

    .line 332
    :cond_f
    :goto_9
    new-instance p1, Lkc0/j0;

    .line 333
    .line 334
    const/4 v0, 0x0

    .line 335
    invoke-direct {p1, p2, v0}, Lkc0/j0;-><init>(Ljava/net/URI;I)V

    .line 336
    .line 337
    .line 338
    invoke-static {v7, p0, p1}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 339
    .line 340
    .line 341
    return-object v6

    .line 342
    :goto_a
    invoke-static {p1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 343
    .line 344
    .line 345
    move-result-object p2

    .line 346
    :goto_b
    invoke-static {p2}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 347
    .line 348
    .line 349
    move-result-object v1

    .line 350
    iget-object p0, p0, Lkc0/m0;->a:Lic0/a;

    .line 351
    .line 352
    if-nez v1, :cond_10

    .line 353
    .line 354
    check-cast p2, Llc0/b;

    .line 355
    .line 356
    new-instance p1, Lne0/e;

    .line 357
    .line 358
    invoke-direct {p1, p2}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 359
    .line 360
    .line 361
    iget-object p0, p0, Lic0/a;->h:Lyy0/q1;

    .line 362
    .line 363
    invoke-virtual {p0, p1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 364
    .line 365
    .line 366
    goto :goto_c

    .line 367
    :cond_10
    new-instance v0, Lne0/c;

    .line 368
    .line 369
    const/4 v4, 0x0

    .line 370
    const/16 v5, 0x1e

    .line 371
    .line 372
    const/4 v2, 0x0

    .line 373
    const/4 v3, 0x0

    .line 374
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 375
    .line 376
    .line 377
    iget-object p0, p0, Lic0/a;->h:Lyy0/q1;

    .line 378
    .line 379
    invoke-virtual {p0, v0}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 380
    .line 381
    .line 382
    :cond_11
    :goto_c
    return-object v6
.end method
