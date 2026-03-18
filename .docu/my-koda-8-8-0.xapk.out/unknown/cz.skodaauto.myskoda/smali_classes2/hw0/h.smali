.class public abstract Lhw0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt21/b;

.field public static final b:Ljava/util/Set;

.field public static final c:Lvw0/a;

.field public static final d:Lgw0/c;


# direct methods
.method static constructor <clinit>()V
    .locals 10

    .line 1
    const-string v0, "io.ktor.client.plugins.contentnegotiation.ContentNegotiation"

    .line 2
    .line 3
    invoke-static {v0}, Lt21/d;->b(Ljava/lang/String;)Lt21/b;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lhw0/h;->a:Lt21/b;

    .line 8
    .line 9
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 10
    .line 11
    const-class v1, [B

    .line 12
    .line 13
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    const-class v2, Ljava/lang/String;

    .line 18
    .line 19
    invoke-virtual {v0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    const-class v3, Low0/v;

    .line 24
    .line 25
    invoke-virtual {v0, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    const-class v4, Lio/ktor/utils/io/t;

    .line 30
    .line 31
    invoke-virtual {v0, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 32
    .line 33
    .line 34
    move-result-object v4

    .line 35
    const-class v5, Lrw0/d;

    .line 36
    .line 37
    invoke-virtual {v0, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 38
    .line 39
    .line 40
    move-result-object v5

    .line 41
    const-class v6, Liw0/a;

    .line 42
    .line 43
    invoke-virtual {v0, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 44
    .line 45
    .line 46
    move-result-object v6

    .line 47
    const-class v7, Liw0/b;

    .line 48
    .line 49
    invoke-virtual {v0, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 50
    .line 51
    .line 52
    move-result-object v7

    .line 53
    const/4 v8, 0x7

    .line 54
    new-array v8, v8, [Lhy0/d;

    .line 55
    .line 56
    const/4 v9, 0x0

    .line 57
    aput-object v1, v8, v9

    .line 58
    .line 59
    const/4 v1, 0x1

    .line 60
    aput-object v2, v8, v1

    .line 61
    .line 62
    const/4 v1, 0x2

    .line 63
    aput-object v3, v8, v1

    .line 64
    .line 65
    const/4 v1, 0x3

    .line 66
    aput-object v4, v8, v1

    .line 67
    .line 68
    const/4 v1, 0x4

    .line 69
    aput-object v5, v8, v1

    .line 70
    .line 71
    const/4 v1, 0x5

    .line 72
    aput-object v6, v8, v1

    .line 73
    .line 74
    const/4 v1, 0x6

    .line 75
    aput-object v7, v8, v1

    .line 76
    .line 77
    invoke-static {v8}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 78
    .line 79
    .line 80
    move-result-object v1

    .line 81
    sput-object v1, Lhw0/h;->b:Ljava/util/Set;

    .line 82
    .line 83
    const-class v1, Ljava/util/List;

    .line 84
    .line 85
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    :try_start_0
    sget-object v2, Lhy0/d0;->c:Lhy0/d0;

    .line 90
    .line 91
    const-class v2, Low0/e;

    .line 92
    .line 93
    invoke-static {v2}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 94
    .line 95
    .line 96
    move-result-object v2

    .line 97
    invoke-static {v2}, Llp/e1;->c(Lhy0/a0;)Lhy0/d0;

    .line 98
    .line 99
    .line 100
    move-result-object v2

    .line 101
    invoke-static {v1, v2}, Lkotlin/jvm/internal/g0;->c(Ljava/lang/Class;Lhy0/d0;)Lhy0/a0;

    .line 102
    .line 103
    .line 104
    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 105
    goto :goto_0

    .line 106
    :catchall_0
    const/4 v1, 0x0

    .line 107
    :goto_0
    new-instance v2, Lzw0/a;

    .line 108
    .line 109
    invoke-direct {v2, v0, v1}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 110
    .line 111
    .line 112
    new-instance v0, Lvw0/a;

    .line 113
    .line 114
    const-string v1, "ExcludedContentTypesAttr"

    .line 115
    .line 116
    invoke-direct {v0, v1, v2}, Lvw0/a;-><init>(Ljava/lang/String;Lzw0/a;)V

    .line 117
    .line 118
    .line 119
    sput-object v0, Lhw0/h;->c:Lvw0/a;

    .line 120
    .line 121
    sget-object v0, Lhw0/c;->d:Lhw0/c;

    .line 122
    .line 123
    new-instance v1, Lh70/f;

    .line 124
    .line 125
    const/16 v2, 0x8

    .line 126
    .line 127
    invoke-direct {v1, v2}, Lh70/f;-><init>(I)V

    .line 128
    .line 129
    .line 130
    const-string v2, "ContentNegotiation"

    .line 131
    .line 132
    invoke-static {v2, v0, v1}, Lkp/q9;->a(Ljava/lang/String;Lay0/a;Lay0/k;)Lgw0/c;

    .line 133
    .line 134
    .line 135
    move-result-object v0

    .line 136
    sput-object v0, Lhw0/h;->d:Lgw0/c;

    .line 137
    .line 138
    return-void
.end method

.method public static final a(Ljava/util/List;Ljava/util/Set;Lgw0/b;Lkw0/c;Ljava/lang/Object;Lrx0/c;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p3

    .line 2
    .line 3
    move-object/from16 v1, p4

    .line 4
    .line 5
    move-object/from16 v2, p5

    .line 6
    .line 7
    instance-of v3, v2, Lhw0/f;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v2

    .line 12
    check-cast v3, Lhw0/f;

    .line 13
    .line 14
    iget v4, v3, Lhw0/f;->k:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Lhw0/f;->k:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lhw0/f;

    .line 27
    .line 28
    invoke-direct {v3, v2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v2, v3, Lhw0/f;->j:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lhw0/f;->k:I

    .line 36
    .line 37
    const/4 v6, 0x1

    .line 38
    sget-object v7, Lhw0/h;->a:Lt21/b;

    .line 39
    .line 40
    if-eqz v5, :cond_2

    .line 41
    .line 42
    if-ne v5, v6, :cond_1

    .line 43
    .line 44
    iget-object v0, v3, Lhw0/f;->i:Lhw0/a;

    .line 45
    .line 46
    iget-object v1, v3, Lhw0/f;->h:Ljava/util/Iterator;

    .line 47
    .line 48
    iget-object v5, v3, Lhw0/f;->g:Ljava/util/List;

    .line 49
    .line 50
    check-cast v5, Ljava/util/List;

    .line 51
    .line 52
    iget-object v9, v3, Lhw0/f;->f:Low0/e;

    .line 53
    .line 54
    iget-object v10, v3, Lhw0/f;->e:Ljava/lang/Object;

    .line 55
    .line 56
    iget-object v11, v3, Lhw0/f;->d:Lkw0/c;

    .line 57
    .line 58
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    move-object v13, v3

    .line 62
    const/16 p5, 0x0

    .line 63
    .line 64
    move-object v3, v1

    .line 65
    move-object v1, v10

    .line 66
    goto/16 :goto_e

    .line 67
    .line 68
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 69
    .line 70
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 71
    .line 72
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    throw v0

    .line 76
    :cond_2
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    iget-object v2, v0, Lkw0/c;->f:Lvw0/d;

    .line 80
    .line 81
    iget-object v5, v0, Lkw0/c;->f:Lvw0/d;

    .line 82
    .line 83
    iget-object v9, v0, Lkw0/c;->c:Low0/n;

    .line 84
    .line 85
    iget-object v10, v0, Lkw0/c;->a:Low0/z;

    .line 86
    .line 87
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 88
    .line 89
    .line 90
    const-string v11, "key"

    .line 91
    .line 92
    sget-object v12, Lhw0/h;->c:Lvw0/a;

    .line 93
    .line 94
    invoke-static {v12, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {v2}, Lvw0/d;->c()Ljava/util/Map;

    .line 98
    .line 99
    .line 100
    move-result-object v2

    .line 101
    invoke-interface {v2, v12}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result v2

    .line 105
    if-eqz v2, :cond_7

    .line 106
    .line 107
    invoke-virtual {v5, v12}, Lvw0/d;->b(Lvw0/a;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v2

    .line 111
    check-cast v2, Ljava/util/List;

    .line 112
    .line 113
    move-object/from16 v11, p0

    .line 114
    .line 115
    check-cast v11, Ljava/lang/Iterable;

    .line 116
    .line 117
    new-instance v12, Ljava/util/ArrayList;

    .line 118
    .line 119
    invoke-direct {v12}, Ljava/util/ArrayList;-><init>()V

    .line 120
    .line 121
    .line 122
    invoke-interface {v11}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 123
    .line 124
    .line 125
    move-result-object v11

    .line 126
    :goto_1
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    .line 127
    .line 128
    .line 129
    move-result v13

    .line 130
    if-eqz v13, :cond_6

    .line 131
    .line 132
    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v13

    .line 136
    move-object v14, v13

    .line 137
    check-cast v14, Lhw0/a;

    .line 138
    .line 139
    move-object v15, v2

    .line 140
    check-cast v15, Ljava/lang/Iterable;

    .line 141
    .line 142
    const/16 p5, 0x0

    .line 143
    .line 144
    instance-of v8, v15, Ljava/util/Collection;

    .line 145
    .line 146
    if-eqz v8, :cond_3

    .line 147
    .line 148
    move-object v8, v15

    .line 149
    check-cast v8, Ljava/util/Collection;

    .line 150
    .line 151
    invoke-interface {v8}, Ljava/util/Collection;->isEmpty()Z

    .line 152
    .line 153
    .line 154
    move-result v8

    .line 155
    if-eqz v8, :cond_3

    .line 156
    .line 157
    goto :goto_4

    .line 158
    :cond_3
    invoke-interface {v15}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 159
    .line 160
    .line 161
    move-result-object v8

    .line 162
    :goto_2
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 163
    .line 164
    .line 165
    move-result v15

    .line 166
    if-eqz v15, :cond_5

    .line 167
    .line 168
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object v15

    .line 172
    check-cast v15, Low0/e;

    .line 173
    .line 174
    iget-object v6, v14, Lhw0/a;->b:Low0/e;

    .line 175
    .line 176
    invoke-virtual {v6, v15}, Low0/e;->q(Low0/e;)Z

    .line 177
    .line 178
    .line 179
    move-result v6

    .line 180
    if-eqz v6, :cond_4

    .line 181
    .line 182
    :goto_3
    const/4 v6, 0x1

    .line 183
    goto :goto_1

    .line 184
    :cond_4
    const/4 v6, 0x1

    .line 185
    goto :goto_2

    .line 186
    :cond_5
    :goto_4
    invoke-virtual {v12, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 187
    .line 188
    .line 189
    goto :goto_3

    .line 190
    :cond_6
    :goto_5
    const/16 p5, 0x0

    .line 191
    .line 192
    goto :goto_6

    .line 193
    :cond_7
    move-object/from16 v12, p0

    .line 194
    .line 195
    goto :goto_5

    .line 196
    :goto_6
    sget-object v2, Low0/q;->a:Ljava/util/List;

    .line 197
    .line 198
    const-string v2, "Accept"

    .line 199
    .line 200
    invoke-virtual {v9, v2}, Lap0/o;->A(Ljava/lang/String;)Ljava/util/List;

    .line 201
    .line 202
    .line 203
    move-result-object v6

    .line 204
    iget-object v8, v9, Lap0/o;->e:Ljava/lang/Object;

    .line 205
    .line 206
    check-cast v8, Ljava/util/Map;

    .line 207
    .line 208
    if-nez v6, :cond_8

    .line 209
    .line 210
    sget-object v6, Lmx0/s;->d:Lmx0/s;

    .line 211
    .line 212
    :cond_8
    check-cast v12, Ljava/lang/Iterable;

    .line 213
    .line 214
    invoke-interface {v12}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 215
    .line 216
    .line 217
    move-result-object v11

    .line 218
    :goto_7
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    .line 219
    .line 220
    .line 221
    move-result v12

    .line 222
    if-eqz v12, :cond_c

    .line 223
    .line 224
    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object v12

    .line 228
    check-cast v12, Lhw0/a;

    .line 229
    .line 230
    move-object v13, v6

    .line 231
    check-cast v13, Ljava/lang/Iterable;

    .line 232
    .line 233
    instance-of v14, v13, Ljava/util/Collection;

    .line 234
    .line 235
    if-eqz v14, :cond_a

    .line 236
    .line 237
    move-object v14, v13

    .line 238
    check-cast v14, Ljava/util/Collection;

    .line 239
    .line 240
    invoke-interface {v14}, Ljava/util/Collection;->isEmpty()Z

    .line 241
    .line 242
    .line 243
    move-result v14

    .line 244
    if-eqz v14, :cond_a

    .line 245
    .line 246
    :cond_9
    move-object/from16 v13, p2

    .line 247
    .line 248
    goto :goto_8

    .line 249
    :cond_a
    invoke-interface {v13}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 250
    .line 251
    .line 252
    move-result-object v13

    .line 253
    :cond_b
    invoke-interface {v13}, Ljava/util/Iterator;->hasNext()Z

    .line 254
    .line 255
    .line 256
    move-result v14

    .line 257
    if-eqz v14, :cond_9

    .line 258
    .line 259
    invoke-interface {v13}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 260
    .line 261
    .line 262
    move-result-object v14

    .line 263
    check-cast v14, Ljava/lang/String;

    .line 264
    .line 265
    sget-object v15, Low0/e;->f:Low0/e;

    .line 266
    .line 267
    invoke-static {v14}, Ljp/hc;->b(Ljava/lang/String;)Low0/e;

    .line 268
    .line 269
    .line 270
    move-result-object v14

    .line 271
    iget-object v15, v12, Lhw0/a;->b:Low0/e;

    .line 272
    .line 273
    invoke-virtual {v14, v15}, Low0/e;->q(Low0/e;)Z

    .line 274
    .line 275
    .line 276
    move-result v14

    .line 277
    if-eqz v14, :cond_b

    .line 278
    .line 279
    move-object/from16 v13, p2

    .line 280
    .line 281
    goto :goto_7

    .line 282
    :goto_8
    iget-object v14, v13, Lgw0/b;->b:Ljava/lang/Object;

    .line 283
    .line 284
    check-cast v14, Lhw0/b;

    .line 285
    .line 286
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 287
    .line 288
    .line 289
    iget-object v12, v12, Lhw0/a;->b:Low0/e;

    .line 290
    .line 291
    new-instance v14, Ljava/lang/StringBuilder;

    .line 292
    .line 293
    const-string v15, "Adding Accept="

    .line 294
    .line 295
    invoke-direct {v14, v15}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 296
    .line 297
    .line 298
    invoke-virtual {v14, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 299
    .line 300
    .line 301
    const-string v15, " header for "

    .line 302
    .line 303
    invoke-virtual {v14, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 304
    .line 305
    .line 306
    invoke-virtual {v14, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 307
    .line 308
    .line 309
    invoke-virtual {v14}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 310
    .line 311
    .line 312
    move-result-object v14

    .line 313
    invoke-interface {v7, v14}, Lt21/b;->h(Ljava/lang/String;)V

    .line 314
    .line 315
    .line 316
    const-string v14, "contentType"

    .line 317
    .line 318
    invoke-static {v12, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 319
    .line 320
    .line 321
    sget-object v14, Low0/q;->a:Ljava/util/List;

    .line 322
    .line 323
    invoke-virtual {v12}, Lh/w;->toString()Ljava/lang/String;

    .line 324
    .line 325
    .line 326
    move-result-object v12

    .line 327
    invoke-virtual {v9, v2, v12}, Lap0/o;->r(Ljava/lang/String;Ljava/lang/String;)V

    .line 328
    .line 329
    .line 330
    goto :goto_7

    .line 331
    :cond_c
    instance-of v2, v1, Lrw0/d;

    .line 332
    .line 333
    const/16 v6, 0x2e

    .line 334
    .line 335
    if-nez v2, :cond_1e

    .line 336
    .line 337
    move-object/from16 v2, p1

    .line 338
    .line 339
    check-cast v2, Ljava/lang/Iterable;

    .line 340
    .line 341
    instance-of v9, v2, Ljava/util/Collection;

    .line 342
    .line 343
    if-eqz v9, :cond_d

    .line 344
    .line 345
    move-object v9, v2

    .line 346
    check-cast v9, Ljava/util/Collection;

    .line 347
    .line 348
    invoke-interface {v9}, Ljava/util/Collection;->isEmpty()Z

    .line 349
    .line 350
    .line 351
    move-result v9

    .line 352
    if-eqz v9, :cond_d

    .line 353
    .line 354
    goto :goto_9

    .line 355
    :cond_d
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 356
    .line 357
    .line 358
    move-result-object v2

    .line 359
    :cond_e
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 360
    .line 361
    .line 362
    move-result v9

    .line 363
    if-eqz v9, :cond_f

    .line 364
    .line 365
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 366
    .line 367
    .line 368
    move-result-object v9

    .line 369
    check-cast v9, Lhy0/d;

    .line 370
    .line 371
    invoke-interface {v9, v1}, Lhy0/d;->isInstance(Ljava/lang/Object;)Z

    .line 372
    .line 373
    .line 374
    move-result v9

    .line 375
    if-eqz v9, :cond_e

    .line 376
    .line 377
    goto/16 :goto_10

    .line 378
    .line 379
    :cond_f
    :goto_9
    invoke-static {v0}, Ljp/pc;->c(Lkw0/c;)Low0/e;

    .line 380
    .line 381
    .line 382
    move-result-object v2

    .line 383
    if-nez v2, :cond_10

    .line 384
    .line 385
    new-instance v0, Ljava/lang/StringBuilder;

    .line 386
    .line 387
    const-string v1, "Request doesn\'t have Content-Type header. Skipping ContentNegotiation for "

    .line 388
    .line 389
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 390
    .line 391
    .line 392
    invoke-virtual {v0, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 393
    .line 394
    .line 395
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 396
    .line 397
    .line 398
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 399
    .line 400
    .line 401
    move-result-object v0

    .line 402
    invoke-interface {v7, v0}, Lt21/b;->h(Ljava/lang/String;)V

    .line 403
    .line 404
    .line 405
    return-object p5

    .line 406
    :cond_10
    instance-of v9, v1, Llx0/b0;

    .line 407
    .line 408
    const-string v11, "Content-Type"

    .line 409
    .line 410
    if-eqz v9, :cond_11

    .line 411
    .line 412
    new-instance v0, Ljava/lang/StringBuilder;

    .line 413
    .line 414
    const-string v1, "Sending empty body for "

    .line 415
    .line 416
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 417
    .line 418
    .line 419
    invoke-virtual {v0, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 420
    .line 421
    .line 422
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 423
    .line 424
    .line 425
    move-result-object v0

    .line 426
    invoke-interface {v7, v0}, Lt21/b;->h(Ljava/lang/String;)V

    .line 427
    .line 428
    .line 429
    sget-object v0, Low0/q;->a:Ljava/util/List;

    .line 430
    .line 431
    invoke-interface {v8, v11}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 432
    .line 433
    .line 434
    sget-object v0, Lmw0/b;->a:Lmw0/b;

    .line 435
    .line 436
    return-object v0

    .line 437
    :cond_11
    move-object/from16 v9, p0

    .line 438
    .line 439
    check-cast v9, Ljava/lang/Iterable;

    .line 440
    .line 441
    new-instance v12, Ljava/util/ArrayList;

    .line 442
    .line 443
    invoke-direct {v12}, Ljava/util/ArrayList;-><init>()V

    .line 444
    .line 445
    .line 446
    invoke-interface {v9}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 447
    .line 448
    .line 449
    move-result-object v9

    .line 450
    :cond_12
    :goto_a
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 451
    .line 452
    .line 453
    move-result v13

    .line 454
    if-eqz v13, :cond_13

    .line 455
    .line 456
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 457
    .line 458
    .line 459
    move-result-object v13

    .line 460
    move-object v14, v13

    .line 461
    check-cast v14, Lhw0/a;

    .line 462
    .line 463
    iget-object v14, v14, Lhw0/a;->c:Low0/f;

    .line 464
    .line 465
    invoke-interface {v14, v2}, Low0/f;->a(Low0/e;)Z

    .line 466
    .line 467
    .line 468
    move-result v14

    .line 469
    if-eqz v14, :cond_12

    .line 470
    .line 471
    invoke-virtual {v12, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 472
    .line 473
    .line 474
    goto :goto_a

    .line 475
    :cond_13
    invoke-virtual {v12}, Ljava/util/ArrayList;->isEmpty()Z

    .line 476
    .line 477
    .line 478
    move-result v9

    .line 479
    if-nez v9, :cond_14

    .line 480
    .line 481
    goto :goto_b

    .line 482
    :cond_14
    move-object/from16 v12, p5

    .line 483
    .line 484
    :goto_b
    if-nez v12, :cond_15

    .line 485
    .line 486
    new-instance v0, Ljava/lang/StringBuilder;

    .line 487
    .line 488
    const-string v1, "None of the registered converters match request Content-Type="

    .line 489
    .line 490
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 491
    .line 492
    .line 493
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 494
    .line 495
    .line 496
    const-string v1, ". Skipping ContentNegotiation for "

    .line 497
    .line 498
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 499
    .line 500
    .line 501
    invoke-virtual {v0, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 502
    .line 503
    .line 504
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 505
    .line 506
    .line 507
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 508
    .line 509
    .line 510
    move-result-object v0

    .line 511
    invoke-interface {v7, v0}, Lt21/b;->h(Ljava/lang/String;)V

    .line 512
    .line 513
    .line 514
    return-object p5

    .line 515
    :cond_15
    sget-object v9, Lkw0/g;->a:Lvw0/a;

    .line 516
    .line 517
    invoke-virtual {v5, v9}, Lvw0/d;->d(Lvw0/a;)Ljava/lang/Object;

    .line 518
    .line 519
    .line 520
    move-result-object v5

    .line 521
    check-cast v5, Lzw0/a;

    .line 522
    .line 523
    if-nez v5, :cond_16

    .line 524
    .line 525
    new-instance v0, Ljava/lang/StringBuilder;

    .line 526
    .line 527
    const-string v1, "Request has unknown body type. Skipping ContentNegotiation for "

    .line 528
    .line 529
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 530
    .line 531
    .line 532
    invoke-virtual {v0, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 533
    .line 534
    .line 535
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 536
    .line 537
    .line 538
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 539
    .line 540
    .line 541
    move-result-object v0

    .line 542
    invoke-interface {v7, v0}, Lt21/b;->h(Ljava/lang/String;)V

    .line 543
    .line 544
    .line 545
    return-object p5

    .line 546
    :cond_16
    sget-object v5, Low0/q;->a:Ljava/util/List;

    .line 547
    .line 548
    invoke-interface {v8, v11}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 549
    .line 550
    .line 551
    invoke-interface {v12}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 552
    .line 553
    .line 554
    move-result-object v5

    .line 555
    move-object v9, v2

    .line 556
    move-object v13, v3

    .line 557
    move-object v2, v12

    .line 558
    :goto_c
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 559
    .line 560
    .line 561
    move-result v3

    .line 562
    if-eqz v3, :cond_1c

    .line 563
    .line 564
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 565
    .line 566
    .line 567
    move-result-object v3

    .line 568
    check-cast v3, Lhw0/a;

    .line 569
    .line 570
    iget-object v8, v3, Lhw0/a;->a:Ltw0/h;

    .line 571
    .line 572
    invoke-static {v9}, Ljp/ic;->e(Low0/e;)Ljava/nio/charset/Charset;

    .line 573
    .line 574
    .line 575
    move-result-object v6

    .line 576
    if-nez v6, :cond_17

    .line 577
    .line 578
    sget-object v6, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 579
    .line 580
    :cond_17
    move-object v10, v6

    .line 581
    iget-object v6, v0, Lkw0/c;->f:Lvw0/d;

    .line 582
    .line 583
    sget-object v11, Lkw0/g;->a:Lvw0/a;

    .line 584
    .line 585
    invoke-virtual {v6, v11}, Lvw0/d;->d(Lvw0/a;)Ljava/lang/Object;

    .line 586
    .line 587
    .line 588
    move-result-object v6

    .line 589
    move-object v11, v6

    .line 590
    check-cast v11, Lzw0/a;

    .line 591
    .line 592
    invoke-static {v11}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 593
    .line 594
    .line 595
    sget-object v6, Lrw0/b;->a:Lrw0/b;

    .line 596
    .line 597
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 598
    .line 599
    .line 600
    move-result v6

    .line 601
    if-nez v6, :cond_18

    .line 602
    .line 603
    move-object v12, v1

    .line 604
    goto :goto_d

    .line 605
    :cond_18
    move-object/from16 v12, p5

    .line 606
    .line 607
    :goto_d
    iput-object v0, v13, Lhw0/f;->d:Lkw0/c;

    .line 608
    .line 609
    iput-object v1, v13, Lhw0/f;->e:Ljava/lang/Object;

    .line 610
    .line 611
    iput-object v9, v13, Lhw0/f;->f:Low0/e;

    .line 612
    .line 613
    move-object v6, v2

    .line 614
    check-cast v6, Ljava/util/List;

    .line 615
    .line 616
    iput-object v6, v13, Lhw0/f;->g:Ljava/util/List;

    .line 617
    .line 618
    iput-object v5, v13, Lhw0/f;->h:Ljava/util/Iterator;

    .line 619
    .line 620
    iput-object v3, v13, Lhw0/f;->i:Lhw0/a;

    .line 621
    .line 622
    const/4 v6, 0x1

    .line 623
    iput v6, v13, Lhw0/f;->k:I

    .line 624
    .line 625
    invoke-virtual/range {v8 .. v13}, Ltw0/h;->b(Low0/e;Ljava/nio/charset/Charset;Lzw0/a;Ljava/lang/Object;Lrx0/c;)Ljava/lang/Object;

    .line 626
    .line 627
    .line 628
    move-result-object v8

    .line 629
    if-ne v8, v4, :cond_19

    .line 630
    .line 631
    return-object v4

    .line 632
    :cond_19
    move-object v11, v0

    .line 633
    move-object v0, v3

    .line 634
    move-object v3, v5

    .line 635
    move-object v5, v2

    .line 636
    move-object v2, v8

    .line 637
    :goto_e
    check-cast v2, Lrw0/d;

    .line 638
    .line 639
    if-eqz v2, :cond_1a

    .line 640
    .line 641
    new-instance v8, Ljava/lang/StringBuilder;

    .line 642
    .line 643
    const-string v10, "Converted request body using "

    .line 644
    .line 645
    invoke-direct {v8, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 646
    .line 647
    .line 648
    iget-object v0, v0, Lhw0/a;->a:Ltw0/h;

    .line 649
    .line 650
    invoke-virtual {v8, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 651
    .line 652
    .line 653
    const-string v0, " for "

    .line 654
    .line 655
    invoke-virtual {v8, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 656
    .line 657
    .line 658
    iget-object v0, v11, Lkw0/c;->a:Low0/z;

    .line 659
    .line 660
    invoke-virtual {v8, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 661
    .line 662
    .line 663
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 664
    .line 665
    .line 666
    move-result-object v0

    .line 667
    invoke-interface {v7, v0}, Lt21/b;->h(Ljava/lang/String;)V

    .line 668
    .line 669
    .line 670
    :cond_1a
    if-eqz v2, :cond_1b

    .line 671
    .line 672
    move-object v8, v2

    .line 673
    move-object v2, v5

    .line 674
    goto :goto_f

    .line 675
    :cond_1b
    move-object v2, v5

    .line 676
    move-object v0, v11

    .line 677
    move-object v5, v3

    .line 678
    goto :goto_c

    .line 679
    :cond_1c
    move-object/from16 v8, p5

    .line 680
    .line 681
    :goto_f
    if-eqz v8, :cond_1d

    .line 682
    .line 683
    return-object v8

    .line 684
    :cond_1d
    new-instance v0, Lb0/l;

    .line 685
    .line 686
    new-instance v3, Ljava/lang/StringBuilder;

    .line 687
    .line 688
    const-string v4, "Can\'t convert "

    .line 689
    .line 690
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 691
    .line 692
    .line 693
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 694
    .line 695
    .line 696
    const-string v1, " with contentType "

    .line 697
    .line 698
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 699
    .line 700
    .line 701
    invoke-virtual {v3, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 702
    .line 703
    .line 704
    const-string v1, " using converters "

    .line 705
    .line 706
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 707
    .line 708
    .line 709
    check-cast v2, Ljava/lang/Iterable;

    .line 710
    .line 711
    new-instance v1, Lh70/f;

    .line 712
    .line 713
    const/16 v4, 0x9

    .line 714
    .line 715
    invoke-direct {v1, v4}, Lh70/f;-><init>(I)V

    .line 716
    .line 717
    .line 718
    const/16 v4, 0x1f

    .line 719
    .line 720
    const/4 v5, 0x0

    .line 721
    const/4 v6, 0x0

    .line 722
    const/4 v7, 0x0

    .line 723
    move-object/from16 p4, v1

    .line 724
    .line 725
    move-object/from16 p0, v2

    .line 726
    .line 727
    move/from16 p5, v4

    .line 728
    .line 729
    move-object/from16 p1, v5

    .line 730
    .line 731
    move-object/from16 p2, v6

    .line 732
    .line 733
    move-object/from16 p3, v7

    .line 734
    .line 735
    invoke-static/range {p0 .. p5}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 736
    .line 737
    .line 738
    move-result-object v1

    .line 739
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 740
    .line 741
    .line 742
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 743
    .line 744
    .line 745
    move-result-object v1

    .line 746
    const-string v2, "message"

    .line 747
    .line 748
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 749
    .line 750
    .line 751
    invoke-direct {v0, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 752
    .line 753
    .line 754
    throw v0

    .line 755
    :cond_1e
    :goto_10
    new-instance v0, Ljava/lang/StringBuilder;

    .line 756
    .line 757
    const-string v2, "Body type "

    .line 758
    .line 759
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 760
    .line 761
    .line 762
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 763
    .line 764
    .line 765
    move-result-object v1

    .line 766
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 767
    .line 768
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 769
    .line 770
    .line 771
    move-result-object v1

    .line 772
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 773
    .line 774
    .line 775
    const-string v1, " is in ignored types. Skipping ContentNegotiation for "

    .line 776
    .line 777
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 778
    .line 779
    .line 780
    invoke-virtual {v0, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 781
    .line 782
    .line 783
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 784
    .line 785
    .line 786
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 787
    .line 788
    .line 789
    move-result-object v0

    .line 790
    invoke-interface {v7, v0}, Lt21/b;->h(Ljava/lang/String;)V

    .line 791
    .line 792
    .line 793
    return-object p5
.end method

.method public static final b(Ljava/util/Set;Ljava/util/List;Low0/f0;Lzw0/a;Ljava/lang/Object;Low0/e;Ljava/nio/charset/Charset;Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p7, Lhw0/g;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p7

    .line 6
    check-cast v0, Lhw0/g;

    .line 7
    .line 8
    iget v1, v0, Lhw0/g;->f:I

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
    iput v1, v0, Lhw0/g;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lhw0/g;

    .line 21
    .line 22
    invoke-direct {v0, p7}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p7, v0, Lhw0/g;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lhw0/g;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    const/16 v4, 0x2e

    .line 33
    .line 34
    sget-object v5, Lhw0/h;->a:Lt21/b;

    .line 35
    .line 36
    if-eqz v2, :cond_2

    .line 37
    .line 38
    if-ne v2, v3, :cond_1

    .line 39
    .line 40
    iget-object p2, v0, Lhw0/g;->d:Low0/f0;

    .line 41
    .line 42
    invoke-static {p7}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    goto/16 :goto_4

    .line 46
    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    invoke-static {p7}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    instance-of p7, p4, Lio/ktor/utils/io/t;

    .line 59
    .line 60
    const/4 v2, 0x0

    .line 61
    if-nez p7, :cond_3

    .line 62
    .line 63
    new-instance p0, Ljava/lang/StringBuilder;

    .line 64
    .line 65
    const-string p1, "Response body is already transformed. Skipping ContentNegotiation for "

    .line 66
    .line 67
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    invoke-virtual {p0, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    invoke-interface {v5, p0}, Lt21/b;->h(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    return-object v2

    .line 84
    :cond_3
    iget-object p7, p3, Lzw0/a;->a:Lhy0/d;

    .line 85
    .line 86
    invoke-interface {p0, p7}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result p0

    .line 90
    if-eqz p0, :cond_4

    .line 91
    .line 92
    new-instance p0, Ljava/lang/StringBuilder;

    .line 93
    .line 94
    const-string p1, "Response body type "

    .line 95
    .line 96
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    iget-object p1, p3, Lzw0/a;->a:Lhy0/d;

    .line 100
    .line 101
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 102
    .line 103
    .line 104
    const-string p1, " is in ignored types. Skipping ContentNegotiation for "

    .line 105
    .line 106
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    invoke-virtual {p0, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 113
    .line 114
    .line 115
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    invoke-interface {v5, p0}, Lt21/b;->h(Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    return-object v2

    .line 123
    :cond_4
    check-cast p1, Ljava/lang/Iterable;

    .line 124
    .line 125
    new-instance p0, Ljava/util/ArrayList;

    .line 126
    .line 127
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 128
    .line 129
    .line 130
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 131
    .line 132
    .line 133
    move-result-object p1

    .line 134
    :cond_5
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 135
    .line 136
    .line 137
    move-result p7

    .line 138
    if-eqz p7, :cond_6

    .line 139
    .line 140
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object p7

    .line 144
    move-object v6, p7

    .line 145
    check-cast v6, Lhw0/a;

    .line 146
    .line 147
    iget-object v6, v6, Lhw0/a;->c:Low0/f;

    .line 148
    .line 149
    invoke-interface {v6, p5}, Low0/f;->a(Low0/e;)Z

    .line 150
    .line 151
    .line 152
    move-result v6

    .line 153
    if-eqz v6, :cond_5

    .line 154
    .line 155
    invoke-virtual {p0, p7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    goto :goto_1

    .line 159
    :cond_6
    new-instance p1, Ljava/util/ArrayList;

    .line 160
    .line 161
    const/16 p7, 0xa

    .line 162
    .line 163
    invoke-static {p0, p7}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 164
    .line 165
    .line 166
    move-result p7

    .line 167
    invoke-direct {p1, p7}, Ljava/util/ArrayList;-><init>(I)V

    .line 168
    .line 169
    .line 170
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 171
    .line 172
    .line 173
    move-result-object p0

    .line 174
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 175
    .line 176
    .line 177
    move-result p7

    .line 178
    if-eqz p7, :cond_7

    .line 179
    .line 180
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object p7

    .line 184
    check-cast p7, Lhw0/a;

    .line 185
    .line 186
    iget-object p7, p7, Lhw0/a;->a:Ltw0/h;

    .line 187
    .line 188
    invoke-virtual {p1, p7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 189
    .line 190
    .line 191
    goto :goto_2

    .line 192
    :cond_7
    invoke-virtual {p1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 193
    .line 194
    .line 195
    move-result p0

    .line 196
    if-nez p0, :cond_8

    .line 197
    .line 198
    goto :goto_3

    .line 199
    :cond_8
    move-object p1, v2

    .line 200
    :goto_3
    if-nez p1, :cond_9

    .line 201
    .line 202
    new-instance p0, Ljava/lang/StringBuilder;

    .line 203
    .line 204
    const-string p1, "None of the registered converters match response with Content-Type="

    .line 205
    .line 206
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 207
    .line 208
    .line 209
    invoke-virtual {p0, p5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 210
    .line 211
    .line 212
    const-string p1, ". Skipping ContentNegotiation for "

    .line 213
    .line 214
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 215
    .line 216
    .line 217
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 218
    .line 219
    .line 220
    invoke-virtual {p0, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 221
    .line 222
    .line 223
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    move-result-object p0

    .line 227
    invoke-interface {v5, p0}, Lt21/b;->h(Ljava/lang/String;)V

    .line 228
    .line 229
    .line 230
    return-object v2

    .line 231
    :cond_9
    check-cast p4, Lio/ktor/utils/io/t;

    .line 232
    .line 233
    iput-object p2, v0, Lhw0/g;->d:Low0/f0;

    .line 234
    .line 235
    iput v3, v0, Lhw0/g;->f:I

    .line 236
    .line 237
    invoke-static {p1, p4, p3, p6, v0}, Lkp/t8;->b(Ljava/util/ArrayList;Lio/ktor/utils/io/t;Lzw0/a;Ljava/nio/charset/Charset;Lrx0/c;)Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object p7

    .line 241
    if-ne p7, v1, :cond_a

    .line 242
    .line 243
    return-object v1

    .line 244
    :cond_a
    :goto_4
    instance-of p0, p7, Lio/ktor/utils/io/t;

    .line 245
    .line 246
    if-nez p0, :cond_b

    .line 247
    .line 248
    new-instance p0, Ljava/lang/StringBuilder;

    .line 249
    .line 250
    const-string p1, "Response body was converted to "

    .line 251
    .line 252
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 253
    .line 254
    .line 255
    invoke-virtual {p7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 256
    .line 257
    .line 258
    move-result-object p1

    .line 259
    sget-object p3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 260
    .line 261
    invoke-virtual {p3, p1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 262
    .line 263
    .line 264
    move-result-object p1

    .line 265
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 266
    .line 267
    .line 268
    const-string p1, " for "

    .line 269
    .line 270
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 271
    .line 272
    .line 273
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 274
    .line 275
    .line 276
    invoke-virtual {p0, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 277
    .line 278
    .line 279
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 280
    .line 281
    .line 282
    move-result-object p0

    .line 283
    invoke-interface {v5, p0}, Lt21/b;->h(Ljava/lang/String;)V

    .line 284
    .line 285
    .line 286
    :cond_b
    return-object p7
.end method
