.class public abstract Lfw0/n0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt21/b;

.field public static final b:Lgv/a;

.field public static final c:Lvw0/a;

.field public static final d:Lvw0/a;

.field public static final e:Lvw0/a;

.field public static final f:Lvw0/a;

.field public static final g:Lvw0/a;


# direct methods
.method static constructor <clinit>()V
    .locals 11

    .line 1
    const-class v0, Lkw0/c;

    .line 2
    .line 3
    sget-object v1, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    .line 4
    .line 5
    const-class v2, Lfw0/r0;

    .line 6
    .line 7
    sget-object v3, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    .line 8
    .line 9
    const-string v4, "io.ktor.client.plugins.HttpRequestRetry"

    .line 10
    .line 11
    invoke-static {v4}, Lt21/d;->b(Ljava/lang/String;)Lt21/b;

    .line 12
    .line 13
    .line 14
    move-result-object v4

    .line 15
    sput-object v4, Lfw0/n0;->a:Lt21/b;

    .line 16
    .line 17
    new-instance v4, Lgv/a;

    .line 18
    .line 19
    const/16 v5, 0xa

    .line 20
    .line 21
    invoke-direct {v4, v5}, Lgv/a;-><init>(I)V

    .line 22
    .line 23
    .line 24
    sput-object v4, Lfw0/n0;->b:Lgv/a;

    .line 25
    .line 26
    sget-object v4, Lfw0/j0;->d:Lfw0/j0;

    .line 27
    .line 28
    new-instance v5, Lfw0/i0;

    .line 29
    .line 30
    const/4 v6, 0x0

    .line 31
    invoke-direct {v5, v6}, Lfw0/i0;-><init>(I)V

    .line 32
    .line 33
    .line 34
    const-string v6, "RetryFeature"

    .line 35
    .line 36
    invoke-static {v6, v4, v5}, Lkp/q9;->a(Ljava/lang/String;Lay0/a;Lay0/k;)Lgw0/c;

    .line 37
    .line 38
    .line 39
    const-class v4, Ljava/lang/Integer;

    .line 40
    .line 41
    sget-object v5, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 42
    .line 43
    invoke-virtual {v5, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    const/4 v5, 0x0

    .line 48
    :try_start_0
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 49
    .line 50
    .line 51
    move-result-object v6
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 52
    goto :goto_0

    .line 53
    :catchall_0
    move-object v6, v5

    .line 54
    :goto_0
    new-instance v7, Lzw0/a;

    .line 55
    .line 56
    invoke-direct {v7, v4, v6}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 57
    .line 58
    .line 59
    new-instance v4, Lvw0/a;

    .line 60
    .line 61
    const-string v6, "MaxRetriesPerRequestAttributeKey"

    .line 62
    .line 63
    invoke-direct {v4, v6, v7}, Lvw0/a;-><init>(Ljava/lang/String;Lzw0/a;)V

    .line 64
    .line 65
    .line 66
    sput-object v4, Lfw0/n0;->c:Lvw0/a;

    .line 67
    .line 68
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 69
    .line 70
    const-class v6, Lay0/o;

    .line 71
    .line 72
    invoke-virtual {v4, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 73
    .line 74
    .line 75
    move-result-object v4

    .line 76
    :try_start_1
    sget-object v7, Lhy0/d0;->c:Lhy0/d0;

    .line 77
    .line 78
    invoke-static {v2}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 79
    .line 80
    .line 81
    move-result-object v7

    .line 82
    invoke-static {v7}, Llp/e1;->c(Lhy0/a0;)Lhy0/d0;

    .line 83
    .line 84
    .line 85
    move-result-object v7

    .line 86
    const-class v8, Lkw0/b;

    .line 87
    .line 88
    invoke-static {v8}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 89
    .line 90
    .line 91
    move-result-object v8

    .line 92
    invoke-static {v8}, Llp/e1;->c(Lhy0/a0;)Lhy0/d0;

    .line 93
    .line 94
    .line 95
    move-result-object v8

    .line 96
    const-class v9, Law0/h;

    .line 97
    .line 98
    invoke-static {v9}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 99
    .line 100
    .line 101
    move-result-object v9

    .line 102
    invoke-static {v9}, Llp/e1;->c(Lhy0/a0;)Lhy0/d0;

    .line 103
    .line 104
    .line 105
    move-result-object v9

    .line 106
    invoke-static {v1}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 107
    .line 108
    .line 109
    move-result-object v10

    .line 110
    invoke-static {v10}, Llp/e1;->c(Lhy0/a0;)Lhy0/d0;

    .line 111
    .line 112
    .line 113
    move-result-object v10

    .line 114
    filled-new-array {v7, v8, v9, v10}, [Lhy0/d0;

    .line 115
    .line 116
    .line 117
    move-result-object v7

    .line 118
    invoke-static {v6, v7}, Lkotlin/jvm/internal/g0;->d(Ljava/lang/Class;[Lhy0/d0;)Lhy0/a0;

    .line 119
    .line 120
    .line 121
    move-result-object v7
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 122
    goto :goto_1

    .line 123
    :catchall_1
    move-object v7, v5

    .line 124
    :goto_1
    new-instance v8, Lzw0/a;

    .line 125
    .line 126
    invoke-direct {v8, v4, v7}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 127
    .line 128
    .line 129
    new-instance v4, Lvw0/a;

    .line 130
    .line 131
    const-string v7, "ShouldRetryPerRequestAttributeKey"

    .line 132
    .line 133
    invoke-direct {v4, v7, v8}, Lvw0/a;-><init>(Ljava/lang/String;Lzw0/a;)V

    .line 134
    .line 135
    .line 136
    sput-object v4, Lfw0/n0;->d:Lvw0/a;

    .line 137
    .line 138
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 139
    .line 140
    invoke-virtual {v4, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 141
    .line 142
    .line 143
    move-result-object v4

    .line 144
    :try_start_2
    sget-object v7, Lhy0/d0;->c:Lhy0/d0;

    .line 145
    .line 146
    invoke-static {v2}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 147
    .line 148
    .line 149
    move-result-object v2

    .line 150
    invoke-static {v2}, Llp/e1;->c(Lhy0/a0;)Lhy0/d0;

    .line 151
    .line 152
    .line 153
    move-result-object v2

    .line 154
    invoke-static {v0}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 155
    .line 156
    .line 157
    move-result-object v7

    .line 158
    invoke-static {v7}, Llp/e1;->c(Lhy0/a0;)Lhy0/d0;

    .line 159
    .line 160
    .line 161
    move-result-object v7

    .line 162
    const-class v8, Ljava/lang/Throwable;

    .line 163
    .line 164
    invoke-static {v8}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 165
    .line 166
    .line 167
    move-result-object v8

    .line 168
    invoke-static {v8}, Llp/e1;->c(Lhy0/a0;)Lhy0/d0;

    .line 169
    .line 170
    .line 171
    move-result-object v8

    .line 172
    invoke-static {v1}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 173
    .line 174
    .line 175
    move-result-object v1

    .line 176
    invoke-static {v1}, Llp/e1;->c(Lhy0/a0;)Lhy0/d0;

    .line 177
    .line 178
    .line 179
    move-result-object v1

    .line 180
    filled-new-array {v2, v7, v8, v1}, [Lhy0/d0;

    .line 181
    .line 182
    .line 183
    move-result-object v1

    .line 184
    invoke-static {v6, v1}, Lkotlin/jvm/internal/g0;->d(Ljava/lang/Class;[Lhy0/d0;)Lhy0/a0;

    .line 185
    .line 186
    .line 187
    move-result-object v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 188
    goto :goto_2

    .line 189
    :catchall_2
    move-object v1, v5

    .line 190
    :goto_2
    new-instance v2, Lzw0/a;

    .line 191
    .line 192
    invoke-direct {v2, v4, v1}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 193
    .line 194
    .line 195
    new-instance v1, Lvw0/a;

    .line 196
    .line 197
    const-string v4, "ShouldRetryOnExceptionPerRequestAttributeKey"

    .line 198
    .line 199
    invoke-direct {v1, v4, v2}, Lvw0/a;-><init>(Ljava/lang/String;Lzw0/a;)V

    .line 200
    .line 201
    .line 202
    sput-object v1, Lfw0/n0;->e:Lvw0/a;

    .line 203
    .line 204
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 205
    .line 206
    const-class v2, Lay0/n;

    .line 207
    .line 208
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 209
    .line 210
    .line 211
    move-result-object v1

    .line 212
    :try_start_3
    sget-object v4, Lhy0/d0;->c:Lhy0/d0;

    .line 213
    .line 214
    const-class v4, Lfw0/q0;

    .line 215
    .line 216
    invoke-static {v4}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 217
    .line 218
    .line 219
    move-result-object v4

    .line 220
    invoke-static {v4}, Llp/e1;->c(Lhy0/a0;)Lhy0/d0;

    .line 221
    .line 222
    .line 223
    move-result-object v4

    .line 224
    invoke-static {v0}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 225
    .line 226
    .line 227
    move-result-object v0

    .line 228
    invoke-static {v0}, Llp/e1;->c(Lhy0/a0;)Lhy0/d0;

    .line 229
    .line 230
    .line 231
    move-result-object v0

    .line 232
    const-class v6, Llx0/b0;

    .line 233
    .line 234
    invoke-static {v6}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 235
    .line 236
    .line 237
    move-result-object v6

    .line 238
    invoke-static {v6}, Llp/e1;->c(Lhy0/a0;)Lhy0/d0;

    .line 239
    .line 240
    .line 241
    move-result-object v6

    .line 242
    filled-new-array {v4, v0, v6}, [Lhy0/d0;

    .line 243
    .line 244
    .line 245
    move-result-object v0

    .line 246
    invoke-static {v2, v0}, Lkotlin/jvm/internal/g0;->d(Ljava/lang/Class;[Lhy0/d0;)Lhy0/a0;

    .line 247
    .line 248
    .line 249
    move-result-object v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 250
    goto :goto_3

    .line 251
    :catchall_3
    move-object v0, v5

    .line 252
    :goto_3
    new-instance v4, Lzw0/a;

    .line 253
    .line 254
    invoke-direct {v4, v1, v0}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 255
    .line 256
    .line 257
    new-instance v0, Lvw0/a;

    .line 258
    .line 259
    const-string v1, "ModifyRequestPerRequestAttributeKey"

    .line 260
    .line 261
    invoke-direct {v0, v1, v4}, Lvw0/a;-><init>(Ljava/lang/String;Lzw0/a;)V

    .line 262
    .line 263
    .line 264
    sput-object v0, Lfw0/n0;->f:Lvw0/a;

    .line 265
    .line 266
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 267
    .line 268
    invoke-virtual {v0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 269
    .line 270
    .line 271
    move-result-object v0

    .line 272
    :try_start_4
    sget-object v1, Lhy0/d0;->c:Lhy0/d0;

    .line 273
    .line 274
    const-class v1, Lfw0/p0;

    .line 275
    .line 276
    invoke-static {v1}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 277
    .line 278
    .line 279
    move-result-object v1

    .line 280
    invoke-static {v1}, Llp/e1;->c(Lhy0/a0;)Lhy0/d0;

    .line 281
    .line 282
    .line 283
    move-result-object v1

    .line 284
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 285
    .line 286
    .line 287
    move-result-object v3

    .line 288
    invoke-static {v3}, Llp/e1;->c(Lhy0/a0;)Lhy0/d0;

    .line 289
    .line 290
    .line 291
    move-result-object v3

    .line 292
    sget-object v4, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    .line 293
    .line 294
    invoke-static {v4}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 295
    .line 296
    .line 297
    move-result-object v4

    .line 298
    invoke-static {v4}, Llp/e1;->c(Lhy0/a0;)Lhy0/d0;

    .line 299
    .line 300
    .line 301
    move-result-object v4

    .line 302
    filled-new-array {v1, v3, v4}, [Lhy0/d0;

    .line 303
    .line 304
    .line 305
    move-result-object v1

    .line 306
    invoke-static {v2, v1}, Lkotlin/jvm/internal/g0;->d(Ljava/lang/Class;[Lhy0/d0;)Lhy0/a0;

    .line 307
    .line 308
    .line 309
    move-result-object v5
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_4

    .line 310
    :catchall_4
    new-instance v1, Lzw0/a;

    .line 311
    .line 312
    invoke-direct {v1, v0, v5}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 313
    .line 314
    .line 315
    new-instance v0, Lvw0/a;

    .line 316
    .line 317
    const-string v2, "RetryDelayPerRequestAttributeKey"

    .line 318
    .line 319
    invoke-direct {v0, v2, v1}, Lvw0/a;-><init>(Ljava/lang/String;Lzw0/a;)V

    .line 320
    .line 321
    .line 322
    sput-object v0, Lfw0/n0;->g:Lvw0/a;

    .line 323
    .line 324
    return-void
.end method

.method public static final a(Law0/h;Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p1, Lfw0/m0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lfw0/m0;

    .line 7
    .line 8
    iget v1, v0, Lfw0/m0;->f:I

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
    iput v1, v0, Lfw0/m0;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lfw0/m0;

    .line 21
    .line 22
    invoke-direct {v0, p1}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lfw0/m0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lfw0/m0;->f:I

    .line 30
    .line 31
    const-string v3, "Failed to close response body channel"

    .line 32
    .line 33
    sget-object v4, Lfw0/n0;->a:Lt21/b;

    .line 34
    .line 35
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    const/4 v6, 0x1

    .line 38
    if-eqz v2, :cond_2

    .line 39
    .line 40
    if-ne v2, v6, :cond_1

    .line 41
    .line 42
    iget-object p0, v0, Lfw0/m0;->d:Lio/ktor/utils/io/t;

    .line 43
    .line 44
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 45
    .line 46
    .line 47
    goto :goto_1

    .line 48
    :catchall_0
    move-exception p1

    .line 49
    goto :goto_3

    .line 50
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 53
    .line 54
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    invoke-static {p0}, Lfw0/k;->b(Law0/h;)Z

    .line 62
    .line 63
    .line 64
    move-result p1

    .line 65
    if-eqz p1, :cond_6

    .line 66
    .line 67
    invoke-virtual {p0}, Law0/h;->b()Lio/ktor/utils/io/t;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    :try_start_1
    iput-object p0, v0, Lfw0/m0;->d:Lio/ktor/utils/io/t;

    .line 72
    .line 73
    iput v6, v0, Lfw0/m0;->f:I

    .line 74
    .line 75
    sget-object p1, Lio/ktor/utils/io/t;->a:Lio/ktor/utils/io/s;

    .line 76
    .line 77
    invoke-interface {p0, v6, v0}, Lio/ktor/utils/io/t;->f(ILrx0/c;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    if-ne p1, v1, :cond_3

    .line 82
    .line 83
    return-object v1

    .line 84
    :cond_3
    :goto_1
    check-cast p1, Ljava/lang/Boolean;

    .line 85
    .line 86
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 87
    .line 88
    .line 89
    move-result p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 90
    :try_start_2
    invoke-static {p0}, Lio/ktor/utils/io/h0;->a(Lio/ktor/utils/io/t;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 91
    .line 92
    .line 93
    goto :goto_2

    .line 94
    :catchall_1
    move-exception p0

    .line 95
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 96
    .line 97
    .line 98
    move-result-object v5

    .line 99
    :goto_2
    invoke-static {v5}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    if-eqz p0, :cond_4

    .line 104
    .line 105
    invoke-interface {v4, v3, p0}, Lt21/b;->f(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 106
    .line 107
    .line 108
    :cond_4
    if-eqz p1, :cond_6

    .line 109
    .line 110
    goto :goto_5

    .line 111
    :goto_3
    :try_start_3
    invoke-static {p0}, Lio/ktor/utils/io/h0;->a(Lio/ktor/utils/io/t;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 112
    .line 113
    .line 114
    goto :goto_4

    .line 115
    :catchall_2
    move-exception p0

    .line 116
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 117
    .line 118
    .line 119
    move-result-object v5

    .line 120
    :goto_4
    invoke-static {v5}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    if-eqz p0, :cond_5

    .line 125
    .line 126
    invoke-interface {v4, v3, p0}, Lt21/b;->f(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 127
    .line 128
    .line 129
    :cond_5
    throw p1

    .line 130
    :cond_6
    const/4 v6, 0x0

    .line 131
    :goto_5
    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    return-object p0
.end method
