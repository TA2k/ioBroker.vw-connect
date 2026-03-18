.class public final Lku/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lku/n;


# static fields
.field public static final g:I

.field public static final h:Lly0/n;


# instance fields
.field public final a:Lhu/a1;

.field public final b:Lht/d;

.field public final c:Lhu/b;

.field public final d:Lku/d;

.field public final e:Lku/m;

.field public final f:Lez0/c;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    sget v0, Lmy0/c;->g:I

    .line 2
    .line 3
    const/16 v0, 0x18

    .line 4
    .line 5
    sget-object v1, Lmy0/e;->j:Lmy0/e;

    .line 6
    .line 7
    invoke-static {v0, v1}, Lmy0/h;->s(ILmy0/e;)J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    sget-object v2, Lmy0/e;->h:Lmy0/e;

    .line 12
    .line 13
    invoke-static {v0, v1, v2}, Lmy0/c;->n(JLmy0/e;)J

    .line 14
    .line 15
    .line 16
    move-result-wide v0

    .line 17
    long-to-int v0, v0

    .line 18
    sput v0, Lku/c;->g:I

    .line 19
    .line 20
    new-instance v0, Lly0/n;

    .line 21
    .line 22
    const-string v1, "/"

    .line 23
    .line 24
    invoke-direct {v0, v1}, Lly0/n;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    sput-object v0, Lku/c;->h:Lly0/n;

    .line 28
    .line 29
    return-void
.end method

.method public constructor <init>(Lhu/a1;Lht/d;Lhu/b;Lku/d;Lku/m;)V
    .locals 1

    .line 1
    const-string v0, "timeProvider"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "firebaseInstallationsApi"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "appInfo"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "configsFetcher"

    .line 17
    .line 18
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v0, "settingsCache"

    .line 22
    .line 23
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 27
    .line 28
    .line 29
    iput-object p1, p0, Lku/c;->a:Lhu/a1;

    .line 30
    .line 31
    iput-object p2, p0, Lku/c;->b:Lht/d;

    .line 32
    .line 33
    iput-object p3, p0, Lku/c;->c:Lhu/b;

    .line 34
    .line 35
    iput-object p4, p0, Lku/c;->d:Lku/d;

    .line 36
    .line 37
    iput-object p5, p0, Lku/c;->e:Lku/m;

    .line 38
    .line 39
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    iput-object p1, p0, Lku/c;->f:Lez0/c;

    .line 44
    .line 45
    return-void
.end method


# virtual methods
.method public final a()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lku/c;->e:Lku/m;

    .line 2
    .line 3
    invoke-virtual {p0}, Lku/m;->a()Lku/g;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget-object p0, p0, Lku/g;->a:Ljava/lang/Boolean;

    .line 8
    .line 9
    return-object p0
.end method

.method public final b()Lmy0/c;
    .locals 2

    .line 1
    iget-object p0, p0, Lku/c;->e:Lku/m;

    .line 2
    .line 3
    invoke-virtual {p0}, Lku/m;->a()Lku/g;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget-object p0, p0, Lku/g;->c:Ljava/lang/Integer;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    sget v0, Lmy0/c;->g:I

    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    sget-object v0, Lmy0/e;->h:Lmy0/e;

    .line 18
    .line 19
    invoke-static {p0, v0}, Lmy0/h;->s(ILmy0/e;)J

    .line 20
    .line 21
    .line 22
    move-result-wide v0

    .line 23
    new-instance p0, Lmy0/c;

    .line 24
    .line 25
    invoke-direct {p0, v0, v1}, Lmy0/c;-><init>(J)V

    .line 26
    .line 27
    .line 28
    return-object p0

    .line 29
    :cond_0
    const/4 p0, 0x0

    .line 30
    return-object p0
.end method

.method public final c()Ljava/lang/Double;
    .locals 0

    .line 1
    iget-object p0, p0, Lku/c;->e:Lku/m;

    .line 2
    .line 3
    invoke-virtual {p0}, Lku/m;->a()Lku/g;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget-object p0, p0, Lku/g;->b:Ljava/lang/Double;

    .line 8
    .line 9
    return-object p0
.end method

.method public final d(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const-string v2, ""

    .line 6
    .line 7
    instance-of v3, v1, Lku/b;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v1

    .line 12
    check-cast v3, Lku/b;

    .line 13
    .line 14
    iget v4, v3, Lku/b;->h:I

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
    iput v4, v3, Lku/b;->h:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lku/b;

    .line 27
    .line 28
    check-cast v1, Lrx0/c;

    .line 29
    .line 30
    invoke-direct {v3, v0, v1}, Lku/b;-><init>(Lku/c;Lrx0/c;)V

    .line 31
    .line 32
    .line 33
    :goto_0
    iget-object v1, v3, Lku/b;->f:Ljava/lang/Object;

    .line 34
    .line 35
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 36
    .line 37
    iget v5, v3, Lku/b;->h:I

    .line 38
    .line 39
    const/4 v6, 0x3

    .line 40
    const/4 v7, 0x1

    .line 41
    const-string v8, "FirebaseSessions"

    .line 42
    .line 43
    const/4 v9, 0x2

    .line 44
    sget-object v10, Llx0/b0;->a:Llx0/b0;

    .line 45
    .line 46
    const/4 v11, 0x0

    .line 47
    if-eqz v5, :cond_4

    .line 48
    .line 49
    if-eq v5, v7, :cond_3

    .line 50
    .line 51
    if-eq v5, v9, :cond_2

    .line 52
    .line 53
    if-ne v5, v6, :cond_1

    .line 54
    .line 55
    iget-object v0, v3, Lku/b;->d:Ljava/lang/Object;

    .line 56
    .line 57
    move-object v2, v0

    .line 58
    check-cast v2, Lez0/a;

    .line 59
    .line 60
    :try_start_0
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 61
    .line 62
    .line 63
    goto/16 :goto_5

    .line 64
    .line 65
    :catchall_0
    move-exception v0

    .line 66
    goto/16 :goto_6

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
    iget-object v5, v3, Lku/b;->e:Lez0/a;

    .line 77
    .line 78
    iget-object v0, v3, Lku/b;->d:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast v0, Lku/c;

    .line 81
    .line 82
    :try_start_1
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 83
    .line 84
    .line 85
    goto :goto_2

    .line 86
    :catchall_1
    move-exception v0

    .line 87
    move-object v2, v5

    .line 88
    goto/16 :goto_6

    .line 89
    .line 90
    :cond_3
    iget-object v0, v3, Lku/b;->e:Lez0/a;

    .line 91
    .line 92
    iget-object v5, v3, Lku/b;->d:Ljava/lang/Object;

    .line 93
    .line 94
    check-cast v5, Lku/c;

    .line 95
    .line 96
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    move-object v1, v0

    .line 100
    move-object v0, v5

    .line 101
    goto :goto_1

    .line 102
    :cond_4
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    iget-object v1, v0, Lku/c;->f:Lez0/c;

    .line 106
    .line 107
    invoke-virtual {v1}, Lez0/c;->b()Z

    .line 108
    .line 109
    .line 110
    move-result v5

    .line 111
    if-nez v5, :cond_5

    .line 112
    .line 113
    iget-object v5, v0, Lku/c;->e:Lku/m;

    .line 114
    .line 115
    invoke-virtual {v5}, Lku/m;->b()Z

    .line 116
    .line 117
    .line 118
    move-result v5

    .line 119
    if-nez v5, :cond_5

    .line 120
    .line 121
    return-object v10

    .line 122
    :cond_5
    iput-object v0, v3, Lku/b;->d:Ljava/lang/Object;

    .line 123
    .line 124
    iput-object v1, v3, Lku/b;->e:Lez0/a;

    .line 125
    .line 126
    iput v7, v3, Lku/b;->h:I

    .line 127
    .line 128
    invoke-virtual {v1, v3}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v5

    .line 132
    if-ne v5, v4, :cond_6

    .line 133
    .line 134
    goto/16 :goto_4

    .line 135
    .line 136
    :cond_6
    :goto_1
    :try_start_2
    iget-object v5, v0, Lku/c;->e:Lku/m;

    .line 137
    .line 138
    invoke-virtual {v5}, Lku/m;->b()Z

    .line 139
    .line 140
    .line 141
    move-result v5

    .line 142
    if-nez v5, :cond_7

    .line 143
    .line 144
    const-string v0, "Remote settings cache not expired. Using cached values."

    .line 145
    .line 146
    invoke-static {v8, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 147
    .line 148
    .line 149
    invoke-interface {v1, v11}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 150
    .line 151
    .line 152
    return-object v10

    .line 153
    :catchall_2
    move-exception v0

    .line 154
    move-object v2, v1

    .line 155
    goto/16 :goto_6

    .line 156
    .line 157
    :cond_7
    :try_start_3
    sget-object v5, Lhu/u;->c:Lhu/o;

    .line 158
    .line 159
    iget-object v7, v0, Lku/c;->b:Lht/d;

    .line 160
    .line 161
    iput-object v0, v3, Lku/b;->d:Ljava/lang/Object;

    .line 162
    .line 163
    iput-object v1, v3, Lku/b;->e:Lez0/a;

    .line 164
    .line 165
    iput v9, v3, Lku/b;->h:I

    .line 166
    .line 167
    invoke-virtual {v5, v7, v3}, Lhu/o;->a(Lht/d;Lrx0/c;)Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v5
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 171
    if-ne v5, v4, :cond_8

    .line 172
    .line 173
    goto/16 :goto_4

    .line 174
    .line 175
    :cond_8
    move-object/from16 v19, v5

    .line 176
    .line 177
    move-object v5, v1

    .line 178
    move-object/from16 v1, v19

    .line 179
    .line 180
    :goto_2
    :try_start_4
    check-cast v1, Lhu/u;

    .line 181
    .line 182
    iget-object v1, v1, Lhu/u;->a:Ljava/lang/String;

    .line 183
    .line 184
    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 185
    .line 186
    .line 187
    move-result v7

    .line 188
    if-eqz v7, :cond_9

    .line 189
    .line 190
    const-string v0, "Error getting Firebase Installation ID. Skipping this Session Event."

    .line 191
    .line 192
    invoke-static {v8, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 193
    .line 194
    .line 195
    invoke-interface {v5, v11}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 196
    .line 197
    .line 198
    return-object v10

    .line 199
    :cond_9
    :try_start_5
    const-string v7, "X-Crashlytics-Installation-ID"

    .line 200
    .line 201
    new-instance v12, Llx0/l;

    .line 202
    .line 203
    invoke-direct {v12, v7, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 204
    .line 205
    .line 206
    const-string v1, "X-Crashlytics-Device-Model"

    .line 207
    .line 208
    new-instance v7, Ljava/lang/StringBuilder;

    .line 209
    .line 210
    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    .line 211
    .line 212
    .line 213
    sget-object v13, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    .line 214
    .line 215
    invoke-virtual {v7, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 216
    .line 217
    .line 218
    sget-object v13, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 219
    .line 220
    invoke-virtual {v7, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 221
    .line 222
    .line 223
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    move-result-object v7

    .line 227
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 228
    .line 229
    .line 230
    sget-object v13, Lku/c;->h:Lly0/n;

    .line 231
    .line 232
    invoke-virtual {v13, v7, v2}, Lly0/n;->e(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 233
    .line 234
    .line 235
    move-result-object v7

    .line 236
    new-instance v14, Llx0/l;

    .line 237
    .line 238
    invoke-direct {v14, v1, v7}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 239
    .line 240
    .line 241
    const-string v1, "X-Crashlytics-OS-Build-Version"

    .line 242
    .line 243
    sget-object v7, Landroid/os/Build$VERSION;->INCREMENTAL:Ljava/lang/String;

    .line 244
    .line 245
    const-string v15, "INCREMENTAL"

    .line 246
    .line 247
    invoke-static {v7, v15}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 248
    .line 249
    .line 250
    invoke-virtual {v13, v7, v2}, Lly0/n;->e(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 251
    .line 252
    .line 253
    move-result-object v7

    .line 254
    new-instance v15, Llx0/l;

    .line 255
    .line 256
    invoke-direct {v15, v1, v7}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 257
    .line 258
    .line 259
    const-string v1, "X-Crashlytics-OS-Display-Version"

    .line 260
    .line 261
    sget-object v7, Landroid/os/Build$VERSION;->RELEASE:Ljava/lang/String;

    .line 262
    .line 263
    const-string v6, "RELEASE"

    .line 264
    .line 265
    invoke-static {v7, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 266
    .line 267
    .line 268
    invoke-virtual {v13, v7, v2}, Lly0/n;->e(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 269
    .line 270
    .line 271
    move-result-object v2

    .line 272
    new-instance v6, Llx0/l;

    .line 273
    .line 274
    invoke-direct {v6, v1, v2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 275
    .line 276
    .line 277
    const-string v1, "X-Crashlytics-API-Client-Version"

    .line 278
    .line 279
    iget-object v2, v0, Lku/c;->c:Lhu/b;

    .line 280
    .line 281
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 282
    .line 283
    .line 284
    const-string v2, "3.0.3"

    .line 285
    .line 286
    new-instance v7, Llx0/l;

    .line 287
    .line 288
    invoke-direct {v7, v1, v2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 289
    .line 290
    .line 291
    filled-new-array {v12, v14, v15, v6, v7}, [Llx0/l;

    .line 292
    .line 293
    .line 294
    move-result-object v1

    .line 295
    invoke-static {v1}, Lmx0/x;->m([Llx0/l;)Ljava/util/Map;

    .line 296
    .line 297
    .line 298
    move-result-object v14

    .line 299
    const-string v1, "Fetching settings from server."

    .line 300
    .line 301
    invoke-static {v8, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 302
    .line 303
    .line 304
    iget-object v13, v0, Lku/c;->d:Lku/d;

    .line 305
    .line 306
    new-instance v15, Lk31/t;

    .line 307
    .line 308
    const/16 v1, 0xd

    .line 309
    .line 310
    invoke-direct {v15, v0, v11, v1}, Lk31/t;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 311
    .line 312
    .line 313
    new-instance v0, Lb40/a;

    .line 314
    .line 315
    const/16 v1, 0x9

    .line 316
    .line 317
    invoke-direct {v0, v9, v11, v1}, Lb40/a;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 318
    .line 319
    .line 320
    iput-object v5, v3, Lku/b;->d:Ljava/lang/Object;

    .line 321
    .line 322
    iput-object v11, v3, Lku/b;->e:Lez0/a;

    .line 323
    .line 324
    const/4 v1, 0x3

    .line 325
    iput v1, v3, Lku/b;->h:I

    .line 326
    .line 327
    iget-object v1, v13, Lku/d;->b:Lpx0/g;

    .line 328
    .line 329
    new-instance v12, Lh7/z;

    .line 330
    .line 331
    const/16 v17, 0x0

    .line 332
    .line 333
    const/16 v18, 0x8

    .line 334
    .line 335
    move-object/from16 v16, v0

    .line 336
    .line 337
    invoke-direct/range {v12 .. v18}, Lh7/z;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 338
    .line 339
    .line 340
    invoke-static {v1, v12, v3}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 341
    .line 342
    .line 343
    move-result-object v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 344
    if-ne v0, v4, :cond_a

    .line 345
    .line 346
    goto :goto_3

    .line 347
    :cond_a
    move-object v0, v10

    .line 348
    :goto_3
    if-ne v0, v4, :cond_b

    .line 349
    .line 350
    :goto_4
    return-object v4

    .line 351
    :cond_b
    move-object v2, v5

    .line 352
    :goto_5
    invoke-interface {v2, v11}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 353
    .line 354
    .line 355
    return-object v10

    .line 356
    :goto_6
    invoke-interface {v2, v11}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 357
    .line 358
    .line 359
    throw v0
.end method
