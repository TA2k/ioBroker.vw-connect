.class public abstract Lcom/google/android/gms/internal/measurement/c4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static a:Landroid/os/UserManager; = null

.field public static volatile b:Z = false


# direct methods
.method public static final a(Lbu/c;)J
    .locals 6

    .line 1
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/view/DragEvent;

    .line 4
    .line 5
    invoke-virtual {p0}, Landroid/view/DragEvent;->getX()F

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    invoke-virtual {p0}, Landroid/view/DragEvent;->getY()F

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    int-to-long v0, v0

    .line 18
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    int-to-long v2, p0

    .line 23
    const/16 p0, 0x20

    .line 24
    .line 25
    shl-long/2addr v0, p0

    .line 26
    const-wide v4, 0xffffffffL

    .line 27
    .line 28
    .line 29
    .line 30
    .line 31
    and-long/2addr v2, v4

    .line 32
    or-long/2addr v0, v2

    .line 33
    return-wide v0
.end method

.method public static final b(Landroid/content/Context;Lym/n;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p6

    .line 4
    .line 5
    instance-of v2, v1, Lym/p;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lym/p;

    .line 11
    .line 12
    iget v3, v2, Lym/p;->i:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Lym/p;->i:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lym/p;

    .line 25
    .line 26
    invoke-direct {v2, v1}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Lym/p;->h:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lym/p;->i:I

    .line 34
    .line 35
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    const/4 v6, 0x3

    .line 38
    const/4 v7, 0x2

    .line 39
    const/4 v8, 0x1

    .line 40
    const/4 v9, 0x0

    .line 41
    if-eqz v4, :cond_4

    .line 42
    .line 43
    if-eq v4, v8, :cond_3

    .line 44
    .line 45
    if-eq v4, v7, :cond_2

    .line 46
    .line 47
    if-ne v4, v6, :cond_1

    .line 48
    .line 49
    iget-object v0, v2, Lym/p;->d:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v0, Lum/a;

    .line 52
    .line 53
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    return-object v0

    .line 57
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 58
    .line 59
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 60
    .line 61
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw v0

    .line 65
    :cond_2
    iget-object v0, v2, Lym/p;->g:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast v0, Lum/a;

    .line 68
    .line 69
    iget-object v4, v2, Lym/p;->f:Ljava/lang/String;

    .line 70
    .line 71
    iget-object v7, v2, Lym/p;->e:Ljava/lang/String;

    .line 72
    .line 73
    iget-object v8, v2, Lym/p;->d:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast v8, Landroid/content/Context;

    .line 76
    .line 77
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    goto/16 :goto_3

    .line 81
    .line 82
    :cond_3
    iget-object v0, v2, Lym/p;->g:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v0, Ljava/lang/String;

    .line 85
    .line 86
    iget-object v4, v2, Lym/p;->f:Ljava/lang/String;

    .line 87
    .line 88
    iget-object v8, v2, Lym/p;->e:Ljava/lang/String;

    .line 89
    .line 90
    iget-object v10, v2, Lym/p;->d:Ljava/lang/Object;

    .line 91
    .line 92
    check-cast v10, Landroid/content/Context;

    .line 93
    .line 94
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    move-object v11, v0

    .line 98
    move-object v0, v4

    .line 99
    move-object v4, v8

    .line 100
    goto :goto_1

    .line 101
    :cond_4
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    move-object/from16 v1, p1

    .line 105
    .line 106
    move-object/from16 v4, p5

    .line 107
    .line 108
    invoke-static {v0, v1, v4}, Lcom/google/android/gms/internal/measurement/c4;->c(Landroid/content/Context;Lym/n;Ljava/lang/String;)Lum/p;

    .line 109
    .line 110
    .line 111
    move-result-object v1

    .line 112
    iput-object v0, v2, Lym/p;->d:Ljava/lang/Object;

    .line 113
    .line 114
    move-object/from16 v4, p2

    .line 115
    .line 116
    iput-object v4, v2, Lym/p;->e:Ljava/lang/String;

    .line 117
    .line 118
    move-object/from16 v10, p3

    .line 119
    .line 120
    iput-object v10, v2, Lym/p;->f:Ljava/lang/String;

    .line 121
    .line 122
    move-object/from16 v11, p4

    .line 123
    .line 124
    iput-object v11, v2, Lym/p;->g:Ljava/lang/Object;

    .line 125
    .line 126
    iput v8, v2, Lym/p;->i:I

    .line 127
    .line 128
    new-instance v12, Lvy0/l;

    .line 129
    .line 130
    invoke-static {v2}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 131
    .line 132
    .line 133
    move-result-object v13

    .line 134
    invoke-direct {v12, v8, v13}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 135
    .line 136
    .line 137
    invoke-virtual {v12}, Lvy0/l;->q()V

    .line 138
    .line 139
    .line 140
    new-instance v13, Lym/o;

    .line 141
    .line 142
    const/4 v14, 0x0

    .line 143
    invoke-direct {v13, v12, v14}, Lym/o;-><init>(Lvy0/l;I)V

    .line 144
    .line 145
    .line 146
    invoke-virtual {v1, v13}, Lum/p;->b(Lum/m;)V

    .line 147
    .line 148
    .line 149
    new-instance v13, Lym/o;

    .line 150
    .line 151
    invoke-direct {v13, v12, v8}, Lym/o;-><init>(Lvy0/l;I)V

    .line 152
    .line 153
    .line 154
    invoke-virtual {v1, v13}, Lum/p;->a(Lum/m;)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {v12}, Lvy0/l;->p()Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object v1

    .line 161
    if-ne v1, v3, :cond_5

    .line 162
    .line 163
    goto/16 :goto_5

    .line 164
    .line 165
    :cond_5
    move-object v15, v10

    .line 166
    move-object v10, v0

    .line 167
    move-object v0, v15

    .line 168
    :goto_1
    check-cast v1, Lum/a;

    .line 169
    .line 170
    iput-object v10, v2, Lym/p;->d:Ljava/lang/Object;

    .line 171
    .line 172
    iput-object v0, v2, Lym/p;->e:Ljava/lang/String;

    .line 173
    .line 174
    iput-object v11, v2, Lym/p;->f:Ljava/lang/String;

    .line 175
    .line 176
    iput-object v1, v2, Lym/p;->g:Ljava/lang/Object;

    .line 177
    .line 178
    iput v7, v2, Lym/p;->i:I

    .line 179
    .line 180
    iget-object v7, v1, Lum/a;->d:Ljava/util/HashMap;

    .line 181
    .line 182
    invoke-virtual {v7}, Ljava/util/HashMap;->isEmpty()Z

    .line 183
    .line 184
    .line 185
    move-result v7

    .line 186
    if-eqz v7, :cond_6

    .line 187
    .line 188
    move-object v4, v5

    .line 189
    move-object v8, v10

    .line 190
    goto :goto_2

    .line 191
    :cond_6
    sget-object v7, Lvy0/p0;->a:Lcz0/e;

    .line 192
    .line 193
    sget-object v7, Lcz0/d;->e:Lcz0/d;

    .line 194
    .line 195
    new-instance v8, Lqh/a;

    .line 196
    .line 197
    const/16 v12, 0x13

    .line 198
    .line 199
    move-object/from16 p2, v1

    .line 200
    .line 201
    move-object/from16 p4, v4

    .line 202
    .line 203
    move-object/from16 p0, v8

    .line 204
    .line 205
    move-object/from16 p5, v9

    .line 206
    .line 207
    move-object/from16 p3, v10

    .line 208
    .line 209
    move/from16 p1, v12

    .line 210
    .line 211
    invoke-direct/range {p0 .. p5}, Lqh/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 212
    .line 213
    .line 214
    move-object/from16 v4, p0

    .line 215
    .line 216
    move-object/from16 v8, p3

    .line 217
    .line 218
    invoke-static {v7, v4, v2}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    move-result-object v4

    .line 222
    if-ne v4, v3, :cond_7

    .line 223
    .line 224
    goto :goto_2

    .line 225
    :cond_7
    move-object v4, v5

    .line 226
    :goto_2
    if-ne v4, v3, :cond_8

    .line 227
    .line 228
    goto :goto_5

    .line 229
    :cond_8
    move-object v7, v0

    .line 230
    move-object v0, v1

    .line 231
    move-object v4, v11

    .line 232
    :goto_3
    iput-object v0, v2, Lym/p;->d:Ljava/lang/Object;

    .line 233
    .line 234
    iput-object v9, v2, Lym/p;->e:Ljava/lang/String;

    .line 235
    .line 236
    iput-object v9, v2, Lym/p;->f:Ljava/lang/String;

    .line 237
    .line 238
    iput-object v9, v2, Lym/p;->g:Ljava/lang/Object;

    .line 239
    .line 240
    iput v6, v2, Lym/p;->i:I

    .line 241
    .line 242
    iget-object v1, v0, Lum/a;->f:Ljava/util/HashMap;

    .line 243
    .line 244
    invoke-virtual {v1}, Ljava/util/HashMap;->isEmpty()Z

    .line 245
    .line 246
    .line 247
    move-result v1

    .line 248
    if-eqz v1, :cond_9

    .line 249
    .line 250
    goto :goto_4

    .line 251
    :cond_9
    sget-object v1, Lvy0/p0;->a:Lcz0/e;

    .line 252
    .line 253
    sget-object v1, Lcz0/d;->e:Lcz0/d;

    .line 254
    .line 255
    new-instance v6, Lff/a;

    .line 256
    .line 257
    const/4 v9, 0x0

    .line 258
    const/16 v10, 0xf

    .line 259
    .line 260
    move-object/from16 p1, v0

    .line 261
    .line 262
    move-object/from16 p4, v4

    .line 263
    .line 264
    move-object/from16 p0, v6

    .line 265
    .line 266
    move-object/from16 p3, v7

    .line 267
    .line 268
    move-object/from16 p2, v8

    .line 269
    .line 270
    move-object/from16 p5, v9

    .line 271
    .line 272
    move/from16 p6, v10

    .line 273
    .line 274
    invoke-direct/range {p0 .. p6}, Lff/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 275
    .line 276
    .line 277
    move-object/from16 v4, p0

    .line 278
    .line 279
    invoke-static {v1, v4, v2}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 280
    .line 281
    .line 282
    move-result-object v1

    .line 283
    if-ne v1, v3, :cond_a

    .line 284
    .line 285
    move-object v5, v1

    .line 286
    :cond_a
    :goto_4
    if-ne v5, v3, :cond_b

    .line 287
    .line 288
    :goto_5
    return-object v3

    .line 289
    :cond_b
    return-object v0
.end method

.method public static final c(Landroid/content/Context;Lym/n;Ljava/lang/String;)Lum/p;
    .locals 5

    .line 1
    instance-of v0, p1, Lym/n;

    .line 2
    .line 3
    if-eqz v0, :cond_c

    .line 4
    .line 5
    const-string v0, "__LottieInternalDefaultCacheKey__"

    .line 6
    .line 7
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    const/4 v1, 0x1

    .line 12
    const/4 v2, 0x0

    .line 13
    const/4 v3, 0x0

    .line 14
    if-eqz v0, :cond_6

    .line 15
    .line 16
    iget p1, p1, Lym/n;->a:I

    .line 17
    .line 18
    sget-object p2, Lum/d;->a:Ljava/util/HashMap;

    .line 19
    .line 20
    new-instance p2, Ljava/lang/StringBuilder;

    .line 21
    .line 22
    const-string v0, "rawRes"

    .line 23
    .line 24
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    invoke-virtual {v0}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    iget v0, v0, Landroid/content/res/Configuration;->uiMode:I

    .line 36
    .line 37
    and-int/lit8 v0, v0, 0x30

    .line 38
    .line 39
    const/16 v4, 0x20

    .line 40
    .line 41
    if-ne v0, v4, :cond_0

    .line 42
    .line 43
    const-string v0, "_night_"

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_0
    const-string v0, "_day_"

    .line 47
    .line 48
    :goto_0
    invoke-static {p1, v0, p2}, Lvj/b;->h(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p2

    .line 52
    new-instance v0, Ljava/lang/ref/WeakReference;

    .line 53
    .line 54
    invoke-direct {v0, p0}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    new-instance v4, Lum/b;

    .line 62
    .line 63
    invoke-direct {v4, v0, p0, p1, p2}, Lum/b;-><init>(Ljava/lang/ref/WeakReference;Landroid/content/Context;ILjava/lang/String;)V

    .line 64
    .line 65
    .line 66
    sget-object p0, Lum/d;->a:Ljava/util/HashMap;

    .line 67
    .line 68
    if-nez p2, :cond_1

    .line 69
    .line 70
    move-object p1, v2

    .line 71
    goto :goto_1

    .line 72
    :cond_1
    sget-object p1, Lan/e;->b:Lan/e;

    .line 73
    .line 74
    invoke-virtual {p1, p2}, Lan/e;->a(Ljava/lang/String;)Lum/a;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    :goto_1
    if-eqz p1, :cond_2

    .line 79
    .line 80
    new-instance v2, Lum/p;

    .line 81
    .line 82
    invoke-direct {v2, p1}, Lum/p;-><init>(Lum/a;)V

    .line 83
    .line 84
    .line 85
    :cond_2
    if-eqz p2, :cond_3

    .line 86
    .line 87
    invoke-virtual {p0, p2}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result p1

    .line 91
    if-eqz p1, :cond_3

    .line 92
    .line 93
    invoke-virtual {p0, p2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object p1

    .line 97
    move-object v2, p1

    .line 98
    check-cast v2, Lum/p;

    .line 99
    .line 100
    :cond_3
    if-eqz v2, :cond_4

    .line 101
    .line 102
    return-object v2

    .line 103
    :cond_4
    new-instance p1, Lum/p;

    .line 104
    .line 105
    invoke-direct {p1, v4}, Lum/p;-><init>(Ljava/util/concurrent/Callable;)V

    .line 106
    .line 107
    .line 108
    if-eqz p2, :cond_5

    .line 109
    .line 110
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 111
    .line 112
    invoke-direct {v0, v3}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 113
    .line 114
    .line 115
    new-instance v2, Lum/c;

    .line 116
    .line 117
    invoke-direct {v2, p2, v0, v3}, Lum/c;-><init>(Ljava/lang/String;Ljava/util/concurrent/atomic/AtomicBoolean;I)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {p1, v2}, Lum/p;->b(Lum/m;)V

    .line 121
    .line 122
    .line 123
    new-instance v2, Lum/c;

    .line 124
    .line 125
    invoke-direct {v2, p2, v0, v1}, Lum/c;-><init>(Ljava/lang/String;Ljava/util/concurrent/atomic/AtomicBoolean;I)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {p1, v2}, Lum/p;->a(Lum/m;)V

    .line 129
    .line 130
    .line 131
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 132
    .line 133
    .line 134
    move-result v0

    .line 135
    if-nez v0, :cond_5

    .line 136
    .line 137
    invoke-virtual {p0, p2, p1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    invoke-virtual {p0}, Ljava/util/HashMap;->size()I

    .line 141
    .line 142
    .line 143
    move-result p0

    .line 144
    if-ne p0, v1, :cond_5

    .line 145
    .line 146
    invoke-static {}, Lum/d;->d()V

    .line 147
    .line 148
    .line 149
    :cond_5
    return-object p1

    .line 150
    :cond_6
    iget p1, p1, Lym/n;->a:I

    .line 151
    .line 152
    sget-object v0, Lum/d;->a:Ljava/util/HashMap;

    .line 153
    .line 154
    new-instance v0, Ljava/lang/ref/WeakReference;

    .line 155
    .line 156
    invoke-direct {v0, p0}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 160
    .line 161
    .line 162
    move-result-object p0

    .line 163
    new-instance v4, Lum/b;

    .line 164
    .line 165
    invoke-direct {v4, v0, p0, p1, p2}, Lum/b;-><init>(Ljava/lang/ref/WeakReference;Landroid/content/Context;ILjava/lang/String;)V

    .line 166
    .line 167
    .line 168
    sget-object p0, Lum/d;->a:Ljava/util/HashMap;

    .line 169
    .line 170
    if-nez p2, :cond_7

    .line 171
    .line 172
    move-object p1, v2

    .line 173
    goto :goto_2

    .line 174
    :cond_7
    sget-object p1, Lan/e;->b:Lan/e;

    .line 175
    .line 176
    invoke-virtual {p1, p2}, Lan/e;->a(Ljava/lang/String;)Lum/a;

    .line 177
    .line 178
    .line 179
    move-result-object p1

    .line 180
    :goto_2
    if-eqz p1, :cond_8

    .line 181
    .line 182
    new-instance v2, Lum/p;

    .line 183
    .line 184
    invoke-direct {v2, p1}, Lum/p;-><init>(Lum/a;)V

    .line 185
    .line 186
    .line 187
    :cond_8
    if-eqz p2, :cond_9

    .line 188
    .line 189
    invoke-virtual {p0, p2}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 190
    .line 191
    .line 192
    move-result p1

    .line 193
    if-eqz p1, :cond_9

    .line 194
    .line 195
    invoke-virtual {p0, p2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object p1

    .line 199
    move-object v2, p1

    .line 200
    check-cast v2, Lum/p;

    .line 201
    .line 202
    :cond_9
    if-eqz v2, :cond_a

    .line 203
    .line 204
    return-object v2

    .line 205
    :cond_a
    new-instance p1, Lum/p;

    .line 206
    .line 207
    invoke-direct {p1, v4}, Lum/p;-><init>(Ljava/util/concurrent/Callable;)V

    .line 208
    .line 209
    .line 210
    if-eqz p2, :cond_b

    .line 211
    .line 212
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 213
    .line 214
    invoke-direct {v0, v3}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 215
    .line 216
    .line 217
    new-instance v2, Lum/c;

    .line 218
    .line 219
    invoke-direct {v2, p2, v0, v3}, Lum/c;-><init>(Ljava/lang/String;Ljava/util/concurrent/atomic/AtomicBoolean;I)V

    .line 220
    .line 221
    .line 222
    invoke-virtual {p1, v2}, Lum/p;->b(Lum/m;)V

    .line 223
    .line 224
    .line 225
    new-instance v2, Lum/c;

    .line 226
    .line 227
    invoke-direct {v2, p2, v0, v1}, Lum/c;-><init>(Ljava/lang/String;Ljava/util/concurrent/atomic/AtomicBoolean;I)V

    .line 228
    .line 229
    .line 230
    invoke-virtual {p1, v2}, Lum/p;->a(Lum/m;)V

    .line 231
    .line 232
    .line 233
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 234
    .line 235
    .line 236
    move-result v0

    .line 237
    if-nez v0, :cond_b

    .line 238
    .line 239
    invoke-virtual {p0, p2, p1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    invoke-virtual {p0}, Ljava/util/HashMap;->size()I

    .line 243
    .line 244
    .line 245
    move-result p0

    .line 246
    if-ne p0, v1, :cond_b

    .line 247
    .line 248
    invoke-static {}, Lum/d;->d()V

    .line 249
    .line 250
    .line 251
    :cond_b
    return-object p1

    .line 252
    :cond_c
    new-instance p0, La8/r0;

    .line 253
    .line 254
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 255
    .line 256
    .line 257
    throw p0
.end method

.method public static final d(Lym/n;Ll2/o;)Lym/m;
    .locals 8

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, -0x4a6a3202

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, v0}, Ll2/t;->Z(I)V

    .line 7
    .line 8
    .line 9
    new-instance v2, Lg1/e1;

    .line 10
    .line 11
    const/4 v0, 0x3

    .line 12
    const/4 v1, 0x7

    .line 13
    const/4 v3, 0x0

    .line 14
    invoke-direct {v2, v0, v3, v1}, Lg1/e1;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 15
    .line 16
    .line 17
    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 18
    .line 19
    invoke-virtual {p1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    move-object v3, v0

    .line 24
    check-cast v3, Landroid/content/Context;

    .line 25
    .line 26
    const v0, 0x52c617e1

    .line 27
    .line 28
    .line 29
    invoke-virtual {p1, v0}, Ll2/t;->Z(I)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p1, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 41
    .line 42
    if-nez v0, :cond_0

    .line 43
    .line 44
    if-ne v1, v4, :cond_1

    .line 45
    .line 46
    :cond_0
    new-instance v0, Lym/m;

    .line 47
    .line 48
    invoke-direct {v0}, Lym/m;-><init>()V

    .line 49
    .line 50
    .line 51
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    invoke-virtual {p1, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    :cond_1
    move-object v5, v1

    .line 59
    check-cast v5, Ll2/b1;

    .line 60
    .line 61
    const/4 v0, 0x0

    .line 62
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 63
    .line 64
    .line 65
    const v1, 0x52c61904

    .line 66
    .line 67
    .line 68
    invoke-virtual {p1, v1}, Ll2/t;->Z(I)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {p1, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v1

    .line 75
    const-string v7, "__LottieInternalDefaultCacheKey__"

    .line 76
    .line 77
    invoke-virtual {p1, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v6

    .line 81
    or-int/2addr v1, v6

    .line 82
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v6

    .line 86
    if-nez v1, :cond_2

    .line 87
    .line 88
    if-ne v6, v4, :cond_3

    .line 89
    .line 90
    :cond_2
    invoke-static {v3, p0, v7}, Lcom/google/android/gms/internal/measurement/c4;->c(Landroid/content/Context;Lym/n;Ljava/lang/String;)Lum/p;

    .line 91
    .line 92
    .line 93
    move-result-object v6

    .line 94
    invoke-virtual {p1, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    :cond_3
    check-cast v6, Lum/p;

    .line 98
    .line 99
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 100
    .line 101
    .line 102
    new-instance v1, Lem0/l;

    .line 103
    .line 104
    const/4 v6, 0x0

    .line 105
    move-object v4, p0

    .line 106
    invoke-direct/range {v1 .. v6}, Lem0/l;-><init>(Lg1/e1;Landroid/content/Context;Lym/n;Ll2/b1;Lkotlin/coroutines/Continuation;)V

    .line 107
    .line 108
    .line 109
    invoke-static {v4, v7, v1, p1}, Ll2/l0;->e(Ljava/lang/Object;Ljava/lang/Object;Lay0/n;Ll2/o;)V

    .line 110
    .line 111
    .line 112
    invoke-interface {v5}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    check-cast p0, Lym/m;

    .line 117
    .line 118
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 119
    .line 120
    .line 121
    return-object p0
.end method

.method public static final e(Lm2/l0;ILjava/lang/Object;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lm2/l0;->f:[Ljava/lang/Object;

    .line 2
    .line 3
    iget v1, p0, Lm2/l0;->g:I

    .line 4
    .line 5
    iget-object v2, p0, Lm2/l0;->b:[Lm2/j0;

    .line 6
    .line 7
    iget p0, p0, Lm2/l0;->c:I

    .line 8
    .line 9
    add-int/lit8 p0, p0, -0x1

    .line 10
    .line 11
    aget-object p0, v2, p0

    .line 12
    .line 13
    iget p0, p0, Lm2/j0;->b:I

    .line 14
    .line 15
    sub-int/2addr v1, p0

    .line 16
    add-int/2addr v1, p1

    .line 17
    aput-object p2, v0, v1

    .line 18
    .line 19
    return-void
.end method

.method public static final f(Lm2/l0;ILjava/lang/Object;ILjava/lang/Object;)V
    .locals 3

    .line 1
    iget v0, p0, Lm2/l0;->g:I

    .line 2
    .line 3
    iget-object v1, p0, Lm2/l0;->b:[Lm2/j0;

    .line 4
    .line 5
    iget v2, p0, Lm2/l0;->c:I

    .line 6
    .line 7
    add-int/lit8 v2, v2, -0x1

    .line 8
    .line 9
    aget-object v1, v1, v2

    .line 10
    .line 11
    iget v1, v1, Lm2/j0;->b:I

    .line 12
    .line 13
    sub-int/2addr v0, v1

    .line 14
    iget-object p0, p0, Lm2/l0;->f:[Ljava/lang/Object;

    .line 15
    .line 16
    add-int/2addr p1, v0

    .line 17
    aput-object p2, p0, p1

    .line 18
    .line 19
    add-int/2addr v0, p3

    .line 20
    aput-object p4, p0, v0

    .line 21
    .line 22
    return-void
.end method
