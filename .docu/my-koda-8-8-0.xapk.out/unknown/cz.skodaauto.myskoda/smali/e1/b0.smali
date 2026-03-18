.class public final Le1/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p5, p0, Le1/b0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Le1/b0;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Le1/b0;->f:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p3, p0, Le1/b0;->g:Ljava/lang/Object;

    .line 8
    .line 9
    iput-object p4, p0, Le1/b0;->h:Ljava/lang/Object;

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public b([ILkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget-object v0, p0, Le1/b0;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, [Ljava/lang/String;

    .line 4
    .line 5
    iget-object v1, p0, Le1/b0;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lyy0/j;

    .line 8
    .line 9
    iget-object v2, p0, Le1/b0;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v2, Lkotlin/jvm/internal/f0;

    .line 12
    .line 13
    instance-of v3, p2, Lla/e0;

    .line 14
    .line 15
    if-eqz v3, :cond_0

    .line 16
    .line 17
    move-object v3, p2

    .line 18
    check-cast v3, Lla/e0;

    .line 19
    .line 20
    iget v4, v3, Lla/e0;->g:I

    .line 21
    .line 22
    const/high16 v5, -0x80000000

    .line 23
    .line 24
    and-int v6, v4, v5

    .line 25
    .line 26
    if-eqz v6, :cond_0

    .line 27
    .line 28
    sub-int/2addr v4, v5

    .line 29
    iput v4, v3, Lla/e0;->g:I

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    new-instance v3, Lla/e0;

    .line 33
    .line 34
    invoke-direct {v3, p0, p2}, Lla/e0;-><init>(Le1/b0;Lkotlin/coroutines/Continuation;)V

    .line 35
    .line 36
    .line 37
    :goto_0
    iget-object p2, v3, Lla/e0;->e:Ljava/lang/Object;

    .line 38
    .line 39
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 40
    .line 41
    iget v5, v3, Lla/e0;->g:I

    .line 42
    .line 43
    const/4 v6, 0x2

    .line 44
    const/4 v7, 0x1

    .line 45
    if-eqz v5, :cond_3

    .line 46
    .line 47
    if-eq v5, v7, :cond_2

    .line 48
    .line 49
    if-ne v5, v6, :cond_1

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 55
    .line 56
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :cond_2
    :goto_1
    iget-object p1, v3, Lla/e0;->d:[I

    .line 61
    .line 62
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    goto :goto_4

    .line 66
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    iget-object p2, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 70
    .line 71
    if-nez p2, :cond_4

    .line 72
    .line 73
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    iput-object p1, v3, Lla/e0;->d:[I

    .line 78
    .line 79
    iput v7, v3, Lla/e0;->g:I

    .line 80
    .line 81
    invoke-interface {v1, p0, v3}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    if-ne p0, v4, :cond_8

    .line 86
    .line 87
    goto :goto_3

    .line 88
    :cond_4
    iget-object p0, p0, Le1/b0;->h:Ljava/lang/Object;

    .line 89
    .line 90
    check-cast p0, [I

    .line 91
    .line 92
    new-instance p2, Ljava/util/ArrayList;

    .line 93
    .line 94
    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    .line 95
    .line 96
    .line 97
    array-length v5, v0

    .line 98
    const/4 v7, 0x0

    .line 99
    move v8, v7

    .line 100
    :goto_2
    if-ge v7, v5, :cond_7

    .line 101
    .line 102
    aget-object v9, v0, v7

    .line 103
    .line 104
    add-int/lit8 v10, v8, 0x1

    .line 105
    .line 106
    iget-object v11, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 107
    .line 108
    if-eqz v11, :cond_6

    .line 109
    .line 110
    check-cast v11, [I

    .line 111
    .line 112
    aget v8, p0, v8

    .line 113
    .line 114
    aget v11, v11, v8

    .line 115
    .line 116
    aget v8, p1, v8

    .line 117
    .line 118
    if-eq v11, v8, :cond_5

    .line 119
    .line 120
    invoke-virtual {p2, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    :cond_5
    add-int/lit8 v7, v7, 0x1

    .line 124
    .line 125
    move v8, v10

    .line 126
    goto :goto_2

    .line 127
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 128
    .line 129
    const-string p1, "Required value was null."

    .line 130
    .line 131
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    throw p0

    .line 135
    :cond_7
    invoke-virtual {p2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 136
    .line 137
    .line 138
    move-result p0

    .line 139
    if-nez p0, :cond_8

    .line 140
    .line 141
    invoke-static {p2}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 142
    .line 143
    .line 144
    move-result-object p0

    .line 145
    iput-object p1, v3, Lla/e0;->d:[I

    .line 146
    .line 147
    iput v6, v3, Lla/e0;->g:I

    .line 148
    .line 149
    invoke-interface {v1, p0, v3}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object p0

    .line 153
    if-ne p0, v4, :cond_8

    .line 154
    .line 155
    :goto_3
    return-object v4

    .line 156
    :cond_8
    :goto_4
    iput-object p1, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 157
    .line 158
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 159
    .line 160
    return-object p0
.end method

.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    iget v3, v0, Le1/b0;->d:I

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    const-string v5, "call to \'resume\' before \'invoke\' with coroutine"

    .line 11
    .line 12
    const/high16 v6, -0x80000000

    .line 13
    .line 14
    const/4 v7, 0x0

    .line 15
    iget-object v8, v0, Le1/b0;->h:Ljava/lang/Object;

    .line 16
    .line 17
    iget-object v9, v0, Le1/b0;->g:Ljava/lang/Object;

    .line 18
    .line 19
    iget-object v10, v0, Le1/b0;->f:Ljava/lang/Object;

    .line 20
    .line 21
    const/4 v11, 0x1

    .line 22
    sget-object v12, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    iget-object v13, v0, Le1/b0;->e:Ljava/lang/Object;

    .line 25
    .line 26
    packed-switch v3, :pswitch_data_0

    .line 27
    .line 28
    .line 29
    instance-of v3, v2, Lzy0/i;

    .line 30
    .line 31
    if-eqz v3, :cond_0

    .line 32
    .line 33
    move-object v3, v2

    .line 34
    check-cast v3, Lzy0/i;

    .line 35
    .line 36
    iget v4, v3, Lzy0/i;->h:I

    .line 37
    .line 38
    and-int v8, v4, v6

    .line 39
    .line 40
    if-eqz v8, :cond_0

    .line 41
    .line 42
    sub-int/2addr v4, v6

    .line 43
    iput v4, v3, Lzy0/i;->h:I

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_0
    new-instance v3, Lzy0/i;

    .line 47
    .line 48
    invoke-direct {v3, v0, v2}, Lzy0/i;-><init>(Le1/b0;Lkotlin/coroutines/Continuation;)V

    .line 49
    .line 50
    .line 51
    :goto_0
    iget-object v2, v3, Lzy0/i;->f:Ljava/lang/Object;

    .line 52
    .line 53
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 54
    .line 55
    iget v6, v3, Lzy0/i;->h:I

    .line 56
    .line 57
    if-eqz v6, :cond_2

    .line 58
    .line 59
    if-ne v6, v11, :cond_1

    .line 60
    .line 61
    iget-object v0, v3, Lzy0/i;->e:Ljava/lang/Object;

    .line 62
    .line 63
    iget-object v1, v3, Lzy0/i;->d:Le1/b0;

    .line 64
    .line 65
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    move-object/from16 v16, v1

    .line 69
    .line 70
    move-object v1, v0

    .line 71
    move-object/from16 v0, v16

    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 75
    .line 76
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    throw v0

    .line 80
    :cond_2
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    check-cast v13, Lkotlin/jvm/internal/f0;

    .line 84
    .line 85
    iget-object v2, v13, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast v2, Lvy0/i1;

    .line 88
    .line 89
    if-eqz v2, :cond_3

    .line 90
    .line 91
    new-instance v5, Lzy0/k;

    .line 92
    .line 93
    invoke-direct {v5}, Lzy0/k;-><init>()V

    .line 94
    .line 95
    .line 96
    invoke-interface {v2, v5}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 97
    .line 98
    .line 99
    iput-object v0, v3, Lzy0/i;->d:Le1/b0;

    .line 100
    .line 101
    iput-object v1, v3, Lzy0/i;->e:Ljava/lang/Object;

    .line 102
    .line 103
    iput v11, v3, Lzy0/i;->h:I

    .line 104
    .line 105
    invoke-interface {v2, v3}, Lvy0/i1;->l(Lrx0/c;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v2

    .line 109
    if-ne v2, v4, :cond_3

    .line 110
    .line 111
    move-object v12, v4

    .line 112
    goto :goto_2

    .line 113
    :cond_3
    :goto_1
    iget-object v2, v0, Le1/b0;->e:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast v2, Lkotlin/jvm/internal/f0;

    .line 116
    .line 117
    iget-object v3, v0, Le1/b0;->f:Ljava/lang/Object;

    .line 118
    .line 119
    check-cast v3, Lvy0/b0;

    .line 120
    .line 121
    sget-object v4, Lvy0/c0;->g:Lvy0/c0;

    .line 122
    .line 123
    new-instance v5, Lzy0/h;

    .line 124
    .line 125
    iget-object v6, v0, Le1/b0;->g:Ljava/lang/Object;

    .line 126
    .line 127
    check-cast v6, Lzy0/j;

    .line 128
    .line 129
    iget-object v0, v0, Le1/b0;->h:Ljava/lang/Object;

    .line 130
    .line 131
    check-cast v0, Lyy0/j;

    .line 132
    .line 133
    invoke-direct {v5, v6, v0, v1, v7}, Lzy0/h;-><init>(Lzy0/j;Lyy0/j;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 134
    .line 135
    .line 136
    invoke-static {v3, v7, v4, v5, v11}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 137
    .line 138
    .line 139
    move-result-object v0

    .line 140
    iput-object v0, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 141
    .line 142
    :goto_2
    return-object v12

    .line 143
    :pswitch_0
    instance-of v3, v2, Lzj0/i;

    .line 144
    .line 145
    if-eqz v3, :cond_4

    .line 146
    .line 147
    move-object v3, v2

    .line 148
    check-cast v3, Lzj0/i;

    .line 149
    .line 150
    iget v4, v3, Lzj0/i;->e:I

    .line 151
    .line 152
    and-int v14, v4, v6

    .line 153
    .line 154
    if-eqz v14, :cond_4

    .line 155
    .line 156
    sub-int/2addr v4, v6

    .line 157
    iput v4, v3, Lzj0/i;->e:I

    .line 158
    .line 159
    goto :goto_3

    .line 160
    :cond_4
    new-instance v3, Lzj0/i;

    .line 161
    .line 162
    invoke-direct {v3, v0, v2}, Lzj0/i;-><init>(Le1/b0;Lkotlin/coroutines/Continuation;)V

    .line 163
    .line 164
    .line 165
    :goto_3
    iget-object v0, v3, Lzj0/i;->d:Ljava/lang/Object;

    .line 166
    .line 167
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 168
    .line 169
    iget v4, v3, Lzj0/i;->e:I

    .line 170
    .line 171
    if-eqz v4, :cond_6

    .line 172
    .line 173
    if-ne v4, v11, :cond_5

    .line 174
    .line 175
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 176
    .line 177
    .line 178
    goto/16 :goto_9

    .line 179
    .line 180
    :cond_5
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 181
    .line 182
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 183
    .line 184
    .line 185
    throw v0

    .line 186
    :cond_6
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 187
    .line 188
    .line 189
    check-cast v13, Lyy0/j;

    .line 190
    .line 191
    move-object v0, v1

    .line 192
    check-cast v0, Lcom/google/android/gms/maps/model/CameraPosition;

    .line 193
    .line 194
    check-cast v10, Luu/g;

    .line 195
    .line 196
    invoke-virtual {v10}, Luu/g;->c()Lqp/g;

    .line 197
    .line 198
    .line 199
    move-result-object v1

    .line 200
    if-eqz v1, :cond_7

    .line 201
    .line 202
    invoke-virtual {v1}, Lqp/g;->c()Lj1/a;

    .line 203
    .line 204
    .line 205
    move-result-object v7

    .line 206
    :cond_7
    if-nez v7, :cond_8

    .line 207
    .line 208
    sget-object v0, Lmx0/s;->d:Lmx0/s;

    .line 209
    .line 210
    goto/16 :goto_8

    .line 211
    .line 212
    :cond_8
    invoke-virtual {v7}, Lj1/a;->q()Lsp/v;

    .line 213
    .line 214
    .line 215
    move-result-object v1

    .line 216
    const-string v4, "getVisibleRegion(...)"

    .line 217
    .line 218
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 219
    .line 220
    .line 221
    iget-object v1, v1, Lsp/v;->h:Lcom/google/android/gms/maps/model/LatLngBounds;

    .line 222
    .line 223
    const-string v4, "latLngBounds"

    .line 224
    .line 225
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 226
    .line 227
    .line 228
    check-cast v9, Lqu/c;

    .line 229
    .line 230
    iget-object v4, v9, Lqu/c;->g:Lap0/o;

    .line 231
    .line 232
    iget v0, v0, Lcom/google/android/gms/maps/model/CameraPosition;->e:F

    .line 233
    .line 234
    invoke-interface {v4, v0}, Lru/a;->m(F)Ljava/util/Set;

    .line 235
    .line 236
    .line 237
    move-result-object v0

    .line 238
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 239
    .line 240
    .line 241
    check-cast v0, Ljava/lang/Iterable;

    .line 242
    .line 243
    new-instance v4, Ljava/util/ArrayList;

    .line 244
    .line 245
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 246
    .line 247
    .line 248
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 249
    .line 250
    .line 251
    move-result-object v0

    .line 252
    :cond_9
    :goto_4
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 253
    .line 254
    .line 255
    move-result v5

    .line 256
    if-eqz v5, :cond_a

    .line 257
    .line 258
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 259
    .line 260
    .line 261
    move-result-object v5

    .line 262
    move-object v6, v5

    .line 263
    check-cast v6, Lqu/a;

    .line 264
    .line 265
    invoke-interface {v6}, Lqu/a;->getPosition()Lcom/google/android/gms/maps/model/LatLng;

    .line 266
    .line 267
    .line 268
    move-result-object v7

    .line 269
    invoke-virtual {v1, v7}, Lcom/google/android/gms/maps/model/LatLngBounds;->x0(Lcom/google/android/gms/maps/model/LatLng;)Z

    .line 270
    .line 271
    .line 272
    move-result v7

    .line 273
    if-eqz v7, :cond_9

    .line 274
    .line 275
    invoke-interface {v6}, Lqu/a;->a()I

    .line 276
    .line 277
    .line 278
    move-result v6

    .line 279
    const/4 v7, 0x3

    .line 280
    if-le v6, v7, :cond_9

    .line 281
    .line 282
    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 283
    .line 284
    .line 285
    goto :goto_4

    .line 286
    :cond_a
    check-cast v8, Ljava/util/List;

    .line 287
    .line 288
    check-cast v8, Ljava/lang/Iterable;

    .line 289
    .line 290
    new-instance v0, Ljava/util/ArrayList;

    .line 291
    .line 292
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 293
    .line 294
    .line 295
    invoke-interface {v8}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 296
    .line 297
    .line 298
    move-result-object v5

    .line 299
    :cond_b
    :goto_5
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 300
    .line 301
    .line 302
    move-result v6

    .line 303
    if-eqz v6, :cond_11

    .line 304
    .line 305
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 306
    .line 307
    .line 308
    move-result-object v6

    .line 309
    move-object v7, v6

    .line 310
    check-cast v7, Lxj0/r;

    .line 311
    .line 312
    invoke-virtual {v7}, Lxj0/r;->c()Lxj0/f;

    .line 313
    .line 314
    .line 315
    move-result-object v8

    .line 316
    invoke-static {v8}, Lzj0/d;->l(Lxj0/f;)Lcom/google/android/gms/maps/model/LatLng;

    .line 317
    .line 318
    .line 319
    move-result-object v8

    .line 320
    invoke-virtual {v1, v8}, Lcom/google/android/gms/maps/model/LatLngBounds;->x0(Lcom/google/android/gms/maps/model/LatLng;)Z

    .line 321
    .line 322
    .line 323
    move-result v8

    .line 324
    if-eqz v8, :cond_b

    .line 325
    .line 326
    sget v8, Lzj0/j;->b:F

    .line 327
    .line 328
    invoke-virtual {v4}, Ljava/util/ArrayList;->isEmpty()Z

    .line 329
    .line 330
    .line 331
    move-result v8

    .line 332
    if-eqz v8, :cond_c

    .line 333
    .line 334
    goto :goto_7

    .line 335
    :cond_c
    invoke-virtual {v4}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 336
    .line 337
    .line 338
    move-result-object v8

    .line 339
    :cond_d
    :goto_6
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 340
    .line 341
    .line 342
    move-result v9

    .line 343
    if-eqz v9, :cond_10

    .line 344
    .line 345
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 346
    .line 347
    .line 348
    move-result-object v9

    .line 349
    check-cast v9, Lqu/a;

    .line 350
    .line 351
    invoke-interface {v9}, Lqu/a;->b()Ljava/util/Collection;

    .line 352
    .line 353
    .line 354
    move-result-object v9

    .line 355
    const-string v10, "getItems(...)"

    .line 356
    .line 357
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 358
    .line 359
    .line 360
    check-cast v9, Ljava/lang/Iterable;

    .line 361
    .line 362
    instance-of v10, v9, Ljava/util/Collection;

    .line 363
    .line 364
    if-eqz v10, :cond_e

    .line 365
    .line 366
    move-object v10, v9

    .line 367
    check-cast v10, Ljava/util/Collection;

    .line 368
    .line 369
    invoke-interface {v10}, Ljava/util/Collection;->isEmpty()Z

    .line 370
    .line 371
    .line 372
    move-result v10

    .line 373
    if-eqz v10, :cond_e

    .line 374
    .line 375
    goto :goto_6

    .line 376
    :cond_e
    invoke-interface {v9}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 377
    .line 378
    .line 379
    move-result-object v9

    .line 380
    :cond_f
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 381
    .line 382
    .line 383
    move-result v10

    .line 384
    if-eqz v10, :cond_d

    .line 385
    .line 386
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 387
    .line 388
    .line 389
    move-result-object v10

    .line 390
    check-cast v10, Lzj0/c;

    .line 391
    .line 392
    iget-object v10, v10, Lzj0/c;->b:Lxj0/r;

    .line 393
    .line 394
    invoke-virtual {v10, v7}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 395
    .line 396
    .line 397
    move-result v10

    .line 398
    if-eqz v10, :cond_f

    .line 399
    .line 400
    goto :goto_5

    .line 401
    :cond_10
    :goto_7
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 402
    .line 403
    .line 404
    goto :goto_5

    .line 405
    :cond_11
    :goto_8
    iput v11, v3, Lzj0/i;->e:I

    .line 406
    .line 407
    invoke-interface {v13, v0, v3}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 408
    .line 409
    .line 410
    move-result-object v0

    .line 411
    if-ne v0, v2, :cond_12

    .line 412
    .line 413
    move-object v12, v2

    .line 414
    :cond_12
    :goto_9
    return-object v12

    .line 415
    :pswitch_1
    instance-of v3, v2, Lve0/q;

    .line 416
    .line 417
    if-eqz v3, :cond_13

    .line 418
    .line 419
    move-object v3, v2

    .line 420
    check-cast v3, Lve0/q;

    .line 421
    .line 422
    iget v14, v3, Lve0/q;->e:I

    .line 423
    .line 424
    and-int v15, v14, v6

    .line 425
    .line 426
    if-eqz v15, :cond_13

    .line 427
    .line 428
    sub-int/2addr v14, v6

    .line 429
    iput v14, v3, Lve0/q;->e:I

    .line 430
    .line 431
    goto :goto_a

    .line 432
    :cond_13
    new-instance v3, Lve0/q;

    .line 433
    .line 434
    invoke-direct {v3, v0, v2}, Lve0/q;-><init>(Le1/b0;Lkotlin/coroutines/Continuation;)V

    .line 435
    .line 436
    .line 437
    :goto_a
    iget-object v0, v3, Lve0/q;->d:Ljava/lang/Object;

    .line 438
    .line 439
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 440
    .line 441
    iget v6, v3, Lve0/q;->e:I

    .line 442
    .line 443
    const/4 v14, 0x2

    .line 444
    if-eqz v6, :cond_16

    .line 445
    .line 446
    if-eq v6, v11, :cond_15

    .line 447
    .line 448
    if-ne v6, v14, :cond_14

    .line 449
    .line 450
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 451
    .line 452
    .line 453
    goto :goto_d

    .line 454
    :cond_14
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 455
    .line 456
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 457
    .line 458
    .line 459
    throw v0

    .line 460
    :cond_15
    iget v4, v3, Lve0/q;->h:I

    .line 461
    .line 462
    iget-object v1, v3, Lve0/q;->g:Lyy0/j;

    .line 463
    .line 464
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 465
    .line 466
    .line 467
    goto :goto_b

    .line 468
    :cond_16
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 469
    .line 470
    .line 471
    move-object v0, v13

    .line 472
    check-cast v0, Lyy0/j;

    .line 473
    .line 474
    check-cast v1, Ljava/lang/String;

    .line 475
    .line 476
    if-eqz v1, :cond_18

    .line 477
    .line 478
    check-cast v9, Lve0/u;

    .line 479
    .line 480
    check-cast v8, Ljava/lang/String;

    .line 481
    .line 482
    iput-object v0, v3, Lve0/q;->g:Lyy0/j;

    .line 483
    .line 484
    iput v4, v3, Lve0/q;->h:I

    .line 485
    .line 486
    iput v11, v3, Lve0/q;->e:I

    .line 487
    .line 488
    invoke-virtual {v9, v8, v1, v3}, Lve0/u;->b(Ljava/lang/String;Ljava/lang/String;Lrx0/c;)Ljava/io/Serializable;

    .line 489
    .line 490
    .line 491
    move-result-object v1

    .line 492
    if-ne v1, v2, :cond_17

    .line 493
    .line 494
    goto :goto_c

    .line 495
    :cond_17
    move-object/from16 v16, v1

    .line 496
    .line 497
    move-object v1, v0

    .line 498
    move-object/from16 v0, v16

    .line 499
    .line 500
    :goto_b
    check-cast v0, Ljava/lang/String;

    .line 501
    .line 502
    if-nez v0, :cond_19

    .line 503
    .line 504
    move-object v0, v1

    .line 505
    :cond_18
    move-object v1, v10

    .line 506
    check-cast v1, Ljava/lang/String;

    .line 507
    .line 508
    move-object/from16 v16, v1

    .line 509
    .line 510
    move-object v1, v0

    .line 511
    move-object/from16 v0, v16

    .line 512
    .line 513
    :cond_19
    iput-object v7, v3, Lve0/q;->g:Lyy0/j;

    .line 514
    .line 515
    iput v4, v3, Lve0/q;->h:I

    .line 516
    .line 517
    iput v14, v3, Lve0/q;->e:I

    .line 518
    .line 519
    invoke-interface {v1, v0, v3}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 520
    .line 521
    .line 522
    move-result-object v0

    .line 523
    if-ne v0, v2, :cond_1a

    .line 524
    .line 525
    :goto_c
    move-object v12, v2

    .line 526
    :cond_1a
    :goto_d
    return-object v12

    .line 527
    :pswitch_2
    move-object v0, v1

    .line 528
    check-cast v0, Ljava/lang/Boolean;

    .line 529
    .line 530
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 531
    .line 532
    .line 533
    move-result v0

    .line 534
    check-cast v9, Le2/w0;

    .line 535
    .line 536
    check-cast v13, Lt1/p0;

    .line 537
    .line 538
    if-eqz v0, :cond_1b

    .line 539
    .line 540
    invoke-virtual {v13}, Lt1/p0;->b()Z

    .line 541
    .line 542
    .line 543
    move-result v0

    .line 544
    if-eqz v0, :cond_1b

    .line 545
    .line 546
    check-cast v10, Ll4/w;

    .line 547
    .line 548
    invoke-virtual {v9}, Le2/w0;->m()Ll4/v;

    .line 549
    .line 550
    .line 551
    move-result-object v0

    .line 552
    check-cast v8, Ll4/j;

    .line 553
    .line 554
    iget-object v1, v9, Le2/w0;->b:Ll4/p;

    .line 555
    .line 556
    invoke-static {v10, v13, v0, v8, v1}, Lt1/l0;->x(Ll4/w;Lt1/p0;Ll4/v;Ll4/j;Ll4/p;)V

    .line 557
    .line 558
    .line 559
    goto :goto_e

    .line 560
    :cond_1b
    invoke-static {v13}, Lt1/l0;->p(Lt1/p0;)V

    .line 561
    .line 562
    .line 563
    :goto_e
    return-object v12

    .line 564
    :pswitch_3
    check-cast v1, [I

    .line 565
    .line 566
    invoke-virtual {v0, v1, v2}, Le1/b0;->b([ILkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 567
    .line 568
    .line 569
    move-result-object v0

    .line 570
    return-object v0

    .line 571
    :pswitch_4
    move-object v0, v1

    .line 572
    check-cast v0, Ljava/lang/Number;

    .line 573
    .line 574
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 575
    .line 576
    .line 577
    check-cast v13, Lm1/t;

    .line 578
    .line 579
    iget-object v0, v13, Lm1/t;->e:Lm1/o;

    .line 580
    .line 581
    iget-object v0, v0, Lm1/o;->b:Ll2/g1;

    .line 582
    .line 583
    invoke-virtual {v0}, Ll2/g1;->o()I

    .line 584
    .line 585
    .line 586
    move-result v0

    .line 587
    div-int/lit8 v0, v0, 0xc

    .line 588
    .line 589
    iget-object v1, v13, Lm1/t;->e:Lm1/o;

    .line 590
    .line 591
    iget-object v1, v1, Lm1/o;->b:Ll2/g1;

    .line 592
    .line 593
    invoke-virtual {v1}, Ll2/g1;->o()I

    .line 594
    .line 595
    .line 596
    move-result v1

    .line 597
    rem-int/lit8 v1, v1, 0xc

    .line 598
    .line 599
    add-int/2addr v1, v11

    .line 600
    check-cast v10, Lay0/k;

    .line 601
    .line 602
    check-cast v9, Li2/z;

    .line 603
    .line 604
    check-cast v8, Lgy0/j;

    .line 605
    .line 606
    iget v2, v8, Lgy0/h;->d:I

    .line 607
    .line 608
    add-int/2addr v2, v0

    .line 609
    check-cast v9, Li2/b0;

    .line 610
    .line 611
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 612
    .line 613
    .line 614
    invoke-static {v2, v1, v11}, Ljava/time/LocalDate;->of(III)Ljava/time/LocalDate;

    .line 615
    .line 616
    .line 617
    move-result-object v0

    .line 618
    invoke-virtual {v9, v0}, Li2/b0;->e(Ljava/time/LocalDate;)Li2/c0;

    .line 619
    .line 620
    .line 621
    move-result-object v0

    .line 622
    iget-wide v0, v0, Li2/c0;->e:J

    .line 623
    .line 624
    new-instance v2, Ljava/lang/Long;

    .line 625
    .line 626
    invoke-direct {v2, v0, v1}, Ljava/lang/Long;-><init>(J)V

    .line 627
    .line 628
    .line 629
    invoke-interface {v10, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 630
    .line 631
    .line 632
    return-object v12

    .line 633
    :pswitch_5
    move-object v0, v1

    .line 634
    check-cast v0, Li1/k;

    .line 635
    .line 636
    check-cast v9, Lkotlin/jvm/internal/d0;

    .line 637
    .line 638
    check-cast v10, Lkotlin/jvm/internal/d0;

    .line 639
    .line 640
    check-cast v13, Lkotlin/jvm/internal/d0;

    .line 641
    .line 642
    instance-of v1, v0, Li1/n;

    .line 643
    .line 644
    if-eqz v1, :cond_1c

    .line 645
    .line 646
    iget v0, v13, Lkotlin/jvm/internal/d0;->d:I

    .line 647
    .line 648
    add-int/2addr v0, v11

    .line 649
    iput v0, v13, Lkotlin/jvm/internal/d0;->d:I

    .line 650
    .line 651
    goto :goto_f

    .line 652
    :cond_1c
    instance-of v1, v0, Li1/o;

    .line 653
    .line 654
    if-eqz v1, :cond_1d

    .line 655
    .line 656
    iget v0, v13, Lkotlin/jvm/internal/d0;->d:I

    .line 657
    .line 658
    add-int/lit8 v0, v0, -0x1

    .line 659
    .line 660
    iput v0, v13, Lkotlin/jvm/internal/d0;->d:I

    .line 661
    .line 662
    goto :goto_f

    .line 663
    :cond_1d
    instance-of v1, v0, Li1/m;

    .line 664
    .line 665
    if-eqz v1, :cond_1e

    .line 666
    .line 667
    iget v0, v13, Lkotlin/jvm/internal/d0;->d:I

    .line 668
    .line 669
    add-int/lit8 v0, v0, -0x1

    .line 670
    .line 671
    iput v0, v13, Lkotlin/jvm/internal/d0;->d:I

    .line 672
    .line 673
    goto :goto_f

    .line 674
    :cond_1e
    instance-of v1, v0, Li1/i;

    .line 675
    .line 676
    if-eqz v1, :cond_1f

    .line 677
    .line 678
    iget v0, v10, Lkotlin/jvm/internal/d0;->d:I

    .line 679
    .line 680
    add-int/2addr v0, v11

    .line 681
    iput v0, v10, Lkotlin/jvm/internal/d0;->d:I

    .line 682
    .line 683
    goto :goto_f

    .line 684
    :cond_1f
    instance-of v1, v0, Li1/j;

    .line 685
    .line 686
    if-eqz v1, :cond_20

    .line 687
    .line 688
    iget v0, v10, Lkotlin/jvm/internal/d0;->d:I

    .line 689
    .line 690
    add-int/lit8 v0, v0, -0x1

    .line 691
    .line 692
    iput v0, v10, Lkotlin/jvm/internal/d0;->d:I

    .line 693
    .line 694
    goto :goto_f

    .line 695
    :cond_20
    instance-of v1, v0, Li1/e;

    .line 696
    .line 697
    if-eqz v1, :cond_21

    .line 698
    .line 699
    iget v0, v9, Lkotlin/jvm/internal/d0;->d:I

    .line 700
    .line 701
    add-int/2addr v0, v11

    .line 702
    iput v0, v9, Lkotlin/jvm/internal/d0;->d:I

    .line 703
    .line 704
    goto :goto_f

    .line 705
    :cond_21
    instance-of v0, v0, Li1/f;

    .line 706
    .line 707
    if-eqz v0, :cond_22

    .line 708
    .line 709
    iget v0, v9, Lkotlin/jvm/internal/d0;->d:I

    .line 710
    .line 711
    add-int/lit8 v0, v0, -0x1

    .line 712
    .line 713
    iput v0, v9, Lkotlin/jvm/internal/d0;->d:I

    .line 714
    .line 715
    :cond_22
    :goto_f
    iget v0, v13, Lkotlin/jvm/internal/d0;->d:I

    .line 716
    .line 717
    if-lez v0, :cond_23

    .line 718
    .line 719
    move v0, v11

    .line 720
    goto :goto_10

    .line 721
    :cond_23
    move v0, v4

    .line 722
    :goto_10
    iget v1, v10, Lkotlin/jvm/internal/d0;->d:I

    .line 723
    .line 724
    if-lez v1, :cond_24

    .line 725
    .line 726
    move v1, v11

    .line 727
    goto :goto_11

    .line 728
    :cond_24
    move v1, v4

    .line 729
    :goto_11
    iget v2, v9, Lkotlin/jvm/internal/d0;->d:I

    .line 730
    .line 731
    if-lez v2, :cond_25

    .line 732
    .line 733
    move v2, v11

    .line 734
    goto :goto_12

    .line 735
    :cond_25
    move v2, v4

    .line 736
    :goto_12
    check-cast v8, Le1/c0;

    .line 737
    .line 738
    iget-boolean v3, v8, Le1/c0;->s:Z

    .line 739
    .line 740
    if-eq v3, v0, :cond_26

    .line 741
    .line 742
    iput-boolean v0, v8, Le1/c0;->s:Z

    .line 743
    .line 744
    move v4, v11

    .line 745
    :cond_26
    iget-boolean v0, v8, Le1/c0;->t:Z

    .line 746
    .line 747
    if-eq v0, v1, :cond_27

    .line 748
    .line 749
    iput-boolean v1, v8, Le1/c0;->t:Z

    .line 750
    .line 751
    move v4, v11

    .line 752
    :cond_27
    iget-boolean v0, v8, Le1/c0;->u:Z

    .line 753
    .line 754
    if-eq v0, v2, :cond_28

    .line 755
    .line 756
    iput-boolean v2, v8, Le1/c0;->u:Z

    .line 757
    .line 758
    goto :goto_13

    .line 759
    :cond_28
    move v11, v4

    .line 760
    :goto_13
    if-eqz v11, :cond_29

    .line 761
    .line 762
    invoke-static {v8}, Lv3/f;->m(Lv3/p;)V

    .line 763
    .line 764
    .line 765
    :cond_29
    return-object v12

    .line 766
    nop

    .line 767
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
