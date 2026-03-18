.class public final Lrh/u;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Z

.field public final e:Lr40/b;

.field public final f:Lxg/b;

.field public final g:Ljd/b;

.field public final h:Lyy0/c2;

.field public final i:Lyy0/l1;


# direct methods
.method public constructor <init>(ZLr40/b;Lxg/b;Ljd/b;)V
    .locals 8

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lrh/u;->d:Z

    .line 5
    .line 6
    iput-object p2, p0, Lrh/u;->e:Lr40/b;

    .line 7
    .line 8
    iput-object p3, p0, Lrh/u;->f:Lxg/b;

    .line 9
    .line 10
    iput-object p4, p0, Lrh/u;->g:Ljd/b;

    .line 11
    .line 12
    new-instance v0, Lrh/v;

    .line 13
    .line 14
    if-eqz p1, :cond_0

    .line 15
    .line 16
    sget-object p1, Lrh/g;->a:Lrh/g;

    .line 17
    .line 18
    :goto_0
    move-object v5, p1

    .line 19
    goto :goto_1

    .line 20
    :cond_0
    sget-object p1, Lrh/f;->a:Lrh/f;

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :goto_1
    const/4 v3, 0x0

    .line 24
    const/4 v6, 0x0

    .line 25
    const/4 v1, 0x0

    .line 26
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 27
    .line 28
    const/4 v4, 0x0

    .line 29
    const/4 v7, 0x0

    .line 30
    invoke-direct/range {v0 .. v7}, Lrh/v;-><init>(ZLjava/util/List;ZLlc/l;Lrh/h;ZLjava/lang/String;)V

    .line 31
    .line 32
    .line 33
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    iput-object p1, p0, Lrh/u;->h:Lyy0/c2;

    .line 38
    .line 39
    new-instance p2, Lag/r;

    .line 40
    .line 41
    const/16 p3, 0xc

    .line 42
    .line 43
    invoke-direct {p2, p1, p3}, Lag/r;-><init>(Lyy0/c2;I)V

    .line 44
    .line 45
    .line 46
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 47
    .line 48
    .line 49
    move-result-object p3

    .line 50
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    check-cast p1, Lrh/v;

    .line 55
    .line 56
    invoke-static {p1}, Lkp/g0;->b(Lrh/v;)Lrh/s;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    sget-object p4, Lyy0/u1;->a:Lyy0/w1;

    .line 61
    .line 62
    invoke-static {p2, p3, p4, p1}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    iput-object p1, p0, Lrh/u;->i:Lyy0/l1;

    .line 67
    .line 68
    return-void
.end method


# virtual methods
.method public final a(Lrh/d;)Z
    .locals 2

    .line 1
    new-instance v0, Lxg/a;

    .line 2
    .line 3
    iget-object v1, p1, Lrh/d;->e:Ljava/lang/String;

    .line 4
    .line 5
    iget-object p1, p1, Lrh/d;->b:Ljava/lang/String;

    .line 6
    .line 7
    invoke-direct {v0, v1, p1}, Lxg/a;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lrh/u;->f:Lxg/b;

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Lxg/b;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    check-cast p0, Llx0/o;

    .line 17
    .line 18
    iget-object p0, p0, Llx0/o;->d:Ljava/lang/Object;

    .line 19
    .line 20
    instance-of p0, p0, Llx0/n;

    .line 21
    .line 22
    xor-int/lit8 p0, p0, 0x1

    .line 23
    .line 24
    return p0
.end method

.method public final b()Lvy0/x1;
    .locals 4

    .line 1
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Ln00/f;

    .line 6
    .line 7
    const/16 v2, 0x1d

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    invoke-direct {v1, p0, v3, v2}, Ln00/f;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 11
    .line 12
    .line 13
    const/4 p0, 0x3

    .line 14
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method

.method public final d(Lrh/r;)V
    .locals 11

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lrh/j;->a:Lrh/j;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    const-string v1, "<this>"

    .line 13
    .line 14
    iget-object v2, p0, Lrh/u;->h:Lyy0/c2;

    .line 15
    .line 16
    if-eqz v0, :cond_2

    .line 17
    .line 18
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    check-cast p1, Lrh/v;

    .line 23
    .line 24
    iget-object p1, p1, Lrh/v;->e:Lrh/h;

    .line 25
    .line 26
    instance-of p1, p1, Lrh/f;

    .line 27
    .line 28
    iget-boolean p0, p0, Lrh/u;->d:Z

    .line 29
    .line 30
    or-int/2addr p0, p1

    .line 31
    if-eqz p0, :cond_1

    .line 32
    .line 33
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    :cond_0
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    move-object v3, p0

    .line 41
    check-cast v3, Lrh/v;

    .line 42
    .line 43
    const/4 v9, 0x0

    .line 44
    const/16 v10, 0x5f

    .line 45
    .line 46
    const/4 v4, 0x0

    .line 47
    const/4 v5, 0x0

    .line 48
    const/4 v6, 0x0

    .line 49
    const/4 v7, 0x0

    .line 50
    const/4 v8, 0x0

    .line 51
    invoke-static/range {v3 .. v10}, Lrh/v;->a(Lrh/v;ZLjava/util/ArrayList;ZLlc/l;Lrh/h;Ljava/lang/String;I)Lrh/v;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    invoke-virtual {v2, p0, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result p0

    .line 59
    if-eqz p0, :cond_0

    .line 60
    .line 61
    goto/16 :goto_2

    .line 62
    .line 63
    :cond_1
    invoke-static {v2}, Lkp/h0;->f(Lyy0/c2;)V

    .line 64
    .line 65
    .line 66
    return-void

    .line 67
    :cond_2
    sget-object v0, Lrh/l;->a:Lrh/l;

    .line 68
    .line 69
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    if-eqz v0, :cond_6

    .line 74
    .line 75
    new-instance v3, Lc00/d;

    .line 76
    .line 77
    const/16 v9, 0x8

    .line 78
    .line 79
    const/16 v10, 0x13

    .line 80
    .line 81
    const/4 v4, 0x0

    .line 82
    const-class v6, Lrh/u;

    .line 83
    .line 84
    const-string v7, "dispatchPairWallbox"

    .line 85
    .line 86
    const-string v8, "dispatchPairWallbox()Lkotlinx/coroutines/Job;"

    .line 87
    .line 88
    move-object v5, p0

    .line 89
    invoke-direct/range {v3 .. v10}, Lc00/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 90
    .line 91
    .line 92
    new-instance p0, Lrh/i;

    .line 93
    .line 94
    const/4 p1, 0x1

    .line 95
    invoke-direct {p0, v5, p1}, Lrh/i;-><init>(Lrh/u;I)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object p1

    .line 102
    check-cast p1, Lrh/v;

    .line 103
    .line 104
    iget-object p1, p1, Lrh/v;->b:Ljava/util/List;

    .line 105
    .line 106
    check-cast p1, Ljava/lang/Iterable;

    .line 107
    .line 108
    instance-of v0, p1, Ljava/util/Collection;

    .line 109
    .line 110
    if-eqz v0, :cond_3

    .line 111
    .line 112
    move-object v0, p1

    .line 113
    check-cast v0, Ljava/util/Collection;

    .line 114
    .line 115
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 116
    .line 117
    .line 118
    move-result v0

    .line 119
    if-eqz v0, :cond_3

    .line 120
    .line 121
    goto :goto_0

    .line 122
    :cond_3
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 123
    .line 124
    .line 125
    move-result-object p1

    .line 126
    :cond_4
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 127
    .line 128
    .line 129
    move-result v0

    .line 130
    if-eqz v0, :cond_5

    .line 131
    .line 132
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v0

    .line 136
    check-cast v0, Lrh/d;

    .line 137
    .line 138
    invoke-virtual {v5, v0}, Lrh/u;->a(Lrh/d;)Z

    .line 139
    .line 140
    .line 141
    move-result v0

    .line 142
    if-nez v0, :cond_4

    .line 143
    .line 144
    invoke-virtual {p0}, Lrh/i;->invoke()Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    return-void

    .line 148
    :cond_5
    :goto_0
    invoke-virtual {v3}, Lc00/d;->invoke()Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    return-void

    .line 152
    :cond_6
    move-object v5, p0

    .line 153
    sget-object p0, Lrh/p;->a:Lrh/p;

    .line 154
    .line 155
    invoke-virtual {p1, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    move-result p0

    .line 159
    if-eqz p0, :cond_7

    .line 160
    .line 161
    invoke-virtual {v5}, Lrh/u;->b()Lvy0/x1;

    .line 162
    .line 163
    .line 164
    return-void

    .line 165
    :cond_7
    sget-object p0, Lrh/q;->a:Lrh/q;

    .line 166
    .line 167
    invoke-virtual {p1, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 168
    .line 169
    .line 170
    move-result p0

    .line 171
    if-eqz p0, :cond_9

    .line 172
    .line 173
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    :cond_8
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object p0

    .line 180
    move-object v3, p0

    .line 181
    check-cast v3, Lrh/v;

    .line 182
    .line 183
    const/4 v9, 0x0

    .line 184
    const/16 v10, 0x6f

    .line 185
    .line 186
    const/4 v4, 0x0

    .line 187
    const/4 v5, 0x0

    .line 188
    const/4 v6, 0x0

    .line 189
    const/4 v7, 0x0

    .line 190
    sget-object v8, Lrh/g;->a:Lrh/g;

    .line 191
    .line 192
    invoke-static/range {v3 .. v10}, Lrh/v;->a(Lrh/v;ZLjava/util/ArrayList;ZLlc/l;Lrh/h;Ljava/lang/String;I)Lrh/v;

    .line 193
    .line 194
    .line 195
    move-result-object p1

    .line 196
    invoke-virtual {v2, p0, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 197
    .line 198
    .line 199
    move-result p0

    .line 200
    if-eqz p0, :cond_8

    .line 201
    .line 202
    goto/16 :goto_2

    .line 203
    .line 204
    :cond_9
    sget-object p0, Lrh/m;->a:Lrh/m;

    .line 205
    .line 206
    invoke-virtual {p1, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 207
    .line 208
    .line 209
    move-result p0

    .line 210
    if-eqz p0, :cond_a

    .line 211
    .line 212
    invoke-static {v2}, Lkp/h0;->f(Lyy0/c2;)V

    .line 213
    .line 214
    .line 215
    return-void

    .line 216
    :cond_a
    sget-object p0, Lrh/k;->a:Lrh/k;

    .line 217
    .line 218
    invoke-virtual {p1, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 219
    .line 220
    .line 221
    move-result p0

    .line 222
    if-eqz p0, :cond_c

    .line 223
    .line 224
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 225
    .line 226
    .line 227
    :cond_b
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 228
    .line 229
    .line 230
    move-result-object p0

    .line 231
    move-object v3, p0

    .line 232
    check-cast v3, Lrh/v;

    .line 233
    .line 234
    const/4 v9, 0x0

    .line 235
    const/16 v10, 0x77

    .line 236
    .line 237
    const/4 v4, 0x0

    .line 238
    const/4 v5, 0x0

    .line 239
    const/4 v6, 0x0

    .line 240
    const/4 v7, 0x0

    .line 241
    const/4 v8, 0x0

    .line 242
    invoke-static/range {v3 .. v10}, Lrh/v;->a(Lrh/v;ZLjava/util/ArrayList;ZLlc/l;Lrh/h;Ljava/lang/String;I)Lrh/v;

    .line 243
    .line 244
    .line 245
    move-result-object p1

    .line 246
    invoke-virtual {v2, p0, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 247
    .line 248
    .line 249
    move-result p0

    .line 250
    if-eqz p0, :cond_b

    .line 251
    .line 252
    goto/16 :goto_2

    .line 253
    .line 254
    :cond_c
    instance-of p0, p1, Lrh/n;

    .line 255
    .line 256
    if-eqz p0, :cond_d

    .line 257
    .line 258
    check-cast p1, Lrh/n;

    .line 259
    .line 260
    iget-object p0, p1, Lrh/n;->a:Ljava/lang/String;

    .line 261
    .line 262
    iget-object p1, p1, Lrh/n;->b:Ljava/lang/String;

    .line 263
    .line 264
    invoke-static {v2, p0, p1}, Lkp/h0;->e(Lyy0/c2;Ljava/lang/String;Ljava/lang/String;)V

    .line 265
    .line 266
    .line 267
    return-void

    .line 268
    :cond_d
    instance-of p0, p1, Lrh/o;

    .line 269
    .line 270
    if-eqz p0, :cond_13

    .line 271
    .line 272
    check-cast p1, Lrh/o;

    .line 273
    .line 274
    iget-object p0, p1, Lrh/o;->a:Ljava/util/List;

    .line 275
    .line 276
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    move-result-object p1

    .line 280
    check-cast p1, Lrh/v;

    .line 281
    .line 282
    iget-object p1, p1, Lrh/v;->b:Ljava/util/List;

    .line 283
    .line 284
    check-cast p1, Ljava/lang/Iterable;

    .line 285
    .line 286
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 287
    .line 288
    .line 289
    move-result-object p1

    .line 290
    :cond_e
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 291
    .line 292
    .line 293
    move-result v0

    .line 294
    if-eqz v0, :cond_f

    .line 295
    .line 296
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    move-result-object v0

    .line 300
    move-object v3, v0

    .line 301
    check-cast v3, Lrh/d;

    .line 302
    .line 303
    iget-object v3, v3, Lrh/d;->h:Lrh/c;

    .line 304
    .line 305
    sget-object v4, Lrh/b;->a:Lrh/b;

    .line 306
    .line 307
    invoke-virtual {v3, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 308
    .line 309
    .line 310
    move-result v3

    .line 311
    if-eqz v3, :cond_e

    .line 312
    .line 313
    goto :goto_1

    .line 314
    :cond_f
    const/4 v0, 0x0

    .line 315
    :goto_1
    check-cast v0, Lrh/d;

    .line 316
    .line 317
    if-eqz v0, :cond_12

    .line 318
    .line 319
    invoke-static {p0}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 320
    .line 321
    .line 322
    move-result-object p1

    .line 323
    check-cast p1, Ljava/lang/String;

    .line 324
    .line 325
    const/4 v3, 0x0

    .line 326
    const/16 v4, 0xfd

    .line 327
    .line 328
    invoke-static {v0, p1, v3, v4}, Lrh/d;->a(Lrh/d;Ljava/lang/String;ZI)Lrh/d;

    .line 329
    .line 330
    .line 331
    move-result-object p1

    .line 332
    invoke-virtual {v5, p1}, Lrh/u;->a(Lrh/d;)Z

    .line 333
    .line 334
    .line 335
    move-result v0

    .line 336
    if-eqz v0, :cond_10

    .line 337
    .line 338
    iget-object p1, p1, Lrh/d;->a:Ljava/lang/String;

    .line 339
    .line 340
    invoke-static {p0}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 341
    .line 342
    .line 343
    move-result-object p0

    .line 344
    check-cast p0, Ljava/lang/String;

    .line 345
    .line 346
    invoke-static {v2, p1, p0}, Lkp/h0;->e(Lyy0/c2;Ljava/lang/String;Ljava/lang/String;)V

    .line 347
    .line 348
    .line 349
    invoke-virtual {v5}, Lrh/u;->b()Lvy0/x1;

    .line 350
    .line 351
    .line 352
    return-void

    .line 353
    :cond_10
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 354
    .line 355
    .line 356
    :cond_11
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 357
    .line 358
    .line 359
    move-result-object p0

    .line 360
    move-object v3, p0

    .line 361
    check-cast v3, Lrh/v;

    .line 362
    .line 363
    const/4 v9, 0x0

    .line 364
    const/16 v10, 0x6f

    .line 365
    .line 366
    const/4 v4, 0x0

    .line 367
    const/4 v5, 0x0

    .line 368
    const/4 v6, 0x0

    .line 369
    const/4 v7, 0x0

    .line 370
    sget-object v8, Lrh/e;->a:Lrh/e;

    .line 371
    .line 372
    invoke-static/range {v3 .. v10}, Lrh/v;->a(Lrh/v;ZLjava/util/ArrayList;ZLlc/l;Lrh/h;Ljava/lang/String;I)Lrh/v;

    .line 373
    .line 374
    .line 375
    move-result-object p1

    .line 376
    invoke-virtual {v2, p0, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 377
    .line 378
    .line 379
    move-result p0

    .line 380
    if-eqz p0, :cond_11

    .line 381
    .line 382
    :cond_12
    :goto_2
    return-void

    .line 383
    :cond_13
    new-instance p0, La8/r0;

    .line 384
    .line 385
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 386
    .line 387
    .line 388
    throw p0
.end method
