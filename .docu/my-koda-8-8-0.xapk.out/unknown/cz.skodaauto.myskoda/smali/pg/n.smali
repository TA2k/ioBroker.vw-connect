.class public final Lpg/n;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lmg/b;

.field public final e:Lkotlin/jvm/internal/k;

.field public final f:Lxh/e;

.field public final g:Lkotlin/jvm/internal/k;

.field public final h:Lyj/b;

.field public final i:Lay0/a;

.field public final j:Lay0/a;

.field public final k:Lxh/e;

.field public final l:Lh2/d6;

.field public final m:Z

.field public final n:Lpg/e;

.field public o:Lug/a;

.field public final p:Lyy0/c2;

.field public final q:Lyy0/c2;


# direct methods
.method public constructor <init>(Lmg/b;Lay0/a;Lxh/e;Lay0/n;Lyj/b;Lay0/a;Lay0/a;Lxh/e;Lh2/d6;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lpg/n;->d:Lmg/b;

    .line 5
    .line 6
    check-cast p2, Lkotlin/jvm/internal/k;

    .line 7
    .line 8
    iput-object p2, p0, Lpg/n;->e:Lkotlin/jvm/internal/k;

    .line 9
    .line 10
    iput-object p3, p0, Lpg/n;->f:Lxh/e;

    .line 11
    .line 12
    check-cast p4, Lkotlin/jvm/internal/k;

    .line 13
    .line 14
    iput-object p4, p0, Lpg/n;->g:Lkotlin/jvm/internal/k;

    .line 15
    .line 16
    iput-object p5, p0, Lpg/n;->h:Lyj/b;

    .line 17
    .line 18
    iput-object p6, p0, Lpg/n;->i:Lay0/a;

    .line 19
    .line 20
    iput-object p7, p0, Lpg/n;->j:Lay0/a;

    .line 21
    .line 22
    iput-object p8, p0, Lpg/n;->k:Lxh/e;

    .line 23
    .line 24
    iput-object p9, p0, Lpg/n;->l:Lh2/d6;

    .line 25
    .line 26
    iput-boolean p10, p0, Lpg/n;->m:Z

    .line 27
    .line 28
    sget-object p2, Lpg/e;->a:Lpg/e;

    .line 29
    .line 30
    iput-object p2, p0, Lpg/n;->n:Lpg/e;

    .line 31
    .line 32
    invoke-static {p1, p10}, Lpg/e;->a(Lmg/b;Z)Lpg/l;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    new-instance p2, Llc/q;

    .line 37
    .line 38
    invoke-direct {p2, p1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    iput-object p1, p0, Lpg/n;->p:Lyy0/c2;

    .line 46
    .line 47
    iput-object p1, p0, Lpg/n;->q:Lyy0/c2;

    .line 48
    .line 49
    return-void
.end method


# virtual methods
.method public final a(Lkg/j0;)V
    .locals 4

    .line 1
    new-instance v0, Llc/q;

    .line 2
    .line 3
    sget-object v1, Llc/a;->c:Llc/c;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lpg/n;->p:Lyy0/c2;

    .line 9
    .line 10
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    invoke-virtual {v1, v2, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    new-instance v1, Lna/e;

    .line 22
    .line 23
    const/16 v3, 0xf

    .line 24
    .line 25
    invoke-direct {v1, v3, p0, p1, v2}, Lna/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 26
    .line 27
    .line 28
    const/4 p0, 0x3

    .line 29
    invoke-static {v0, v2, v2, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 30
    .line 31
    .line 32
    return-void
.end method

.method public final b(Lpg/k;)V
    .locals 11

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lpg/g;->f:Lpg/g;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    const/4 v1, 0x0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-virtual {p0, v1}, Lpg/n;->a(Lkg/j0;)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    sget-object v0, Lpg/g;->i:Lpg/g;

    .line 20
    .line 21
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_1

    .line 26
    .line 27
    sget-object p1, Lkg/j0;->e:Lkg/j0;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Lpg/n;->a(Lkg/j0;)V

    .line 30
    .line 31
    .line 32
    return-void

    .line 33
    :cond_1
    sget-object v0, Lpg/g;->d:Lpg/g;

    .line 34
    .line 35
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    if-eqz v0, :cond_2

    .line 40
    .line 41
    sget-object p1, Lkg/j0;->f:Lkg/j0;

    .line 42
    .line 43
    invoke-virtual {p0, p1}, Lpg/n;->a(Lkg/j0;)V

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :cond_2
    sget-object v0, Lpg/g;->h:Lpg/g;

    .line 48
    .line 49
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    if-eqz v0, :cond_4

    .line 54
    .line 55
    iget-object p1, p0, Lpg/n;->o:Lug/a;

    .line 56
    .line 57
    sget-object v0, Lug/a;->d:Lug/a;

    .line 58
    .line 59
    if-ne p1, v0, :cond_3

    .line 60
    .line 61
    sget-object p1, Lkg/j0;->e:Lkg/j0;

    .line 62
    .line 63
    invoke-virtual {p0, p1}, Lpg/n;->a(Lkg/j0;)V

    .line 64
    .line 65
    .line 66
    :cond_3
    iget-object p1, p0, Lpg/n;->o:Lug/a;

    .line 67
    .line 68
    sget-object v0, Lug/a;->e:Lug/a;

    .line 69
    .line 70
    if-ne p1, v0, :cond_a

    .line 71
    .line 72
    sget-object p1, Lkg/j0;->f:Lkg/j0;

    .line 73
    .line 74
    invoke-virtual {p0, p1}, Lpg/n;->a(Lkg/j0;)V

    .line 75
    .line 76
    .line 77
    return-void

    .line 78
    :cond_4
    instance-of v0, p1, Lpg/h;

    .line 79
    .line 80
    iget-object v2, p0, Lpg/n;->h:Lyj/b;

    .line 81
    .line 82
    iget-object v3, p0, Lpg/n;->p:Lyy0/c2;

    .line 83
    .line 84
    iget-object v4, p0, Lpg/n;->d:Lmg/b;

    .line 85
    .line 86
    if-eqz v0, :cond_6

    .line 87
    .line 88
    check-cast p1, Lpg/h;

    .line 89
    .line 90
    iget-object p1, p1, Lpg/h;->a:Llc/b;

    .line 91
    .line 92
    sget-object v0, Llc/b;->g:Llc/b;

    .line 93
    .line 94
    if-ne p1, v0, :cond_5

    .line 95
    .line 96
    invoke-virtual {v2}, Lyj/b;->invoke()Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    return-void

    .line 100
    :cond_5
    iget-object p1, p0, Lpg/n;->n:Lpg/e;

    .line 101
    .line 102
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 103
    .line 104
    .line 105
    iget-boolean p0, p0, Lpg/n;->m:Z

    .line 106
    .line 107
    invoke-static {v4, p0}, Lpg/e;->a(Lmg/b;Z)Lpg/l;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    new-instance p1, Llc/q;

    .line 112
    .line 113
    invoke-direct {p1, p0}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 117
    .line 118
    .line 119
    invoke-virtual {v3, v1, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    return-void

    .line 123
    :cond_6
    sget-object v0, Lpg/g;->g:Lpg/g;

    .line 124
    .line 125
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    move-result v0

    .line 129
    iget-object v5, p0, Lpg/n;->q:Lyy0/c2;

    .line 130
    .line 131
    if-eqz v0, :cond_7

    .line 132
    .line 133
    invoke-virtual {v5}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    check-cast p0, Llc/q;

    .line 138
    .line 139
    new-instance p1, Lp81/c;

    .line 140
    .line 141
    const/16 v0, 0x8

    .line 142
    .line 143
    invoke-direct {p1, v0}, Lp81/c;-><init>(I)V

    .line 144
    .line 145
    .line 146
    invoke-static {p0, p1}, Llc/a;->b(Llc/q;Lay0/k;)Llc/q;

    .line 147
    .line 148
    .line 149
    move-result-object p0

    .line 150
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 151
    .line 152
    .line 153
    invoke-virtual {v3, v1, p0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 154
    .line 155
    .line 156
    return-void

    .line 157
    :cond_7
    instance-of v0, p1, Lpg/f;

    .line 158
    .line 159
    if-eqz v0, :cond_b

    .line 160
    .line 161
    check-cast p1, Lpg/f;

    .line 162
    .line 163
    iget-object p1, p1, Lpg/f;->a:Ljava/lang/String;

    .line 164
    .line 165
    iget-object v0, v4, Lmg/b;->a:Ljava/util/List;

    .line 166
    .line 167
    check-cast v0, Ljava/lang/Iterable;

    .line 168
    .line 169
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 170
    .line 171
    .line 172
    move-result-object v0

    .line 173
    :cond_8
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 174
    .line 175
    .line 176
    move-result v2

    .line 177
    if-eqz v2, :cond_9

    .line 178
    .line 179
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object v2

    .line 183
    move-object v3, v2

    .line 184
    check-cast v3, Ldc/w;

    .line 185
    .line 186
    iget-object v3, v3, Ldc/w;->d:Ljava/lang/String;

    .line 187
    .line 188
    const/4 v4, 0x0

    .line 189
    invoke-static {p1, v3, v4}, Lly0/p;->A(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    .line 190
    .line 191
    .line 192
    move-result v3

    .line 193
    if-eqz v3, :cond_8

    .line 194
    .line 195
    move-object v1, v2

    .line 196
    :cond_9
    check-cast v1, Ldc/w;

    .line 197
    .line 198
    if-eqz v1, :cond_a

    .line 199
    .line 200
    iget-object p1, v1, Ldc/w;->f:Ljava/util/List;

    .line 201
    .line 202
    invoke-static {p1}, Lic/s;->a(Ljava/util/List;)Lhc/a;

    .line 203
    .line 204
    .line 205
    move-result-object p1

    .line 206
    iget-object p0, p0, Lpg/n;->f:Lxh/e;

    .line 207
    .line 208
    invoke-virtual {p0, p1}, Lxh/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    :cond_a
    return-void

    .line 212
    :cond_b
    sget-object v0, Lpg/g;->c:Lpg/g;

    .line 213
    .line 214
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 215
    .line 216
    .line 217
    move-result v0

    .line 218
    if-eqz v0, :cond_c

    .line 219
    .line 220
    invoke-virtual {v2}, Lyj/b;->invoke()Ljava/lang/Object;

    .line 221
    .line 222
    .line 223
    return-void

    .line 224
    :cond_c
    sget-object v0, Lpg/g;->a:Lpg/g;

    .line 225
    .line 226
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 227
    .line 228
    .line 229
    move-result v0

    .line 230
    if-eqz v0, :cond_d

    .line 231
    .line 232
    iget-object p0, p0, Lpg/n;->i:Lay0/a;

    .line 233
    .line 234
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 235
    .line 236
    .line 237
    return-void

    .line 238
    :cond_d
    sget-object v0, Lpg/g;->b:Lpg/g;

    .line 239
    .line 240
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 241
    .line 242
    .line 243
    move-result v0

    .line 244
    if-eqz v0, :cond_e

    .line 245
    .line 246
    iget-object p0, p0, Lpg/n;->j:Lay0/a;

    .line 247
    .line 248
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 249
    .line 250
    .line 251
    return-void

    .line 252
    :cond_e
    sget-object v0, Lpg/g;->e:Lpg/g;

    .line 253
    .line 254
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 255
    .line 256
    .line 257
    move-result v0

    .line 258
    if-eqz v0, :cond_f

    .line 259
    .line 260
    iget-object p1, v4, Lmg/b;->b:Lkg/p0;

    .line 261
    .line 262
    iget-object p1, p1, Lkg/p0;->d:Ljava/lang/String;

    .line 263
    .line 264
    iget-object p0, p0, Lpg/n;->k:Lxh/e;

    .line 265
    .line 266
    invoke-virtual {p0, p1}, Lxh/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    return-void

    .line 270
    :cond_f
    instance-of v0, p1, Lpg/i;

    .line 271
    .line 272
    if-eqz v0, :cond_10

    .line 273
    .line 274
    check-cast p1, Lpg/i;

    .line 275
    .line 276
    iget-object v5, p1, Lpg/i;->a:Ljava/lang/String;

    .line 277
    .line 278
    iget-object p1, v4, Lmg/b;->b:Lkg/p0;

    .line 279
    .line 280
    iget-object v6, p1, Lkg/p0;->d:Ljava/lang/String;

    .line 281
    .line 282
    const/4 v9, 0x0

    .line 283
    const/16 v10, 0x10

    .line 284
    .line 285
    iget-object v7, p0, Lpg/n;->k:Lxh/e;

    .line 286
    .line 287
    iget-object v8, p0, Lpg/n;->l:Lh2/d6;

    .line 288
    .line 289
    invoke-static/range {v5 .. v10}, Lqc/a;->a(Ljava/lang/String;Ljava/lang/String;Lay0/k;Lay0/k;Lzb/s0;I)V

    .line 290
    .line 291
    .line 292
    return-void

    .line 293
    :cond_10
    instance-of v0, p1, Lpg/j;

    .line 294
    .line 295
    if-eqz v0, :cond_11

    .line 296
    .line 297
    check-cast p1, Lpg/j;

    .line 298
    .line 299
    iget-object p1, p1, Lpg/j;->a:Lug/a;

    .line 300
    .line 301
    iput-object p1, p0, Lpg/n;->o:Lug/a;

    .line 302
    .line 303
    invoke-virtual {v5}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 304
    .line 305
    .line 306
    move-result-object p1

    .line 307
    check-cast p1, Llc/q;

    .line 308
    .line 309
    new-instance v0, Lpg/m;

    .line 310
    .line 311
    const/4 v2, 0x0

    .line 312
    invoke-direct {v0, p0, v2}, Lpg/m;-><init>(Ljava/lang/Object;I)V

    .line 313
    .line 314
    .line 315
    invoke-static {p1, v0}, Llc/a;->b(Llc/q;Lay0/k;)Llc/q;

    .line 316
    .line 317
    .line 318
    move-result-object p0

    .line 319
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 320
    .line 321
    .line 322
    invoke-virtual {v3, v1, p0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 323
    .line 324
    .line 325
    return-void

    .line 326
    :cond_11
    new-instance p0, La8/r0;

    .line 327
    .line 328
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 329
    .line 330
    .line 331
    throw p0
.end method
