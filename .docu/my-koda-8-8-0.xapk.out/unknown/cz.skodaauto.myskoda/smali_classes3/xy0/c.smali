.class public final Lxy0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvy0/k2;


# instance fields
.field public d:Ljava/lang/Object;

.field public e:Lvy0/l;

.field public final synthetic f:Lxy0/j;


# direct methods
.method public constructor <init>(Lxy0/j;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxy0/c;->f:Lxy0/j;

    .line 5
    .line 6
    sget-object p1, Lxy0/l;->p:Lj51/i;

    .line 7
    .line 8
    iput-object p1, p0, Lxy0/c;->d:Ljava/lang/Object;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Lrx0/c;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget-object v0, p0, Lxy0/c;->d:Ljava/lang/Object;

    .line 2
    .line 3
    sget-object v1, Lxy0/l;->p:Lj51/i;

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    if-eq v0, v1, :cond_0

    .line 7
    .line 8
    sget-object v1, Lxy0/l;->l:Lj51/i;

    .line 9
    .line 10
    if-eq v0, v1, :cond_0

    .line 11
    .line 12
    goto/16 :goto_5

    .line 13
    .line 14
    :cond_0
    sget-object v0, Lxy0/j;->j:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 15
    .line 16
    iget-object v6, p0, Lxy0/c;->f:Lxy0/j;

    .line 17
    .line 18
    invoke-virtual {v0, v6}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    check-cast v0, Lxy0/r;

    .line 23
    .line 24
    :goto_0
    invoke-virtual {v6}, Lxy0/j;->A()Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-eqz v1, :cond_2

    .line 29
    .line 30
    sget-object v0, Lxy0/l;->l:Lj51/i;

    .line 31
    .line 32
    iput-object v0, p0, Lxy0/c;->d:Ljava/lang/Object;

    .line 33
    .line 34
    invoke-virtual {v6}, Lxy0/j;->s()Ljava/lang/Throwable;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    if-nez v0, :cond_1

    .line 39
    .line 40
    const/4 v2, 0x0

    .line 41
    goto/16 :goto_5

    .line 42
    .line 43
    :cond_1
    sget v1, Laz0/r;->a:I

    .line 44
    .line 45
    throw v0

    .line 46
    :cond_2
    sget-object v1, Lxy0/j;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 47
    .line 48
    invoke-virtual {v1, v6}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->getAndIncrement(Ljava/lang/Object;)J

    .line 49
    .line 50
    .line 51
    move-result-wide v3

    .line 52
    sget v1, Lxy0/l;->b:I

    .line 53
    .line 54
    int-to-long v7, v1

    .line 55
    div-long v9, v3, v7

    .line 56
    .line 57
    rem-long v7, v3, v7

    .line 58
    .line 59
    long-to-int v8, v7

    .line 60
    iget-wide v11, v0, Laz0/q;->f:J

    .line 61
    .line 62
    cmp-long v1, v11, v9

    .line 63
    .line 64
    if-eqz v1, :cond_3

    .line 65
    .line 66
    invoke-virtual {v6, v9, v10, v0}, Lxy0/j;->q(JLxy0/r;)Lxy0/r;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    if-nez v1, :cond_4

    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_3
    move-object v1, v0

    .line 74
    :cond_4
    const/4 v11, 0x0

    .line 75
    move-object v7, v1

    .line 76
    move-wide v9, v3

    .line 77
    invoke-virtual/range {v6 .. v11}, Lxy0/j;->L(Lxy0/r;IJLjava/lang/Object;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    sget-object v7, Lxy0/l;->m:Lj51/i;

    .line 82
    .line 83
    if-eq v0, v7, :cond_13

    .line 84
    .line 85
    sget-object v9, Lxy0/l;->o:Lj51/i;

    .line 86
    .line 87
    if-ne v0, v9, :cond_6

    .line 88
    .line 89
    invoke-virtual {v6}, Lxy0/j;->w()J

    .line 90
    .line 91
    .line 92
    move-result-wide v7

    .line 93
    cmp-long v0, v3, v7

    .line 94
    .line 95
    if-gez v0, :cond_5

    .line 96
    .line 97
    invoke-virtual {v1}, Laz0/c;->b()V

    .line 98
    .line 99
    .line 100
    :cond_5
    move-object v0, v1

    .line 101
    goto :goto_0

    .line 102
    :cond_6
    sget-object v10, Lxy0/l;->n:Lj51/i;

    .line 103
    .line 104
    if-ne v0, v10, :cond_12

    .line 105
    .line 106
    iget-object v0, p0, Lxy0/c;->f:Lxy0/j;

    .line 107
    .line 108
    invoke-static {p1}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 109
    .line 110
    .line 111
    move-result-object v2

    .line 112
    invoke-static {v2}, Lvy0/e0;->x(Lkotlin/coroutines/Continuation;)Lvy0/l;

    .line 113
    .line 114
    .line 115
    move-result-object v10

    .line 116
    :try_start_0
    iput-object v10, p0, Lxy0/c;->e:Lvy0/l;

    .line 117
    .line 118
    move-object v5, p0

    .line 119
    move v2, v8

    .line 120
    invoke-virtual/range {v0 .. v5}, Lxy0/j;->L(Lxy0/r;IJLjava/lang/Object;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v8

    .line 124
    if-ne v8, v7, :cond_7

    .line 125
    .line 126
    invoke-virtual {p0, v1, v2}, Lxy0/c;->b(Laz0/q;I)V

    .line 127
    .line 128
    .line 129
    goto/16 :goto_3

    .line 130
    .line 131
    :catchall_0
    move-exception v0

    .line 132
    goto/16 :goto_4

    .line 133
    .line 134
    :cond_7
    const/4 v7, 0x0

    .line 135
    if-ne v8, v9, :cond_11

    .line 136
    .line 137
    invoke-virtual {v0}, Lxy0/j;->w()J

    .line 138
    .line 139
    .line 140
    move-result-wide v8

    .line 141
    cmp-long v2, v3, v8

    .line 142
    .line 143
    if-gez v2, :cond_8

    .line 144
    .line 145
    invoke-virtual {v1}, Laz0/c;->b()V

    .line 146
    .line 147
    .line 148
    :cond_8
    sget-object v1, Lxy0/j;->j:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 149
    .line 150
    invoke-virtual {v1, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v1

    .line 154
    check-cast v1, Lxy0/r;

    .line 155
    .line 156
    :cond_9
    :goto_1
    invoke-virtual {v0}, Lxy0/j;->A()Z

    .line 157
    .line 158
    .line 159
    move-result v2

    .line 160
    if-eqz v2, :cond_b

    .line 161
    .line 162
    iget-object v0, p0, Lxy0/c;->e:Lvy0/l;

    .line 163
    .line 164
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 165
    .line 166
    .line 167
    iput-object v7, p0, Lxy0/c;->e:Lvy0/l;

    .line 168
    .line 169
    sget-object v1, Lxy0/l;->l:Lj51/i;

    .line 170
    .line 171
    iput-object v1, p0, Lxy0/c;->d:Ljava/lang/Object;

    .line 172
    .line 173
    invoke-virtual {v6}, Lxy0/j;->s()Ljava/lang/Throwable;

    .line 174
    .line 175
    .line 176
    move-result-object v1

    .line 177
    if-nez v1, :cond_a

    .line 178
    .line 179
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 180
    .line 181
    invoke-virtual {v0, v1}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 182
    .line 183
    .line 184
    goto :goto_3

    .line 185
    :cond_a
    invoke-static {v1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 186
    .line 187
    .line 188
    move-result-object v1

    .line 189
    invoke-virtual {v0, v1}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 190
    .line 191
    .line 192
    goto :goto_3

    .line 193
    :cond_b
    sget-object v2, Lxy0/j;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 194
    .line 195
    invoke-virtual {v2, v0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->getAndIncrement(Ljava/lang/Object;)J

    .line 196
    .line 197
    .line 198
    move-result-wide v3

    .line 199
    sget v2, Lxy0/l;->b:I

    .line 200
    .line 201
    int-to-long v8, v2

    .line 202
    div-long v11, v3, v8

    .line 203
    .line 204
    rem-long v8, v3, v8

    .line 205
    .line 206
    long-to-int v2, v8

    .line 207
    iget-wide v8, v1, Laz0/q;->f:J

    .line 208
    .line 209
    cmp-long v8, v8, v11

    .line 210
    .line 211
    if-eqz v8, :cond_d

    .line 212
    .line 213
    invoke-virtual {v0, v11, v12, v1}, Lxy0/j;->q(JLxy0/r;)Lxy0/r;

    .line 214
    .line 215
    .line 216
    move-result-object v8

    .line 217
    if-nez v8, :cond_c

    .line 218
    .line 219
    goto :goto_1

    .line 220
    :cond_c
    move-object v1, v8

    .line 221
    :cond_d
    move-object v5, p0

    .line 222
    invoke-virtual/range {v0 .. v5}, Lxy0/j;->L(Lxy0/r;IJLjava/lang/Object;)Ljava/lang/Object;

    .line 223
    .line 224
    .line 225
    move-result-object v8

    .line 226
    sget-object v9, Lxy0/l;->m:Lj51/i;

    .line 227
    .line 228
    if-ne v8, v9, :cond_e

    .line 229
    .line 230
    invoke-virtual {p0, v1, v2}, Lxy0/c;->b(Laz0/q;I)V

    .line 231
    .line 232
    .line 233
    goto :goto_3

    .line 234
    :cond_e
    sget-object v2, Lxy0/l;->o:Lj51/i;

    .line 235
    .line 236
    if-ne v8, v2, :cond_f

    .line 237
    .line 238
    invoke-virtual {v0}, Lxy0/j;->w()J

    .line 239
    .line 240
    .line 241
    move-result-wide v8

    .line 242
    cmp-long v2, v3, v8

    .line 243
    .line 244
    if-gez v2, :cond_9

    .line 245
    .line 246
    invoke-virtual {v1}, Laz0/c;->b()V

    .line 247
    .line 248
    .line 249
    goto :goto_1

    .line 250
    :cond_f
    sget-object v0, Lxy0/l;->n:Lj51/i;

    .line 251
    .line 252
    if-eq v8, v0, :cond_10

    .line 253
    .line 254
    invoke-virtual {v1}, Laz0/c;->b()V

    .line 255
    .line 256
    .line 257
    iput-object v8, p0, Lxy0/c;->d:Ljava/lang/Object;

    .line 258
    .line 259
    iput-object v7, p0, Lxy0/c;->e:Lvy0/l;

    .line 260
    .line 261
    :goto_2
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 262
    .line 263
    invoke-virtual {v10, v0, v7}, Lvy0/l;->t(Ljava/lang/Object;Lay0/o;)V

    .line 264
    .line 265
    .line 266
    goto :goto_3

    .line 267
    :cond_10
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 268
    .line 269
    const-string v1, "unexpected"

    .line 270
    .line 271
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 272
    .line 273
    .line 274
    throw v0

    .line 275
    :cond_11
    invoke-virtual {v1}, Laz0/c;->b()V

    .line 276
    .line 277
    .line 278
    iput-object v8, p0, Lxy0/c;->d:Ljava/lang/Object;

    .line 279
    .line 280
    iput-object v7, p0, Lxy0/c;->e:Lvy0/l;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 281
    .line 282
    goto :goto_2

    .line 283
    :goto_3
    invoke-virtual {v10}, Lvy0/l;->p()Ljava/lang/Object;

    .line 284
    .line 285
    .line 286
    move-result-object v0

    .line 287
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 288
    .line 289
    return-object v0

    .line 290
    :goto_4
    invoke-virtual {v10}, Lvy0/l;->B()V

    .line 291
    .line 292
    .line 293
    throw v0

    .line 294
    :cond_12
    invoke-virtual {v1}, Laz0/c;->b()V

    .line 295
    .line 296
    .line 297
    iput-object v0, p0, Lxy0/c;->d:Ljava/lang/Object;

    .line 298
    .line 299
    :goto_5
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 300
    .line 301
    .line 302
    move-result-object v0

    .line 303
    return-object v0

    .line 304
    :cond_13
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 305
    .line 306
    const-string v1, "unreachable"

    .line 307
    .line 308
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 309
    .line 310
    .line 311
    throw v0
.end method

.method public final b(Laz0/q;I)V
    .locals 0

    .line 1
    iget-object p0, p0, Lxy0/c;->e:Lvy0/l;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lvy0/l;->b(Laz0/q;I)V

    .line 6
    .line 7
    .line 8
    :cond_0
    return-void
.end method

.method public final c()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lxy0/c;->d:Ljava/lang/Object;

    .line 2
    .line 3
    sget-object v1, Lxy0/l;->p:Lj51/i;

    .line 4
    .line 5
    if-eq v0, v1, :cond_1

    .line 6
    .line 7
    iput-object v1, p0, Lxy0/c;->d:Ljava/lang/Object;

    .line 8
    .line 9
    sget-object v1, Lxy0/l;->l:Lj51/i;

    .line 10
    .line 11
    if-eq v0, v1, :cond_0

    .line 12
    .line 13
    return-object v0

    .line 14
    :cond_0
    iget-object p0, p0, Lxy0/c;->f:Lxy0/j;

    .line 15
    .line 16
    invoke-virtual {p0}, Lxy0/j;->t()Ljava/lang/Throwable;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    sget v0, Laz0/r;->a:I

    .line 21
    .line 22
    throw p0

    .line 23
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 24
    .line 25
    const-string v0, "`hasNext()` has not been invoked"

    .line 26
    .line 27
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0
.end method
