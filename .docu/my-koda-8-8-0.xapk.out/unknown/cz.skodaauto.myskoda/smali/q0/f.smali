.class public final synthetic Lq0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p7, p0, Lq0/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lq0/f;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Lq0/f;->f:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p3, p0, Lq0/f;->g:Ljava/lang/Object;

    .line 8
    .line 9
    iput-object p4, p0, Lq0/f;->h:Ljava/lang/Object;

    .line 10
    .line 11
    iput-object p5, p0, Lq0/f;->i:Ljava/lang/Object;

    .line 12
    .line 13
    iput-object p6, p0, Lq0/f;->j:Ljava/lang/Object;

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 12

    .line 1
    iget v0, p0, Lq0/f;->d:I

    .line 2
    .line 3
    iget-object v1, p0, Lq0/f;->j:Ljava/lang/Object;

    .line 4
    .line 5
    iget-object v2, p0, Lq0/f;->i:Ljava/lang/Object;

    .line 6
    .line 7
    iget-object v3, p0, Lq0/f;->h:Ljava/lang/Object;

    .line 8
    .line 9
    iget-object v4, p0, Lq0/f;->g:Ljava/lang/Object;

    .line 10
    .line 11
    iget-object v5, p0, Lq0/f;->f:Ljava/lang/Object;

    .line 12
    .line 13
    iget-object p0, p0, Lq0/f;->e:Ljava/lang/Object;

    .line 14
    .line 15
    packed-switch v0, :pswitch_data_0

    .line 16
    .line 17
    .line 18
    check-cast p0, Lg4/p0;

    .line 19
    .line 20
    check-cast v5, Lt4/m;

    .line 21
    .line 22
    check-cast v4, Ljava/util/List;

    .line 23
    .line 24
    move-object v7, v3

    .line 25
    check-cast v7, Lg4/g;

    .line 26
    .line 27
    move-object v10, v2

    .line 28
    check-cast v10, Lt4/c;

    .line 29
    .line 30
    move-object v11, v1

    .line 31
    check-cast v11, Lk4/m;

    .line 32
    .line 33
    const-string v0, "BackgroundTextMeasurement"

    .line 34
    .line 35
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    :try_start_0
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    instance-of v1, v0, Lv2/b;

    .line 43
    .line 44
    const/4 v2, 0x0

    .line 45
    if-eqz v1, :cond_0

    .line 46
    .line 47
    check-cast v0, Lv2/b;

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_0
    move-object v0, v2

    .line 51
    :goto_0
    if-eqz v0, :cond_2

    .line 52
    .line 53
    invoke-virtual {v0, v2, v2}, Lv2/b;->C(Lay0/k;Lay0/k;)Lv2/b;

    .line 54
    .line 55
    .line 56
    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_3

    .line 57
    if-eqz v1, :cond_2

    .line 58
    .line 59
    :try_start_1
    invoke-virtual {v1}, Lv2/f;->j()Lv2/f;

    .line 60
    .line 61
    .line 62
    move-result-object v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 63
    :try_start_2
    invoke-static {p0, v5}, Lg4/f0;->h(Lg4/p0;Lt4/m;)Lg4/p0;

    .line 64
    .line 65
    .line 66
    move-result-object v8

    .line 67
    if-nez v4, :cond_1

    .line 68
    .line 69
    sget-object v4, Lmx0/s;->d:Lmx0/s;

    .line 70
    .line 71
    :cond_1
    move-object v9, v4

    .line 72
    goto :goto_1

    .line 73
    :catchall_0
    move-exception v0

    .line 74
    move-object p0, v0

    .line 75
    goto :goto_2

    .line 76
    :goto_1
    new-instance v6, Landroidx/lifecycle/c1;

    .line 77
    .line 78
    invoke-direct/range {v6 .. v11}, Landroidx/lifecycle/c1;-><init>(Lg4/g;Lg4/p0;Ljava/util/List;Lt4/c;Lk4/m;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {v6}, Landroidx/lifecycle/c1;->b()F
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 82
    .line 83
    .line 84
    :try_start_3
    invoke-static {v2}, Lv2/f;->q(Lv2/f;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 85
    .line 86
    .line 87
    :try_start_4
    invoke-virtual {v1}, Lv2/b;->w()Lv2/p;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    invoke-virtual {p0}, Lv2/p;->d()V

    .line 92
    .line 93
    .line 94
    invoke-virtual {v1}, Lv2/b;->c()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    .line 95
    .line 96
    .line 97
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 98
    .line 99
    .line 100
    return-void

    .line 101
    :catchall_1
    move-exception v0

    .line 102
    move-object p0, v0

    .line 103
    goto :goto_3

    .line 104
    :goto_2
    :try_start_5
    invoke-static {v2}, Lv2/f;->q(Lv2/f;)V

    .line 105
    .line 106
    .line 107
    throw p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 108
    :goto_3
    :try_start_6
    throw p0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 109
    :catchall_2
    move-exception v0

    .line 110
    move-object p0, v0

    .line 111
    :try_start_7
    invoke-virtual {v1}, Lv2/b;->c()V

    .line 112
    .line 113
    .line 114
    throw p0

    .line 115
    :catchall_3
    move-exception v0

    .line 116
    move-object p0, v0

    .line 117
    goto :goto_4

    .line 118
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 119
    .line 120
    const-string v0, "Cannot create a mutable snapshot of an read-only snapshot"

    .line 121
    .line 122
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    throw p0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_3

    .line 126
    :goto_4
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 127
    .line 128
    .line 129
    throw p0

    .line 130
    :pswitch_0
    check-cast p0, Lk0/b;

    .line 131
    .line 132
    check-cast v5, Landroidx/lifecycle/x;

    .line 133
    .line 134
    check-cast v4, Lb0/r;

    .line 135
    .line 136
    check-cast v3, Ll2/b1;

    .line 137
    .line 138
    check-cast v2, Lrb/b;

    .line 139
    .line 140
    check-cast v1, Landroid/content/Context;

    .line 141
    .line 142
    invoke-virtual {p0}, Lk0/b;->get()Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object p0

    .line 146
    const-string v0, "get(...)"

    .line 147
    .line 148
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    check-cast p0, Lv0/f;

    .line 152
    .line 153
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object v0

    .line 157
    check-cast v0, Lb0/k1;

    .line 158
    .line 159
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 160
    .line 161
    .line 162
    const-string v3, "context"

    .line 163
    .line 164
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 165
    .line 166
    .line 167
    new-instance v3, Lb0/f0;

    .line 168
    .line 169
    const/4 v6, 0x0

    .line 170
    invoke-direct {v3, v6}, Lb0/f0;-><init>(I)V

    .line 171
    .line 172
    .line 173
    new-instance v7, Landroid/util/Size;

    .line 174
    .line 175
    const/16 v8, 0x500

    .line 176
    .line 177
    const/16 v9, 0x2d0

    .line 178
    .line 179
    invoke-direct {v7, v8, v9}, Landroid/util/Size;-><init>(II)V

    .line 180
    .line 181
    .line 182
    sget-object v8, Lh0/a1;->J0:Lh0/g;

    .line 183
    .line 184
    iget-object v3, v3, Lb0/f0;->b:Lh0/j1;

    .line 185
    .line 186
    invoke-virtual {v3, v8, v7}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 187
    .line 188
    .line 189
    sget-object v7, Lh0/x0;->e:Lh0/g;

    .line 190
    .line 191
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 192
    .line 193
    .line 194
    move-result-object v8

    .line 195
    invoke-virtual {v3, v7, v8}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 196
    .line 197
    .line 198
    new-instance v7, Lh0/x0;

    .line 199
    .line 200
    invoke-static {v3}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 201
    .line 202
    .line 203
    move-result-object v3

    .line 204
    invoke-direct {v7, v3}, Lh0/x0;-><init>(Lh0/n1;)V

    .line 205
    .line 206
    .line 207
    invoke-static {v7}, Lh0/a1;->L(Lh0/a1;)V

    .line 208
    .line 209
    .line 210
    new-instance v3, Lb0/i0;

    .line 211
    .line 212
    invoke-direct {v3, v7}, Lb0/i0;-><init>(Lh0/x0;)V

    .line 213
    .line 214
    .line 215
    invoke-virtual {v1}, Landroid/content/Context;->getMainExecutor()Ljava/util/concurrent/Executor;

    .line 216
    .line 217
    .line 218
    move-result-object v1

    .line 219
    invoke-virtual {v3, v1, v2}, Lb0/i0;->G(Ljava/util/concurrent/Executor;Lb0/d0;)V

    .line 220
    .line 221
    .line 222
    :try_start_8
    iget-object v1, p0, Lv0/f;->a:Lcom/google/android/material/datepicker/d;

    .line 223
    .line 224
    invoke-virtual {v1}, Lcom/google/android/material/datepicker/d;->h()V

    .line 225
    .line 226
    .line 227
    const/4 v1, 0x2

    .line 228
    new-array v1, v1, [Lb0/z1;

    .line 229
    .line 230
    aput-object v0, v1, v6

    .line 231
    .line 232
    const/4 v0, 0x1

    .line 233
    aput-object v3, v1, v0

    .line 234
    .line 235
    invoke-virtual {p0, v5, v4, v1}, Lv0/f;->a(Landroidx/lifecycle/x;Lb0/r;[Lb0/z1;)V
    :try_end_8
    .catch Ljava/lang/Exception; {:try_start_8 .. :try_end_8} :catch_0

    .line 236
    .line 237
    .line 238
    goto :goto_6

    .line 239
    :catch_0
    move-exception v0

    .line 240
    move-object p0, v0

    .line 241
    sget-object v0, Lgi/b;->h:Lgi/b;

    .line 242
    .line 243
    new-instance v1, Lsb/a;

    .line 244
    .line 245
    invoke-direct {v1, v6}, Lsb/a;-><init>(I)V

    .line 246
    .line 247
    .line 248
    sget-object v2, Lgi/a;->e:Lgi/a;

    .line 249
    .line 250
    const-class v3, Lv0/f;

    .line 251
    .line 252
    invoke-virtual {v3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 253
    .line 254
    .line 255
    move-result-object v3

    .line 256
    const/16 v4, 0x24

    .line 257
    .line 258
    invoke-static {v3, v4}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 259
    .line 260
    .line 261
    move-result-object v4

    .line 262
    const/16 v5, 0x2e

    .line 263
    .line 264
    invoke-static {v5, v4, v4}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 265
    .line 266
    .line 267
    move-result-object v4

    .line 268
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 269
    .line 270
    .line 271
    move-result v5

    .line 272
    if-nez v5, :cond_3

    .line 273
    .line 274
    goto :goto_5

    .line 275
    :cond_3
    const-string v3, "Kt"

    .line 276
    .line 277
    invoke-static {v4, v3}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 278
    .line 279
    .line 280
    move-result-object v3

    .line 281
    :goto_5
    invoke-static {v3, v2, v0, p0, v1}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 282
    .line 283
    .line 284
    :goto_6
    return-void

    .line 285
    :pswitch_1
    check-cast p0, Landroidx/lifecycle/c1;

    .line 286
    .line 287
    check-cast v5, Lh0/b0;

    .line 288
    .line 289
    move-object v6, v4

    .line 290
    check-cast v6, Lh0/b0;

    .line 291
    .line 292
    move-object v7, v3

    .line 293
    check-cast v7, Lp0/k;

    .line 294
    .line 295
    move-object v8, v2

    .line 296
    check-cast v8, Lp0/k;

    .line 297
    .line 298
    move-object v9, v1

    .line 299
    check-cast v9, Ljava/util/Map$Entry;

    .line 300
    .line 301
    move-object v4, p0

    .line 302
    invoke-virtual/range {v4 .. v9}, Landroidx/lifecycle/c1;->m(Lh0/b0;Lh0/b0;Lp0/k;Lp0/k;Ljava/util/Map$Entry;)V

    .line 303
    .line 304
    .line 305
    return-void

    .line 306
    nop

    .line 307
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
