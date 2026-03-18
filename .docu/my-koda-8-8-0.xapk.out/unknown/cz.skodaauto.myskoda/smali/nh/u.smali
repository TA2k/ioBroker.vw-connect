.class public final Lnh/u;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ln70/x;

.field public final e:Ljd/b;

.field public final f:Lyy0/c2;

.field public final g:Lyy0/l1;


# direct methods
.method public constructor <init>(Ln70/x;Ljd/b;)V
    .locals 11

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lnh/u;->d:Ln70/x;

    .line 5
    .line 6
    iput-object p2, p0, Lnh/u;->e:Ljd/b;

    .line 7
    .line 8
    new-instance v0, Lnh/v;

    .line 9
    .line 10
    const/4 v9, 0x0

    .line 11
    const/4 v10, 0x0

    .line 12
    const-string v1, ""

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    const/4 v3, 0x0

    .line 16
    const/4 v4, 0x0

    .line 17
    const/4 v5, 0x0

    .line 18
    sget-object v6, Lmx0/s;->d:Lmx0/s;

    .line 19
    .line 20
    sget-object v7, Lnh/f;->a:Lnh/f;

    .line 21
    .line 22
    const/4 v8, 0x0

    .line 23
    invoke-direct/range {v0 .. v10}, Lnh/v;-><init>(Ljava/lang/String;ZZZLlc/l;Ljava/util/List;Lnh/h;ZZZ)V

    .line 24
    .line 25
    .line 26
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    iput-object p1, p0, Lnh/u;->f:Lyy0/c2;

    .line 31
    .line 32
    new-instance p2, Lag/r;

    .line 33
    .line 34
    const/16 v0, 0x8

    .line 35
    .line 36
    invoke-direct {p2, p1, v0}, Lag/r;-><init>(Lyy0/c2;I)V

    .line 37
    .line 38
    .line 39
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    check-cast p1, Lnh/v;

    .line 48
    .line 49
    invoke-static {p1}, Ljp/qa;->b(Lnh/v;)Lnh/r;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    sget-object v1, Lyy0/u1;->a:Lyy0/w1;

    .line 54
    .line 55
    invoke-static {p2, v0, v1, p1}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    iput-object p1, p0, Lnh/u;->g:Lyy0/l1;

    .line 60
    .line 61
    return-void
.end method


# virtual methods
.method public final a(Lnh/q;)V
    .locals 12

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Lnh/l;

    .line 7
    .line 8
    const-string v1, "<this>"

    .line 9
    .line 10
    iget-object v2, p0, Lnh/u;->f:Lyy0/c2;

    .line 11
    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    check-cast p1, Lnh/l;

    .line 15
    .line 16
    iget-object v4, p1, Lnh/l;->a:Ljava/lang/String;

    .line 17
    .line 18
    sget-object p0, Lnh/w;->a:Lly0/n;

    .line 19
    .line 20
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    const-string p0, "code"

    .line 24
    .line 25
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    :cond_0
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    move-object v3, p0

    .line 33
    check-cast v3, Lnh/v;

    .line 34
    .line 35
    const/4 v10, 0x0

    .line 36
    const/16 v11, 0x3f6

    .line 37
    .line 38
    const/4 v5, 0x0

    .line 39
    const/4 v6, 0x0

    .line 40
    const/4 v7, 0x0

    .line 41
    const/4 v8, 0x0

    .line 42
    const/4 v9, 0x0

    .line 43
    invoke-static/range {v3 .. v11}, Lnh/v;->a(Lnh/v;Ljava/lang/String;ZZZLlc/l;Ljava/util/ArrayList;Lnh/h;I)Lnh/v;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    invoke-virtual {v2, p0, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result p0

    .line 51
    if-eqz p0, :cond_0

    .line 52
    .line 53
    goto/16 :goto_0

    .line 54
    .line 55
    :cond_1
    sget-object v0, Lnh/j;->a:Lnh/j;

    .line 56
    .line 57
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    if-eqz v0, :cond_2

    .line 62
    .line 63
    invoke-static {v2}, Lnh/w;->a(Lyy0/c2;)V

    .line 64
    .line 65
    .line 66
    return-void

    .line 67
    :cond_2
    sget-object v0, Lnh/n;->a:Lnh/n;

    .line 68
    .line 69
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    if-eqz v0, :cond_4

    .line 74
    .line 75
    sget-object p0, Lnh/w;->a:Lly0/n;

    .line 76
    .line 77
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    :cond_3
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    move-object v3, p0

    .line 85
    check-cast v3, Lnh/v;

    .line 86
    .line 87
    const/4 v9, 0x0

    .line 88
    const/16 v11, 0x3be

    .line 89
    .line 90
    const-string v4, ""

    .line 91
    .line 92
    const/4 v5, 0x0

    .line 93
    const/4 v6, 0x0

    .line 94
    const/4 v7, 0x0

    .line 95
    const/4 v8, 0x0

    .line 96
    sget-object v10, Lnh/e;->a:Lnh/e;

    .line 97
    .line 98
    invoke-static/range {v3 .. v11}, Lnh/v;->a(Lnh/v;Ljava/lang/String;ZZZLlc/l;Ljava/util/ArrayList;Lnh/h;I)Lnh/v;

    .line 99
    .line 100
    .line 101
    move-result-object p1

    .line 102
    invoke-virtual {v2, p0, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    move-result p0

    .line 106
    if-eqz p0, :cond_3

    .line 107
    .line 108
    goto/16 :goto_0

    .line 109
    .line 110
    :cond_4
    sget-object v0, Lnh/k;->a:Lnh/k;

    .line 111
    .line 112
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result v0

    .line 116
    if-eqz v0, :cond_8

    .line 117
    .line 118
    sget-object p0, Lnh/w;->a:Lly0/n;

    .line 119
    .line 120
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    check-cast p0, Lnh/v;

    .line 128
    .line 129
    iget-object p0, p0, Lnh/v;->g:Lnh/h;

    .line 130
    .line 131
    instance-of p0, p0, Lnh/e;

    .line 132
    .line 133
    if-eqz p0, :cond_5

    .line 134
    .line 135
    invoke-static {v2}, Lnh/w;->a(Lyy0/c2;)V

    .line 136
    .line 137
    .line 138
    return-void

    .line 139
    :cond_5
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    check-cast p0, Lnh/v;

    .line 144
    .line 145
    iget-object p0, p0, Lnh/v;->g:Lnh/h;

    .line 146
    .line 147
    instance-of p0, p0, Lnh/g;

    .line 148
    .line 149
    if-eqz p0, :cond_7

    .line 150
    .line 151
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object p0

    .line 155
    check-cast p0, Lnh/v;

    .line 156
    .line 157
    iget-object p0, p0, Lnh/v;->f:Ljava/util/List;

    .line 158
    .line 159
    check-cast p0, Ljava/util/Collection;

    .line 160
    .line 161
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 162
    .line 163
    .line 164
    move-result p0

    .line 165
    if-nez p0, :cond_7

    .line 166
    .line 167
    :cond_6
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object p0

    .line 171
    move-object v3, p0

    .line 172
    check-cast v3, Lnh/v;

    .line 173
    .line 174
    sget-object v10, Lnh/f;->a:Lnh/f;

    .line 175
    .line 176
    const/16 v11, 0x3bf

    .line 177
    .line 178
    const/4 v4, 0x0

    .line 179
    const/4 v5, 0x0

    .line 180
    const/4 v6, 0x0

    .line 181
    const/4 v7, 0x0

    .line 182
    const/4 v8, 0x0

    .line 183
    const/4 v9, 0x0

    .line 184
    invoke-static/range {v3 .. v11}, Lnh/v;->a(Lnh/v;Ljava/lang/String;ZZZLlc/l;Ljava/util/ArrayList;Lnh/h;I)Lnh/v;

    .line 185
    .line 186
    .line 187
    move-result-object p1

    .line 188
    invoke-virtual {v2, p0, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 189
    .line 190
    .line 191
    move-result p0

    .line 192
    if-eqz p0, :cond_6

    .line 193
    .line 194
    goto :goto_0

    .line 195
    :cond_7
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object p0

    .line 199
    move-object v3, p0

    .line 200
    check-cast v3, Lnh/v;

    .line 201
    .line 202
    const/4 v10, 0x0

    .line 203
    const/16 v11, 0x2ff

    .line 204
    .line 205
    const/4 v4, 0x0

    .line 206
    const/4 v5, 0x0

    .line 207
    const/4 v6, 0x0

    .line 208
    const/4 v7, 0x0

    .line 209
    const/4 v8, 0x0

    .line 210
    const/4 v9, 0x0

    .line 211
    invoke-static/range {v3 .. v11}, Lnh/v;->a(Lnh/v;Ljava/lang/String;ZZZLlc/l;Ljava/util/ArrayList;Lnh/h;I)Lnh/v;

    .line 212
    .line 213
    .line 214
    move-result-object p1

    .line 215
    invoke-virtual {v2, p0, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 216
    .line 217
    .line 218
    move-result p0

    .line 219
    if-eqz p0, :cond_7

    .line 220
    .line 221
    goto :goto_0

    .line 222
    :cond_8
    sget-object v0, Lnh/o;->a:Lnh/o;

    .line 223
    .line 224
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 225
    .line 226
    .line 227
    move-result v0

    .line 228
    const/4 v3, 0x3

    .line 229
    const/4 v4, 0x0

    .line 230
    if-eqz v0, :cond_9

    .line 231
    .line 232
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 233
    .line 234
    .line 235
    move-result-object p1

    .line 236
    new-instance v0, Lnh/s;

    .line 237
    .line 238
    const/4 v1, 0x0

    .line 239
    invoke-direct {v0, p0, v4, v1}, Lnh/s;-><init>(Lnh/u;Lkotlin/coroutines/Continuation;I)V

    .line 240
    .line 241
    .line 242
    invoke-static {p1, v4, v4, v0, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 243
    .line 244
    .line 245
    return-void

    .line 246
    :cond_9
    sget-object v0, Lnh/p;->a:Lnh/p;

    .line 247
    .line 248
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 249
    .line 250
    .line 251
    move-result v0

    .line 252
    if-eqz v0, :cond_a

    .line 253
    .line 254
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 255
    .line 256
    .line 257
    move-result-object p1

    .line 258
    new-instance v0, Lnh/s;

    .line 259
    .line 260
    const/4 v1, 0x1

    .line 261
    invoke-direct {v0, p0, v4, v1}, Lnh/s;-><init>(Lnh/u;Lkotlin/coroutines/Continuation;I)V

    .line 262
    .line 263
    .line 264
    invoke-static {p1, v4, v4, v0, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 265
    .line 266
    .line 267
    return-void

    .line 268
    :cond_a
    sget-object p0, Lnh/m;->a:Lnh/m;

    .line 269
    .line 270
    invoke-virtual {p1, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 271
    .line 272
    .line 273
    move-result p0

    .line 274
    if-eqz p0, :cond_c

    .line 275
    .line 276
    sget-object p0, Lnh/w;->a:Lly0/n;

    .line 277
    .line 278
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 279
    .line 280
    .line 281
    :cond_b
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 282
    .line 283
    .line 284
    move-result-object p0

    .line 285
    move-object v3, p0

    .line 286
    check-cast v3, Lnh/v;

    .line 287
    .line 288
    const/4 v10, 0x0

    .line 289
    const/16 v11, 0x37f

    .line 290
    .line 291
    const/4 v4, 0x0

    .line 292
    const/4 v5, 0x0

    .line 293
    const/4 v6, 0x0

    .line 294
    const/4 v7, 0x0

    .line 295
    const/4 v8, 0x0

    .line 296
    const/4 v9, 0x0

    .line 297
    invoke-static/range {v3 .. v11}, Lnh/v;->a(Lnh/v;Ljava/lang/String;ZZZLlc/l;Ljava/util/ArrayList;Lnh/h;I)Lnh/v;

    .line 298
    .line 299
    .line 300
    move-result-object p1

    .line 301
    invoke-virtual {v2, p0, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 302
    .line 303
    .line 304
    move-result p0

    .line 305
    if-eqz p0, :cond_b

    .line 306
    .line 307
    :goto_0
    return-void

    .line 308
    :cond_c
    new-instance p0, La8/r0;

    .line 309
    .line 310
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 311
    .line 312
    .line 313
    throw p0
.end method
