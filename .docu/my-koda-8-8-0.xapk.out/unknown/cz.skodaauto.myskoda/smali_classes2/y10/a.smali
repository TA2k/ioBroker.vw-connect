.class public final Ly10/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ly10/g;


# direct methods
.method public synthetic constructor <init>(Ly10/g;I)V
    .locals 0

    .line 1
    iput p2, p0, Ly10/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly10/a;->e:Ly10/g;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget p2, p0, Ly10/a;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/s;

    .line 7
    .line 8
    sget-object p2, Lne0/d;->a:Lne0/d;

    .line 9
    .line 10
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    iget-object p0, p0, Ly10/a;->e:Ly10/g;

    .line 15
    .line 16
    if-eqz p2, :cond_0

    .line 17
    .line 18
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    move-object v0, p1

    .line 23
    check-cast v0, Ly10/e;

    .line 24
    .line 25
    const/4 v8, 0x0

    .line 26
    const/16 v9, 0xfe

    .line 27
    .line 28
    const/4 v1, 0x1

    .line 29
    const/4 v2, 0x0

    .line 30
    const/4 v3, 0x0

    .line 31
    const/4 v4, 0x0

    .line 32
    const/4 v5, 0x0

    .line 33
    const/4 v6, 0x0

    .line 34
    const/4 v7, 0x0

    .line 35
    invoke-static/range {v0 .. v9}, Ly10/e;->a(Ly10/e;ZZLjava/util/ArrayList;Ljava/lang/String;Lql0/g;ZLy10/d;ZI)Ly10/e;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    goto/16 :goto_2

    .line 40
    .line 41
    :cond_0
    instance-of p2, p1, Lne0/c;

    .line 42
    .line 43
    if-eqz p2, :cond_1

    .line 44
    .line 45
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 46
    .line 47
    .line 48
    move-result-object p2

    .line 49
    move-object v0, p2

    .line 50
    check-cast v0, Ly10/e;

    .line 51
    .line 52
    check-cast p1, Lne0/c;

    .line 53
    .line 54
    iget-object p2, p0, Ly10/g;->n:Lij0/a;

    .line 55
    .line 56
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 57
    .line 58
    .line 59
    move-result-object v5

    .line 60
    const/4 v8, 0x0

    .line 61
    const/16 v9, 0xec

    .line 62
    .line 63
    const/4 v1, 0x0

    .line 64
    const/4 v2, 0x0

    .line 65
    const/4 v3, 0x0

    .line 66
    const/4 v4, 0x0

    .line 67
    const/4 v6, 0x0

    .line 68
    const/4 v7, 0x0

    .line 69
    invoke-static/range {v0 .. v9}, Ly10/e;->a(Ly10/e;ZZLjava/util/ArrayList;Ljava/lang/String;Lql0/g;ZLy10/d;ZI)Ly10/e;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    goto/16 :goto_2

    .line 74
    .line 75
    :cond_1
    instance-of p2, p1, Lne0/e;

    .line 76
    .line 77
    if-eqz p2, :cond_6

    .line 78
    .line 79
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 80
    .line 81
    .line 82
    move-result-object p2

    .line 83
    move-object v0, p2

    .line 84
    check-cast v0, Ly10/e;

    .line 85
    .line 86
    check-cast p1, Lne0/e;

    .line 87
    .line 88
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 89
    .line 90
    check-cast p1, Ljava/util/List;

    .line 91
    .line 92
    iget-object p2, p0, Ly10/g;->n:Lij0/a;

    .line 93
    .line 94
    check-cast p1, Ljava/lang/Iterable;

    .line 95
    .line 96
    new-instance v3, Ljava/util/ArrayList;

    .line 97
    .line 98
    const/16 v1, 0xa

    .line 99
    .line 100
    invoke-static {p1, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 101
    .line 102
    .line 103
    move-result v1

    .line 104
    invoke-direct {v3, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 105
    .line 106
    .line 107
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 112
    .line 113
    .line 114
    move-result v1

    .line 115
    if-eqz v1, :cond_5

    .line 116
    .line 117
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v1

    .line 121
    check-cast v1, Lx10/a;

    .line 122
    .line 123
    iget-object v2, p0, Ly10/g;->j:Lw10/a;

    .line 124
    .line 125
    iget-object v4, v1, Lx10/a;->d:Ljava/time/OffsetDateTime;

    .line 126
    .line 127
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 128
    .line 129
    .line 130
    invoke-static {v4}, Lw10/a;->a(Ljava/time/OffsetDateTime;)Llp/be;

    .line 131
    .line 132
    .line 133
    move-result-object v2

    .line 134
    new-instance v4, Ly10/c;

    .line 135
    .line 136
    instance-of v5, v2, Lx10/b;

    .line 137
    .line 138
    const/4 v6, 0x0

    .line 139
    if-eqz v5, :cond_2

    .line 140
    .line 141
    check-cast v2, Lx10/b;

    .line 142
    .line 143
    iget v2, v2, Lx10/b;->a:I

    .line 144
    .line 145
    new-array v5, v6, [Ljava/lang/Object;

    .line 146
    .line 147
    move-object v6, p2

    .line 148
    check-cast v6, Ljj0/f;

    .line 149
    .line 150
    const v7, 0x7f100006

    .line 151
    .line 152
    .line 153
    invoke-virtual {v6, v7, v2, v5}, Ljj0/f;->a(II[Ljava/lang/Object;)Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object v2

    .line 157
    goto :goto_1

    .line 158
    :cond_2
    instance-of v5, v2, Lx10/c;

    .line 159
    .line 160
    if-eqz v5, :cond_3

    .line 161
    .line 162
    check-cast v2, Lx10/c;

    .line 163
    .line 164
    iget-object v2, v2, Lx10/c;->a:Ljava/time/LocalDate;

    .line 165
    .line 166
    invoke-static {v2}, Lu7/b;->c(Ljava/time/LocalDate;)Ljava/lang/String;

    .line 167
    .line 168
    .line 169
    move-result-object v2

    .line 170
    goto :goto_1

    .line 171
    :cond_3
    instance-of v2, v2, Lx10/d;

    .line 172
    .line 173
    if-eqz v2, :cond_4

    .line 174
    .line 175
    new-array v2, v6, [Ljava/lang/Object;

    .line 176
    .line 177
    move-object v5, p2

    .line 178
    check-cast v5, Ljj0/f;

    .line 179
    .line 180
    const v6, 0x7f12021e

    .line 181
    .line 182
    .line 183
    invoke-virtual {v5, v6, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 184
    .line 185
    .line 186
    move-result-object v2

    .line 187
    :goto_1
    invoke-direct {v4, v1, v2}, Ly10/c;-><init>(Lx10/a;Ljava/lang/String;)V

    .line 188
    .line 189
    .line 190
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 191
    .line 192
    .line 193
    goto :goto_0

    .line 194
    :cond_4
    new-instance p0, La8/r0;

    .line 195
    .line 196
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 197
    .line 198
    .line 199
    throw p0

    .line 200
    :cond_5
    const/4 v8, 0x0

    .line 201
    const/16 v9, 0xf8

    .line 202
    .line 203
    const/4 v1, 0x0

    .line 204
    const/4 v2, 0x0

    .line 205
    const/4 v4, 0x0

    .line 206
    const/4 v5, 0x0

    .line 207
    const/4 v6, 0x0

    .line 208
    const/4 v7, 0x0

    .line 209
    invoke-static/range {v0 .. v9}, Ly10/e;->a(Ly10/e;ZZLjava/util/ArrayList;Ljava/lang/String;Lql0/g;ZLy10/d;ZI)Ly10/e;

    .line 210
    .line 211
    .line 212
    move-result-object p1

    .line 213
    :goto_2
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 214
    .line 215
    .line 216
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 217
    .line 218
    return-object p0

    .line 219
    :cond_6
    new-instance p0, La8/r0;

    .line 220
    .line 221
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 222
    .line 223
    .line 224
    throw p0

    .line 225
    :pswitch_0
    check-cast p1, Lne0/s;

    .line 226
    .line 227
    instance-of p2, p1, Lne0/e;

    .line 228
    .line 229
    if-eqz p2, :cond_7

    .line 230
    .line 231
    check-cast p1, Lne0/e;

    .line 232
    .line 233
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 234
    .line 235
    check-cast p1, Lyr0/e;

    .line 236
    .line 237
    iget-object p1, p1, Lyr0/e;->n:Ljava/util/List;

    .line 238
    .line 239
    sget-object p2, Lyr0/f;->j:Lyr0/f;

    .line 240
    .line 241
    invoke-interface {p1, p2}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 242
    .line 243
    .line 244
    move-result v8

    .line 245
    iget-object p0, p0, Ly10/a;->e:Ly10/g;

    .line 246
    .line 247
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 248
    .line 249
    .line 250
    move-result-object p1

    .line 251
    move-object v0, p1

    .line 252
    check-cast v0, Ly10/e;

    .line 253
    .line 254
    const/4 v7, 0x0

    .line 255
    const/16 v9, 0x7f

    .line 256
    .line 257
    const/4 v1, 0x0

    .line 258
    const/4 v2, 0x0

    .line 259
    const/4 v3, 0x0

    .line 260
    const/4 v4, 0x0

    .line 261
    const/4 v5, 0x0

    .line 262
    const/4 v6, 0x0

    .line 263
    invoke-static/range {v0 .. v9}, Ly10/e;->a(Ly10/e;ZZLjava/util/ArrayList;Ljava/lang/String;Lql0/g;ZLy10/d;ZI)Ly10/e;

    .line 264
    .line 265
    .line 266
    move-result-object p1

    .line 267
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 268
    .line 269
    .line 270
    :cond_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 271
    .line 272
    return-object p0

    .line 273
    :pswitch_1
    check-cast p1, Lmp0/a;

    .line 274
    .line 275
    sget-object p2, Lmp0/a;->d:Lmp0/a;

    .line 276
    .line 277
    if-ne p1, p2, :cond_8

    .line 278
    .line 279
    iget-object p0, p0, Ly10/a;->e:Ly10/g;

    .line 280
    .line 281
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 282
    .line 283
    .line 284
    move-result-object p1

    .line 285
    move-object v0, p1

    .line 286
    check-cast v0, Ly10/e;

    .line 287
    .line 288
    const/4 v8, 0x0

    .line 289
    const/16 v9, 0xdf

    .line 290
    .line 291
    const/4 v1, 0x0

    .line 292
    const/4 v2, 0x0

    .line 293
    const/4 v3, 0x0

    .line 294
    const/4 v4, 0x0

    .line 295
    const/4 v5, 0x0

    .line 296
    const/4 v6, 0x1

    .line 297
    const/4 v7, 0x0

    .line 298
    invoke-static/range {v0 .. v9}, Ly10/e;->a(Ly10/e;ZZLjava/util/ArrayList;Ljava/lang/String;Lql0/g;ZLy10/d;ZI)Ly10/e;

    .line 299
    .line 300
    .line 301
    move-result-object p1

    .line 302
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 303
    .line 304
    .line 305
    :cond_8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 306
    .line 307
    return-object p0

    .line 308
    nop

    .line 309
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
