.class public final Ly70/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ly70/f;


# direct methods
.method public synthetic constructor <init>(Ly70/f;I)V
    .locals 0

    .line 1
    iput p2, p0, Ly70/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly70/a;->e:Ly70/f;

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
    .locals 11

    .line 1
    iget p2, p0, Ly70/a;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/s;

    .line 7
    .line 8
    instance-of p2, p1, Lne0/e;

    .line 9
    .line 10
    iget-object p0, p0, Ly70/a;->e:Ly70/f;

    .line 11
    .line 12
    if-eqz p2, :cond_0

    .line 13
    .line 14
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    move-object v0, p1

    .line 19
    check-cast v0, Ly70/d;

    .line 20
    .line 21
    const/4 v9, 0x0

    .line 22
    const/16 v10, 0x1bf

    .line 23
    .line 24
    const/4 v1, 0x0

    .line 25
    const/4 v2, 0x0

    .line 26
    const/4 v3, 0x0

    .line 27
    const/4 v4, 0x0

    .line 28
    const/4 v5, 0x0

    .line 29
    const/4 v6, 0x0

    .line 30
    const/4 v7, 0x0

    .line 31
    const/4 v8, 0x0

    .line 32
    invoke-static/range {v0 .. v10}, Ly70/d;->a(Ly70/d;Lql0/g;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;ZLjava/lang/String;Ljava/util/ArrayList;ZLqr0/d;Ljava/util/List;I)Ly70/d;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 37
    .line 38
    .line 39
    iget-object p0, p0, Ly70/f;->i:Lw70/n0;

    .line 40
    .line 41
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_0
    instance-of p2, p1, Lne0/c;

    .line 46
    .line 47
    if-eqz p2, :cond_1

    .line 48
    .line 49
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 50
    .line 51
    .line 52
    move-result-object p2

    .line 53
    move-object v0, p2

    .line 54
    check-cast v0, Ly70/d;

    .line 55
    .line 56
    check-cast p1, Lne0/c;

    .line 57
    .line 58
    iget-object p2, p0, Ly70/f;->m:Lij0/a;

    .line 59
    .line 60
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    const/4 v9, 0x0

    .line 65
    const/16 v10, 0x1be

    .line 66
    .line 67
    const/4 v2, 0x0

    .line 68
    const/4 v3, 0x0

    .line 69
    const/4 v4, 0x0

    .line 70
    const/4 v5, 0x0

    .line 71
    const/4 v6, 0x0

    .line 72
    const/4 v7, 0x0

    .line 73
    const/4 v8, 0x0

    .line 74
    invoke-static/range {v0 .. v10}, Ly70/d;->a(Ly70/d;Lql0/g;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;ZLjava/lang/String;Ljava/util/ArrayList;ZLqr0/d;Ljava/util/List;I)Ly70/d;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 79
    .line 80
    .line 81
    goto :goto_0

    .line 82
    :cond_1
    sget-object p2, Lne0/d;->a:Lne0/d;

    .line 83
    .line 84
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    move-result p1

    .line 88
    if-eqz p1, :cond_2

    .line 89
    .line 90
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 91
    .line 92
    .line 93
    move-result-object p1

    .line 94
    move-object v0, p1

    .line 95
    check-cast v0, Ly70/d;

    .line 96
    .line 97
    const/4 v9, 0x0

    .line 98
    const/16 v10, 0x1bf

    .line 99
    .line 100
    const/4 v1, 0x0

    .line 101
    const/4 v2, 0x0

    .line 102
    const/4 v3, 0x0

    .line 103
    const/4 v4, 0x0

    .line 104
    const/4 v5, 0x0

    .line 105
    const/4 v6, 0x0

    .line 106
    const/4 v7, 0x1

    .line 107
    const/4 v8, 0x0

    .line 108
    invoke-static/range {v0 .. v10}, Ly70/d;->a(Ly70/d;Lql0/g;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;ZLjava/lang/String;Ljava/util/ArrayList;ZLqr0/d;Ljava/util/List;I)Ly70/d;

    .line 109
    .line 110
    .line 111
    move-result-object p1

    .line 112
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 113
    .line 114
    .line 115
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 116
    .line 117
    return-object p0

    .line 118
    :cond_2
    new-instance p0, La8/r0;

    .line 119
    .line 120
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 121
    .line 122
    .line 123
    throw p0

    .line 124
    :pswitch_0
    check-cast p1, Lne0/s;

    .line 125
    .line 126
    instance-of p2, p1, Lne0/e;

    .line 127
    .line 128
    if-eqz p2, :cond_b

    .line 129
    .line 130
    iget-object p0, p0, Ly70/a;->e:Ly70/f;

    .line 131
    .line 132
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 133
    .line 134
    .line 135
    move-result-object p2

    .line 136
    move-object v0, p2

    .line 137
    check-cast v0, Ly70/d;

    .line 138
    .line 139
    check-cast p1, Lne0/e;

    .line 140
    .line 141
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 142
    .line 143
    check-cast p1, Lcq0/m;

    .line 144
    .line 145
    iget-object p2, p1, Lcq0/m;->a:Lcq0/e;

    .line 146
    .line 147
    if-eqz p2, :cond_3

    .line 148
    .line 149
    iget-object p2, p2, Lcq0/e;->d:Lqr0/d;

    .line 150
    .line 151
    :goto_1
    move-object v8, p2

    .line 152
    goto :goto_2

    .line 153
    :cond_3
    const/4 p2, 0x0

    .line 154
    goto :goto_1

    .line 155
    :goto_2
    iget-object p1, p1, Lcq0/m;->b:Lcq0/n;

    .line 156
    .line 157
    if-eqz p1, :cond_a

    .line 158
    .line 159
    iget-object p1, p1, Lcq0/n;->l:Ljava/lang/Object;

    .line 160
    .line 161
    invoke-static {}, Ljp/k1;->f()Lnx0/c;

    .line 162
    .line 163
    .line 164
    move-result-object p2

    .line 165
    check-cast p1, Ljava/lang/Iterable;

    .line 166
    .line 167
    new-instance v1, Ljava/util/ArrayList;

    .line 168
    .line 169
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 170
    .line 171
    .line 172
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 173
    .line 174
    .line 175
    move-result-object p1

    .line 176
    :cond_4
    :goto_3
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 177
    .line 178
    .line 179
    move-result v2

    .line 180
    if-eqz v2, :cond_5

    .line 181
    .line 182
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v2

    .line 186
    move-object v3, v2

    .line 187
    check-cast v3, Lcq0/u;

    .line 188
    .line 189
    iget-object v3, v3, Lcq0/u;->c:Ljava/util/ArrayList;

    .line 190
    .line 191
    invoke-virtual {v3}, Ljava/util/ArrayList;->isEmpty()Z

    .line 192
    .line 193
    .line 194
    move-result v3

    .line 195
    if-eqz v3, :cond_4

    .line 196
    .line 197
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 198
    .line 199
    .line 200
    goto :goto_3

    .line 201
    :cond_5
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 202
    .line 203
    .line 204
    move-result-object p1

    .line 205
    :goto_4
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 206
    .line 207
    .line 208
    move-result v1

    .line 209
    if-eqz v1, :cond_8

    .line 210
    .line 211
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v1

    .line 215
    check-cast v1, Lcq0/u;

    .line 216
    .line 217
    sget-object v2, Ldq0/a;->a:Lsx0/b;

    .line 218
    .line 219
    new-instance v3, Ljava/util/ArrayList;

    .line 220
    .line 221
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 222
    .line 223
    .line 224
    invoke-virtual {v2}, Lmx0/e;->iterator()Ljava/util/Iterator;

    .line 225
    .line 226
    .line 227
    move-result-object v2

    .line 228
    :cond_6
    :goto_5
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 229
    .line 230
    .line 231
    move-result v4

    .line 232
    if-eqz v4, :cond_7

    .line 233
    .line 234
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 235
    .line 236
    .line 237
    move-result-object v4

    .line 238
    move-object v5, v4

    .line 239
    check-cast v5, Ljava/time/DayOfWeek;

    .line 240
    .line 241
    iget-object v6, v1, Lcq0/u;->a:Ljava/time/DayOfWeek;

    .line 242
    .line 243
    invoke-virtual {v5, v6}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 244
    .line 245
    .line 246
    move-result v6

    .line 247
    if-ltz v6, :cond_6

    .line 248
    .line 249
    iget-object v6, v1, Lcq0/u;->b:Ljava/time/DayOfWeek;

    .line 250
    .line 251
    invoke-virtual {v5, v6}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 252
    .line 253
    .line 254
    move-result v5

    .line 255
    if-gtz v5, :cond_6

    .line 256
    .line 257
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 258
    .line 259
    .line 260
    goto :goto_5

    .line 261
    :cond_7
    invoke-virtual {p2, v3}, Lnx0/c;->addAll(Ljava/util/Collection;)Z

    .line 262
    .line 263
    .line 264
    goto :goto_4

    .line 265
    :cond_8
    invoke-static {p2}, Ljp/k1;->d(Ljava/util/List;)Lnx0/c;

    .line 266
    .line 267
    .line 268
    move-result-object p1

    .line 269
    if-nez p1, :cond_9

    .line 270
    .line 271
    goto :goto_7

    .line 272
    :cond_9
    :goto_6
    move-object v9, p1

    .line 273
    goto :goto_8

    .line 274
    :cond_a
    :goto_7
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    .line 275
    .line 276
    goto :goto_6

    .line 277
    :goto_8
    const/16 v10, 0x7f

    .line 278
    .line 279
    const/4 v1, 0x0

    .line 280
    const/4 v2, 0x0

    .line 281
    const/4 v3, 0x0

    .line 282
    const/4 v4, 0x0

    .line 283
    const/4 v5, 0x0

    .line 284
    const/4 v6, 0x0

    .line 285
    const/4 v7, 0x0

    .line 286
    invoke-static/range {v0 .. v10}, Ly70/d;->a(Ly70/d;Lql0/g;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;ZLjava/lang/String;Ljava/util/ArrayList;ZLqr0/d;Ljava/util/List;I)Ly70/d;

    .line 287
    .line 288
    .line 289
    move-result-object p1

    .line 290
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 291
    .line 292
    .line 293
    :cond_b
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 294
    .line 295
    return-object p0

    .line 296
    nop

    .line 297
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
