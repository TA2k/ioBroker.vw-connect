.class public final Lq81/c;
.super Leb/j0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic h:I

.field public final i:Ll71/z;


# direct methods
.method public synthetic constructor <init>(Ll71/z;I)V
    .locals 0

    .line 1
    iput p2, p0, Lq81/c;->h:I

    .line 2
    .line 3
    const/4 p2, 0x6

    .line 4
    invoke-direct {p0, p2}, Leb/j0;-><init>(I)V

    .line 5
    .line 6
    .line 7
    iput-object p1, p0, Lq81/c;->i:Ll71/z;

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final F(I)Z
    .locals 0

    .line 1
    iget p0, p0, Lq81/c;->h:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x1

    .line 7
    return p0

    .line 8
    :pswitch_0
    const/4 p0, -0x2

    .line 9
    if-eq p1, p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    :goto_0
    return p0

    .line 15
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final G(Ls71/o;Lv71/f;Lv71/f;)Ls71/o;
    .locals 2

    .line 1
    iget p0, p0, Lq81/c;->h:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p0, "drivingDirection"

    .line 7
    .line 8
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "currentVehiclePosition"

    .line 12
    .line 13
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    if-eqz p3, :cond_3

    .line 17
    .line 18
    sget-object p0, Ls71/o;->f:Ls71/o;

    .line 19
    .line 20
    if-ne p1, p0, :cond_3

    .line 21
    .line 22
    iget-object p0, p2, Lv71/f;->a:Lw71/c;

    .line 23
    .line 24
    iget-object p3, p3, Lv71/f;->a:Lw71/c;

    .line 25
    .line 26
    invoke-static {p3, p0}, Lw71/d;->f(Lw71/c;Lw71/c;)Lw71/c;

    .line 27
    .line 28
    .line 29
    move-result-object p3

    .line 30
    invoke-static {p0, p3}, Lmb/e;->o(Lw71/c;Lw71/c;)Lw71/a;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    if-eqz p0, :cond_1

    .line 35
    .line 36
    invoke-virtual {p0}, Lw71/a;->a()D

    .line 37
    .line 38
    .line 39
    move-result-wide v0

    .line 40
    iget-wide p2, p2, Lv71/f;->b:D

    .line 41
    .line 42
    sub-double/2addr p2, v0

    .line 43
    invoke-static {p2, p3}, Ljava/lang/Math;->abs(D)D

    .line 44
    .line 45
    .line 46
    move-result-wide p2

    .line 47
    const-wide v0, 0x3ff921fb54442d18L    # 1.5707963267948966

    .line 48
    .line 49
    .line 50
    .line 51
    .line 52
    cmpl-double p0, p2, v0

    .line 53
    .line 54
    if-lez p0, :cond_0

    .line 55
    .line 56
    const-wide v0, 0x4012d97c7f3321d2L    # 4.71238898038469

    .line 57
    .line 58
    .line 59
    .line 60
    .line 61
    cmpg-double p0, p2, v0

    .line 62
    .line 63
    if-gez p0, :cond_0

    .line 64
    .line 65
    sget-object p0, Ls71/o;->e:Ls71/o;

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_0
    sget-object p0, Ls71/o;->d:Ls71/o;

    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_1
    const/4 p0, 0x0

    .line 72
    :goto_0
    if-nez p0, :cond_2

    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_2
    move-object p1, p0

    .line 76
    :cond_3
    :goto_1
    return-object p1

    .line 77
    :pswitch_0
    const-string p0, "drivingDirection"

    .line 78
    .line 79
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    const-string p0, "currentVehiclePosition"

    .line 83
    .line 84
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    return-object p1

    .line 88
    nop

    .line 89
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final H(Ls71/o;)Z
    .locals 0

    .line 1
    iget p0, p0, Lq81/c;->h:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p0, "trajectoryDirection"

    .line 7
    .line 8
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sget-object p0, Ls71/o;->e:Ls71/o;

    .line 12
    .line 13
    if-ne p1, p0, :cond_0

    .line 14
    .line 15
    const/4 p0, 0x1

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    :goto_0
    return p0

    .line 19
    :pswitch_0
    const-string p0, "trajectoryDirection"

    .line 20
    .line 21
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    const/4 p0, 0x0

    .line 25
    return p0

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final j(Lv71/h;I)Ljava/util/ArrayList;
    .locals 13

    .line 1
    iget p0, p0, Lq81/c;->h:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lx81/b;

    .line 7
    .line 8
    iget p0, p1, Lx81/b;->a:I

    .line 9
    .line 10
    iget-object p1, p1, Lx81/b;->f:Ljava/util/ArrayList;

    .line 11
    .line 12
    new-instance p2, Ljava/util/ArrayList;

    .line 13
    .line 14
    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    .line 15
    .line 16
    .line 17
    add-int/lit8 p0, p0, -0x1

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    :cond_0
    :goto_0
    if-ge v0, p0, :cond_3

    .line 21
    .line 22
    invoke-static {v0, p1}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    check-cast v1, Lw71/b;

    .line 27
    .line 28
    add-int/lit8 v0, v0, 0x1

    .line 29
    .line 30
    invoke-static {v0, p1}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    check-cast v2, Lw71/b;

    .line 35
    .line 36
    if-eqz v1, :cond_0

    .line 37
    .line 38
    if-eqz v2, :cond_0

    .line 39
    .line 40
    iget-wide v3, v1, Lw71/b;->b:D

    .line 41
    .line 42
    const-wide v5, 0x3ff921fb54442d18L    # 1.5707963267948966

    .line 43
    .line 44
    .line 45
    .line 46
    .line 47
    add-double/2addr v3, v5

    .line 48
    const-wide v7, 0x4062c00000000000L    # 150.0

    .line 49
    .line 50
    .line 51
    .line 52
    .line 53
    invoke-static {v3, v4, v7, v8}, Lw71/d;->c(DD)Lw71/c;

    .line 54
    .line 55
    .line 56
    move-result-object v3

    .line 57
    iget-wide v9, v2, Lw71/b;->b:D

    .line 58
    .line 59
    add-double/2addr v9, v5

    .line 60
    invoke-static {v9, v10, v7, v8}, Lw71/d;->c(DD)Lw71/c;

    .line 61
    .line 62
    .line 63
    move-result-object v4

    .line 64
    iget-object v1, v1, Lw71/b;->a:Lw71/c;

    .line 65
    .line 66
    invoke-static {v1, v3}, Lw71/d;->h(Lw71/c;Lw71/c;)Lw71/c;

    .line 67
    .line 68
    .line 69
    move-result-object v3

    .line 70
    invoke-static {v3, v1}, Lw71/d;->f(Lw71/c;Lw71/c;)Lw71/c;

    .line 71
    .line 72
    .line 73
    move-result-object v3

    .line 74
    invoke-static {v1, v3}, Lmb/e;->o(Lw71/c;Lw71/c;)Lw71/a;

    .line 75
    .line 76
    .line 77
    move-result-object v1

    .line 78
    iget-object v2, v2, Lw71/b;->a:Lw71/c;

    .line 79
    .line 80
    invoke-static {v2, v4}, Lw71/d;->h(Lw71/c;Lw71/c;)Lw71/c;

    .line 81
    .line 82
    .line 83
    move-result-object v3

    .line 84
    invoke-static {v3, v2}, Lw71/d;->f(Lw71/c;Lw71/c;)Lw71/c;

    .line 85
    .line 86
    .line 87
    move-result-object v3

    .line 88
    invoke-static {v2, v3}, Lmb/e;->o(Lw71/c;Lw71/c;)Lw71/a;

    .line 89
    .line 90
    .line 91
    move-result-object v2

    .line 92
    if-eqz v1, :cond_1

    .line 93
    .line 94
    if-eqz v2, :cond_1

    .line 95
    .line 96
    invoke-virtual {v1, v2}, Lw71/a;->b(Lw71/a;)Lw71/c;

    .line 97
    .line 98
    .line 99
    move-result-object v1

    .line 100
    if-eqz v1, :cond_1

    .line 101
    .line 102
    const/16 v2, 0xa

    .line 103
    .line 104
    invoke-static {v1, v2}, Lw71/d;->i(Lw71/c;I)Lw71/c;

    .line 105
    .line 106
    .line 107
    move-result-object v1

    .line 108
    goto :goto_1

    .line 109
    :cond_1
    const/4 v1, 0x0

    .line 110
    :goto_1
    if-nez v1, :cond_2

    .line 111
    .line 112
    new-instance v1, Lw71/c;

    .line 113
    .line 114
    const-wide/16 v2, 0x0

    .line 115
    .line 116
    invoke-direct {v1, v2, v3, v2, v3}, Lw71/c;-><init>(DD)V

    .line 117
    .line 118
    .line 119
    :cond_2
    invoke-virtual {p2, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    goto :goto_0

    .line 123
    :cond_3
    return-object p2

    .line 124
    :pswitch_0
    check-cast p1, Lq81/b;

    .line 125
    .line 126
    iget v1, p1, Lq81/b;->a:I

    .line 127
    .line 128
    iget-object v2, p1, Lq81/b;->e:Ljava/util/List;

    .line 129
    .line 130
    iget-object p0, p1, Lq81/b;->d:Lw71/b;

    .line 131
    .line 132
    iget-object v4, p0, Lw71/b;->a:Lw71/c;

    .line 133
    .line 134
    iget-wide v5, p0, Lw71/b;->b:D

    .line 135
    .line 136
    new-instance v7, Ln1/t;

    .line 137
    .line 138
    move v3, p2

    .line 139
    move-object v0, v7

    .line 140
    invoke-direct/range {v0 .. v6}, Ln1/t;-><init>(ILjava/util/List;ILw71/c;D)V

    .line 141
    .line 142
    .line 143
    move v8, v3

    .line 144
    new-instance p0, Ljava/util/ArrayList;

    .line 145
    .line 146
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 147
    .line 148
    .line 149
    if-ltz v8, :cond_b

    .line 150
    .line 151
    invoke-static {v8, v2}, Llp/bd;->d(ILjava/util/List;)Llx0/l;

    .line 152
    .line 153
    .line 154
    move-result-object p1

    .line 155
    if-nez p1, :cond_4

    .line 156
    .line 157
    goto/16 :goto_5

    .line 158
    .line 159
    :cond_4
    iget-object p2, p1, Llx0/l;->d:Ljava/lang/Object;

    .line 160
    .line 161
    check-cast p2, Lw71/c;

    .line 162
    .line 163
    iget-object p1, p1, Llx0/l;->e:Ljava/lang/Object;

    .line 164
    .line 165
    check-cast p1, Lw71/c;

    .line 166
    .line 167
    invoke-static {v4, p2}, Lw71/d;->a(Lw71/c;Lw71/c;)D

    .line 168
    .line 169
    .line 170
    move-result-wide v0

    .line 171
    invoke-static {v4, p1}, Lw71/d;->a(Lw71/c;Lw71/c;)D

    .line 172
    .line 173
    .line 174
    move-result-wide v2

    .line 175
    cmpl-double v0, v0, v2

    .line 176
    .line 177
    if-lez v0, :cond_5

    .line 178
    .line 179
    move-object v0, p2

    .line 180
    goto :goto_2

    .line 181
    :cond_5
    move-object v0, p1

    .line 182
    :goto_2
    const-wide v1, 0x3ff921fb54442d18L    # 1.5707963267948966

    .line 183
    .line 184
    .line 185
    .line 186
    .line 187
    add-double/2addr v5, v1

    .line 188
    const-wide v1, 0x4062c00000000000L    # 150.0

    .line 189
    .line 190
    .line 191
    .line 192
    .line 193
    invoke-static {v5, v6, v1, v2}, Lw71/d;->c(DD)Lw71/c;

    .line 194
    .line 195
    .line 196
    move-result-object v1

    .line 197
    invoke-static {v4, v1}, Lw71/d;->h(Lw71/c;Lw71/c;)Lw71/c;

    .line 198
    .line 199
    .line 200
    move-result-object v1

    .line 201
    sget-object v2, Lw71/a;->c:Lmb/e;

    .line 202
    .line 203
    invoke-static {v2, v4, v1}, Lmb/e;->p(Lmb/e;Lw71/c;Lw71/c;)Lw71/a;

    .line 204
    .line 205
    .line 206
    move-result-object v1

    .line 207
    invoke-virtual {v2, v4, v0}, Lmb/e;->m(Lw71/c;Lw71/c;)Lw71/a;

    .line 208
    .line 209
    .line 210
    move-result-object v0

    .line 211
    const/4 v3, 0x0

    .line 212
    if-eqz v0, :cond_6

    .line 213
    .line 214
    if-eqz v1, :cond_6

    .line 215
    .line 216
    invoke-virtual {v1, v0}, Lw71/a;->b(Lw71/a;)Lw71/c;

    .line 217
    .line 218
    .line 219
    move-result-object v0

    .line 220
    goto :goto_3

    .line 221
    :cond_6
    move-object v0, v3

    .line 222
    :goto_3
    if-eqz v0, :cond_7

    .line 223
    .line 224
    const/4 v1, 0x5

    .line 225
    invoke-static {v0, v1}, Lw71/d;->i(Lw71/c;I)Lw71/c;

    .line 226
    .line 227
    .line 228
    move-result-object v3

    .line 229
    :cond_7
    move-object v9, v3

    .line 230
    invoke-static {v2, p2, p1}, Lmb/e;->p(Lmb/e;Lw71/c;Lw71/c;)Lw71/a;

    .line 231
    .line 232
    .line 233
    move-result-object p1

    .line 234
    if-nez p1, :cond_8

    .line 235
    .line 236
    goto :goto_5

    .line 237
    :cond_8
    invoke-virtual {p1}, Lw71/a;->a()D

    .line 238
    .line 239
    .line 240
    move-result-wide v10

    .line 241
    const/4 v12, -0x1

    .line 242
    invoke-virtual/range {v7 .. v12}, Ln1/t;->a(ILw71/c;DI)Ljava/util/ArrayList;

    .line 243
    .line 244
    .line 245
    move-result-object p1

    .line 246
    const/4 v12, 0x1

    .line 247
    invoke-virtual/range {v7 .. v12}, Ln1/t;->a(ILw71/c;DI)Ljava/util/ArrayList;

    .line 248
    .line 249
    .line 250
    move-result-object p2

    .line 251
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 252
    .line 253
    .line 254
    move-result v0

    .line 255
    add-int/lit8 v0, v0, -0x1

    .line 256
    .line 257
    :goto_4
    const/4 v1, -0x1

    .line 258
    if-ge v1, v0, :cond_9

    .line 259
    .line 260
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 261
    .line 262
    .line 263
    move-result-object v1

    .line 264
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 265
    .line 266
    .line 267
    add-int/lit8 v0, v0, -0x1

    .line 268
    .line 269
    goto :goto_4

    .line 270
    :cond_9
    if-eqz v9, :cond_a

    .line 271
    .line 272
    invoke-virtual {p0, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 273
    .line 274
    .line 275
    :cond_a
    invoke-virtual {p0, p2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 276
    .line 277
    .line 278
    :cond_b
    :goto_5
    return-object p0

    .line 279
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final p(Lv71/h;Lv71/e;Ljava/util/List;)Ljava/util/ArrayList;
    .locals 7

    .line 1
    iget p0, p0, Lq81/c;->h:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lx81/b;

    .line 7
    .line 8
    const-string p0, "vehicleDimensions"

    .line 9
    .line 10
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const-string p0, "segmentCenters"

    .line 14
    .line 15
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    iget-object p0, p1, Lx81/b;->f:Ljava/util/ArrayList;

    .line 19
    .line 20
    new-instance p1, Ljava/util/ArrayList;

    .line 21
    .line 22
    const/16 p3, 0xa

    .line 23
    .line 24
    invoke-static {p0, p3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 25
    .line 26
    .line 27
    move-result p3

    .line 28
    invoke-direct {p1, p3}, Ljava/util/ArrayList;-><init>(I)V

    .line 29
    .line 30
    .line 31
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 36
    .line 37
    .line 38
    move-result p3

    .line 39
    if-eqz p3, :cond_0

    .line 40
    .line 41
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object p3

    .line 45
    check-cast p3, Lw71/b;

    .line 46
    .line 47
    iget-wide v0, p3, Lw71/b;->b:D

    .line 48
    .line 49
    iget-object p3, p3, Lw71/b;->a:Lw71/c;

    .line 50
    .line 51
    new-instance v2, Lv71/f;

    .line 52
    .line 53
    invoke-direct {v2, p3, v0, v1, p2}, Lv71/f;-><init>(Lw71/c;DLv71/e;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {p1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_0
    return-object p1

    .line 61
    :pswitch_0
    check-cast p1, Lq81/b;

    .line 62
    .line 63
    const-string p0, "vehicleDimensions"

    .line 64
    .line 65
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    const-string p0, "segmentCenters"

    .line 69
    .line 70
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    iget v1, p1, Lq81/b;->a:I

    .line 74
    .line 75
    iget-object v2, p1, Lq81/b;->e:Ljava/util/List;

    .line 76
    .line 77
    iget-object v3, p1, Lq81/b;->c:Ls71/o;

    .line 78
    .line 79
    new-instance v0, Lil/g;

    .line 80
    .line 81
    move-object v5, p2

    .line 82
    move-object v4, p3

    .line 83
    invoke-direct/range {v0 .. v5}, Lil/g;-><init>(ILjava/util/List;Ls71/o;Ljava/util/List;Lv71/e;)V

    .line 84
    .line 85
    .line 86
    new-instance p0, Ljava/util/ArrayList;

    .line 87
    .line 88
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 89
    .line 90
    .line 91
    sget-object p1, Ls71/o;->d:Ls71/o;

    .line 92
    .line 93
    const/4 p2, 0x0

    .line 94
    if-ne v3, p1, :cond_1

    .line 95
    .line 96
    invoke-static {p2, v1}, Lkp/r9;->m(II)Lgy0/j;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    goto :goto_1

    .line 101
    :cond_1
    add-int/lit8 v1, v1, -0x1

    .line 102
    .line 103
    invoke-static {v1, p2}, Lkp/r9;->k(II)Lgy0/h;

    .line 104
    .line 105
    .line 106
    move-result-object p1

    .line 107
    :goto_1
    invoke-virtual {p1}, Lgy0/h;->iterator()Ljava/util/Iterator;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    :cond_2
    :goto_2
    move-object p2, p1

    .line 112
    check-cast p2, Lgy0/i;

    .line 113
    .line 114
    iget-boolean p2, p2, Lgy0/i;->f:Z

    .line 115
    .line 116
    if-eqz p2, :cond_9

    .line 117
    .line 118
    move-object p2, p1

    .line 119
    check-cast p2, Lmx0/w;

    .line 120
    .line 121
    invoke-virtual {p2}, Lmx0/w;->nextInt()I

    .line 122
    .line 123
    .line 124
    move-result p2

    .line 125
    iget-object p3, v0, Lil/g;->f:Ljava/lang/Object;

    .line 126
    .line 127
    check-cast p3, Ljava/util/List;

    .line 128
    .line 129
    iget-object v1, v0, Lil/g;->e:Ljava/lang/Object;

    .line 130
    .line 131
    check-cast v1, Ljava/util/List;

    .line 132
    .line 133
    add-int/lit8 v2, p2, -0x1

    .line 134
    .line 135
    add-int/lit8 v4, p2, 0x1

    .line 136
    .line 137
    if-nez p2, :cond_3

    .line 138
    .line 139
    goto :goto_3

    .line 140
    :cond_3
    move v4, v2

    .line 141
    :goto_3
    if-nez p2, :cond_4

    .line 142
    .line 143
    move v2, p2

    .line 144
    :cond_4
    invoke-static {p2, v1}, Llp/bd;->f(ILjava/util/List;)Lw71/c;

    .line 145
    .line 146
    .line 147
    move-result-object v5

    .line 148
    const/4 v6, 0x0

    .line 149
    if-nez v5, :cond_5

    .line 150
    .line 151
    goto :goto_4

    .line 152
    :cond_5
    invoke-static {v4, v1}, Llp/bd;->f(ILjava/util/List;)Lw71/c;

    .line 153
    .line 154
    .line 155
    move-result-object v1

    .line 156
    if-nez v1, :cond_6

    .line 157
    .line 158
    goto :goto_4

    .line 159
    :cond_6
    invoke-interface {p3}, Ljava/util/List;->size()I

    .line 160
    .line 161
    .line 162
    move-result v4

    .line 163
    if-ge v2, v4, :cond_7

    .line 164
    .line 165
    invoke-interface {p3, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object p3

    .line 169
    move-object v6, p3

    .line 170
    check-cast v6, Lw71/c;

    .line 171
    .line 172
    :cond_7
    if-nez p2, :cond_8

    .line 173
    .line 174
    invoke-virtual {v0, v5, v1, v5, v6}, Lil/g;->r(Lw71/c;Lw71/c;Lw71/c;Lw71/c;)Lv71/f;

    .line 175
    .line 176
    .line 177
    move-result-object v6

    .line 178
    goto :goto_4

    .line 179
    :cond_8
    invoke-virtual {v0, v1, v5, v5, v6}, Lil/g;->r(Lw71/c;Lw71/c;Lw71/c;Lw71/c;)Lv71/f;

    .line 180
    .line 181
    .line 182
    move-result-object v6

    .line 183
    :goto_4
    if-eqz v6, :cond_2

    .line 184
    .line 185
    invoke-virtual {p0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 186
    .line 187
    .line 188
    goto :goto_2

    .line 189
    :cond_9
    sget-object p1, Ls71/o;->e:Ls71/o;

    .line 190
    .line 191
    if-ne v3, p1, :cond_a

    .line 192
    .line 193
    invoke-static {p0}, Ljava/util/Collections;->reverse(Ljava/util/List;)V

    .line 194
    .line 195
    .line 196
    :cond_a
    return-object p0

    .line 197
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final s(Ljava/util/List;Ls71/o;)Llx0/l;
    .locals 0

    .line 1
    iget p0, p0, Lq81/c;->h:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p0, "trajectoryDirection"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-static {p1}, Ljp/k1;->h(Ljava/util/List;)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    invoke-static {p0, p1}, Llp/bd;->e(ILjava/util/List;)Llx0/l;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    :pswitch_0
    const-string p0, "trajectoryDirection"

    .line 21
    .line 22
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    sget-object p0, Ls71/o;->e:Ls71/o;

    .line 26
    .line 27
    if-ne p2, p0, :cond_0

    .line 28
    .line 29
    const/4 p0, 0x0

    .line 30
    invoke-static {p0, p1}, Llp/bd;->d(ILjava/util/List;)Llx0/l;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    invoke-static {p1}, Ljp/k1;->h(Ljava/util/List;)I

    .line 36
    .line 37
    .line 38
    move-result p0

    .line 39
    invoke-static {p0, p1}, Llp/bd;->e(ILjava/util/List;)Llx0/l;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    :goto_0
    return-object p0

    .line 44
    nop

    .line 45
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final u(Lv71/h;Ljava/util/List;Ljava/util/List;ILv71/f;)Llx0/l;
    .locals 8

    .line 1
    iget p0, p0, Lq81/c;->h:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lx81/b;

    .line 7
    .line 8
    const-string p0, "segmentCenters"

    .line 9
    .line 10
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const-string p0, "vehiclePositions"

    .line 14
    .line 15
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    iget-object p0, p1, Lx81/b;->f:Ljava/util/ArrayList;

    .line 19
    .line 20
    invoke-static {p0}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    check-cast p0, Lw71/b;

    .line 25
    .line 26
    const-string p1, "firstTrajectoryPoint"

    .line 27
    .line 28
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    const/4 p1, 0x0

    .line 32
    if-gez p4, :cond_1

    .line 33
    .line 34
    iget-object p4, p5, Lv71/f;->a:Lw71/c;

    .line 35
    .line 36
    iget-wide v0, p5, Lv71/f;->b:D

    .line 37
    .line 38
    const-wide v2, 0x3ff921fb54442d18L    # 1.5707963267948966

    .line 39
    .line 40
    .line 41
    .line 42
    .line 43
    add-double/2addr v0, v2

    .line 44
    const-wide v4, 0x4062c00000000000L    # 150.0

    .line 45
    .line 46
    .line 47
    .line 48
    .line 49
    invoke-static {v0, v1, v4, v5}, Lw71/d;->c(DD)Lw71/c;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    iget-wide v6, p0, Lw71/b;->b:D

    .line 54
    .line 55
    add-double/2addr v6, v2

    .line 56
    invoke-static {v6, v7, v4, v5}, Lw71/d;->c(DD)Lw71/c;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    invoke-static {p4, v0}, Lw71/d;->h(Lw71/c;Lw71/c;)Lw71/c;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    invoke-static {v0, p4}, Lw71/d;->f(Lw71/c;Lw71/c;)Lw71/c;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    invoke-static {p4, v0}, Lmb/e;->o(Lw71/c;Lw71/c;)Lw71/a;

    .line 69
    .line 70
    .line 71
    move-result-object p4

    .line 72
    iget-object p0, p0, Lw71/b;->a:Lw71/c;

    .line 73
    .line 74
    invoke-static {p0, v1}, Lw71/d;->h(Lw71/c;Lw71/c;)Lw71/c;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    invoke-static {v0, p0}, Lw71/d;->f(Lw71/c;Lw71/c;)Lw71/c;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    invoke-static {p0, v0}, Lmb/e;->o(Lw71/c;Lw71/c;)Lw71/a;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    if-eqz p4, :cond_0

    .line 87
    .line 88
    if-eqz p0, :cond_0

    .line 89
    .line 90
    invoke-virtual {p4, p0}, Lw71/a;->b(Lw71/a;)Lw71/c;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    if-eqz p0, :cond_0

    .line 95
    .line 96
    const/16 p1, 0xa

    .line 97
    .line 98
    invoke-static {p0, p1}, Lw71/d;->i(Lw71/c;I)Lw71/c;

    .line 99
    .line 100
    .line 101
    move-result-object p1

    .line 102
    :cond_0
    const/4 p4, 0x0

    .line 103
    :cond_1
    add-int/lit8 p0, p4, 0x1

    .line 104
    .line 105
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 106
    .line 107
    .line 108
    move-result v0

    .line 109
    if-gt p4, v0, :cond_4

    .line 110
    .line 111
    invoke-interface {p3}, Ljava/util/List;->size()I

    .line 112
    .line 113
    .line 114
    move-result v0

    .line 115
    if-gt p0, v0, :cond_4

    .line 116
    .line 117
    new-instance v0, Ljava/util/ArrayList;

    .line 118
    .line 119
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 120
    .line 121
    .line 122
    if-eqz p1, :cond_2

    .line 123
    .line 124
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    :cond_2
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 128
    .line 129
    .line 130
    move-result v1

    .line 131
    invoke-interface {p2, p4, v1}, Ljava/util/List;->subList(II)Ljava/util/List;

    .line 132
    .line 133
    .line 134
    move-result-object p2

    .line 135
    check-cast p2, Ljava/util/Collection;

    .line 136
    .line 137
    invoke-virtual {v0, p2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 138
    .line 139
    .line 140
    new-instance p2, Ljava/util/ArrayList;

    .line 141
    .line 142
    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    .line 143
    .line 144
    .line 145
    invoke-virtual {p2, p5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    if-nez p1, :cond_3

    .line 149
    .line 150
    move p4, p0

    .line 151
    :cond_3
    invoke-interface {p3}, Ljava/util/List;->size()I

    .line 152
    .line 153
    .line 154
    move-result p0

    .line 155
    invoke-interface {p3, p4, p0}, Ljava/util/List;->subList(II)Ljava/util/List;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    check-cast p0, Ljava/util/Collection;

    .line 160
    .line 161
    invoke-virtual {p2, p0}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 162
    .line 163
    .line 164
    new-instance p0, Llx0/l;

    .line 165
    .line 166
    invoke-direct {p0, v0, p2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 167
    .line 168
    .line 169
    goto :goto_0

    .line 170
    :cond_4
    new-instance p0, Llx0/l;

    .line 171
    .line 172
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    .line 173
    .line 174
    invoke-direct {p0, p1, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 175
    .line 176
    .line 177
    :goto_0
    return-object p0

    .line 178
    :pswitch_0
    check-cast p1, Lq81/b;

    .line 179
    .line 180
    const-string p0, "segmentCenters"

    .line 181
    .line 182
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 183
    .line 184
    .line 185
    const-string p0, "vehiclePositions"

    .line 186
    .line 187
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 188
    .line 189
    .line 190
    iget-object p0, p1, Lq81/b;->c:Ls71/o;

    .line 191
    .line 192
    add-int/lit8 p1, p4, 0x1

    .line 193
    .line 194
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 195
    .line 196
    .line 197
    move-result v0

    .line 198
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 199
    .line 200
    if-gt p4, v0, :cond_7

    .line 201
    .line 202
    invoke-interface {p3}, Ljava/util/List;->size()I

    .line 203
    .line 204
    .line 205
    move-result v0

    .line 206
    if-gt p1, v0, :cond_7

    .line 207
    .line 208
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 209
    .line 210
    .line 211
    move-result p0

    .line 212
    if-eqz p0, :cond_6

    .line 213
    .line 214
    const/4 p4, 0x1

    .line 215
    if-eq p0, p4, :cond_5

    .line 216
    .line 217
    new-instance p0, Llx0/l;

    .line 218
    .line 219
    invoke-direct {p0, v1, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 220
    .line 221
    .line 222
    goto :goto_2

    .line 223
    :cond_5
    new-instance p0, Ljava/util/ArrayList;

    .line 224
    .line 225
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 226
    .line 227
    .line 228
    const/4 p4, 0x0

    .line 229
    invoke-interface {p2, p4, p1}, Ljava/util/List;->subList(II)Ljava/util/List;

    .line 230
    .line 231
    .line 232
    move-result-object p2

    .line 233
    check-cast p2, Ljava/util/Collection;

    .line 234
    .line 235
    invoke-virtual {p0, p2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 236
    .line 237
    .line 238
    new-instance p2, Ljava/util/ArrayList;

    .line 239
    .line 240
    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    .line 241
    .line 242
    .line 243
    invoke-interface {p3, p4, p1}, Ljava/util/List;->subList(II)Ljava/util/List;

    .line 244
    .line 245
    .line 246
    move-result-object p1

    .line 247
    check-cast p1, Ljava/util/Collection;

    .line 248
    .line 249
    invoke-virtual {p2, p1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 250
    .line 251
    .line 252
    invoke-virtual {p2, p5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 253
    .line 254
    .line 255
    new-instance p1, Llx0/l;

    .line 256
    .line 257
    invoke-direct {p1, p0, p2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 258
    .line 259
    .line 260
    :goto_1
    move-object p0, p1

    .line 261
    goto :goto_2

    .line 262
    :cond_6
    new-instance p0, Ljava/util/ArrayList;

    .line 263
    .line 264
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 265
    .line 266
    .line 267
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 268
    .line 269
    .line 270
    move-result v0

    .line 271
    invoke-interface {p2, p4, v0}, Ljava/util/List;->subList(II)Ljava/util/List;

    .line 272
    .line 273
    .line 274
    move-result-object p2

    .line 275
    check-cast p2, Ljava/util/Collection;

    .line 276
    .line 277
    invoke-virtual {p0, p2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 278
    .line 279
    .line 280
    new-instance p2, Ljava/util/ArrayList;

    .line 281
    .line 282
    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    .line 283
    .line 284
    .line 285
    invoke-virtual {p2, p5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 286
    .line 287
    .line 288
    invoke-interface {p3}, Ljava/util/List;->size()I

    .line 289
    .line 290
    .line 291
    move-result p4

    .line 292
    invoke-interface {p3, p1, p4}, Ljava/util/List;->subList(II)Ljava/util/List;

    .line 293
    .line 294
    .line 295
    move-result-object p1

    .line 296
    check-cast p1, Ljava/util/Collection;

    .line 297
    .line 298
    invoke-virtual {p2, p1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 299
    .line 300
    .line 301
    new-instance p1, Llx0/l;

    .line 302
    .line 303
    invoke-direct {p1, p0, p2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 304
    .line 305
    .line 306
    goto :goto_1

    .line 307
    :cond_7
    new-instance p0, Llx0/l;

    .line 308
    .line 309
    invoke-direct {p0, v1, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 310
    .line 311
    .line 312
    :goto_2
    return-object p0

    .line 313
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final v()Ll71/z;
    .locals 1

    .line 1
    iget v0, p0, Lq81/c;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lq81/c;->i:Ll71/z;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    iget-object p0, p0, Lq81/c;->i:Ll71/z;

    .line 10
    .line 11
    return-object p0

    .line 12
    nop

    .line 13
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
