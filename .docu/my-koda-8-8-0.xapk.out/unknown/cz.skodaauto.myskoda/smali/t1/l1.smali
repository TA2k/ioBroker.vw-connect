.class public final Lt1/l1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# instance fields
.field public final synthetic a:I

.field public final b:Ljava/lang/Object;

.field public final c:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lt1/l1;->a:I

    .line 2
    .line 3
    iput-object p2, p0, Lt1/l1;->b:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Lt1/l1;->c:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 19

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
    iget v3, v0, Lt1/l1;->a:I

    .line 8
    .line 9
    packed-switch v3, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    iget-object v2, v0, Lt1/l1;->b:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v2, Lx4/t;

    .line 15
    .line 16
    iget-object v0, v0, Lt1/l1;->c:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v0, Lt4/m;

    .line 19
    .line 20
    invoke-virtual {v2, v0}, Lx4/t;->setParentLayoutDirection(Lt4/m;)V

    .line 21
    .line 22
    .line 23
    sget-object v0, Lx4/c;->i:Lx4/c;

    .line 24
    .line 25
    sget-object v2, Lmx0/t;->d:Lmx0/t;

    .line 26
    .line 27
    const/4 v3, 0x0

    .line 28
    invoke-interface {v1, v3, v3, v2, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    return-object v0

    .line 33
    :pswitch_0
    new-instance v3, Ljava/util/ArrayList;

    .line 34
    .line 35
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 36
    .line 37
    .line 38
    move-result v4

    .line 39
    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 40
    .line 41
    .line 42
    move-object v4, v2

    .line 43
    check-cast v4, Ljava/util/Collection;

    .line 44
    .line 45
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 46
    .line 47
    .line 48
    move-result v5

    .line 49
    const/4 v7, 0x0

    .line 50
    :goto_0
    if-ge v7, v5, :cond_1

    .line 51
    .line 52
    invoke-interface {v2, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v8

    .line 56
    move-object v9, v8

    .line 57
    check-cast v9, Lt3/p0;

    .line 58
    .line 59
    invoke-interface {v9}, Lt3/p0;->l()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v9

    .line 63
    instance-of v9, v9, Lt1/m1;

    .line 64
    .line 65
    if-nez v9, :cond_0

    .line 66
    .line 67
    invoke-virtual {v3, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    :cond_0
    add-int/lit8 v7, v7, 0x1

    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_1
    iget-object v5, v0, Lt1/l1;->c:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast v5, Lay0/a;

    .line 76
    .line 77
    invoke-interface {v5}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v5

    .line 81
    check-cast v5, Ljava/util/List;

    .line 82
    .line 83
    if-eqz v5, :cond_5

    .line 84
    .line 85
    new-instance v8, Ljava/util/ArrayList;

    .line 86
    .line 87
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 88
    .line 89
    .line 90
    move-result v9

    .line 91
    invoke-direct {v8, v9}, Ljava/util/ArrayList;-><init>(I)V

    .line 92
    .line 93
    .line 94
    move-object v9, v5

    .line 95
    check-cast v9, Ljava/util/Collection;

    .line 96
    .line 97
    invoke-interface {v9}, Ljava/util/Collection;->size()I

    .line 98
    .line 99
    .line 100
    move-result v9

    .line 101
    const/4 v10, 0x0

    .line 102
    :goto_1
    if-ge v10, v9, :cond_4

    .line 103
    .line 104
    invoke-interface {v5, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v11

    .line 108
    check-cast v11, Ld3/c;

    .line 109
    .line 110
    if-eqz v11, :cond_2

    .line 111
    .line 112
    iget v12, v11, Ld3/c;->b:F

    .line 113
    .line 114
    iget v13, v11, Ld3/c;->a:F

    .line 115
    .line 116
    new-instance v14, Llx0/l;

    .line 117
    .line 118
    invoke-virtual {v3, v10}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v15

    .line 122
    check-cast v15, Lt3/p0;

    .line 123
    .line 124
    iget v6, v11, Ld3/c;->c:F

    .line 125
    .line 126
    sub-float/2addr v6, v13

    .line 127
    move-object/from16 v16, v8

    .line 128
    .line 129
    float-to-double v7, v6

    .line 130
    invoke-static {v7, v8}, Ljava/lang/Math;->floor(D)D

    .line 131
    .line 132
    .line 133
    move-result-wide v6

    .line 134
    double-to-float v6, v6

    .line 135
    float-to-int v6, v6

    .line 136
    iget v7, v11, Ld3/c;->d:F

    .line 137
    .line 138
    sub-float/2addr v7, v12

    .line 139
    float-to-double v7, v7

    .line 140
    invoke-static {v7, v8}, Ljava/lang/Math;->floor(D)D

    .line 141
    .line 142
    .line 143
    move-result-wide v7

    .line 144
    double-to-float v7, v7

    .line 145
    float-to-int v7, v7

    .line 146
    const/4 v8, 0x5

    .line 147
    invoke-static {v6, v7, v8}, Lt4/b;->b(III)J

    .line 148
    .line 149
    .line 150
    move-result-wide v6

    .line 151
    invoke-interface {v15, v6, v7}, Lt3/p0;->L(J)Lt3/e1;

    .line 152
    .line 153
    .line 154
    move-result-object v6

    .line 155
    invoke-static {v13}, Ljava/lang/Math;->round(F)I

    .line 156
    .line 157
    .line 158
    move-result v7

    .line 159
    invoke-static {v12}, Ljava/lang/Math;->round(F)I

    .line 160
    .line 161
    .line 162
    move-result v8

    .line 163
    int-to-long v11, v7

    .line 164
    const/16 v7, 0x20

    .line 165
    .line 166
    shl-long/2addr v11, v7

    .line 167
    int-to-long v7, v8

    .line 168
    const-wide v17, 0xffffffffL

    .line 169
    .line 170
    .line 171
    .line 172
    .line 173
    and-long v7, v7, v17

    .line 174
    .line 175
    or-long/2addr v7, v11

    .line 176
    new-instance v11, Lt4/j;

    .line 177
    .line 178
    invoke-direct {v11, v7, v8}, Lt4/j;-><init>(J)V

    .line 179
    .line 180
    .line 181
    invoke-direct {v14, v6, v11}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 182
    .line 183
    .line 184
    goto :goto_2

    .line 185
    :cond_2
    move-object/from16 v16, v8

    .line 186
    .line 187
    const/4 v14, 0x0

    .line 188
    :goto_2
    move-object/from16 v6, v16

    .line 189
    .line 190
    if-eqz v14, :cond_3

    .line 191
    .line 192
    invoke-virtual {v6, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 193
    .line 194
    .line 195
    :cond_3
    add-int/lit8 v10, v10, 0x1

    .line 196
    .line 197
    move-object v8, v6

    .line 198
    goto :goto_1

    .line 199
    :cond_4
    move-object v6, v8

    .line 200
    move-object v7, v6

    .line 201
    goto :goto_3

    .line 202
    :cond_5
    const/4 v7, 0x0

    .line 203
    :goto_3
    new-instance v3, Ljava/util/ArrayList;

    .line 204
    .line 205
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 206
    .line 207
    .line 208
    move-result v5

    .line 209
    invoke-direct {v3, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 210
    .line 211
    .line 212
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 213
    .line 214
    .line 215
    move-result v4

    .line 216
    const/4 v6, 0x0

    .line 217
    :goto_4
    if-ge v6, v4, :cond_7

    .line 218
    .line 219
    invoke-interface {v2, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object v5

    .line 223
    move-object v8, v5

    .line 224
    check-cast v8, Lt3/p0;

    .line 225
    .line 226
    invoke-interface {v8}, Lt3/p0;->l()Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object v8

    .line 230
    instance-of v8, v8, Lt1/m1;

    .line 231
    .line 232
    if-eqz v8, :cond_6

    .line 233
    .line 234
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 235
    .line 236
    .line 237
    :cond_6
    add-int/lit8 v6, v6, 0x1

    .line 238
    .line 239
    goto :goto_4

    .line 240
    :cond_7
    iget-object v0, v0, Lt1/l1;->b:Ljava/lang/Object;

    .line 241
    .line 242
    check-cast v0, Lay0/a;

    .line 243
    .line 244
    invoke-static {v3, v0}, Lt1/l0;->n(Ljava/util/List;Lay0/a;)Ljava/util/ArrayList;

    .line 245
    .line 246
    .line 247
    move-result-object v0

    .line 248
    invoke-static/range {p3 .. p4}, Lt4/a;->h(J)I

    .line 249
    .line 250
    .line 251
    move-result v2

    .line 252
    invoke-static/range {p3 .. p4}, Lt4/a;->g(J)I

    .line 253
    .line 254
    .line 255
    move-result v3

    .line 256
    new-instance v4, Lbc/e;

    .line 257
    .line 258
    const/4 v5, 0x2

    .line 259
    invoke-direct {v4, v7, v0, v5}, Lbc/e;-><init>(Ljava/util/List;Ljava/util/List;I)V

    .line 260
    .line 261
    .line 262
    sget-object v0, Lmx0/t;->d:Lmx0/t;

    .line 263
    .line 264
    invoke-interface {v1, v2, v3, v0, v4}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 265
    .line 266
    .line 267
    move-result-object v0

    .line 268
    return-object v0

    .line 269
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
