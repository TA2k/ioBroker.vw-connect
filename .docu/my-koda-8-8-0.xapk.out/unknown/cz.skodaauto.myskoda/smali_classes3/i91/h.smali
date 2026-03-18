.class public final Li91/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# instance fields
.field public final synthetic a:Lay0/n;

.field public final synthetic b:F


# direct methods
.method public constructor <init>(Lay0/n;F)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li91/h;->a:Lay0/n;

    .line 5
    .line 6
    iput p2, p0, Li91/h;->b:F

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 21

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
    move-wide/from16 v3, p3

    .line 8
    .line 9
    const-string v5, "$this$Layout"

    .line 10
    .line 11
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const-string v5, "measurables"

    .line 15
    .line 16
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    move-object v5, v2

    .line 20
    check-cast v5, Ljava/util/Collection;

    .line 21
    .line 22
    invoke-interface {v5}, Ljava/util/Collection;->size()I

    .line 23
    .line 24
    .line 25
    move-result v6

    .line 26
    const/4 v9, 0x0

    .line 27
    move v7, v9

    .line 28
    :goto_0
    const-string v8, "Collection contains no element matching the predicate."

    .line 29
    .line 30
    if-ge v7, v6, :cond_6

    .line 31
    .line 32
    invoke-interface {v2, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v10

    .line 36
    check-cast v10, Lt3/p0;

    .line 37
    .line 38
    invoke-static {v10}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v11

    .line 42
    const-string v12, "icon"

    .line 43
    .line 44
    invoke-static {v11, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v11

    .line 48
    if-eqz v11, :cond_5

    .line 49
    .line 50
    invoke-interface {v10, v3, v4}, Lt3/p0;->L(J)Lt3/e1;

    .line 51
    .line 52
    .line 53
    move-result-object v10

    .line 54
    iget-object v11, v0, Li91/h;->a:Lay0/n;

    .line 55
    .line 56
    if-eqz v11, :cond_2

    .line 57
    .line 58
    invoke-interface {v5}, Ljava/util/Collection;->size()I

    .line 59
    .line 60
    .line 61
    move-result v5

    .line 62
    move v6, v9

    .line 63
    :goto_1
    if-ge v6, v5, :cond_1

    .line 64
    .line 65
    invoke-interface {v2, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v7

    .line 69
    move-object v12, v7

    .line 70
    check-cast v12, Lt3/p0;

    .line 71
    .line 72
    invoke-static {v12}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v7

    .line 76
    const-string v13, "label"

    .line 77
    .line 78
    invoke-static {v7, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v7

    .line 82
    if-eqz v7, :cond_0

    .line 83
    .line 84
    const/4 v7, 0x0

    .line 85
    const/16 v8, 0xb

    .line 86
    .line 87
    const/4 v4, 0x0

    .line 88
    const/4 v5, 0x0

    .line 89
    const/4 v6, 0x0

    .line 90
    move-wide/from16 v2, p3

    .line 91
    .line 92
    invoke-static/range {v2 .. v8}, Lt4/a;->a(JIIIII)J

    .line 93
    .line 94
    .line 95
    move-result-wide v4

    .line 96
    move-wide v13, v2

    .line 97
    invoke-interface {v12, v4, v5}, Lt3/p0;->L(J)Lt3/e1;

    .line 98
    .line 99
    .line 100
    move-result-object v2

    .line 101
    goto :goto_2

    .line 102
    :cond_0
    move-wide v13, v3

    .line 103
    add-int/lit8 v6, v6, 0x1

    .line 104
    .line 105
    goto :goto_1

    .line 106
    :cond_1
    invoke-static {v8}, Lf2/m0;->c(Ljava/lang/String;)La8/r0;

    .line 107
    .line 108
    .line 109
    move-result-object v0

    .line 110
    throw v0

    .line 111
    :cond_2
    move-wide v13, v3

    .line 112
    const/4 v2, 0x0

    .line 113
    :goto_2
    sget-object v3, Lmx0/t;->d:Lmx0/t;

    .line 114
    .line 115
    const/16 v4, 0x38

    .line 116
    .line 117
    if-nez v11, :cond_3

    .line 118
    .line 119
    int-to-float v0, v4

    .line 120
    invoke-interface {v1, v0}, Lt4/c;->Q(F)I

    .line 121
    .line 122
    .line 123
    move-result v0

    .line 124
    invoke-static {v0, v13, v14}, Lt4/b;->f(IJ)I

    .line 125
    .line 126
    .line 127
    move-result v0

    .line 128
    iget v2, v10, Lt3/e1;->e:I

    .line 129
    .line 130
    sub-int v2, v0, v2

    .line 131
    .line 132
    div-int/lit8 v2, v2, 0x2

    .line 133
    .line 134
    iget v4, v10, Lt3/e1;->d:I

    .line 135
    .line 136
    new-instance v5, Li2/a;

    .line 137
    .line 138
    const/4 v6, 0x2

    .line 139
    invoke-direct {v5, v10, v2, v6}, Li2/a;-><init>(Lt3/e1;II)V

    .line 140
    .line 141
    .line 142
    invoke-interface {v1, v4, v0, v3, v5}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    return-object v0

    .line 147
    :cond_3
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    sget-object v5, Lt3/d;->a:Lt3/o;

    .line 151
    .line 152
    invoke-virtual {v2, v5}, Lt3/e1;->a0(Lt3/a;)I

    .line 153
    .line 154
    .line 155
    move-result v5

    .line 156
    const/16 v6, 0xc

    .line 157
    .line 158
    int-to-float v6, v6

    .line 159
    invoke-interface {v1, v6}, Lt4/c;->Q(F)I

    .line 160
    .line 161
    .line 162
    move-result v6

    .line 163
    sub-int/2addr v6, v5

    .line 164
    iget v5, v10, Lt3/e1;->e:I

    .line 165
    .line 166
    iget v7, v2, Lt3/e1;->e:I

    .line 167
    .line 168
    add-int/2addr v5, v7

    .line 169
    add-int/2addr v5, v6

    .line 170
    int-to-float v4, v4

    .line 171
    invoke-interface {v1, v4}, Lt4/c;->Q(F)I

    .line 172
    .line 173
    .line 174
    move-result v4

    .line 175
    invoke-static {v5, v4}, Ljava/lang/Math;->max(II)I

    .line 176
    .line 177
    .line 178
    move-result v4

    .line 179
    invoke-static {v4, v13, v14}, Lt4/b;->f(IJ)I

    .line 180
    .line 181
    .line 182
    move-result v4

    .line 183
    sub-int v5, v4, v5

    .line 184
    .line 185
    div-int/lit8 v5, v5, 0x2

    .line 186
    .line 187
    if-gez v5, :cond_4

    .line 188
    .line 189
    move/from16 v20, v9

    .line 190
    .line 191
    goto :goto_3

    .line 192
    :cond_4
    move/from16 v20, v5

    .line 193
    .line 194
    :goto_3
    iget v5, v10, Lt3/e1;->e:I

    .line 195
    .line 196
    sub-int v7, v4, v5

    .line 197
    .line 198
    div-int/lit8 v7, v7, 0x2

    .line 199
    .line 200
    add-int v5, v20, v5

    .line 201
    .line 202
    add-int v16, v5, v6

    .line 203
    .line 204
    iget v5, v2, Lt3/e1;->d:I

    .line 205
    .line 206
    iget v6, v10, Lt3/e1;->d:I

    .line 207
    .line 208
    invoke-static {v5, v6}, Ljava/lang/Math;->max(II)I

    .line 209
    .line 210
    .line 211
    move-result v5

    .line 212
    iget v6, v2, Lt3/e1;->d:I

    .line 213
    .line 214
    sub-int v6, v5, v6

    .line 215
    .line 216
    div-int/lit8 v15, v6, 0x2

    .line 217
    .line 218
    iget v6, v10, Lt3/e1;->d:I

    .line 219
    .line 220
    sub-int v6, v5, v6

    .line 221
    .line 222
    div-int/lit8 v19, v6, 0x2

    .line 223
    .line 224
    sub-int v7, v7, v20

    .line 225
    .line 226
    int-to-float v6, v7

    .line 227
    const/4 v7, 0x1

    .line 228
    int-to-float v7, v7

    .line 229
    iget v13, v0, Li91/h;->b:F

    .line 230
    .line 231
    sub-float/2addr v7, v13

    .line 232
    mul-float/2addr v7, v6

    .line 233
    invoke-static {v7}, Lcy0/a;->i(F)I

    .line 234
    .line 235
    .line 236
    move-result v17

    .line 237
    new-instance v12, Li91/c;

    .line 238
    .line 239
    move-object v14, v2

    .line 240
    move-object/from16 v18, v10

    .line 241
    .line 242
    invoke-direct/range {v12 .. v20}, Li91/c;-><init>(FLt3/e1;IIILt3/e1;II)V

    .line 243
    .line 244
    .line 245
    invoke-interface {v1, v5, v4, v3, v12}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 246
    .line 247
    .line 248
    move-result-object v0

    .line 249
    return-object v0

    .line 250
    :cond_5
    move-wide v13, v3

    .line 251
    add-int/lit8 v7, v7, 0x1

    .line 252
    .line 253
    goto/16 :goto_0

    .line 254
    .line 255
    :cond_6
    invoke-static {v8}, Lf2/m0;->c(Ljava/lang/String;)La8/r0;

    .line 256
    .line 257
    .line 258
    move-result-object v0

    .line 259
    throw v0
.end method
