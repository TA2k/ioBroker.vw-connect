.class public final synthetic Lh2/y8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J

.field public final synthetic f:J

.field public final synthetic g:J

.field public final synthetic h:J

.field public final synthetic i:F

.field public final synthetic j:F

.field public final synthetic k:Lay0/n;

.field public final synthetic l:Lay0/o;

.field public final synthetic m:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;JJJJFFLay0/n;Lay0/o;I)V
    .locals 0

    .line 1
    iput p14, p0, Lh2/y8;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/y8;->m:Ljava/lang/Object;

    .line 4
    .line 5
    iput-wide p2, p0, Lh2/y8;->e:J

    .line 6
    .line 7
    iput-wide p4, p0, Lh2/y8;->f:J

    .line 8
    .line 9
    iput-wide p6, p0, Lh2/y8;->g:J

    .line 10
    .line 11
    iput-wide p8, p0, Lh2/y8;->h:J

    .line 12
    .line 13
    iput p10, p0, Lh2/y8;->i:F

    .line 14
    .line 15
    iput p11, p0, Lh2/y8;->j:F

    .line 16
    .line 17
    iput-object p12, p0, Lh2/y8;->k:Lay0/n;

    .line 18
    .line 19
    iput-object p13, p0, Lh2/y8;->l:Lay0/o;

    .line 20
    .line 21
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 22
    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 31

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh2/y8;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    const-wide v3, 0xffffffffL

    .line 8
    .line 9
    .line 10
    .line 11
    .line 12
    const/4 v5, 0x2

    .line 13
    iget-object v6, v0, Lh2/y8;->m:Ljava/lang/Object;

    .line 14
    .line 15
    const/high16 v7, 0x7fc00000    # Float.NaN

    .line 16
    .line 17
    packed-switch v1, :pswitch_data_0

    .line 18
    .line 19
    .line 20
    check-cast v6, Lh2/s9;

    .line 21
    .line 22
    move-object/from16 v8, p1

    .line 23
    .line 24
    check-cast v8, Lg3/d;

    .line 25
    .line 26
    invoke-static {v7, v7}, Lt4/f;->a(FF)Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-eqz v1, :cond_1

    .line 31
    .line 32
    iget-object v1, v6, Lh2/s9;->m:Lg1/w1;

    .line 33
    .line 34
    sget-object v7, Lg1/w1;->d:Lg1/w1;

    .line 35
    .line 36
    if-ne v1, v7, :cond_0

    .line 37
    .line 38
    invoke-interface {v8}, Lg3/d;->e()J

    .line 39
    .line 40
    .line 41
    move-result-wide v3

    .line 42
    const/16 v1, 0x20

    .line 43
    .line 44
    shr-long/2addr v3, v1

    .line 45
    long-to-int v1, v3

    .line 46
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    :goto_0
    int-to-float v3, v5

    .line 51
    div-float/2addr v1, v3

    .line 52
    goto :goto_1

    .line 53
    :cond_0
    invoke-interface {v8}, Lg3/d;->e()J

    .line 54
    .line 55
    .line 56
    move-result-wide v9

    .line 57
    and-long/2addr v3, v9

    .line 58
    long-to-int v1, v3

    .line 59
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    goto :goto_0

    .line 64
    :cond_1
    invoke-interface {v8, v7}, Lt4/c;->w0(F)F

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    :goto_1
    sget-object v3, Lh2/a9;->a:Lh2/a9;

    .line 69
    .line 70
    iget-object v9, v6, Lh2/s9;->g:[F

    .line 71
    .line 72
    invoke-virtual {v6}, Lh2/s9;->c()F

    .line 73
    .line 74
    .line 75
    move-result v11

    .line 76
    const/4 v3, 0x0

    .line 77
    invoke-interface {v8, v3}, Lt4/c;->n0(I)F

    .line 78
    .line 79
    .line 80
    move-result v20

    .line 81
    invoke-interface {v8, v3}, Lt4/c;->n0(I)F

    .line 82
    .line 83
    .line 84
    move-result v21

    .line 85
    iget-object v3, v6, Lh2/s9;->k:Ll2/g1;

    .line 86
    .line 87
    invoke-virtual {v3}, Ll2/g1;->o()I

    .line 88
    .line 89
    .line 90
    move-result v3

    .line 91
    invoke-interface {v8, v3}, Lt4/c;->n0(I)F

    .line 92
    .line 93
    .line 94
    move-result v22

    .line 95
    iget-object v3, v6, Lh2/s9;->l:Ll2/g1;

    .line 96
    .line 97
    invoke-virtual {v3}, Ll2/g1;->o()I

    .line 98
    .line 99
    .line 100
    move-result v3

    .line 101
    invoke-interface {v8, v3}, Lt4/c;->n0(I)F

    .line 102
    .line 103
    .line 104
    move-result v23

    .line 105
    invoke-interface {v8, v1}, Lt4/c;->o0(F)F

    .line 106
    .line 107
    .line 108
    move-result v26

    .line 109
    const/16 v29, 0x0

    .line 110
    .line 111
    iget-object v1, v6, Lh2/s9;->m:Lg1/w1;

    .line 112
    .line 113
    iget-wide v12, v0, Lh2/y8;->e:J

    .line 114
    .line 115
    iget-wide v14, v0, Lh2/y8;->f:J

    .line 116
    .line 117
    iget-wide v3, v0, Lh2/y8;->g:J

    .line 118
    .line 119
    iget-wide v5, v0, Lh2/y8;->h:J

    .line 120
    .line 121
    iget v7, v0, Lh2/y8;->i:F

    .line 122
    .line 123
    iget v10, v0, Lh2/y8;->j:F

    .line 124
    .line 125
    move-object/from16 v30, v1

    .line 126
    .line 127
    iget-object v1, v0, Lh2/y8;->k:Lay0/n;

    .line 128
    .line 129
    iget-object v0, v0, Lh2/y8;->l:Lay0/o;

    .line 130
    .line 131
    move-object/from16 v28, v0

    .line 132
    .line 133
    move-object/from16 v27, v1

    .line 134
    .line 135
    move-wide/from16 v16, v3

    .line 136
    .line 137
    move-wide/from16 v18, v5

    .line 138
    .line 139
    move/from16 v24, v7

    .line 140
    .line 141
    move/from16 v25, v10

    .line 142
    .line 143
    const/4 v10, 0x0

    .line 144
    invoke-static/range {v8 .. v30}, Lh2/a9;->g(Lg3/d;[FFFJJJJFFFFFFFLay0/n;Lay0/o;ZLg1/w1;)V

    .line 145
    .line 146
    .line 147
    return-object v2

    .line 148
    :pswitch_0
    check-cast v6, Lh2/u7;

    .line 149
    .line 150
    move-object/from16 v8, p1

    .line 151
    .line 152
    check-cast v8, Lg3/d;

    .line 153
    .line 154
    invoke-static {v7, v7}, Lt4/f;->a(FF)Z

    .line 155
    .line 156
    .line 157
    move-result v1

    .line 158
    if-eqz v1, :cond_2

    .line 159
    .line 160
    invoke-interface {v8}, Lg3/d;->e()J

    .line 161
    .line 162
    .line 163
    move-result-wide v9

    .line 164
    and-long/2addr v3, v9

    .line 165
    long-to-int v1, v3

    .line 166
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 167
    .line 168
    .line 169
    move-result v1

    .line 170
    int-to-float v3, v5

    .line 171
    div-float/2addr v1, v3

    .line 172
    goto :goto_2

    .line 173
    :cond_2
    invoke-interface {v8, v7}, Lt4/c;->w0(F)F

    .line 174
    .line 175
    .line 176
    move-result v1

    .line 177
    :goto_2
    sget-object v3, Lh2/a9;->a:Lh2/a9;

    .line 178
    .line 179
    iget-object v9, v6, Lh2/u7;->g:[F

    .line 180
    .line 181
    invoke-virtual {v6}, Lh2/u7;->b()F

    .line 182
    .line 183
    .line 184
    move-result v10

    .line 185
    invoke-virtual {v6}, Lh2/u7;->a()F

    .line 186
    .line 187
    .line 188
    move-result v11

    .line 189
    iget-object v3, v6, Lh2/u7;->h:Ll2/f1;

    .line 190
    .line 191
    invoke-virtual {v3}, Ll2/f1;->o()F

    .line 192
    .line 193
    .line 194
    move-result v3

    .line 195
    invoke-interface {v8, v3}, Lt4/c;->o0(F)F

    .line 196
    .line 197
    .line 198
    move-result v20

    .line 199
    iget-object v3, v6, Lh2/u7;->i:Ll2/f1;

    .line 200
    .line 201
    invoke-virtual {v3}, Ll2/f1;->o()F

    .line 202
    .line 203
    .line 204
    move-result v3

    .line 205
    invoke-interface {v8, v3}, Lt4/c;->o0(F)F

    .line 206
    .line 207
    .line 208
    move-result v21

    .line 209
    iget-object v3, v6, Lh2/u7;->j:Ll2/f1;

    .line 210
    .line 211
    invoke-virtual {v3}, Ll2/f1;->o()F

    .line 212
    .line 213
    .line 214
    move-result v3

    .line 215
    invoke-interface {v8, v3}, Lt4/c;->o0(F)F

    .line 216
    .line 217
    .line 218
    move-result v22

    .line 219
    iget-object v3, v6, Lh2/u7;->k:Ll2/f1;

    .line 220
    .line 221
    invoke-virtual {v3}, Ll2/f1;->o()F

    .line 222
    .line 223
    .line 224
    move-result v3

    .line 225
    invoke-interface {v8, v3}, Lt4/c;->o0(F)F

    .line 226
    .line 227
    .line 228
    move-result v23

    .line 229
    invoke-interface {v8, v1}, Lt4/c;->o0(F)F

    .line 230
    .line 231
    .line 232
    move-result v26

    .line 233
    const/16 v29, 0x1

    .line 234
    .line 235
    sget-object v30, Lg1/w1;->e:Lg1/w1;

    .line 236
    .line 237
    iget-wide v12, v0, Lh2/y8;->e:J

    .line 238
    .line 239
    iget-wide v14, v0, Lh2/y8;->f:J

    .line 240
    .line 241
    iget-wide v3, v0, Lh2/y8;->g:J

    .line 242
    .line 243
    iget-wide v5, v0, Lh2/y8;->h:J

    .line 244
    .line 245
    iget v1, v0, Lh2/y8;->i:F

    .line 246
    .line 247
    iget v7, v0, Lh2/y8;->j:F

    .line 248
    .line 249
    move/from16 v24, v1

    .line 250
    .line 251
    iget-object v1, v0, Lh2/y8;->k:Lay0/n;

    .line 252
    .line 253
    iget-object v0, v0, Lh2/y8;->l:Lay0/o;

    .line 254
    .line 255
    move-object/from16 v28, v0

    .line 256
    .line 257
    move-object/from16 v27, v1

    .line 258
    .line 259
    move-wide/from16 v16, v3

    .line 260
    .line 261
    move-wide/from16 v18, v5

    .line 262
    .line 263
    move/from16 v25, v7

    .line 264
    .line 265
    invoke-static/range {v8 .. v30}, Lh2/a9;->g(Lg3/d;[FFFJJJJFFFFFFFLay0/n;Lay0/o;ZLg1/w1;)V

    .line 266
    .line 267
    .line 268
    return-object v2

    .line 269
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
