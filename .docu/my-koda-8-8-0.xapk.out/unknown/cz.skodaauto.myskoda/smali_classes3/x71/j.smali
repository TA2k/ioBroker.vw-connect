.class public abstract Lx71/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lx71/i;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lx71/i;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lx71/j;->a:Lx71/i;

    .line 7
    .line 8
    return-void
.end method

.method public static final a(Lio/o;Lio/o;)Z
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    :cond_0
    iget-object v2, v1, Lio/o;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Lx71/h;

    .line 8
    .line 9
    iget-wide v3, v2, Lx71/h;->a:J

    .line 10
    .line 11
    iget-wide v5, v2, Lx71/h;->b:J

    .line 12
    .line 13
    iget-object v2, v0, Lio/o;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v2, Lx71/h;

    .line 16
    .line 17
    iget-wide v7, v2, Lx71/h;->a:J

    .line 18
    .line 19
    iget-wide v9, v2, Lx71/h;->b:J

    .line 20
    .line 21
    move-object v11, v0

    .line 22
    const/4 v12, 0x0

    .line 23
    :goto_0
    invoke-virtual {v11}, Lio/o;->a()Lio/o;

    .line 24
    .line 25
    .line 26
    move-result-object v11

    .line 27
    iget-object v13, v11, Lio/o;->e:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v13, Lx71/h;

    .line 30
    .line 31
    iget-wide v14, v13, Lx71/h;->a:J

    .line 32
    .line 33
    move-wide/from16 v16, v3

    .line 34
    .line 35
    const/4 v4, 0x0

    .line 36
    iget-wide v2, v13, Lx71/h;->b:J

    .line 37
    .line 38
    cmp-long v13, v2, v5

    .line 39
    .line 40
    const/16 v18, 0x1

    .line 41
    .line 42
    const/16 v19, -0x1

    .line 43
    .line 44
    if-nez v13, :cond_3

    .line 45
    .line 46
    cmp-long v20, v14, v16

    .line 47
    .line 48
    if-eqz v20, :cond_4

    .line 49
    .line 50
    cmp-long v21, v9, v5

    .line 51
    .line 52
    if-nez v21, :cond_3

    .line 53
    .line 54
    if-lez v20, :cond_1

    .line 55
    .line 56
    move/from16 v20, v4

    .line 57
    .line 58
    move/from16 v4, v18

    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_1
    move/from16 v20, v4

    .line 62
    .line 63
    :goto_1
    cmp-long v21, v7, v16

    .line 64
    .line 65
    if-gez v21, :cond_2

    .line 66
    .line 67
    move-object/from16 v21, v1

    .line 68
    .line 69
    move/from16 v1, v18

    .line 70
    .line 71
    goto :goto_2

    .line 72
    :cond_2
    move-object/from16 v21, v1

    .line 73
    .line 74
    move/from16 v1, v20

    .line 75
    .line 76
    :goto_2
    if-ne v4, v1, :cond_5

    .line 77
    .line 78
    goto/16 :goto_c

    .line 79
    .line 80
    :cond_3
    move-object/from16 v21, v1

    .line 81
    .line 82
    move/from16 v20, v4

    .line 83
    .line 84
    goto :goto_3

    .line 85
    :cond_4
    move-object/from16 v21, v1

    .line 86
    .line 87
    move/from16 v20, v4

    .line 88
    .line 89
    goto/16 :goto_c

    .line 90
    .line 91
    :cond_5
    :goto_3
    cmp-long v1, v9, v5

    .line 92
    .line 93
    if-gez v1, :cond_6

    .line 94
    .line 95
    move/from16 v1, v18

    .line 96
    .line 97
    goto :goto_4

    .line 98
    :cond_6
    move/from16 v1, v20

    .line 99
    .line 100
    :goto_4
    if-gez v13, :cond_7

    .line 101
    .line 102
    move/from16 v4, v18

    .line 103
    .line 104
    goto :goto_5

    .line 105
    :cond_7
    move/from16 v4, v20

    .line 106
    .line 107
    :goto_5
    if-eq v1, v4, :cond_8

    .line 108
    .line 109
    cmp-long v1, v7, v16

    .line 110
    .line 111
    const-wide/16 v22, 0x0

    .line 112
    .line 113
    if-ltz v1, :cond_d

    .line 114
    .line 115
    cmp-long v1, v14, v16

    .line 116
    .line 117
    if-lez v1, :cond_9

    .line 118
    .line 119
    rsub-int/lit8 v12, v12, 0x1

    .line 120
    .line 121
    :cond_8
    move-wide/from16 v24, v2

    .line 122
    .line 123
    goto/16 :goto_b

    .line 124
    .line 125
    :cond_9
    sub-long v7, v7, v16

    .line 126
    .line 127
    long-to-double v7, v7

    .line 128
    move-wide/from16 v24, v2

    .line 129
    .line 130
    sub-long v1, v24, v5

    .line 131
    .line 132
    long-to-double v1, v1

    .line 133
    mul-double/2addr v7, v1

    .line 134
    sub-long v1, v14, v16

    .line 135
    .line 136
    long-to-double v1, v1

    .line 137
    sub-long v3, v9, v5

    .line 138
    .line 139
    long-to-double v3, v3

    .line 140
    mul-double/2addr v1, v3

    .line 141
    sub-double/2addr v7, v1

    .line 142
    cmpg-double v1, v7, v22

    .line 143
    .line 144
    if-nez v1, :cond_a

    .line 145
    .line 146
    goto :goto_c

    .line 147
    :cond_a
    cmpl-double v1, v7, v22

    .line 148
    .line 149
    if-lez v1, :cond_b

    .line 150
    .line 151
    move/from16 v1, v18

    .line 152
    .line 153
    goto :goto_6

    .line 154
    :cond_b
    move/from16 v1, v20

    .line 155
    .line 156
    :goto_6
    cmp-long v2, v24, v9

    .line 157
    .line 158
    if-lez v2, :cond_c

    .line 159
    .line 160
    move/from16 v2, v18

    .line 161
    .line 162
    goto :goto_7

    .line 163
    :cond_c
    move/from16 v2, v20

    .line 164
    .line 165
    :goto_7
    if-ne v1, v2, :cond_11

    .line 166
    .line 167
    :goto_8
    rsub-int/lit8 v12, v12, 0x1

    .line 168
    .line 169
    goto :goto_b

    .line 170
    :cond_d
    move-wide/from16 v24, v2

    .line 171
    .line 172
    cmp-long v1, v14, v16

    .line 173
    .line 174
    if-lez v1, :cond_11

    .line 175
    .line 176
    sub-long v7, v7, v16

    .line 177
    .line 178
    long-to-double v1, v7

    .line 179
    sub-long v3, v24, v5

    .line 180
    .line 181
    long-to-double v3, v3

    .line 182
    mul-double/2addr v1, v3

    .line 183
    sub-long v3, v14, v16

    .line 184
    .line 185
    long-to-double v3, v3

    .line 186
    sub-long v7, v9, v5

    .line 187
    .line 188
    long-to-double v7, v7

    .line 189
    mul-double/2addr v3, v7

    .line 190
    sub-double/2addr v1, v3

    .line 191
    cmpg-double v3, v1, v22

    .line 192
    .line 193
    if-nez v3, :cond_e

    .line 194
    .line 195
    goto :goto_c

    .line 196
    :cond_e
    cmpl-double v1, v1, v22

    .line 197
    .line 198
    if-lez v1, :cond_f

    .line 199
    .line 200
    move/from16 v1, v18

    .line 201
    .line 202
    goto :goto_9

    .line 203
    :cond_f
    move/from16 v1, v20

    .line 204
    .line 205
    :goto_9
    cmp-long v2, v24, v9

    .line 206
    .line 207
    if-lez v2, :cond_10

    .line 208
    .line 209
    move/from16 v2, v18

    .line 210
    .line 211
    goto :goto_a

    .line 212
    :cond_10
    move/from16 v2, v20

    .line 213
    .line 214
    :goto_a
    if-ne v1, v2, :cond_11

    .line 215
    .line 216
    goto :goto_8

    .line 217
    :cond_11
    :goto_b
    invoke-virtual {v0, v11}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 218
    .line 219
    .line 220
    move-result v1

    .line 221
    if-eqz v1, :cond_14

    .line 222
    .line 223
    move/from16 v19, v12

    .line 224
    .line 225
    :goto_c
    if-ltz v19, :cond_13

    .line 226
    .line 227
    if-lez v19, :cond_12

    .line 228
    .line 229
    goto :goto_d

    .line 230
    :cond_12
    return v20

    .line 231
    :cond_13
    invoke-virtual/range {v21 .. v21}, Lio/o;->a()Lio/o;

    .line 232
    .line 233
    .line 234
    move-result-object v1

    .line 235
    move-object/from16 v2, p1

    .line 236
    .line 237
    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 238
    .line 239
    .line 240
    move-result v3

    .line 241
    if-eqz v3, :cond_0

    .line 242
    .line 243
    :goto_d
    return v18

    .line 244
    :cond_14
    move-object/from16 v2, p1

    .line 245
    .line 246
    move-wide v7, v14

    .line 247
    move-wide/from16 v3, v16

    .line 248
    .line 249
    move-object/from16 v1, v21

    .line 250
    .line 251
    move-wide/from16 v9, v24

    .line 252
    .line 253
    goto/16 :goto_0
.end method

.method public static final b(Lx71/h;Lx71/h;)D
    .locals 6

    .line 1
    iget-wide v0, p0, Lx71/h;->b:J

    .line 2
    .line 3
    iget-wide v2, p1, Lx71/h;->b:J

    .line 4
    .line 5
    cmp-long v4, v0, v2

    .line 6
    .line 7
    if-nez v4, :cond_0

    .line 8
    .line 9
    const-wide p0, -0x381006cc38732053L    # -3.4E38

    .line 10
    .line 11
    .line 12
    .line 13
    .line 14
    return-wide p0

    .line 15
    :cond_0
    iget-wide v4, p1, Lx71/h;->a:J

    .line 16
    .line 17
    iget-wide p0, p0, Lx71/h;->a:J

    .line 18
    .line 19
    sub-long/2addr v4, p0

    .line 20
    long-to-double p0, v4

    .line 21
    sub-long/2addr v2, v0

    .line 22
    long-to-double v0, v2

    .line 23
    div-double/2addr p0, v0

    .line 24
    return-wide p0
.end method

.method public static final c(Lx71/n;Lx71/n;Lx71/n;Lx71/h;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    const-string v0, "<set-?>"

    .line 5
    .line 6
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lx71/n;->l:Lx71/n;

    .line 10
    .line 11
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    iput-object p2, p0, Lx71/n;->m:Lx71/n;

    .line 15
    .line 16
    iget-object p1, p0, Lx71/n;->b:Lx71/h;

    .line 17
    .line 18
    iget-wide v0, p3, Lx71/h;->a:J

    .line 19
    .line 20
    iput-wide v0, p1, Lx71/h;->a:J

    .line 21
    .line 22
    iget-wide p2, p3, Lx71/h;->b:J

    .line 23
    .line 24
    iput-wide p2, p1, Lx71/h;->b:J

    .line 25
    .line 26
    const/4 p1, -0x1

    .line 27
    iput p1, p0, Lx71/n;->k:I

    .line 28
    .line 29
    return-void
.end method

.method public static final d(Lx71/n;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lx71/n;->c:Lx71/h;

    .line 2
    .line 3
    iget-wide v1, v0, Lx71/h;->a:J

    .line 4
    .line 5
    iget-object p0, p0, Lx71/n;->a:Lx71/h;

    .line 6
    .line 7
    iget-wide v3, p0, Lx71/h;->a:J

    .line 8
    .line 9
    iput-wide v3, v0, Lx71/h;->a:J

    .line 10
    .line 11
    iput-wide v1, p0, Lx71/h;->a:J

    .line 12
    .line 13
    return-void
.end method

.method public static final e(Lio/o;)V
    .locals 3

    .line 1
    move-object v0, p0

    .line 2
    :goto_0
    invoke-virtual {v0}, Lio/o;->a()Lio/o;

    .line 3
    .line 4
    .line 5
    move-result-object v1

    .line 6
    invoke-virtual {v0}, Lio/o;->b()Lio/o;

    .line 7
    .line 8
    .line 9
    move-result-object v2

    .line 10
    iput-object v2, v0, Lio/o;->f:Ljava/lang/Object;

    .line 11
    .line 12
    iput-object v1, v0, Lio/o;->g:Ljava/lang/Object;

    .line 13
    .line 14
    invoke-virtual {v1, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    move-object v0, v1

    .line 22
    goto :goto_0
.end method

.method public static final f(Lx71/n;J)J
    .locals 7

    .line 1
    iget-object v0, p0, Lx71/n;->c:Lx71/h;

    .line 2
    .line 3
    iget-wide v1, v0, Lx71/h;->b:J

    .line 4
    .line 5
    cmp-long v1, p1, v1

    .line 6
    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    iget-wide p0, v0, Lx71/h;->a:J

    .line 10
    .line 11
    return-wide p0

    .line 12
    :cond_0
    iget-object v0, p0, Lx71/n;->a:Lx71/h;

    .line 13
    .line 14
    iget-wide v1, v0, Lx71/h;->a:J

    .line 15
    .line 16
    iget-wide v3, p0, Lx71/n;->e:D

    .line 17
    .line 18
    iget-wide v5, v0, Lx71/h;->b:J

    .line 19
    .line 20
    sub-long/2addr p1, v5

    .line 21
    long-to-double p0, p1

    .line 22
    mul-double/2addr v3, p0

    .line 23
    invoke-static {v3, v4}, Lcy0/a;->j(D)J

    .line 24
    .line 25
    .line 26
    move-result-wide p0

    .line 27
    add-long/2addr p0, v1

    .line 28
    return-wide p0
.end method

.method public static final g(Lio/o;)D
    .locals 10

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-wide/16 v0, 0x0

    .line 7
    .line 8
    move-object v2, p0

    .line 9
    :cond_0
    iget-object v3, v2, Lio/o;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v3, Lx71/h;

    .line 12
    .line 13
    invoke-virtual {v2}, Lio/o;->b()Lio/o;

    .line 14
    .line 15
    .line 16
    move-result-object v4

    .line 17
    iget-object v4, v4, Lio/o;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v4, Lx71/h;

    .line 20
    .line 21
    iget-wide v4, v4, Lx71/h;->a:J

    .line 22
    .line 23
    iget-wide v6, v3, Lx71/h;->a:J

    .line 24
    .line 25
    add-long/2addr v4, v6

    .line 26
    long-to-double v4, v4

    .line 27
    invoke-virtual {v2}, Lio/o;->b()Lio/o;

    .line 28
    .line 29
    .line 30
    move-result-object v6

    .line 31
    iget-object v6, v6, Lio/o;->e:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v6, Lx71/h;

    .line 34
    .line 35
    iget-wide v6, v6, Lx71/h;->b:J

    .line 36
    .line 37
    iget-wide v8, v3, Lx71/h;->b:J

    .line 38
    .line 39
    sub-long/2addr v6, v8

    .line 40
    long-to-double v6, v6

    .line 41
    mul-double/2addr v4, v6

    .line 42
    add-double/2addr v0, v4

    .line 43
    invoke-virtual {v2}, Lio/o;->a()Lio/o;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    invoke-virtual {v2, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v3

    .line 51
    if-eqz v3, :cond_0

    .line 52
    .line 53
    const-wide/high16 v2, 0x3fe0000000000000L    # 0.5

    .line 54
    .line 55
    mul-double/2addr v0, v2

    .line 56
    return-wide v0
.end method

.method public static final h(Lx71/n;)Z
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lx71/n;->d:Lx71/h;

    .line 7
    .line 8
    iget-wide v0, p0, Lx71/h;->b:J

    .line 9
    .line 10
    const-wide/16 v2, 0x0

    .line 11
    .line 12
    cmp-long p0, v0, v2

    .line 13
    .line 14
    if-nez p0, :cond_0

    .line 15
    .line 16
    const/4 p0, 0x1

    .line 17
    return p0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    return p0
.end method

.method public static final i(Lx71/k;Lx71/k;)Z
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "outRec2"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    :cond_0
    iget-object p0, p0, Lx71/k;->d:Lx71/k;

    .line 12
    .line 13
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_1

    .line 18
    .line 19
    const/4 p0, 0x1

    .line 20
    return p0

    .line 21
    :cond_1
    if-nez p0, :cond_0

    .line 22
    .line 23
    const/4 p0, 0x0

    .line 24
    return p0
.end method

.method public static final j(Lx71/h;Lx71/h;Lx71/h;)Z
    .locals 7

    .line 1
    invoke-virtual {p0, p2}, Lx71/h;->equals(Ljava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-nez v0, :cond_6

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lx71/h;->equals(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-nez v0, :cond_6

    .line 13
    .line 14
    invoke-virtual {p2, p1}, Lx71/h;->equals(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    goto :goto_5

    .line 21
    :cond_0
    iget-wide v2, p0, Lx71/h;->a:J

    .line 22
    .line 23
    iget-wide v4, p2, Lx71/h;->a:J

    .line 24
    .line 25
    cmp-long v0, v2, v4

    .line 26
    .line 27
    const/4 v6, 0x1

    .line 28
    if-eqz v0, :cond_3

    .line 29
    .line 30
    iget-wide p0, p1, Lx71/h;->a:J

    .line 31
    .line 32
    cmp-long p2, p0, v2

    .line 33
    .line 34
    if-lez p2, :cond_1

    .line 35
    .line 36
    move p2, v6

    .line 37
    goto :goto_0

    .line 38
    :cond_1
    move p2, v1

    .line 39
    :goto_0
    cmp-long p0, p0, v4

    .line 40
    .line 41
    if-gez p0, :cond_2

    .line 42
    .line 43
    move p0, v6

    .line 44
    goto :goto_1

    .line 45
    :cond_2
    move p0, v1

    .line 46
    :goto_1
    if-ne p2, p0, :cond_6

    .line 47
    .line 48
    goto :goto_4

    .line 49
    :cond_3
    iget-wide v2, p1, Lx71/h;->b:J

    .line 50
    .line 51
    iget-wide p0, p0, Lx71/h;->b:J

    .line 52
    .line 53
    cmp-long p0, v2, p0

    .line 54
    .line 55
    if-lez p0, :cond_4

    .line 56
    .line 57
    move p0, v6

    .line 58
    goto :goto_2

    .line 59
    :cond_4
    move p0, v1

    .line 60
    :goto_2
    iget-wide p1, p2, Lx71/h;->b:J

    .line 61
    .line 62
    cmp-long p1, v2, p1

    .line 63
    .line 64
    if-gez p1, :cond_5

    .line 65
    .line 66
    move p1, v6

    .line 67
    goto :goto_3

    .line 68
    :cond_5
    move p1, v1

    .line 69
    :goto_3
    if-ne p0, p1, :cond_6

    .line 70
    .line 71
    :goto_4
    return v6

    .line 72
    :cond_6
    :goto_5
    return v1
.end method

.method public static final k(Lx71/h;Lx71/h;Lx71/h;Lx71/h;Z)Z
    .locals 6

    .line 1
    if-eqz p4, :cond_0

    .line 2
    .line 3
    iget-wide v0, p0, Lx71/h;->b:J

    .line 4
    .line 5
    iget-wide v2, p1, Lx71/h;->b:J

    .line 6
    .line 7
    sub-long/2addr v0, v2

    .line 8
    iget-wide v2, p2, Lx71/h;->a:J

    .line 9
    .line 10
    iget-wide v4, p3, Lx71/h;->a:J

    .line 11
    .line 12
    sub-long/2addr v2, v4

    .line 13
    mul-long/2addr v2, v0

    .line 14
    iget-wide v0, p0, Lx71/h;->a:J

    .line 15
    .line 16
    iget-wide p0, p1, Lx71/h;->a:J

    .line 17
    .line 18
    sub-long/2addr v0, p0

    .line 19
    iget-wide p0, p2, Lx71/h;->b:J

    .line 20
    .line 21
    iget-wide p2, p3, Lx71/h;->b:J

    .line 22
    .line 23
    sub-long/2addr p0, p2

    .line 24
    mul-long/2addr p0, v0

    .line 25
    cmp-long p0, v2, p0

    .line 26
    .line 27
    if-nez p0, :cond_1

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    iget-wide v0, p0, Lx71/h;->b:J

    .line 31
    .line 32
    iget-wide v2, p1, Lx71/h;->b:J

    .line 33
    .line 34
    sub-long/2addr v0, v2

    .line 35
    iget-wide v2, p2, Lx71/h;->a:J

    .line 36
    .line 37
    iget-wide v4, p3, Lx71/h;->a:J

    .line 38
    .line 39
    sub-long/2addr v2, v4

    .line 40
    mul-long/2addr v2, v0

    .line 41
    iget-wide v0, p0, Lx71/h;->a:J

    .line 42
    .line 43
    iget-wide p0, p1, Lx71/h;->a:J

    .line 44
    .line 45
    sub-long/2addr v0, p0

    .line 46
    iget-wide p0, p2, Lx71/h;->b:J

    .line 47
    .line 48
    iget-wide p2, p3, Lx71/h;->b:J

    .line 49
    .line 50
    sub-long/2addr p0, p2

    .line 51
    mul-long/2addr p0, v0

    .line 52
    cmp-long p0, v2, p0

    .line 53
    .line 54
    if-nez p0, :cond_1

    .line 55
    .line 56
    :goto_0
    const/4 p0, 0x1

    .line 57
    return p0

    .line 58
    :cond_1
    const/4 p0, 0x0

    .line 59
    return p0
.end method

.method public static final l(Lx71/h;Lx71/h;Lx71/h;Z)Z
    .locals 8

    .line 1
    if-eqz p3, :cond_0

    .line 2
    .line 3
    iget-wide v0, p0, Lx71/h;->b:J

    .line 4
    .line 5
    iget-wide v2, p1, Lx71/h;->b:J

    .line 6
    .line 7
    sub-long/2addr v0, v2

    .line 8
    iget-wide v4, p1, Lx71/h;->a:J

    .line 9
    .line 10
    iget-wide v6, p2, Lx71/h;->a:J

    .line 11
    .line 12
    sub-long v6, v4, v6

    .line 13
    .line 14
    mul-long/2addr v6, v0

    .line 15
    iget-wide p0, p0, Lx71/h;->a:J

    .line 16
    .line 17
    sub-long/2addr p0, v4

    .line 18
    iget-wide p2, p2, Lx71/h;->b:J

    .line 19
    .line 20
    sub-long/2addr v2, p2

    .line 21
    mul-long/2addr v2, p0

    .line 22
    cmp-long p0, v6, v2

    .line 23
    .line 24
    if-nez p0, :cond_1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    iget-wide v0, p0, Lx71/h;->b:J

    .line 28
    .line 29
    iget-wide v2, p1, Lx71/h;->b:J

    .line 30
    .line 31
    sub-long/2addr v0, v2

    .line 32
    iget-wide v4, p1, Lx71/h;->a:J

    .line 33
    .line 34
    iget-wide v6, p2, Lx71/h;->a:J

    .line 35
    .line 36
    sub-long v6, v4, v6

    .line 37
    .line 38
    mul-long/2addr v6, v0

    .line 39
    iget-wide p0, p0, Lx71/h;->a:J

    .line 40
    .line 41
    sub-long/2addr p0, v4

    .line 42
    iget-wide p2, p2, Lx71/h;->b:J

    .line 43
    .line 44
    sub-long/2addr v2, p2

    .line 45
    mul-long/2addr v2, p0

    .line 46
    cmp-long p0, v6, v2

    .line 47
    .line 48
    if-nez p0, :cond_1

    .line 49
    .line 50
    :goto_0
    const/4 p0, 0x1

    .line 51
    return p0

    .line 52
    :cond_1
    const/4 p0, 0x0

    .line 53
    return p0
.end method

.method public static final m(Lx71/n;Lx71/n;Z)Z
    .locals 4

    .line 1
    const-string v0, "e1"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lx71/n;->d:Lx71/h;

    .line 7
    .line 8
    iget-object p1, p1, Lx71/n;->d:Lx71/h;

    .line 9
    .line 10
    if-eqz p2, :cond_0

    .line 11
    .line 12
    iget-wide v0, p0, Lx71/h;->b:J

    .line 13
    .line 14
    iget-wide v2, p1, Lx71/h;->a:J

    .line 15
    .line 16
    mul-long/2addr v0, v2

    .line 17
    iget-wide v2, p0, Lx71/h;->a:J

    .line 18
    .line 19
    iget-wide p0, p1, Lx71/h;->b:J

    .line 20
    .line 21
    mul-long/2addr v2, p0

    .line 22
    cmp-long p0, v0, v2

    .line 23
    .line 24
    if-nez p0, :cond_1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    iget-wide v0, p0, Lx71/h;->b:J

    .line 28
    .line 29
    iget-wide v2, p1, Lx71/h;->a:J

    .line 30
    .line 31
    mul-long/2addr v0, v2

    .line 32
    iget-wide v2, p0, Lx71/h;->a:J

    .line 33
    .line 34
    iget-wide p0, p1, Lx71/h;->b:J

    .line 35
    .line 36
    mul-long/2addr v2, p0

    .line 37
    cmp-long p0, v0, v2

    .line 38
    .line 39
    if-nez p0, :cond_1

    .line 40
    .line 41
    :goto_0
    const/4 p0, 0x1

    .line 42
    return p0

    .line 43
    :cond_1
    const/4 p0, 0x0

    .line 44
    return p0
.end method
