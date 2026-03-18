.class public abstract Li40/b2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x50

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Li40/b2;->a:F

    .line 5
    .line 6
    const/16 v0, 0x8c

    .line 7
    .line 8
    int-to-float v0, v0

    .line 9
    sput v0, Li40/b2;->b:F

    .line 10
    .line 11
    return-void
.end method

.method public static final a(Lh40/m3;Lx2/s;Lay0/k;Ll2/o;II)V
    .locals 18

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    const-string v0, "luckyDraw"

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    move-object/from16 v6, p3

    .line 9
    .line 10
    check-cast v6, Ll2/t;

    .line 11
    .line 12
    const v0, 0x441474b0

    .line 13
    .line 14
    .line 15
    invoke-virtual {v6, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v6, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    const/4 v0, 0x4

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v0, 0x2

    .line 27
    :goto_0
    or-int v0, p4, v0

    .line 28
    .line 29
    and-int/lit8 v2, p5, 0x2

    .line 30
    .line 31
    if-eqz v2, :cond_2

    .line 32
    .line 33
    or-int/lit8 v0, v0, 0x30

    .line 34
    .line 35
    :cond_1
    move-object/from16 v3, p1

    .line 36
    .line 37
    goto :goto_2

    .line 38
    :cond_2
    and-int/lit8 v3, p4, 0x30

    .line 39
    .line 40
    if-nez v3, :cond_1

    .line 41
    .line 42
    move-object/from16 v3, p1

    .line 43
    .line 44
    invoke-virtual {v6, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v4

    .line 48
    if-eqz v4, :cond_3

    .line 49
    .line 50
    const/16 v4, 0x20

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_3
    const/16 v4, 0x10

    .line 54
    .line 55
    :goto_1
    or-int/2addr v0, v4

    .line 56
    :goto_2
    and-int/lit8 v4, p5, 0x4

    .line 57
    .line 58
    const/16 v5, 0x100

    .line 59
    .line 60
    if-eqz v4, :cond_4

    .line 61
    .line 62
    or-int/lit16 v0, v0, 0x180

    .line 63
    .line 64
    move-object/from16 v7, p2

    .line 65
    .line 66
    goto :goto_4

    .line 67
    :cond_4
    move-object/from16 v7, p2

    .line 68
    .line 69
    invoke-virtual {v6, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v8

    .line 73
    if-eqz v8, :cond_5

    .line 74
    .line 75
    move v8, v5

    .line 76
    goto :goto_3

    .line 77
    :cond_5
    const/16 v8, 0x80

    .line 78
    .line 79
    :goto_3
    or-int/2addr v0, v8

    .line 80
    :goto_4
    and-int/lit16 v8, v0, 0x93

    .line 81
    .line 82
    const/16 v9, 0x92

    .line 83
    .line 84
    const/4 v10, 0x0

    .line 85
    const/4 v11, 0x1

    .line 86
    if-eq v8, v9, :cond_6

    .line 87
    .line 88
    move v8, v11

    .line 89
    goto :goto_5

    .line 90
    :cond_6
    move v8, v10

    .line 91
    :goto_5
    and-int/lit8 v9, v0, 0x1

    .line 92
    .line 93
    invoke-virtual {v6, v9, v8}, Ll2/t;->O(IZ)Z

    .line 94
    .line 95
    .line 96
    move-result v8

    .line 97
    if-eqz v8, :cond_d

    .line 98
    .line 99
    if-eqz v2, :cond_7

    .line 100
    .line 101
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 102
    .line 103
    move-object v12, v2

    .line 104
    goto :goto_6

    .line 105
    :cond_7
    move-object v12, v3

    .line 106
    :goto_6
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 107
    .line 108
    if-eqz v4, :cond_9

    .line 109
    .line 110
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v3

    .line 114
    if-ne v3, v2, :cond_8

    .line 115
    .line 116
    new-instance v3, Lhz0/t1;

    .line 117
    .line 118
    const/16 v4, 0x18

    .line 119
    .line 120
    invoke-direct {v3, v4}, Lhz0/t1;-><init>(I)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {v6, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    :cond_8
    check-cast v3, Lay0/k;

    .line 127
    .line 128
    move-object v9, v3

    .line 129
    goto :goto_7

    .line 130
    :cond_9
    move-object v9, v7

    .line 131
    :goto_7
    and-int/lit16 v0, v0, 0x380

    .line 132
    .line 133
    if-ne v0, v5, :cond_a

    .line 134
    .line 135
    move v10, v11

    .line 136
    :cond_a
    invoke-virtual {v6, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result v0

    .line 140
    or-int/2addr v0, v10

    .line 141
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v3

    .line 145
    if-nez v0, :cond_b

    .line 146
    .line 147
    if-ne v3, v2, :cond_c

    .line 148
    .line 149
    :cond_b
    new-instance v3, Li40/z1;

    .line 150
    .line 151
    const/4 v0, 0x0

    .line 152
    invoke-direct {v3, v9, v1, v0}, Li40/z1;-><init>(Lay0/k;Lh40/m3;I)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {v6, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    :cond_c
    move-object/from16 v16, v3

    .line 159
    .line 160
    check-cast v16, Lay0/a;

    .line 161
    .line 162
    const/16 v17, 0xf

    .line 163
    .line 164
    const/4 v13, 0x0

    .line 165
    const/4 v14, 0x0

    .line 166
    const/4 v15, 0x0

    .line 167
    invoke-static/range {v12 .. v17}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 168
    .line 169
    .line 170
    move-result-object v2

    .line 171
    new-instance v0, Li40/k0;

    .line 172
    .line 173
    const/16 v3, 0xb

    .line 174
    .line 175
    invoke-direct {v0, v3, v1, v9}, Li40/k0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 176
    .line 177
    .line 178
    const v3, -0x1fb5e465

    .line 179
    .line 180
    .line 181
    invoke-static {v3, v6, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 182
    .line 183
    .line 184
    move-result-object v5

    .line 185
    const/16 v7, 0xc00

    .line 186
    .line 187
    const/4 v8, 0x6

    .line 188
    const/4 v3, 0x0

    .line 189
    const/4 v4, 0x0

    .line 190
    invoke-static/range {v2 .. v8}, Li91/d0;->a(Lx2/s;Lay0/a;ZLay0/n;Ll2/o;II)V

    .line 191
    .line 192
    .line 193
    move-object v3, v9

    .line 194
    move-object v2, v12

    .line 195
    goto :goto_8

    .line 196
    :cond_d
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 197
    .line 198
    .line 199
    move-object v2, v3

    .line 200
    move-object v3, v7

    .line 201
    :goto_8
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 202
    .line 203
    .line 204
    move-result-object v7

    .line 205
    if-eqz v7, :cond_e

    .line 206
    .line 207
    new-instance v0, Li40/a2;

    .line 208
    .line 209
    const/4 v6, 0x0

    .line 210
    move/from16 v4, p4

    .line 211
    .line 212
    move/from16 v5, p5

    .line 213
    .line 214
    invoke-direct/range {v0 .. v6}, Li40/a2;-><init>(Lh40/m3;Lx2/s;Lay0/k;III)V

    .line 215
    .line 216
    .line 217
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 218
    .line 219
    :cond_e
    return-void
.end method

.method public static final b(Lh40/m3;Lx2/s;Lay0/k;Ll2/o;II)V
    .locals 18

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    const-string v0, "luckyDraw"

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    move-object/from16 v6, p3

    .line 9
    .line 10
    check-cast v6, Ll2/t;

    .line 11
    .line 12
    const v0, -0x3406e1c9    # -3.2652398E7f

    .line 13
    .line 14
    .line 15
    invoke-virtual {v6, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v6, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    const/4 v0, 0x4

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v0, 0x2

    .line 27
    :goto_0
    or-int v0, p4, v0

    .line 28
    .line 29
    and-int/lit8 v2, p5, 0x2

    .line 30
    .line 31
    if-eqz v2, :cond_2

    .line 32
    .line 33
    or-int/lit8 v0, v0, 0x30

    .line 34
    .line 35
    :cond_1
    move-object/from16 v3, p1

    .line 36
    .line 37
    goto :goto_2

    .line 38
    :cond_2
    and-int/lit8 v3, p4, 0x30

    .line 39
    .line 40
    if-nez v3, :cond_1

    .line 41
    .line 42
    move-object/from16 v3, p1

    .line 43
    .line 44
    invoke-virtual {v6, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v4

    .line 48
    if-eqz v4, :cond_3

    .line 49
    .line 50
    const/16 v4, 0x20

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_3
    const/16 v4, 0x10

    .line 54
    .line 55
    :goto_1
    or-int/2addr v0, v4

    .line 56
    :goto_2
    and-int/lit8 v4, p5, 0x4

    .line 57
    .line 58
    const/16 v5, 0x100

    .line 59
    .line 60
    if-eqz v4, :cond_4

    .line 61
    .line 62
    or-int/lit16 v0, v0, 0x180

    .line 63
    .line 64
    move-object/from16 v7, p2

    .line 65
    .line 66
    goto :goto_4

    .line 67
    :cond_4
    move-object/from16 v7, p2

    .line 68
    .line 69
    invoke-virtual {v6, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v8

    .line 73
    if-eqz v8, :cond_5

    .line 74
    .line 75
    move v8, v5

    .line 76
    goto :goto_3

    .line 77
    :cond_5
    const/16 v8, 0x80

    .line 78
    .line 79
    :goto_3
    or-int/2addr v0, v8

    .line 80
    :goto_4
    and-int/lit16 v8, v0, 0x93

    .line 81
    .line 82
    const/16 v9, 0x92

    .line 83
    .line 84
    const/4 v10, 0x0

    .line 85
    const/4 v11, 0x1

    .line 86
    if-eq v8, v9, :cond_6

    .line 87
    .line 88
    move v8, v11

    .line 89
    goto :goto_5

    .line 90
    :cond_6
    move v8, v10

    .line 91
    :goto_5
    and-int/lit8 v9, v0, 0x1

    .line 92
    .line 93
    invoke-virtual {v6, v9, v8}, Ll2/t;->O(IZ)Z

    .line 94
    .line 95
    .line 96
    move-result v8

    .line 97
    if-eqz v8, :cond_d

    .line 98
    .line 99
    if-eqz v2, :cond_7

    .line 100
    .line 101
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 102
    .line 103
    move-object v12, v2

    .line 104
    goto :goto_6

    .line 105
    :cond_7
    move-object v12, v3

    .line 106
    :goto_6
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 107
    .line 108
    if-eqz v4, :cond_9

    .line 109
    .line 110
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v3

    .line 114
    if-ne v3, v2, :cond_8

    .line 115
    .line 116
    new-instance v3, Lhz0/t1;

    .line 117
    .line 118
    const/16 v4, 0x19

    .line 119
    .line 120
    invoke-direct {v3, v4}, Lhz0/t1;-><init>(I)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {v6, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    :cond_8
    check-cast v3, Lay0/k;

    .line 127
    .line 128
    move-object v9, v3

    .line 129
    goto :goto_7

    .line 130
    :cond_9
    move-object v9, v7

    .line 131
    :goto_7
    and-int/lit16 v0, v0, 0x380

    .line 132
    .line 133
    if-ne v0, v5, :cond_a

    .line 134
    .line 135
    move v10, v11

    .line 136
    :cond_a
    invoke-virtual {v6, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result v0

    .line 140
    or-int/2addr v0, v10

    .line 141
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v3

    .line 145
    if-nez v0, :cond_b

    .line 146
    .line 147
    if-ne v3, v2, :cond_c

    .line 148
    .line 149
    :cond_b
    new-instance v3, Li40/z1;

    .line 150
    .line 151
    const/4 v0, 0x3

    .line 152
    invoke-direct {v3, v9, v1, v0}, Li40/z1;-><init>(Lay0/k;Lh40/m3;I)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {v6, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    :cond_c
    move-object/from16 v16, v3

    .line 159
    .line 160
    check-cast v16, Lay0/a;

    .line 161
    .line 162
    const/16 v17, 0xf

    .line 163
    .line 164
    const/4 v13, 0x0

    .line 165
    const/4 v14, 0x0

    .line 166
    const/4 v15, 0x0

    .line 167
    invoke-static/range {v12 .. v17}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 168
    .line 169
    .line 170
    move-result-object v2

    .line 171
    new-instance v0, Lh2/y5;

    .line 172
    .line 173
    const/16 v3, 0x9

    .line 174
    .line 175
    invoke-direct {v0, v1, v3}, Lh2/y5;-><init>(Ljava/lang/Object;I)V

    .line 176
    .line 177
    .line 178
    const v3, 0x58f0e8ec

    .line 179
    .line 180
    .line 181
    invoke-static {v3, v6, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 182
    .line 183
    .line 184
    move-result-object v5

    .line 185
    const/16 v7, 0xc00

    .line 186
    .line 187
    const/4 v8, 0x6

    .line 188
    const/4 v3, 0x0

    .line 189
    const/4 v4, 0x0

    .line 190
    invoke-static/range {v2 .. v8}, Li91/d0;->a(Lx2/s;Lay0/a;ZLay0/n;Ll2/o;II)V

    .line 191
    .line 192
    .line 193
    move-object v3, v9

    .line 194
    move-object v2, v12

    .line 195
    goto :goto_8

    .line 196
    :cond_d
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 197
    .line 198
    .line 199
    move-object v2, v3

    .line 200
    move-object v3, v7

    .line 201
    :goto_8
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 202
    .line 203
    .line 204
    move-result-object v7

    .line 205
    if-eqz v7, :cond_e

    .line 206
    .line 207
    new-instance v0, Li40/a2;

    .line 208
    .line 209
    const/4 v6, 0x1

    .line 210
    move/from16 v4, p4

    .line 211
    .line 212
    move/from16 v5, p5

    .line 213
    .line 214
    invoke-direct/range {v0 .. v6}, Li40/a2;-><init>(Lh40/m3;Lx2/s;Lay0/k;III)V

    .line 215
    .line 216
    .line 217
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 218
    .line 219
    :cond_e
    return-void
.end method
