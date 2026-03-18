.class public abstract Lxf0/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x7a

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Lxf0/g0;->a:F

    .line 5
    .line 6
    return-void
.end method

.method public static final a(Lt2/b;FLe1/n1;Ll2/o;I)V
    .locals 8

    .line 1
    check-cast p3, Ll2/t;

    .line 2
    .line 3
    const v0, 0x67dd8e9b

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p3, p1}, Ll2/t;->d(F)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    const/16 v0, 0x20

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/16 v0, 0x10

    .line 19
    .line 20
    :goto_0
    or-int/2addr v0, p4

    .line 21
    invoke-virtual {p3, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-eqz v1, :cond_1

    .line 26
    .line 27
    const/16 v1, 0x100

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_1
    const/16 v1, 0x80

    .line 31
    .line 32
    :goto_1
    or-int/2addr v0, v1

    .line 33
    and-int/lit16 v1, v0, 0x93

    .line 34
    .line 35
    const/16 v2, 0x92

    .line 36
    .line 37
    const/4 v3, 0x1

    .line 38
    if-eq v1, v2, :cond_2

    .line 39
    .line 40
    move v1, v3

    .line 41
    goto :goto_2

    .line 42
    :cond_2
    const/4 v1, 0x0

    .line 43
    :goto_2
    and-int/2addr v0, v3

    .line 44
    invoke-virtual {p3, v0, v1}, Ll2/t;->O(IZ)Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-eqz v0, :cond_6

    .line 49
    .line 50
    sget-object v0, Lx2/c;->q:Lx2/h;

    .line 51
    .line 52
    const/16 v1, 0xe

    .line 53
    .line 54
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 55
    .line 56
    invoke-static {v2, p2, v1}, Lkp/n;->d(Lx2/s;Le1/n1;I)Lx2/s;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    sget-object v4, Lk1/j;->c:Lk1/e;

    .line 61
    .line 62
    const/16 v5, 0x30

    .line 63
    .line 64
    invoke-static {v4, v0, p3, v5}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    iget-wide v4, p3, Ll2/t;->T:J

    .line 69
    .line 70
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 71
    .line 72
    .line 73
    move-result v4

    .line 74
    invoke-virtual {p3}, Ll2/t;->m()Ll2/p1;

    .line 75
    .line 76
    .line 77
    move-result-object v5

    .line 78
    invoke-static {p3, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 79
    .line 80
    .line 81
    move-result-object v1

    .line 82
    sget-object v6, Lv3/k;->m1:Lv3/j;

    .line 83
    .line 84
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 85
    .line 86
    .line 87
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 88
    .line 89
    invoke-virtual {p3}, Ll2/t;->c0()V

    .line 90
    .line 91
    .line 92
    iget-boolean v7, p3, Ll2/t;->S:Z

    .line 93
    .line 94
    if-eqz v7, :cond_3

    .line 95
    .line 96
    invoke-virtual {p3, v6}, Ll2/t;->l(Lay0/a;)V

    .line 97
    .line 98
    .line 99
    goto :goto_3

    .line 100
    :cond_3
    invoke-virtual {p3}, Ll2/t;->m0()V

    .line 101
    .line 102
    .line 103
    :goto_3
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 104
    .line 105
    invoke-static {v6, v0, p3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 106
    .line 107
    .line 108
    sget-object v0, Lv3/j;->f:Lv3/h;

    .line 109
    .line 110
    invoke-static {v0, v5, p3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 111
    .line 112
    .line 113
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 114
    .line 115
    iget-boolean v5, p3, Ll2/t;->S:Z

    .line 116
    .line 117
    if-nez v5, :cond_4

    .line 118
    .line 119
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v5

    .line 123
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 124
    .line 125
    .line 126
    move-result-object v6

    .line 127
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result v5

    .line 131
    if-nez v5, :cond_5

    .line 132
    .line 133
    :cond_4
    invoke-static {v4, p3, v4, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 134
    .line 135
    .line 136
    :cond_5
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 137
    .line 138
    invoke-static {v0, v1, p3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 139
    .line 140
    .line 141
    const/16 v0, 0x18

    .line 142
    .line 143
    int-to-float v0, v0

    .line 144
    add-float/2addr v0, p1

    .line 145
    invoke-static {v2, v0}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 146
    .line 147
    .line 148
    move-result-object v0

    .line 149
    invoke-static {p3, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 150
    .line 151
    .line 152
    const/4 v0, 0x6

    .line 153
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 154
    .line 155
    .line 156
    move-result-object v0

    .line 157
    invoke-virtual {p0, p3, v0}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    invoke-virtual {p3, v3}, Ll2/t;->q(Z)V

    .line 161
    .line 162
    .line 163
    goto :goto_4

    .line 164
    :cond_6
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 165
    .line 166
    .line 167
    :goto_4
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 168
    .line 169
    .line 170
    move-result-object p3

    .line 171
    if-eqz p3, :cond_7

    .line 172
    .line 173
    new-instance v0, Li91/e;

    .line 174
    .line 175
    invoke-direct {v0, p0, p1, p2, p4}, Li91/e;-><init>(Lt2/b;FLe1/n1;I)V

    .line 176
    .line 177
    .line 178
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 179
    .line 180
    :cond_7
    return-void
.end method

.method public static final b(Lt2/b;Ll2/o;I)V
    .locals 10

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, -0x6419b2b2

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    const v0, 0x7f0805d3

    .line 10
    .line 11
    .line 12
    invoke-virtual {p1, v0}, Ll2/t;->e(I)Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    const/16 v2, 0x20

    .line 17
    .line 18
    if-eqz v1, :cond_0

    .line 19
    .line 20
    move v1, v2

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/16 v1, 0x10

    .line 23
    .line 24
    :goto_0
    or-int/2addr v1, p2

    .line 25
    and-int/lit8 v3, v1, 0x13

    .line 26
    .line 27
    const/16 v4, 0x12

    .line 28
    .line 29
    const/4 v5, 0x1

    .line 30
    const/4 v6, 0x0

    .line 31
    if-eq v3, v4, :cond_1

    .line 32
    .line 33
    move v3, v5

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    move v3, v6

    .line 36
    :goto_1
    and-int/lit8 v4, v1, 0x1

    .line 37
    .line 38
    invoke-virtual {p1, v4, v3}, Ll2/t;->O(IZ)Z

    .line 39
    .line 40
    .line 41
    move-result v3

    .line 42
    if-eqz v3, :cond_8

    .line 43
    .line 44
    shr-int/lit8 v3, v1, 0x3

    .line 45
    .line 46
    and-int/lit8 v3, v3, 0xe

    .line 47
    .line 48
    invoke-static {v0, v3, p1}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    and-int/lit8 v1, v1, 0x70

    .line 53
    .line 54
    if-ne v1, v2, :cond_2

    .line 55
    .line 56
    move v1, v5

    .line 57
    goto :goto_2

    .line 58
    :cond_2
    move v1, v6

    .line 59
    :goto_2
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    if-nez v1, :cond_3

    .line 64
    .line 65
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 66
    .line 67
    if-ne v2, v1, :cond_4

    .line 68
    .line 69
    :cond_3
    invoke-virtual {v0}, Li3/c;->g()J

    .line 70
    .line 71
    .line 72
    move-result-wide v1

    .line 73
    const-wide v3, 0xffffffffL

    .line 74
    .line 75
    .line 76
    .line 77
    .line 78
    and-long/2addr v1, v3

    .line 79
    long-to-int v1, v1

    .line 80
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 81
    .line 82
    .line 83
    move-result v1

    .line 84
    invoke-static {}, Landroid/content/res/Resources;->getSystem()Landroid/content/res/Resources;

    .line 85
    .line 86
    .line 87
    move-result-object v2

    .line 88
    invoke-virtual {v2}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 89
    .line 90
    .line 91
    move-result-object v2

    .line 92
    iget v2, v2, Landroid/util/DisplayMetrics;->density:F

    .line 93
    .line 94
    div-float/2addr v1, v2

    .line 95
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 96
    .line 97
    .line 98
    move-result-object v2

    .line 99
    invoke-virtual {p1, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    :cond_4
    check-cast v2, Ljava/lang/Number;

    .line 103
    .line 104
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 105
    .line 106
    .line 107
    move-result v1

    .line 108
    sget-object v2, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 109
    .line 110
    sget-object v3, Lx2/c;->d:Lx2/j;

    .line 111
    .line 112
    invoke-static {v3, v6}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 113
    .line 114
    .line 115
    move-result-object v3

    .line 116
    iget-wide v7, p1, Ll2/t;->T:J

    .line 117
    .line 118
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 119
    .line 120
    .line 121
    move-result v4

    .line 122
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 123
    .line 124
    .line 125
    move-result-object v7

    .line 126
    invoke-static {p1, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 127
    .line 128
    .line 129
    move-result-object v2

    .line 130
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 131
    .line 132
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 133
    .line 134
    .line 135
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 136
    .line 137
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 138
    .line 139
    .line 140
    iget-boolean v9, p1, Ll2/t;->S:Z

    .line 141
    .line 142
    if-eqz v9, :cond_5

    .line 143
    .line 144
    invoke-virtual {p1, v8}, Ll2/t;->l(Lay0/a;)V

    .line 145
    .line 146
    .line 147
    goto :goto_3

    .line 148
    :cond_5
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 149
    .line 150
    .line 151
    :goto_3
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 152
    .line 153
    invoke-static {v8, v3, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 154
    .line 155
    .line 156
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 157
    .line 158
    invoke-static {v3, v7, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 159
    .line 160
    .line 161
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 162
    .line 163
    iget-boolean v7, p1, Ll2/t;->S:Z

    .line 164
    .line 165
    if-nez v7, :cond_6

    .line 166
    .line 167
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v7

    .line 171
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 172
    .line 173
    .line 174
    move-result-object v8

    .line 175
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 176
    .line 177
    .line 178
    move-result v7

    .line 179
    if-nez v7, :cond_7

    .line 180
    .line 181
    :cond_6
    invoke-static {v4, p1, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 182
    .line 183
    .line 184
    :cond_7
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 185
    .line 186
    invoke-static {v3, v2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 187
    .line 188
    .line 189
    const/4 v2, 0x6

    .line 190
    invoke-static {v2, v6, p1}, Lkp/n;->b(IILl2/o;)Le1/n1;

    .line 191
    .line 192
    .line 193
    move-result-object v3

    .line 194
    invoke-static {v0, v3, p1, v6}, Lxf0/g0;->c(Li3/c;Le1/n1;Ll2/o;I)V

    .line 195
    .line 196
    .line 197
    invoke-static {p0, v1, v3, p1, v2}, Lxf0/g0;->a(Lt2/b;FLe1/n1;Ll2/o;I)V

    .line 198
    .line 199
    .line 200
    invoke-virtual {p1, v5}, Ll2/t;->q(Z)V

    .line 201
    .line 202
    .line 203
    goto :goto_4

    .line 204
    :cond_8
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 205
    .line 206
    .line 207
    :goto_4
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 208
    .line 209
    .line 210
    move-result-object p1

    .line 211
    if-eqz p1, :cond_9

    .line 212
    .line 213
    new-instance v0, Ld71/d;

    .line 214
    .line 215
    const/16 v1, 0x16

    .line 216
    .line 217
    invoke-direct {v0, p0, p2, v1}, Ld71/d;-><init>(Lt2/b;II)V

    .line 218
    .line 219
    .line 220
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 221
    .line 222
    :cond_9
    return-void
.end method

.method public static final c(Li3/c;Le1/n1;Ll2/o;I)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v10, p1

    .line 4
    .line 5
    move/from16 v11, p3

    .line 6
    .line 7
    move-object/from16 v7, p2

    .line 8
    .line 9
    check-cast v7, Ll2/t;

    .line 10
    .line 11
    const v1, 0x26dc0162

    .line 12
    .line 13
    .line 14
    invoke-virtual {v7, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v7, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_0

    .line 22
    .line 23
    const/4 v1, 0x4

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 v1, 0x2

    .line 26
    :goto_0
    or-int/2addr v1, v11

    .line 27
    invoke-virtual {v7, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    const/16 v3, 0x20

    .line 32
    .line 33
    if-eqz v2, :cond_1

    .line 34
    .line 35
    move v2, v3

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    const/16 v2, 0x10

    .line 38
    .line 39
    :goto_1
    or-int/2addr v1, v2

    .line 40
    and-int/lit8 v2, v1, 0x13

    .line 41
    .line 42
    const/16 v4, 0x12

    .line 43
    .line 44
    const/4 v12, 0x0

    .line 45
    const/4 v13, 0x1

    .line 46
    if-eq v2, v4, :cond_2

    .line 47
    .line 48
    move v2, v13

    .line 49
    goto :goto_2

    .line 50
    :cond_2
    move v2, v12

    .line 51
    :goto_2
    and-int/lit8 v4, v1, 0x1

    .line 52
    .line 53
    invoke-virtual {v7, v4, v2}, Ll2/t;->O(IZ)Z

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    if-eqz v2, :cond_9

    .line 58
    .line 59
    sget-object v14, Lx2/p;->b:Lx2/p;

    .line 60
    .line 61
    const/high16 v15, 0x3f800000    # 1.0f

    .line 62
    .line 63
    invoke-static {v14, v15}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 64
    .line 65
    .line 66
    move-result-object v2

    .line 67
    invoke-virtual {v0}, Li3/c;->g()J

    .line 68
    .line 69
    .line 70
    move-result-wide v4

    .line 71
    const-wide v8, 0xffffffffL

    .line 72
    .line 73
    .line 74
    .line 75
    .line 76
    and-long/2addr v4, v8

    .line 77
    long-to-int v4, v4

    .line 78
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 79
    .line 80
    .line 81
    move-result v4

    .line 82
    invoke-static {v2, v4}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 83
    .line 84
    .line 85
    move-result-object v2

    .line 86
    and-int/lit8 v4, v1, 0x70

    .line 87
    .line 88
    if-ne v4, v3, :cond_3

    .line 89
    .line 90
    move v3, v13

    .line 91
    goto :goto_3

    .line 92
    :cond_3
    move v3, v12

    .line 93
    :goto_3
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v4

    .line 97
    if-nez v3, :cond_4

    .line 98
    .line 99
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 100
    .line 101
    if-ne v4, v3, :cond_5

    .line 102
    .line 103
    :cond_4
    new-instance v4, Le1/l1;

    .line 104
    .line 105
    const/4 v3, 0x1

    .line 106
    invoke-direct {v4, v10, v3}, Le1/l1;-><init>(Le1/n1;I)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {v7, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    :cond_5
    check-cast v4, Lay0/k;

    .line 113
    .line 114
    invoke-static {v2, v4}, Landroidx/compose/ui/graphics/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 115
    .line 116
    .line 117
    move-result-object v2

    .line 118
    sget-object v3, Lx2/c;->d:Lx2/j;

    .line 119
    .line 120
    invoke-static {v3, v12}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 121
    .line 122
    .line 123
    move-result-object v3

    .line 124
    iget-wide v4, v7, Ll2/t;->T:J

    .line 125
    .line 126
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 127
    .line 128
    .line 129
    move-result v4

    .line 130
    invoke-virtual {v7}, Ll2/t;->m()Ll2/p1;

    .line 131
    .line 132
    .line 133
    move-result-object v5

    .line 134
    invoke-static {v7, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 135
    .line 136
    .line 137
    move-result-object v2

    .line 138
    sget-object v6, Lv3/k;->m1:Lv3/j;

    .line 139
    .line 140
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 141
    .line 142
    .line 143
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 144
    .line 145
    invoke-virtual {v7}, Ll2/t;->c0()V

    .line 146
    .line 147
    .line 148
    iget-boolean v8, v7, Ll2/t;->S:Z

    .line 149
    .line 150
    if-eqz v8, :cond_6

    .line 151
    .line 152
    invoke-virtual {v7, v6}, Ll2/t;->l(Lay0/a;)V

    .line 153
    .line 154
    .line 155
    goto :goto_4

    .line 156
    :cond_6
    invoke-virtual {v7}, Ll2/t;->m0()V

    .line 157
    .line 158
    .line 159
    :goto_4
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 160
    .line 161
    invoke-static {v6, v3, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 162
    .line 163
    .line 164
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 165
    .line 166
    invoke-static {v3, v5, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 167
    .line 168
    .line 169
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 170
    .line 171
    iget-boolean v5, v7, Ll2/t;->S:Z

    .line 172
    .line 173
    if-nez v5, :cond_7

    .line 174
    .line 175
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object v5

    .line 179
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 180
    .line 181
    .line 182
    move-result-object v6

    .line 183
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 184
    .line 185
    .line 186
    move-result v5

    .line 187
    if-nez v5, :cond_8

    .line 188
    .line 189
    :cond_7
    invoke-static {v4, v7, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 190
    .line 191
    .line 192
    :cond_8
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 193
    .line 194
    invoke-static {v3, v2, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 195
    .line 196
    .line 197
    invoke-static {v14, v15}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 198
    .line 199
    .line 200
    move-result-object v2

    .line 201
    and-int/lit8 v1, v1, 0xe

    .line 202
    .line 203
    or-int/lit16 v8, v1, 0x61b0

    .line 204
    .line 205
    const/16 v9, 0x68

    .line 206
    .line 207
    const/4 v1, 0x0

    .line 208
    const/4 v3, 0x0

    .line 209
    sget-object v4, Lt3/j;->d:Lt3/x0;

    .line 210
    .line 211
    const/4 v5, 0x0

    .line 212
    const/4 v6, 0x0

    .line 213
    invoke-static/range {v0 .. v9}, Lkp/m;->a(Li3/c;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;FLe3/m;Ll2/o;II)V

    .line 214
    .line 215
    .line 216
    invoke-static {v14, v15}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 217
    .line 218
    .line 219
    move-result-object v1

    .line 220
    sget v2, Lxf0/g0;->a:F

    .line 221
    .line 222
    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 223
    .line 224
    .line 225
    move-result-object v1

    .line 226
    sget-object v2, Lj91/h;->a:Ll2/u2;

    .line 227
    .line 228
    invoke-virtual {v7, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 229
    .line 230
    .line 231
    move-result-object v2

    .line 232
    check-cast v2, Lj91/e;

    .line 233
    .line 234
    invoke-virtual {v2}, Lj91/e;->b()J

    .line 235
    .line 236
    .line 237
    move-result-wide v2

    .line 238
    const v4, 0x3f4ccccd    # 0.8f

    .line 239
    .line 240
    .line 241
    invoke-static {v2, v3, v4}, Le3/s;->b(JF)J

    .line 242
    .line 243
    .line 244
    move-result-wide v2

    .line 245
    new-instance v4, Le3/s;

    .line 246
    .line 247
    invoke-direct {v4, v2, v3}, Le3/s;-><init>(J)V

    .line 248
    .line 249
    .line 250
    sget-wide v2, Le3/s;->h:J

    .line 251
    .line 252
    new-instance v5, Le3/s;

    .line 253
    .line 254
    invoke-direct {v5, v2, v3}, Le3/s;-><init>(J)V

    .line 255
    .line 256
    .line 257
    filled-new-array {v4, v5}, [Le3/s;

    .line 258
    .line 259
    .line 260
    move-result-object v2

    .line 261
    invoke-static {v2}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 262
    .line 263
    .line 264
    move-result-object v2

    .line 265
    const/16 v3, 0xc

    .line 266
    .line 267
    const/4 v4, 0x0

    .line 268
    invoke-static {v2, v4, v4, v3}, Lpy/a;->t(Ljava/util/List;FFI)Le3/b0;

    .line 269
    .line 270
    .line 271
    move-result-object v2

    .line 272
    invoke-static {v1, v2}, Landroidx/compose/foundation/a;->a(Lx2/s;Le3/b0;)Lx2/s;

    .line 273
    .line 274
    .line 275
    move-result-object v1

    .line 276
    invoke-static {v1, v7, v12}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 277
    .line 278
    .line 279
    invoke-virtual {v7, v13}, Ll2/t;->q(Z)V

    .line 280
    .line 281
    .line 282
    goto :goto_5

    .line 283
    :cond_9
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 284
    .line 285
    .line 286
    :goto_5
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 287
    .line 288
    .line 289
    move-result-object v1

    .line 290
    if-eqz v1, :cond_a

    .line 291
    .line 292
    new-instance v2, Lx40/n;

    .line 293
    .line 294
    const/4 v3, 0x3

    .line 295
    invoke-direct {v2, v11, v3, v0, v10}, Lx40/n;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 296
    .line 297
    .line 298
    iput-object v2, v1, Ll2/u1;->d:Lay0/n;

    .line 299
    .line 300
    :cond_a
    return-void
.end method
