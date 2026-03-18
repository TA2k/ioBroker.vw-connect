.class public abstract Lkl0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x78

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Lkl0/b;->a:F

    .line 5
    .line 6
    return-void
.end method

.method public static final a(Lay0/k;Lay0/a;Lxj0/j;Ll2/o;I)V
    .locals 7

    .line 1
    const-string v0, "onSelectTileType"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "onDismissed"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "selectedMapTileType"

    .line 12
    .line 13
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    move-object v5, p3

    .line 17
    check-cast v5, Ll2/t;

    .line 18
    .line 19
    const p3, -0x5cca529b

    .line 20
    .line 21
    .line 22
    invoke-virtual {v5, p3}, Ll2/t;->a0(I)Ll2/t;

    .line 23
    .line 24
    .line 25
    and-int/lit8 p3, p4, 0x6

    .line 26
    .line 27
    if-nez p3, :cond_1

    .line 28
    .line 29
    sget-object p3, Lx2/p;->b:Lx2/p;

    .line 30
    .line 31
    invoke-virtual {v5, p3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result p3

    .line 35
    if-eqz p3, :cond_0

    .line 36
    .line 37
    const/4 p3, 0x4

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    const/4 p3, 0x2

    .line 40
    :goto_0
    or-int/2addr p3, p4

    .line 41
    goto :goto_1

    .line 42
    :cond_1
    move p3, p4

    .line 43
    :goto_1
    and-int/lit8 v0, p4, 0x30

    .line 44
    .line 45
    if-nez v0, :cond_3

    .line 46
    .line 47
    invoke-virtual {v5, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    if-eqz v0, :cond_2

    .line 52
    .line 53
    const/16 v0, 0x20

    .line 54
    .line 55
    goto :goto_2

    .line 56
    :cond_2
    const/16 v0, 0x10

    .line 57
    .line 58
    :goto_2
    or-int/2addr p3, v0

    .line 59
    :cond_3
    and-int/lit16 v0, p4, 0x180

    .line 60
    .line 61
    if-nez v0, :cond_5

    .line 62
    .line 63
    invoke-virtual {v5, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result v0

    .line 67
    if-eqz v0, :cond_4

    .line 68
    .line 69
    const/16 v0, 0x100

    .line 70
    .line 71
    goto :goto_3

    .line 72
    :cond_4
    const/16 v0, 0x80

    .line 73
    .line 74
    :goto_3
    or-int/2addr p3, v0

    .line 75
    :cond_5
    and-int/lit16 v0, p4, 0xc00

    .line 76
    .line 77
    if-nez v0, :cond_7

    .line 78
    .line 79
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    invoke-virtual {v5, v0}, Ll2/t;->e(I)Z

    .line 84
    .line 85
    .line 86
    move-result v0

    .line 87
    if-eqz v0, :cond_6

    .line 88
    .line 89
    const/16 v0, 0x800

    .line 90
    .line 91
    goto :goto_4

    .line 92
    :cond_6
    const/16 v0, 0x400

    .line 93
    .line 94
    :goto_4
    or-int/2addr p3, v0

    .line 95
    :cond_7
    and-int/lit16 v0, p4, 0x6000

    .line 96
    .line 97
    const-string v4, "trip_detail_map_type"

    .line 98
    .line 99
    if-nez v0, :cond_9

    .line 100
    .line 101
    invoke-virtual {v5, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result v0

    .line 105
    if-eqz v0, :cond_8

    .line 106
    .line 107
    const/16 v0, 0x4000

    .line 108
    .line 109
    goto :goto_5

    .line 110
    :cond_8
    const/16 v0, 0x2000

    .line 111
    .line 112
    :goto_5
    or-int/2addr p3, v0

    .line 113
    :cond_9
    and-int/lit16 v0, p3, 0x2493

    .line 114
    .line 115
    const/16 v1, 0x2492

    .line 116
    .line 117
    if-eq v0, v1, :cond_a

    .line 118
    .line 119
    const/4 v0, 0x1

    .line 120
    goto :goto_6

    .line 121
    :cond_a
    const/4 v0, 0x0

    .line 122
    :goto_6
    and-int/lit8 v1, p3, 0x1

    .line 123
    .line 124
    invoke-virtual {v5, v1, v0}, Ll2/t;->O(IZ)Z

    .line 125
    .line 126
    .line 127
    move-result v0

    .line 128
    if-eqz v0, :cond_b

    .line 129
    .line 130
    const v0, 0xfffe

    .line 131
    .line 132
    .line 133
    and-int v6, p3, v0

    .line 134
    .line 135
    move-object v1, p0

    .line 136
    move-object v2, p1

    .line 137
    move-object v3, p2

    .line 138
    invoke-static/range {v1 .. v6}, Lkl0/b;->b(Lay0/k;Lay0/a;Lxj0/j;Ljava/lang/String;Ll2/o;I)V

    .line 139
    .line 140
    .line 141
    goto :goto_7

    .line 142
    :cond_b
    move-object v1, p0

    .line 143
    move-object v2, p1

    .line 144
    move-object v3, p2

    .line 145
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 146
    .line 147
    .line 148
    :goto_7
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    if-eqz p0, :cond_c

    .line 153
    .line 154
    new-instance p1, Li50/j0;

    .line 155
    .line 156
    invoke-direct {p1, v1, v2, v3, p4}, Li50/j0;-><init>(Lay0/k;Lay0/a;Lxj0/j;I)V

    .line 157
    .line 158
    .line 159
    iput-object p1, p0, Ll2/u1;->d:Lay0/n;

    .line 160
    .line 161
    :cond_c
    return-void
.end method

.method public static final b(Lay0/k;Lay0/a;Lxj0/j;Ljava/lang/String;Ll2/o;I)V
    .locals 6

    .line 1
    move-object v4, p4

    .line 2
    check-cast v4, Ll2/t;

    .line 3
    .line 4
    const p4, -0x4c2134db

    .line 5
    .line 6
    .line 7
    invoke-virtual {v4, p4}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 p4, p5, 0x6

    .line 11
    .line 12
    if-nez p4, :cond_1

    .line 13
    .line 14
    sget-object p4, Lx2/p;->b:Lx2/p;

    .line 15
    .line 16
    invoke-virtual {v4, p4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result p4

    .line 20
    if-eqz p4, :cond_0

    .line 21
    .line 22
    const/4 p4, 0x4

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const/4 p4, 0x2

    .line 25
    :goto_0
    or-int/2addr p4, p5

    .line 26
    goto :goto_1

    .line 27
    :cond_1
    move p4, p5

    .line 28
    :goto_1
    and-int/lit8 v0, p5, 0x30

    .line 29
    .line 30
    if-nez v0, :cond_3

    .line 31
    .line 32
    invoke-virtual {v4, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    if-eqz v0, :cond_2

    .line 37
    .line 38
    const/16 v0, 0x20

    .line 39
    .line 40
    goto :goto_2

    .line 41
    :cond_2
    const/16 v0, 0x10

    .line 42
    .line 43
    :goto_2
    or-int/2addr p4, v0

    .line 44
    :cond_3
    and-int/lit16 v0, p5, 0x180

    .line 45
    .line 46
    if-nez v0, :cond_5

    .line 47
    .line 48
    invoke-virtual {v4, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    if-eqz v0, :cond_4

    .line 53
    .line 54
    const/16 v0, 0x100

    .line 55
    .line 56
    goto :goto_3

    .line 57
    :cond_4
    const/16 v0, 0x80

    .line 58
    .line 59
    :goto_3
    or-int/2addr p4, v0

    .line 60
    :cond_5
    and-int/lit16 v0, p5, 0xc00

    .line 61
    .line 62
    if-nez v0, :cond_8

    .line 63
    .line 64
    if-nez p2, :cond_6

    .line 65
    .line 66
    const/4 v0, -0x1

    .line 67
    goto :goto_4

    .line 68
    :cond_6
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    :goto_4
    invoke-virtual {v4, v0}, Ll2/t;->e(I)Z

    .line 73
    .line 74
    .line 75
    move-result v0

    .line 76
    if-eqz v0, :cond_7

    .line 77
    .line 78
    const/16 v0, 0x800

    .line 79
    .line 80
    goto :goto_5

    .line 81
    :cond_7
    const/16 v0, 0x400

    .line 82
    .line 83
    :goto_5
    or-int/2addr p4, v0

    .line 84
    :cond_8
    and-int/lit16 v0, p5, 0x6000

    .line 85
    .line 86
    if-nez v0, :cond_a

    .line 87
    .line 88
    invoke-virtual {v4, p3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    if-eqz v0, :cond_9

    .line 93
    .line 94
    const/16 v0, 0x4000

    .line 95
    .line 96
    goto :goto_6

    .line 97
    :cond_9
    const/16 v0, 0x2000

    .line 98
    .line 99
    :goto_6
    or-int/2addr p4, v0

    .line 100
    :cond_a
    and-int/lit16 v0, p4, 0x2493

    .line 101
    .line 102
    const/16 v1, 0x2492

    .line 103
    .line 104
    if-eq v0, v1, :cond_b

    .line 105
    .line 106
    const/4 v0, 0x1

    .line 107
    goto :goto_7

    .line 108
    :cond_b
    const/4 v0, 0x0

    .line 109
    :goto_7
    and-int/lit8 v1, p4, 0x1

    .line 110
    .line 111
    invoke-virtual {v4, v1, v0}, Ll2/t;->O(IZ)Z

    .line 112
    .line 113
    .line 114
    move-result v0

    .line 115
    if-eqz v0, :cond_c

    .line 116
    .line 117
    new-instance v0, Li40/n2;

    .line 118
    .line 119
    invoke-direct {v0, p0, p2, p3}, Li40/n2;-><init>(Lay0/k;Lxj0/j;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    const v1, -0x4996d8d7

    .line 123
    .line 124
    .line 125
    invoke-static {v1, v4, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 126
    .line 127
    .line 128
    move-result-object v3

    .line 129
    shr-int/lit8 p4, p4, 0x6

    .line 130
    .line 131
    and-int/lit8 p4, p4, 0xe

    .line 132
    .line 133
    or-int/lit16 v5, p4, 0xc00

    .line 134
    .line 135
    const/4 v1, 0x0

    .line 136
    const/4 v2, 0x0

    .line 137
    move-object v0, p1

    .line 138
    invoke-static/range {v0 .. v5}, Lxf0/y1;->h(Lay0/a;ZZLt2/b;Ll2/o;I)V

    .line 139
    .line 140
    .line 141
    goto :goto_8

    .line 142
    :cond_c
    move-object v0, p1

    .line 143
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 144
    .line 145
    .line 146
    :goto_8
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 147
    .line 148
    .line 149
    move-result-object v1

    .line 150
    if-eqz v1, :cond_d

    .line 151
    .line 152
    move-object p1, p0

    .line 153
    new-instance p0, La71/e;

    .line 154
    .line 155
    move-object p4, p3

    .line 156
    move-object p3, p2

    .line 157
    move-object p2, v0

    .line 158
    invoke-direct/range {p0 .. p5}, La71/e;-><init>(Lay0/k;Lay0/a;Lxj0/j;Ljava/lang/String;I)V

    .line 159
    .line 160
    .line 161
    iput-object p0, v1, Ll2/u1;->d:Lay0/n;

    .line 162
    .line 163
    :cond_d
    return-void
.end method

.method public static final c(Lay0/k;Lxj0/j;Ljava/lang/String;Ll2/o;I)V
    .locals 35

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v3, p2

    .line 4
    .line 5
    move-object/from16 v10, p3

    .line 6
    .line 7
    check-cast v10, Ll2/t;

    .line 8
    .line 9
    const v0, -0x46402f26

    .line 10
    .line 11
    .line 12
    invoke-virtual {v10, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 16
    .line 17
    invoke-virtual {v10, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-eqz v0, :cond_0

    .line 22
    .line 23
    const/4 v0, 0x4

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 v0, 0x2

    .line 26
    :goto_0
    or-int v0, p4, v0

    .line 27
    .line 28
    invoke-virtual {v10, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    if-eqz v5, :cond_1

    .line 33
    .line 34
    const/16 v5, 0x20

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    const/16 v5, 0x10

    .line 38
    .line 39
    :goto_1
    or-int/2addr v0, v5

    .line 40
    invoke-virtual/range {p1 .. p1}, Ljava/lang/Enum;->ordinal()I

    .line 41
    .line 42
    .line 43
    move-result v5

    .line 44
    invoke-virtual {v10, v5}, Ll2/t;->e(I)Z

    .line 45
    .line 46
    .line 47
    move-result v5

    .line 48
    if-eqz v5, :cond_2

    .line 49
    .line 50
    const/16 v5, 0x100

    .line 51
    .line 52
    goto :goto_2

    .line 53
    :cond_2
    const/16 v5, 0x80

    .line 54
    .line 55
    :goto_2
    or-int/2addr v0, v5

    .line 56
    invoke-virtual {v10, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v5

    .line 60
    if-eqz v5, :cond_3

    .line 61
    .line 62
    const/16 v5, 0x800

    .line 63
    .line 64
    goto :goto_3

    .line 65
    :cond_3
    const/16 v5, 0x400

    .line 66
    .line 67
    :goto_3
    or-int/2addr v0, v5

    .line 68
    and-int/lit16 v5, v0, 0x493

    .line 69
    .line 70
    const/16 v6, 0x492

    .line 71
    .line 72
    const/4 v13, 0x0

    .line 73
    const/4 v14, 0x1

    .line 74
    if-eq v5, v6, :cond_4

    .line 75
    .line 76
    move v5, v14

    .line 77
    goto :goto_4

    .line 78
    :cond_4
    move v5, v13

    .line 79
    :goto_4
    and-int/lit8 v6, v0, 0x1

    .line 80
    .line 81
    invoke-virtual {v10, v6, v5}, Ll2/t;->O(IZ)Z

    .line 82
    .line 83
    .line 84
    move-result v5

    .line 85
    if-eqz v5, :cond_17

    .line 86
    .line 87
    sget-object v15, Lj91/a;->a:Ll2/u2;

    .line 88
    .line 89
    invoke-virtual {v10, v15}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v5

    .line 93
    check-cast v5, Lj91/c;

    .line 94
    .line 95
    iget v5, v5, Lj91/c;->f:F

    .line 96
    .line 97
    const/4 v6, 0x0

    .line 98
    invoke-static {v4, v6, v5, v14}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 99
    .line 100
    .line 101
    move-result-object v5

    .line 102
    sget-object v7, Lx2/c;->d:Lx2/j;

    .line 103
    .line 104
    invoke-static {v7, v13}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 105
    .line 106
    .line 107
    move-result-object v7

    .line 108
    iget-wide v8, v10, Ll2/t;->T:J

    .line 109
    .line 110
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 111
    .line 112
    .line 113
    move-result v8

    .line 114
    invoke-virtual {v10}, Ll2/t;->m()Ll2/p1;

    .line 115
    .line 116
    .line 117
    move-result-object v9

    .line 118
    invoke-static {v10, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 119
    .line 120
    .line 121
    move-result-object v5

    .line 122
    sget-object v16, Lv3/k;->m1:Lv3/j;

    .line 123
    .line 124
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 125
    .line 126
    .line 127
    sget-object v12, Lv3/j;->b:Lv3/i;

    .line 128
    .line 129
    invoke-virtual {v10}, Ll2/t;->c0()V

    .line 130
    .line 131
    .line 132
    iget-boolean v6, v10, Ll2/t;->S:Z

    .line 133
    .line 134
    if-eqz v6, :cond_5

    .line 135
    .line 136
    invoke-virtual {v10, v12}, Ll2/t;->l(Lay0/a;)V

    .line 137
    .line 138
    .line 139
    goto :goto_5

    .line 140
    :cond_5
    invoke-virtual {v10}, Ll2/t;->m0()V

    .line 141
    .line 142
    .line 143
    :goto_5
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 144
    .line 145
    invoke-static {v6, v7, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 146
    .line 147
    .line 148
    sget-object v7, Lv3/j;->f:Lv3/h;

    .line 149
    .line 150
    invoke-static {v7, v9, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 151
    .line 152
    .line 153
    sget-object v9, Lv3/j;->j:Lv3/h;

    .line 154
    .line 155
    iget-boolean v14, v10, Ll2/t;->S:Z

    .line 156
    .line 157
    if-nez v14, :cond_6

    .line 158
    .line 159
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object v14

    .line 163
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 164
    .line 165
    .line 166
    move-result-object v11

    .line 167
    invoke-static {v14, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 168
    .line 169
    .line 170
    move-result v11

    .line 171
    if-nez v11, :cond_7

    .line 172
    .line 173
    :cond_6
    invoke-static {v8, v10, v8, v9}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 174
    .line 175
    .line 176
    :cond_7
    sget-object v11, Lv3/j;->d:Lv3/h;

    .line 177
    .line 178
    invoke-static {v11, v5, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 179
    .line 180
    .line 181
    sget-object v5, Lk1/j;->c:Lk1/e;

    .line 182
    .line 183
    sget-object v8, Lx2/c;->p:Lx2/h;

    .line 184
    .line 185
    invoke-static {v5, v8, v10, v13}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 186
    .line 187
    .line 188
    move-result-object v5

    .line 189
    iget-wide v13, v10, Ll2/t;->T:J

    .line 190
    .line 191
    invoke-static {v13, v14}, Ljava/lang/Long;->hashCode(J)I

    .line 192
    .line 193
    .line 194
    move-result v8

    .line 195
    invoke-virtual {v10}, Ll2/t;->m()Ll2/p1;

    .line 196
    .line 197
    .line 198
    move-result-object v13

    .line 199
    invoke-static {v10, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 200
    .line 201
    .line 202
    move-result-object v14

    .line 203
    invoke-virtual {v10}, Ll2/t;->c0()V

    .line 204
    .line 205
    .line 206
    move/from16 v26, v0

    .line 207
    .line 208
    iget-boolean v0, v10, Ll2/t;->S:Z

    .line 209
    .line 210
    if-eqz v0, :cond_8

    .line 211
    .line 212
    invoke-virtual {v10, v12}, Ll2/t;->l(Lay0/a;)V

    .line 213
    .line 214
    .line 215
    goto :goto_6

    .line 216
    :cond_8
    invoke-virtual {v10}, Ll2/t;->m0()V

    .line 217
    .line 218
    .line 219
    :goto_6
    invoke-static {v6, v5, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 220
    .line 221
    .line 222
    invoke-static {v7, v13, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 223
    .line 224
    .line 225
    iget-boolean v0, v10, Ll2/t;->S:Z

    .line 226
    .line 227
    if-nez v0, :cond_9

    .line 228
    .line 229
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 230
    .line 231
    .line 232
    move-result-object v0

    .line 233
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 234
    .line 235
    .line 236
    move-result-object v5

    .line 237
    invoke-static {v0, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 238
    .line 239
    .line 240
    move-result v0

    .line 241
    if-nez v0, :cond_a

    .line 242
    .line 243
    :cond_9
    invoke-static {v8, v10, v8, v9}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 244
    .line 245
    .line 246
    :cond_a
    invoke-static {v11, v14, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 247
    .line 248
    .line 249
    const v0, 0x7f12066d

    .line 250
    .line 251
    .line 252
    invoke-static {v10, v0}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 253
    .line 254
    .line 255
    move-result-object v0

    .line 256
    sget-object v5, Lj91/j;->a:Ll2/u2;

    .line 257
    .line 258
    invoke-virtual {v10, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 259
    .line 260
    .line 261
    move-result-object v5

    .line 262
    check-cast v5, Lj91/f;

    .line 263
    .line 264
    invoke-virtual {v5}, Lj91/f;->k()Lg4/p0;

    .line 265
    .line 266
    .line 267
    move-result-object v13

    .line 268
    invoke-virtual {v10, v15}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 269
    .line 270
    .line 271
    move-result-object v5

    .line 272
    check-cast v5, Lj91/c;

    .line 273
    .line 274
    iget v8, v5, Lj91/c;->e:F

    .line 275
    .line 276
    move-object v5, v9

    .line 277
    const/4 v9, 0x7

    .line 278
    move-object v14, v5

    .line 279
    const/4 v5, 0x0

    .line 280
    move-object/from16 v20, v6

    .line 281
    .line 282
    const/4 v6, 0x0

    .line 283
    move-object/from16 v21, v7

    .line 284
    .line 285
    const/4 v7, 0x0

    .line 286
    move-object/from16 v16, v0

    .line 287
    .line 288
    const/4 v0, 0x0

    .line 289
    invoke-static/range {v4 .. v9}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 290
    .line 291
    .line 292
    move-result-object v5

    .line 293
    invoke-virtual {v10, v15}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 294
    .line 295
    .line 296
    move-result-object v6

    .line 297
    check-cast v6, Lj91/c;

    .line 298
    .line 299
    iget v6, v6, Lj91/c;->d:F

    .line 300
    .line 301
    const/4 v7, 0x2

    .line 302
    invoke-static {v5, v6, v0, v7}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 303
    .line 304
    .line 305
    move-result-object v0

    .line 306
    const-string v5, "_title"

    .line 307
    .line 308
    invoke-virtual {v3, v5}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 309
    .line 310
    .line 311
    move-result-object v5

    .line 312
    invoke-static {v0, v5}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 313
    .line 314
    .line 315
    move-result-object v6

    .line 316
    const/16 v24, 0x0

    .line 317
    .line 318
    const v25, 0xfff8

    .line 319
    .line 320
    .line 321
    const-wide/16 v7, 0x0

    .line 322
    .line 323
    move-object/from16 v22, v10

    .line 324
    .line 325
    const-wide/16 v9, 0x0

    .line 326
    .line 327
    move-object v0, v11

    .line 328
    const/4 v11, 0x0

    .line 329
    move-object v5, v12

    .line 330
    move-object v15, v13

    .line 331
    const-wide/16 v12, 0x0

    .line 332
    .line 333
    move-object/from16 v18, v14

    .line 334
    .line 335
    const/4 v14, 0x0

    .line 336
    move-object/from16 v23, v5

    .line 337
    .line 338
    move-object v5, v15

    .line 339
    const/4 v15, 0x0

    .line 340
    move-object/from16 v27, v4

    .line 341
    .line 342
    move-object/from16 v4, v16

    .line 343
    .line 344
    const/16 v28, 0x1

    .line 345
    .line 346
    const-wide/16 v16, 0x0

    .line 347
    .line 348
    move-object/from16 v29, v18

    .line 349
    .line 350
    const/16 v18, 0x0

    .line 351
    .line 352
    const/16 v30, 0x0

    .line 353
    .line 354
    const/16 v19, 0x0

    .line 355
    .line 356
    move-object/from16 v31, v20

    .line 357
    .line 358
    const/16 v20, 0x0

    .line 359
    .line 360
    move-object/from16 v32, v21

    .line 361
    .line 362
    const/16 v21, 0x0

    .line 363
    .line 364
    move-object/from16 v33, v23

    .line 365
    .line 366
    const/16 v23, 0x0

    .line 367
    .line 368
    move-object/from16 v34, v0

    .line 369
    .line 370
    move-object/from16 v2, v27

    .line 371
    .line 372
    move-object/from16 v1, v31

    .line 373
    .line 374
    move-object/from16 v3, v32

    .line 375
    .line 376
    move-object/from16 v0, v33

    .line 377
    .line 378
    invoke-static/range {v4 .. v25}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 379
    .line 380
    .line 381
    move-object/from16 v10, v22

    .line 382
    .line 383
    const/high16 v4, 0x3f800000    # 1.0f

    .line 384
    .line 385
    invoke-static {v2, v4}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 386
    .line 387
    .line 388
    move-result-object v2

    .line 389
    sget-object v4, Lk1/j;->f:Lk1/f;

    .line 390
    .line 391
    sget-object v5, Lx2/c;->m:Lx2/i;

    .line 392
    .line 393
    const/4 v6, 0x6

    .line 394
    invoke-static {v4, v5, v10, v6}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 395
    .line 396
    .line 397
    move-result-object v4

    .line 398
    iget-wide v5, v10, Ll2/t;->T:J

    .line 399
    .line 400
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 401
    .line 402
    .line 403
    move-result v5

    .line 404
    invoke-virtual {v10}, Ll2/t;->m()Ll2/p1;

    .line 405
    .line 406
    .line 407
    move-result-object v6

    .line 408
    invoke-static {v10, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 409
    .line 410
    .line 411
    move-result-object v2

    .line 412
    invoke-virtual {v10}, Ll2/t;->c0()V

    .line 413
    .line 414
    .line 415
    iget-boolean v7, v10, Ll2/t;->S:Z

    .line 416
    .line 417
    if-eqz v7, :cond_b

    .line 418
    .line 419
    invoke-virtual {v10, v0}, Ll2/t;->l(Lay0/a;)V

    .line 420
    .line 421
    .line 422
    goto :goto_7

    .line 423
    :cond_b
    invoke-virtual {v10}, Ll2/t;->m0()V

    .line 424
    .line 425
    .line 426
    :goto_7
    invoke-static {v1, v4, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 427
    .line 428
    .line 429
    invoke-static {v3, v6, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 430
    .line 431
    .line 432
    iget-boolean v0, v10, Ll2/t;->S:Z

    .line 433
    .line 434
    if-nez v0, :cond_c

    .line 435
    .line 436
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 437
    .line 438
    .line 439
    move-result-object v0

    .line 440
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 441
    .line 442
    .line 443
    move-result-object v1

    .line 444
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 445
    .line 446
    .line 447
    move-result v0

    .line 448
    if-nez v0, :cond_d

    .line 449
    .line 450
    :cond_c
    move-object/from16 v14, v29

    .line 451
    .line 452
    goto :goto_9

    .line 453
    :cond_d
    :goto_8
    move-object/from16 v0, v34

    .line 454
    .line 455
    goto :goto_a

    .line 456
    :goto_9
    invoke-static {v5, v10, v5, v14}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 457
    .line 458
    .line 459
    goto :goto_8

    .line 460
    :goto_a
    invoke-static {v0, v2, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 461
    .line 462
    .line 463
    sget-object v0, Lxj0/j;->d:Lxj0/j;

    .line 464
    .line 465
    move-object/from16 v2, p1

    .line 466
    .line 467
    if-ne v2, v0, :cond_e

    .line 468
    .line 469
    const/4 v4, 0x1

    .line 470
    goto :goto_b

    .line 471
    :cond_e
    move/from16 v4, v30

    .line 472
    .line 473
    :goto_b
    invoke-static {v10}, Lkp/k;->c(Ll2/o;)Z

    .line 474
    .line 475
    .line 476
    move-result v0

    .line 477
    if-eqz v0, :cond_f

    .line 478
    .line 479
    const v0, 0x7f080254

    .line 480
    .line 481
    .line 482
    :goto_c
    move v5, v0

    .line 483
    goto :goto_d

    .line 484
    :cond_f
    const v0, 0x7f080255

    .line 485
    .line 486
    .line 487
    goto :goto_c

    .line 488
    :goto_d
    const v0, 0x7f12066e

    .line 489
    .line 490
    .line 491
    invoke-static {v10, v0}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 492
    .line 493
    .line 494
    move-result-object v7

    .line 495
    const-string v0, "_default_map_type"

    .line 496
    .line 497
    move-object/from16 v3, p2

    .line 498
    .line 499
    invoke-virtual {v3, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 500
    .line 501
    .line 502
    move-result-object v8

    .line 503
    and-int/lit8 v0, v26, 0x70

    .line 504
    .line 505
    const/16 v1, 0x20

    .line 506
    .line 507
    if-ne v0, v1, :cond_10

    .line 508
    .line 509
    const/4 v13, 0x1

    .line 510
    goto :goto_e

    .line 511
    :cond_10
    move/from16 v13, v30

    .line 512
    .line 513
    :goto_e
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 514
    .line 515
    .line 516
    move-result-object v6

    .line 517
    sget-object v12, Ll2/n;->a:Ll2/x0;

    .line 518
    .line 519
    if-nez v13, :cond_12

    .line 520
    .line 521
    if-ne v6, v12, :cond_11

    .line 522
    .line 523
    goto :goto_f

    .line 524
    :cond_11
    move-object/from16 v13, p0

    .line 525
    .line 526
    goto :goto_10

    .line 527
    :cond_12
    :goto_f
    new-instance v6, Lik/b;

    .line 528
    .line 529
    const/16 v9, 0x11

    .line 530
    .line 531
    move-object/from16 v13, p0

    .line 532
    .line 533
    invoke-direct {v6, v9, v13}, Lik/b;-><init>(ILay0/k;)V

    .line 534
    .line 535
    .line 536
    invoke-virtual {v10, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 537
    .line 538
    .line 539
    :goto_10
    move-object v9, v6

    .line 540
    check-cast v9, Lay0/a;

    .line 541
    .line 542
    const/16 v11, 0x180

    .line 543
    .line 544
    sget v6, Lkl0/b;->a:F

    .line 545
    .line 546
    invoke-static/range {v4 .. v11}, Lkl0/d;->a(ZIFLjava/lang/String;Ljava/lang/String;Lay0/a;Ll2/o;I)V

    .line 547
    .line 548
    .line 549
    sget-object v4, Lxj0/j;->e:Lxj0/j;

    .line 550
    .line 551
    if-ne v2, v4, :cond_13

    .line 552
    .line 553
    const/4 v4, 0x1

    .line 554
    goto :goto_11

    .line 555
    :cond_13
    move/from16 v4, v30

    .line 556
    .line 557
    :goto_11
    const v5, 0x7f12066f

    .line 558
    .line 559
    .line 560
    invoke-static {v10, v5}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 561
    .line 562
    .line 563
    move-result-object v7

    .line 564
    const-string v5, "_satellite_map_type"

    .line 565
    .line 566
    invoke-virtual {v3, v5}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 567
    .line 568
    .line 569
    move-result-object v8

    .line 570
    if-ne v0, v1, :cond_14

    .line 571
    .line 572
    const/16 v30, 0x1

    .line 573
    .line 574
    :cond_14
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 575
    .line 576
    .line 577
    move-result-object v0

    .line 578
    if-nez v30, :cond_15

    .line 579
    .line 580
    if-ne v0, v12, :cond_16

    .line 581
    .line 582
    :cond_15
    new-instance v0, Lik/b;

    .line 583
    .line 584
    const/16 v1, 0x12

    .line 585
    .line 586
    invoke-direct {v0, v1, v13}, Lik/b;-><init>(ILay0/k;)V

    .line 587
    .line 588
    .line 589
    invoke-virtual {v10, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 590
    .line 591
    .line 592
    :cond_16
    move-object v9, v0

    .line 593
    check-cast v9, Lay0/a;

    .line 594
    .line 595
    const/16 v11, 0x180

    .line 596
    .line 597
    const v5, 0x7f080256

    .line 598
    .line 599
    .line 600
    invoke-static/range {v4 .. v11}, Lkl0/d;->a(ZIFLjava/lang/String;Ljava/lang/String;Lay0/a;Ll2/o;I)V

    .line 601
    .line 602
    .line 603
    const/4 v0, 0x1

    .line 604
    invoke-static {v10, v0, v0, v0}, Lf2/m0;->w(Ll2/t;ZZZ)V

    .line 605
    .line 606
    .line 607
    goto :goto_12

    .line 608
    :cond_17
    move-object/from16 v2, p1

    .line 609
    .line 610
    move-object v13, v1

    .line 611
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 612
    .line 613
    .line 614
    :goto_12
    invoke-virtual {v10}, Ll2/t;->s()Ll2/u1;

    .line 615
    .line 616
    .line 617
    move-result-object v6

    .line 618
    if-eqz v6, :cond_18

    .line 619
    .line 620
    new-instance v0, Li91/k3;

    .line 621
    .line 622
    const/4 v5, 0x4

    .line 623
    move/from16 v4, p4

    .line 624
    .line 625
    move-object v1, v13

    .line 626
    invoke-direct/range {v0 .. v5}, Li91/k3;-><init>(Llx0/e;Ljava/lang/Object;Ljava/lang/String;II)V

    .line 627
    .line 628
    .line 629
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 630
    .line 631
    :cond_18
    return-void
.end method
