.class public abstract Li40/f3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x72

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Li40/f3;->a:F

    .line 5
    .line 6
    const/16 v0, 0x4c

    .line 7
    .line 8
    int-to-float v0, v0

    .line 9
    sput v0, Li40/f3;->b:F

    .line 10
    .line 11
    return-void
.end method

.method public static final a(Lh40/x;Lx2/s;Lay0/k;Ll2/o;II)V
    .locals 10

    .line 1
    move-object v6, p3

    .line 2
    check-cast v6, Ll2/t;

    .line 3
    .line 4
    const v0, 0x5fbb4fc5

    .line 5
    .line 6
    .line 7
    invoke-virtual {v6, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    invoke-virtual {v6, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    const/4 v0, 0x4

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 v0, 0x2

    .line 19
    :goto_0
    or-int/2addr v0, p4

    .line 20
    and-int/lit8 v2, p5, 0x2

    .line 21
    .line 22
    if-eqz v2, :cond_1

    .line 23
    .line 24
    or-int/lit8 v0, v0, 0x30

    .line 25
    .line 26
    goto :goto_2

    .line 27
    :cond_1
    invoke-virtual {v6, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    if-eqz v4, :cond_2

    .line 32
    .line 33
    const/16 v4, 0x20

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_2
    const/16 v4, 0x10

    .line 37
    .line 38
    :goto_1
    or-int/2addr v0, v4

    .line 39
    :goto_2
    and-int/lit8 v4, p5, 0x4

    .line 40
    .line 41
    if-eqz v4, :cond_3

    .line 42
    .line 43
    or-int/lit16 v0, v0, 0x180

    .line 44
    .line 45
    goto :goto_4

    .line 46
    :cond_3
    invoke-virtual {v6, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v7

    .line 50
    if-eqz v7, :cond_4

    .line 51
    .line 52
    const/16 v7, 0x100

    .line 53
    .line 54
    goto :goto_3

    .line 55
    :cond_4
    const/16 v7, 0x80

    .line 56
    .line 57
    :goto_3
    or-int/2addr v0, v7

    .line 58
    :goto_4
    and-int/lit16 v7, v0, 0x93

    .line 59
    .line 60
    const/16 v8, 0x92

    .line 61
    .line 62
    if-eq v7, v8, :cond_5

    .line 63
    .line 64
    const/4 v7, 0x1

    .line 65
    goto :goto_5

    .line 66
    :cond_5
    const/4 v7, 0x0

    .line 67
    :goto_5
    and-int/lit8 v8, v0, 0x1

    .line 68
    .line 69
    invoke-virtual {v6, v8, v7}, Ll2/t;->O(IZ)Z

    .line 70
    .line 71
    .line 72
    move-result v7

    .line 73
    if-eqz v7, :cond_9

    .line 74
    .line 75
    if-eqz v2, :cond_6

    .line 76
    .line 77
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 78
    .line 79
    goto :goto_6

    .line 80
    :cond_6
    move-object v2, p1

    .line 81
    :goto_6
    if-eqz v4, :cond_8

    .line 82
    .line 83
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v3

    .line 87
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 88
    .line 89
    if-ne v3, v4, :cond_7

    .line 90
    .line 91
    new-instance v3, Li40/r2;

    .line 92
    .line 93
    const/4 v4, 0x2

    .line 94
    invoke-direct {v3, v4}, Li40/r2;-><init>(I)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {v6, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    :cond_7
    check-cast v3, Lay0/k;

    .line 101
    .line 102
    move-object v9, v3

    .line 103
    goto :goto_7

    .line 104
    :cond_8
    move-object v9, p2

    .line 105
    :goto_7
    new-instance v3, Li40/k0;

    .line 106
    .line 107
    const/16 v4, 0xf

    .line 108
    .line 109
    invoke-direct {v3, v4, p0, v9}, Li40/k0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    const v4, 0x1eb0fc3a

    .line 113
    .line 114
    .line 115
    invoke-static {v4, v6, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 116
    .line 117
    .line 118
    move-result-object v5

    .line 119
    shr-int/lit8 v0, v0, 0x3

    .line 120
    .line 121
    and-int/lit8 v0, v0, 0xe

    .line 122
    .line 123
    or-int/lit16 v7, v0, 0xc00

    .line 124
    .line 125
    const/4 v8, 0x6

    .line 126
    const/4 v3, 0x0

    .line 127
    const/4 v4, 0x0

    .line 128
    invoke-static/range {v2 .. v8}, Li91/d0;->a(Lx2/s;Lay0/a;ZLay0/n;Ll2/o;II)V

    .line 129
    .line 130
    .line 131
    move-object v3, v9

    .line 132
    goto :goto_8

    .line 133
    :cond_9
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 134
    .line 135
    .line 136
    move-object v2, p1

    .line 137
    move-object v3, p2

    .line 138
    :goto_8
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 139
    .line 140
    .line 141
    move-result-object v7

    .line 142
    if-eqz v7, :cond_a

    .line 143
    .line 144
    new-instance v0, La2/f;

    .line 145
    .line 146
    const/16 v6, 0x1c

    .line 147
    .line 148
    move-object v1, p0

    .line 149
    move v4, p4

    .line 150
    move v5, p5

    .line 151
    invoke-direct/range {v0 .. v6}, La2/f;-><init>(Ljava/lang/Object;Lx2/s;Lay0/k;III)V

    .line 152
    .line 153
    .line 154
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 155
    .line 156
    :cond_a
    return-void
.end method

.method public static final b(Lh40/y;Lx2/s;Lay0/k;Ll2/o;II)V
    .locals 10

    .line 1
    move-object v6, p3

    .line 2
    check-cast v6, Ll2/t;

    .line 3
    .line 4
    const v0, 0x70d8e44b

    .line 5
    .line 6
    .line 7
    invoke-virtual {v6, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    invoke-virtual {v6, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    const/4 v0, 0x4

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 v0, 0x2

    .line 19
    :goto_0
    or-int/2addr v0, p4

    .line 20
    and-int/lit8 v2, p5, 0x2

    .line 21
    .line 22
    if-eqz v2, :cond_1

    .line 23
    .line 24
    or-int/lit8 v0, v0, 0x30

    .line 25
    .line 26
    goto :goto_2

    .line 27
    :cond_1
    invoke-virtual {v6, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    if-eqz v4, :cond_2

    .line 32
    .line 33
    const/16 v4, 0x20

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_2
    const/16 v4, 0x10

    .line 37
    .line 38
    :goto_1
    or-int/2addr v0, v4

    .line 39
    :goto_2
    and-int/lit8 v4, p5, 0x4

    .line 40
    .line 41
    if-eqz v4, :cond_3

    .line 42
    .line 43
    or-int/lit16 v0, v0, 0x180

    .line 44
    .line 45
    goto :goto_4

    .line 46
    :cond_3
    invoke-virtual {v6, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v7

    .line 50
    if-eqz v7, :cond_4

    .line 51
    .line 52
    const/16 v7, 0x100

    .line 53
    .line 54
    goto :goto_3

    .line 55
    :cond_4
    const/16 v7, 0x80

    .line 56
    .line 57
    :goto_3
    or-int/2addr v0, v7

    .line 58
    :goto_4
    and-int/lit16 v7, v0, 0x93

    .line 59
    .line 60
    const/16 v8, 0x92

    .line 61
    .line 62
    if-eq v7, v8, :cond_5

    .line 63
    .line 64
    const/4 v7, 0x1

    .line 65
    goto :goto_5

    .line 66
    :cond_5
    const/4 v7, 0x0

    .line 67
    :goto_5
    and-int/lit8 v8, v0, 0x1

    .line 68
    .line 69
    invoke-virtual {v6, v8, v7}, Ll2/t;->O(IZ)Z

    .line 70
    .line 71
    .line 72
    move-result v7

    .line 73
    if-eqz v7, :cond_9

    .line 74
    .line 75
    if-eqz v2, :cond_6

    .line 76
    .line 77
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 78
    .line 79
    goto :goto_6

    .line 80
    :cond_6
    move-object v2, p1

    .line 81
    :goto_6
    if-eqz v4, :cond_8

    .line 82
    .line 83
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v3

    .line 87
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 88
    .line 89
    if-ne v3, v4, :cond_7

    .line 90
    .line 91
    new-instance v3, Li40/r2;

    .line 92
    .line 93
    const/4 v4, 0x5

    .line 94
    invoke-direct {v3, v4}, Li40/r2;-><init>(I)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {v6, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    :cond_7
    check-cast v3, Lay0/k;

    .line 101
    .line 102
    move-object v9, v3

    .line 103
    goto :goto_7

    .line 104
    :cond_8
    move-object v9, p2

    .line 105
    :goto_7
    new-instance v3, Li40/k0;

    .line 106
    .line 107
    const/16 v4, 0xe

    .line 108
    .line 109
    invoke-direct {v3, v4, p0, v9}, Li40/k0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    const v4, 0x49154780    # 611448.0f

    .line 113
    .line 114
    .line 115
    invoke-static {v4, v6, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 116
    .line 117
    .line 118
    move-result-object v5

    .line 119
    shr-int/lit8 v0, v0, 0x3

    .line 120
    .line 121
    and-int/lit8 v0, v0, 0xe

    .line 122
    .line 123
    or-int/lit16 v7, v0, 0xc00

    .line 124
    .line 125
    const/4 v8, 0x6

    .line 126
    const/4 v3, 0x0

    .line 127
    const/4 v4, 0x0

    .line 128
    invoke-static/range {v2 .. v8}, Li91/d0;->a(Lx2/s;Lay0/a;ZLay0/n;Ll2/o;II)V

    .line 129
    .line 130
    .line 131
    move-object v3, v9

    .line 132
    goto :goto_8

    .line 133
    :cond_9
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 134
    .line 135
    .line 136
    move-object v2, p1

    .line 137
    move-object v3, p2

    .line 138
    :goto_8
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 139
    .line 140
    .line 141
    move-result-object v7

    .line 142
    if-eqz v7, :cond_a

    .line 143
    .line 144
    new-instance v0, La2/f;

    .line 145
    .line 146
    const/16 v6, 0x1b

    .line 147
    .line 148
    move-object v1, p0

    .line 149
    move v4, p4

    .line 150
    move v5, p5

    .line 151
    invoke-direct/range {v0 .. v6}, La2/f;-><init>(Ljava/lang/Object;Lx2/s;Lay0/k;III)V

    .line 152
    .line 153
    .line 154
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 155
    .line 156
    :cond_a
    return-void
.end method

.method public static final c(Lh40/z;Lx2/s;Lay0/k;Lay0/k;Ll2/o;II)V
    .locals 11

    .line 1
    move-object v6, p4

    .line 2
    check-cast v6, Ll2/t;

    .line 3
    .line 4
    const v0, -0x1a0fd4fe

    .line 5
    .line 6
    .line 7
    invoke-virtual {v6, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    invoke-virtual {v6, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    const/4 v0, 0x4

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 v0, 0x2

    .line 19
    :goto_0
    or-int v0, p5, v0

    .line 20
    .line 21
    and-int/lit8 v2, p6, 0x2

    .line 22
    .line 23
    if-eqz v2, :cond_1

    .line 24
    .line 25
    or-int/lit8 v0, v0, 0x30

    .line 26
    .line 27
    goto :goto_2

    .line 28
    :cond_1
    invoke-virtual {v6, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v4

    .line 32
    if-eqz v4, :cond_2

    .line 33
    .line 34
    const/16 v4, 0x20

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_2
    const/16 v4, 0x10

    .line 38
    .line 39
    :goto_1
    or-int/2addr v0, v4

    .line 40
    :goto_2
    and-int/lit8 v4, p6, 0x4

    .line 41
    .line 42
    if-eqz v4, :cond_3

    .line 43
    .line 44
    or-int/lit16 v0, v0, 0x180

    .line 45
    .line 46
    goto :goto_4

    .line 47
    :cond_3
    invoke-virtual {v6, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v7

    .line 51
    if-eqz v7, :cond_4

    .line 52
    .line 53
    const/16 v7, 0x100

    .line 54
    .line 55
    goto :goto_3

    .line 56
    :cond_4
    const/16 v7, 0x80

    .line 57
    .line 58
    :goto_3
    or-int/2addr v0, v7

    .line 59
    :goto_4
    and-int/lit8 v7, p6, 0x8

    .line 60
    .line 61
    if-eqz v7, :cond_5

    .line 62
    .line 63
    or-int/lit16 v0, v0, 0xc00

    .line 64
    .line 65
    goto :goto_6

    .line 66
    :cond_5
    invoke-virtual {v6, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v9

    .line 70
    if-eqz v9, :cond_6

    .line 71
    .line 72
    const/16 v9, 0x800

    .line 73
    .line 74
    goto :goto_5

    .line 75
    :cond_6
    const/16 v9, 0x400

    .line 76
    .line 77
    :goto_5
    or-int/2addr v0, v9

    .line 78
    :goto_6
    and-int/lit16 v9, v0, 0x493

    .line 79
    .line 80
    const/16 v10, 0x492

    .line 81
    .line 82
    if-eq v9, v10, :cond_7

    .line 83
    .line 84
    const/4 v9, 0x1

    .line 85
    goto :goto_7

    .line 86
    :cond_7
    const/4 v9, 0x0

    .line 87
    :goto_7
    and-int/lit8 v10, v0, 0x1

    .line 88
    .line 89
    invoke-virtual {v6, v10, v9}, Ll2/t;->O(IZ)Z

    .line 90
    .line 91
    .line 92
    move-result v9

    .line 93
    if-eqz v9, :cond_d

    .line 94
    .line 95
    if-eqz v2, :cond_8

    .line 96
    .line 97
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 98
    .line 99
    goto :goto_8

    .line 100
    :cond_8
    move-object v2, p1

    .line 101
    :goto_8
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 102
    .line 103
    if-eqz v4, :cond_a

    .line 104
    .line 105
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v4

    .line 109
    if-ne v4, v3, :cond_9

    .line 110
    .line 111
    new-instance v4, Li40/r2;

    .line 112
    .line 113
    const/4 v5, 0x3

    .line 114
    invoke-direct {v4, v5}, Li40/r2;-><init>(I)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v6, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    :cond_9
    check-cast v4, Lay0/k;

    .line 121
    .line 122
    move-object v9, v4

    .line 123
    goto :goto_9

    .line 124
    :cond_a
    move-object v9, p2

    .line 125
    :goto_9
    if-eqz v7, :cond_c

    .line 126
    .line 127
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v4

    .line 131
    if-ne v4, v3, :cond_b

    .line 132
    .line 133
    new-instance v4, Li40/r2;

    .line 134
    .line 135
    const/4 v3, 0x4

    .line 136
    invoke-direct {v4, v3}, Li40/r2;-><init>(I)V

    .line 137
    .line 138
    .line 139
    invoke-virtual {v6, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 140
    .line 141
    .line 142
    :cond_b
    move-object v3, v4

    .line 143
    check-cast v3, Lay0/k;

    .line 144
    .line 145
    move-object v10, v3

    .line 146
    goto :goto_a

    .line 147
    :cond_c
    move-object v10, p3

    .line 148
    :goto_a
    new-instance v3, Lf20/f;

    .line 149
    .line 150
    const/16 v4, 0x1a

    .line 151
    .line 152
    invoke-direct {v3, p0, v9, v10, v4}, Lf20/f;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 153
    .line 154
    .line 155
    const v4, -0x49d21449

    .line 156
    .line 157
    .line 158
    invoke-static {v4, v6, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 159
    .line 160
    .line 161
    move-result-object v5

    .line 162
    shr-int/lit8 v0, v0, 0x3

    .line 163
    .line 164
    and-int/lit8 v0, v0, 0xe

    .line 165
    .line 166
    or-int/lit16 v7, v0, 0xc00

    .line 167
    .line 168
    const/4 v8, 0x6

    .line 169
    const/4 v3, 0x0

    .line 170
    const/4 v4, 0x0

    .line 171
    invoke-static/range {v2 .. v8}, Li91/d0;->a(Lx2/s;Lay0/a;ZLay0/n;Ll2/o;II)V

    .line 172
    .line 173
    .line 174
    move-object v3, v9

    .line 175
    move-object v4, v10

    .line 176
    goto :goto_b

    .line 177
    :cond_d
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 178
    .line 179
    .line 180
    move-object v2, p1

    .line 181
    move-object v3, p2

    .line 182
    move-object v4, p3

    .line 183
    :goto_b
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 184
    .line 185
    .line 186
    move-result-object v8

    .line 187
    if-eqz v8, :cond_e

    .line 188
    .line 189
    new-instance v0, La71/e;

    .line 190
    .line 191
    const/16 v7, 0x12

    .line 192
    .line 193
    move-object v1, p0

    .line 194
    move/from16 v5, p5

    .line 195
    .line 196
    move/from16 v6, p6

    .line 197
    .line 198
    invoke-direct/range {v0 .. v7}, La71/e;-><init>(Ljava/lang/Object;Lx2/s;Llx0/e;Lay0/k;III)V

    .line 199
    .line 200
    .line 201
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 202
    .line 203
    :cond_e
    return-void
.end method

.method public static final d(Lh40/a0;Lx2/s;Ll2/o;II)V
    .locals 11

    .line 1
    move-object v4, p2

    .line 2
    check-cast v4, Ll2/t;

    .line 3
    .line 4
    const p2, -0x635728a8

    .line 5
    .line 6
    .line 7
    invoke-virtual {v4, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 p2, p3, 0x6

    .line 11
    .line 12
    if-nez p2, :cond_1

    .line 13
    .line 14
    invoke-virtual {v4, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    if-eqz p2, :cond_0

    .line 19
    .line 20
    const/4 p2, 0x4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 p2, 0x2

    .line 23
    :goto_0
    or-int/2addr p2, p3

    .line 24
    goto :goto_1

    .line 25
    :cond_1
    move p2, p3

    .line 26
    :goto_1
    and-int/lit8 v0, p4, 0x2

    .line 27
    .line 28
    if-eqz v0, :cond_2

    .line 29
    .line 30
    or-int/lit8 p2, p2, 0x30

    .line 31
    .line 32
    goto :goto_3

    .line 33
    :cond_2
    invoke-virtual {v4, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    if-eqz v1, :cond_3

    .line 38
    .line 39
    const/16 v1, 0x20

    .line 40
    .line 41
    goto :goto_2

    .line 42
    :cond_3
    const/16 v1, 0x10

    .line 43
    .line 44
    :goto_2
    or-int/2addr p2, v1

    .line 45
    :goto_3
    and-int/lit8 v1, p2, 0x13

    .line 46
    .line 47
    const/16 v2, 0x12

    .line 48
    .line 49
    if-eq v1, v2, :cond_4

    .line 50
    .line 51
    const/4 v1, 0x1

    .line 52
    goto :goto_4

    .line 53
    :cond_4
    const/4 v1, 0x0

    .line 54
    :goto_4
    and-int/lit8 v2, p2, 0x1

    .line 55
    .line 56
    invoke-virtual {v4, v2, v1}, Ll2/t;->O(IZ)Z

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    if-eqz v1, :cond_6

    .line 61
    .line 62
    if-eqz v0, :cond_5

    .line 63
    .line 64
    sget-object p1, Lx2/p;->b:Lx2/p;

    .line 65
    .line 66
    :cond_5
    move-object v0, p1

    .line 67
    new-instance p1, Lh2/y5;

    .line 68
    .line 69
    const/16 v1, 0xb

    .line 70
    .line 71
    invoke-direct {p1, p0, v1}, Lh2/y5;-><init>(Ljava/lang/Object;I)V

    .line 72
    .line 73
    .line 74
    const v1, 0x2f0dcb4d

    .line 75
    .line 76
    .line 77
    invoke-static {v1, v4, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 78
    .line 79
    .line 80
    move-result-object v3

    .line 81
    shr-int/lit8 p1, p2, 0x3

    .line 82
    .line 83
    and-int/lit8 p1, p1, 0xe

    .line 84
    .line 85
    or-int/lit16 v5, p1, 0xc00

    .line 86
    .line 87
    const/4 v6, 0x6

    .line 88
    const/4 v1, 0x0

    .line 89
    const/4 v2, 0x0

    .line 90
    invoke-static/range {v0 .. v6}, Li91/d0;->a(Lx2/s;Lay0/a;ZLay0/n;Ll2/o;II)V

    .line 91
    .line 92
    .line 93
    move-object v7, v0

    .line 94
    goto :goto_5

    .line 95
    :cond_6
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 96
    .line 97
    .line 98
    move-object v7, p1

    .line 99
    :goto_5
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    if-eqz p1, :cond_7

    .line 104
    .line 105
    new-instance v5, Lck/h;

    .line 106
    .line 107
    const/4 v10, 0x2

    .line 108
    move-object v6, p0

    .line 109
    move v8, p3

    .line 110
    move v9, p4

    .line 111
    invoke-direct/range {v5 .. v10}, Lck/h;-><init>(Ljava/lang/Object;Ljava/lang/Object;III)V

    .line 112
    .line 113
    .line 114
    iput-object v5, p1, Ll2/u1;->d:Lay0/n;

    .line 115
    .line 116
    :cond_7
    return-void
.end method

.method public static final e(Lh40/b0;Lx2/s;Ll2/o;II)V
    .locals 11

    .line 1
    move-object v4, p2

    .line 2
    check-cast v4, Ll2/t;

    .line 3
    .line 4
    const p2, 0x6911233c

    .line 5
    .line 6
    .line 7
    invoke-virtual {v4, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    invoke-virtual {v4, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    if-eqz p2, :cond_0

    .line 15
    .line 16
    const/4 p2, 0x4

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 p2, 0x2

    .line 19
    :goto_0
    or-int/2addr p2, p3

    .line 20
    and-int/lit8 v0, p4, 0x2

    .line 21
    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    or-int/lit8 p2, p2, 0x30

    .line 25
    .line 26
    goto :goto_2

    .line 27
    :cond_1
    invoke-virtual {v4, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-eqz v1, :cond_2

    .line 32
    .line 33
    const/16 v1, 0x20

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_2
    const/16 v1, 0x10

    .line 37
    .line 38
    :goto_1
    or-int/2addr p2, v1

    .line 39
    :goto_2
    and-int/lit8 v1, p2, 0x13

    .line 40
    .line 41
    const/16 v2, 0x12

    .line 42
    .line 43
    if-eq v1, v2, :cond_3

    .line 44
    .line 45
    const/4 v1, 0x1

    .line 46
    goto :goto_3

    .line 47
    :cond_3
    const/4 v1, 0x0

    .line 48
    :goto_3
    and-int/lit8 v2, p2, 0x1

    .line 49
    .line 50
    invoke-virtual {v4, v2, v1}, Ll2/t;->O(IZ)Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-eqz v1, :cond_5

    .line 55
    .line 56
    if-eqz v0, :cond_4

    .line 57
    .line 58
    sget-object p1, Lx2/p;->b:Lx2/p;

    .line 59
    .line 60
    :cond_4
    move-object v0, p1

    .line 61
    new-instance p1, Lh2/y5;

    .line 62
    .line 63
    const/16 v1, 0xc

    .line 64
    .line 65
    invoke-direct {p1, p0, v1}, Lh2/y5;-><init>(Ljava/lang/Object;I)V

    .line 66
    .line 67
    .line 68
    const v1, -0x9f7120f

    .line 69
    .line 70
    .line 71
    invoke-static {v1, v4, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 72
    .line 73
    .line 74
    move-result-object v3

    .line 75
    shr-int/lit8 p1, p2, 0x3

    .line 76
    .line 77
    and-int/lit8 p1, p1, 0xe

    .line 78
    .line 79
    or-int/lit16 v5, p1, 0xc00

    .line 80
    .line 81
    const/4 v6, 0x6

    .line 82
    const/4 v1, 0x0

    .line 83
    const/4 v2, 0x0

    .line 84
    invoke-static/range {v0 .. v6}, Li91/d0;->a(Lx2/s;Lay0/a;ZLay0/n;Ll2/o;II)V

    .line 85
    .line 86
    .line 87
    move-object v7, v0

    .line 88
    goto :goto_4

    .line 89
    :cond_5
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 90
    .line 91
    .line 92
    move-object v7, p1

    .line 93
    :goto_4
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 94
    .line 95
    .line 96
    move-result-object p1

    .line 97
    if-eqz p1, :cond_6

    .line 98
    .line 99
    new-instance v5, La71/n0;

    .line 100
    .line 101
    const/16 v10, 0x15

    .line 102
    .line 103
    move-object v6, p0

    .line 104
    move v8, p3

    .line 105
    move v9, p4

    .line 106
    invoke-direct/range {v5 .. v10}, La71/n0;-><init>(Ljava/lang/Object;Ljava/lang/Object;III)V

    .line 107
    .line 108
    .line 109
    iput-object v5, p1, Ll2/u1;->d:Lay0/n;

    .line 110
    .line 111
    :cond_6
    return-void
.end method

.method public static final f(IFLl2/o;I)V
    .locals 28

    .line 1
    move/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p3

    .line 6
    .line 7
    move-object/from16 v3, p2

    .line 8
    .line 9
    check-cast v3, Ll2/t;

    .line 10
    .line 11
    const v4, 0x796a4b92

    .line 12
    .line 13
    .line 14
    invoke-virtual {v3, v4}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v3, v0}, Ll2/t;->e(I)Z

    .line 18
    .line 19
    .line 20
    move-result v4

    .line 21
    if-eqz v4, :cond_0

    .line 22
    .line 23
    const/4 v4, 0x4

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 v4, 0x2

    .line 26
    :goto_0
    or-int/2addr v4, v2

    .line 27
    invoke-virtual {v3, v1}, Ll2/t;->d(F)Z

    .line 28
    .line 29
    .line 30
    move-result v5

    .line 31
    if-eqz v5, :cond_1

    .line 32
    .line 33
    const/16 v5, 0x20

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    const/16 v5, 0x10

    .line 37
    .line 38
    :goto_1
    or-int v25, v4, v5

    .line 39
    .line 40
    and-int/lit8 v4, v25, 0x13

    .line 41
    .line 42
    const/16 v5, 0x12

    .line 43
    .line 44
    const/4 v6, 0x1

    .line 45
    const/4 v7, 0x0

    .line 46
    if-eq v4, v5, :cond_2

    .line 47
    .line 48
    move v4, v6

    .line 49
    goto :goto_2

    .line 50
    :cond_2
    move v4, v7

    .line 51
    :goto_2
    and-int/lit8 v5, v25, 0x1

    .line 52
    .line 53
    invoke-virtual {v3, v5, v4}, Ll2/t;->O(IZ)Z

    .line 54
    .line 55
    .line 56
    move-result v4

    .line 57
    if-eqz v4, :cond_6

    .line 58
    .line 59
    sget-object v4, Lk1/j;->c:Lk1/e;

    .line 60
    .line 61
    sget-object v5, Lx2/c;->p:Lx2/h;

    .line 62
    .line 63
    invoke-static {v4, v5, v3, v7}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 64
    .line 65
    .line 66
    move-result-object v4

    .line 67
    iget-wide v7, v3, Ll2/t;->T:J

    .line 68
    .line 69
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 70
    .line 71
    .line 72
    move-result v5

    .line 73
    invoke-virtual {v3}, Ll2/t;->m()Ll2/p1;

    .line 74
    .line 75
    .line 76
    move-result-object v7

    .line 77
    sget-object v8, Lx2/p;->b:Lx2/p;

    .line 78
    .line 79
    invoke-static {v3, v8}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 80
    .line 81
    .line 82
    move-result-object v9

    .line 83
    sget-object v10, Lv3/k;->m1:Lv3/j;

    .line 84
    .line 85
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 86
    .line 87
    .line 88
    sget-object v10, Lv3/j;->b:Lv3/i;

    .line 89
    .line 90
    invoke-virtual {v3}, Ll2/t;->c0()V

    .line 91
    .line 92
    .line 93
    iget-boolean v11, v3, Ll2/t;->S:Z

    .line 94
    .line 95
    if-eqz v11, :cond_3

    .line 96
    .line 97
    invoke-virtual {v3, v10}, Ll2/t;->l(Lay0/a;)V

    .line 98
    .line 99
    .line 100
    goto :goto_3

    .line 101
    :cond_3
    invoke-virtual {v3}, Ll2/t;->m0()V

    .line 102
    .line 103
    .line 104
    :goto_3
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 105
    .line 106
    invoke-static {v10, v4, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 107
    .line 108
    .line 109
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 110
    .line 111
    invoke-static {v4, v7, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 112
    .line 113
    .line 114
    sget-object v4, Lv3/j;->j:Lv3/h;

    .line 115
    .line 116
    iget-boolean v7, v3, Ll2/t;->S:Z

    .line 117
    .line 118
    if-nez v7, :cond_4

    .line 119
    .line 120
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v7

    .line 124
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 125
    .line 126
    .line 127
    move-result-object v10

    .line 128
    invoke-static {v7, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    move-result v7

    .line 132
    if-nez v7, :cond_5

    .line 133
    .line 134
    :cond_4
    invoke-static {v5, v3, v5, v4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 135
    .line 136
    .line 137
    :cond_5
    sget-object v4, Lv3/j;->d:Lv3/h;

    .line 138
    .line 139
    invoke-static {v4, v9, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 140
    .line 141
    .line 142
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 143
    .line 144
    .line 145
    move-result-object v4

    .line 146
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v4

    .line 150
    const v5, 0x7f120cff

    .line 151
    .line 152
    .line 153
    invoke-static {v5, v4, v3}, Ljp/ga;->c(I[Ljava/lang/Object;Ll2/o;)Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object v4

    .line 157
    sget-object v5, Lj91/j;->a:Ll2/u2;

    .line 158
    .line 159
    invoke-virtual {v3, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object v5

    .line 163
    check-cast v5, Lj91/f;

    .line 164
    .line 165
    invoke-virtual {v5}, Lj91/f;->b()Lg4/p0;

    .line 166
    .line 167
    .line 168
    move-result-object v5

    .line 169
    const/16 v23, 0x0

    .line 170
    .line 171
    const v24, 0xfffc

    .line 172
    .line 173
    .line 174
    move-object/from16 v21, v3

    .line 175
    .line 176
    move-object v3, v4

    .line 177
    move-object v4, v5

    .line 178
    const/4 v5, 0x0

    .line 179
    move v9, v6

    .line 180
    const-wide/16 v6, 0x0

    .line 181
    .line 182
    move-object v11, v8

    .line 183
    move v10, v9

    .line 184
    const-wide/16 v8, 0x0

    .line 185
    .line 186
    move v12, v10

    .line 187
    const/4 v10, 0x0

    .line 188
    move-object v14, v11

    .line 189
    move v13, v12

    .line 190
    const-wide/16 v11, 0x0

    .line 191
    .line 192
    move v15, v13

    .line 193
    const/4 v13, 0x0

    .line 194
    move-object/from16 v16, v14

    .line 195
    .line 196
    const/4 v14, 0x0

    .line 197
    move/from16 v17, v15

    .line 198
    .line 199
    move-object/from16 v18, v16

    .line 200
    .line 201
    const-wide/16 v15, 0x0

    .line 202
    .line 203
    move/from16 v19, v17

    .line 204
    .line 205
    const/16 v17, 0x0

    .line 206
    .line 207
    move-object/from16 v20, v18

    .line 208
    .line 209
    const/16 v18, 0x0

    .line 210
    .line 211
    move/from16 v22, v19

    .line 212
    .line 213
    const/16 v19, 0x0

    .line 214
    .line 215
    move-object/from16 v26, v20

    .line 216
    .line 217
    const/16 v20, 0x0

    .line 218
    .line 219
    move/from16 v27, v22

    .line 220
    .line 221
    const/16 v22, 0x0

    .line 222
    .line 223
    move-object/from16 v0, v26

    .line 224
    .line 225
    invoke-static/range {v3 .. v24}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 226
    .line 227
    .line 228
    move-object/from16 v3, v21

    .line 229
    .line 230
    const/4 v4, 0x5

    .line 231
    int-to-float v4, v4

    .line 232
    invoke-static {v0, v4}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 233
    .line 234
    .line 235
    move-result-object v4

    .line 236
    invoke-static {v3, v4}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 237
    .line 238
    .line 239
    sget-object v4, Lj91/a;->a:Ll2/u2;

    .line 240
    .line 241
    invoke-virtual {v3, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    move-result-object v4

    .line 245
    check-cast v4, Lj91/c;

    .line 246
    .line 247
    iget v4, v4, Lj91/c;->c:F

    .line 248
    .line 249
    invoke-static {v4}, Ls1/f;->b(F)Ls1/e;

    .line 250
    .line 251
    .line 252
    move-result-object v4

    .line 253
    invoke-static {v0, v4}, Ljp/ba;->c(Lx2/s;Le3/n0;)Lx2/s;

    .line 254
    .line 255
    .line 256
    move-result-object v0

    .line 257
    const/16 v4, 0x80

    .line 258
    .line 259
    int-to-float v4, v4

    .line 260
    invoke-static {v0, v4}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 261
    .line 262
    .line 263
    move-result-object v0

    .line 264
    const/4 v4, 0x7

    .line 265
    int-to-float v4, v4

    .line 266
    invoke-static {v0, v4}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 267
    .line 268
    .line 269
    move-result-object v0

    .line 270
    shr-int/lit8 v4, v25, 0x3

    .line 271
    .line 272
    and-int/lit8 v4, v4, 0xe

    .line 273
    .line 274
    invoke-static {v1, v4, v3, v0}, Li91/j0;->y(FILl2/o;Lx2/s;)V

    .line 275
    .line 276
    .line 277
    const/4 v12, 0x1

    .line 278
    invoke-virtual {v3, v12}, Ll2/t;->q(Z)V

    .line 279
    .line 280
    .line 281
    goto :goto_4

    .line 282
    :cond_6
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 283
    .line 284
    .line 285
    :goto_4
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 286
    .line 287
    .line 288
    move-result-object v0

    .line 289
    if-eqz v0, :cond_7

    .line 290
    .line 291
    new-instance v3, Li40/e3;

    .line 292
    .line 293
    move/from16 v4, p0

    .line 294
    .line 295
    invoke-direct {v3, v4, v1, v2}, Li40/e3;-><init>(IFI)V

    .line 296
    .line 297
    .line 298
    iput-object v3, v0, Ll2/u1;->d:Lay0/n;

    .line 299
    .line 300
    :cond_7
    return-void
.end method
