.class public abstract Ldk/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lzb/k;->a:Lzb/u;

    .line 2
    .line 3
    return-void
.end method

.method public static final a(Lx2/s;Lg4/p0;Ljava/lang/String;Ll2/o;I)V
    .locals 4

    .line 1
    sget-object v0, Loi/b;->d:Loi/b;

    .line 2
    .line 3
    check-cast p3, Ll2/t;

    .line 4
    .line 5
    const v0, 0x561c3766

    .line 6
    .line 7
    .line 8
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 9
    .line 10
    .line 11
    and-int/lit8 v0, p4, 0x6

    .line 12
    .line 13
    if-nez v0, :cond_1

    .line 14
    .line 15
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    const/4 v0, 0x4

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 v0, 0x2

    .line 24
    :goto_0
    or-int/2addr v0, p4

    .line 25
    goto :goto_1

    .line 26
    :cond_1
    move v0, p4

    .line 27
    :goto_1
    and-int/lit8 v1, p4, 0x30

    .line 28
    .line 29
    if-nez v1, :cond_3

    .line 30
    .line 31
    invoke-virtual {p3, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-eqz v1, :cond_2

    .line 36
    .line 37
    const/16 v1, 0x20

    .line 38
    .line 39
    goto :goto_2

    .line 40
    :cond_2
    const/16 v1, 0x10

    .line 41
    .line 42
    :goto_2
    or-int/2addr v0, v1

    .line 43
    :cond_3
    and-int/lit16 v1, p4, 0x180

    .line 44
    .line 45
    if-nez v1, :cond_5

    .line 46
    .line 47
    invoke-virtual {p3, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v1

    .line 51
    if-eqz v1, :cond_4

    .line 52
    .line 53
    const/16 v1, 0x100

    .line 54
    .line 55
    goto :goto_3

    .line 56
    :cond_4
    const/16 v1, 0x80

    .line 57
    .line 58
    :goto_3
    or-int/2addr v0, v1

    .line 59
    :cond_5
    and-int/lit16 v1, p4, 0xc00

    .line 60
    .line 61
    const/4 v2, 0x1

    .line 62
    if-nez v1, :cond_7

    .line 63
    .line 64
    invoke-virtual {p3, v2}, Ll2/t;->e(I)Z

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    if-eqz v1, :cond_6

    .line 69
    .line 70
    const/16 v1, 0x800

    .line 71
    .line 72
    goto :goto_4

    .line 73
    :cond_6
    const/16 v1, 0x400

    .line 74
    .line 75
    :goto_4
    or-int/2addr v0, v1

    .line 76
    :cond_7
    and-int/lit16 v1, v0, 0x493

    .line 77
    .line 78
    const/16 v3, 0x492

    .line 79
    .line 80
    if-eq v1, v3, :cond_8

    .line 81
    .line 82
    goto :goto_5

    .line 83
    :cond_8
    const/4 v2, 0x0

    .line 84
    :goto_5
    and-int/lit8 v1, v0, 0x1

    .line 85
    .line 86
    invoke-virtual {p3, v1, v2}, Ll2/t;->O(IZ)Z

    .line 87
    .line 88
    .line 89
    move-result v1

    .line 90
    if-eqz v1, :cond_b

    .line 91
    .line 92
    invoke-virtual {p3}, Ll2/t;->T()V

    .line 93
    .line 94
    .line 95
    and-int/lit8 v1, p4, 0x1

    .line 96
    .line 97
    if-eqz v1, :cond_a

    .line 98
    .line 99
    invoke-virtual {p3}, Ll2/t;->y()Z

    .line 100
    .line 101
    .line 102
    move-result v1

    .line 103
    if-eqz v1, :cond_9

    .line 104
    .line 105
    goto :goto_6

    .line 106
    :cond_9
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 107
    .line 108
    .line 109
    :cond_a
    :goto_6
    invoke-virtual {p3}, Ll2/t;->r()V

    .line 110
    .line 111
    .line 112
    new-instance v1, La71/a1;

    .line 113
    .line 114
    const/16 v2, 0xe

    .line 115
    .line 116
    invoke-direct {v1, p0, p2, p1, v2}, La71/a1;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 117
    .line 118
    .line 119
    const v3, -0x7a7052f8

    .line 120
    .line 121
    .line 122
    invoke-static {v3, p3, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 123
    .line 124
    .line 125
    move-result-object v1

    .line 126
    shr-int/lit8 v0, v0, 0x9

    .line 127
    .line 128
    and-int/2addr v0, v2

    .line 129
    or-int/lit8 v0, v0, 0x30

    .line 130
    .line 131
    invoke-static {v1, p3, v0}, Ljp/vb;->a(Lt2/b;Ll2/o;I)V

    .line 132
    .line 133
    .line 134
    goto :goto_7

    .line 135
    :cond_b
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 136
    .line 137
    .line 138
    :goto_7
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 139
    .line 140
    .line 141
    move-result-object p3

    .line 142
    if-eqz p3, :cond_c

    .line 143
    .line 144
    new-instance v0, La2/f;

    .line 145
    .line 146
    invoke-direct {v0, p0, p1, p2, p4}, La2/f;-><init>(Lx2/s;Lg4/p0;Ljava/lang/String;I)V

    .line 147
    .line 148
    .line 149
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 150
    .line 151
    :cond_c
    return-void
.end method

.method public static final b(Lx2/s;Lg4/p0;Ljava/lang/String;Ll2/o;II)V
    .locals 8

    .line 1
    check-cast p3, Ll2/t;

    .line 2
    .line 3
    const v0, -0x202fc922    # -3.0006847E19f

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p5, 0x1

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    or-int/lit8 v1, p4, 0x6

    .line 14
    .line 15
    goto :goto_1

    .line 16
    :cond_0
    and-int/lit8 v1, p4, 0x6

    .line 17
    .line 18
    if-nez v1, :cond_2

    .line 19
    .line 20
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    if-eqz v1, :cond_1

    .line 25
    .line 26
    const/4 v1, 0x4

    .line 27
    goto :goto_0

    .line 28
    :cond_1
    const/4 v1, 0x2

    .line 29
    :goto_0
    or-int/2addr v1, p4

    .line 30
    goto :goto_1

    .line 31
    :cond_2
    move v1, p4

    .line 32
    :goto_1
    or-int/lit8 v2, v1, 0x10

    .line 33
    .line 34
    and-int/lit8 v3, p5, 0x4

    .line 35
    .line 36
    if-eqz v3, :cond_3

    .line 37
    .line 38
    or-int/lit16 v2, v1, 0x190

    .line 39
    .line 40
    goto :goto_3

    .line 41
    :cond_3
    and-int/lit16 v1, p4, 0x180

    .line 42
    .line 43
    if-nez v1, :cond_5

    .line 44
    .line 45
    invoke-virtual {p3, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    if-eqz v1, :cond_4

    .line 50
    .line 51
    const/16 v1, 0x100

    .line 52
    .line 53
    goto :goto_2

    .line 54
    :cond_4
    const/16 v1, 0x80

    .line 55
    .line 56
    :goto_2
    or-int/2addr v2, v1

    .line 57
    :cond_5
    :goto_3
    and-int/lit16 v1, v2, 0x93

    .line 58
    .line 59
    const/16 v4, 0x92

    .line 60
    .line 61
    if-eq v1, v4, :cond_6

    .line 62
    .line 63
    const/4 v1, 0x1

    .line 64
    goto :goto_4

    .line 65
    :cond_6
    const/4 v1, 0x0

    .line 66
    :goto_4
    and-int/lit8 v4, v2, 0x1

    .line 67
    .line 68
    invoke-virtual {p3, v4, v1}, Ll2/t;->O(IZ)Z

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    if-eqz v1, :cond_b

    .line 73
    .line 74
    invoke-virtual {p3}, Ll2/t;->T()V

    .line 75
    .line 76
    .line 77
    and-int/lit8 v1, p4, 0x1

    .line 78
    .line 79
    if-eqz v1, :cond_8

    .line 80
    .line 81
    invoke-virtual {p3}, Ll2/t;->y()Z

    .line 82
    .line 83
    .line 84
    move-result v1

    .line 85
    if-eqz v1, :cond_7

    .line 86
    .line 87
    goto :goto_5

    .line 88
    :cond_7
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 89
    .line 90
    .line 91
    and-int/lit8 v0, v2, -0x71

    .line 92
    .line 93
    goto :goto_6

    .line 94
    :cond_8
    :goto_5
    if-eqz v0, :cond_9

    .line 95
    .line 96
    sget-object p0, Lx2/p;->b:Lx2/p;

    .line 97
    .line 98
    :cond_9
    sget-object p1, Lj91/j;->a:Ll2/u2;

    .line 99
    .line 100
    invoke-virtual {p3, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    check-cast p1, Lj91/f;

    .line 105
    .line 106
    invoke-virtual {p1}, Lj91/f;->e()Lg4/p0;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    and-int/lit8 v0, v2, -0x71

    .line 111
    .line 112
    if-eqz v3, :cond_a

    .line 113
    .line 114
    const-string p2, ""

    .line 115
    .line 116
    :cond_a
    :goto_6
    invoke-virtual {p3}, Ll2/t;->r()V

    .line 117
    .line 118
    .line 119
    sget-object v1, Loi/b;->d:Loi/b;

    .line 120
    .line 121
    and-int/lit8 v1, v0, 0xe

    .line 122
    .line 123
    or-int/lit16 v1, v1, 0xc00

    .line 124
    .line 125
    and-int/lit16 v0, v0, 0x380

    .line 126
    .line 127
    or-int/2addr v0, v1

    .line 128
    invoke-static {p0, p1, p2, p3, v0}, Ldk/c;->a(Lx2/s;Lg4/p0;Ljava/lang/String;Ll2/o;I)V

    .line 129
    .line 130
    .line 131
    :goto_7
    move-object v2, p0

    .line 132
    move-object v3, p1

    .line 133
    move-object v4, p2

    .line 134
    goto :goto_8

    .line 135
    :cond_b
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 136
    .line 137
    .line 138
    goto :goto_7

    .line 139
    :goto_8
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    if-eqz p0, :cond_c

    .line 144
    .line 145
    new-instance v1, Lc71/c;

    .line 146
    .line 147
    const/4 v7, 0x5

    .line 148
    move v5, p4

    .line 149
    move v6, p5

    .line 150
    invoke-direct/range {v1 .. v7}, Lc71/c;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;III)V

    .line 151
    .line 152
    .line 153
    iput-object v1, p0, Ll2/u1;->d:Lay0/n;

    .line 154
    .line 155
    :cond_c
    return-void
.end method
