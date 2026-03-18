.class public abstract Llp/ec;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lvv/m0;ZLt2/b;Ll2/o;I)V
    .locals 5

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p3, Ll2/t;

    .line 7
    .line 8
    const v0, 0x549ba27a

    .line 9
    .line 10
    .line 11
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 12
    .line 13
    .line 14
    and-int/lit8 v0, p4, 0xe

    .line 15
    .line 16
    if-nez v0, :cond_1

    .line 17
    .line 18
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

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
    or-int/2addr v0, p4

    .line 28
    goto :goto_1

    .line 29
    :cond_1
    move v0, p4

    .line 30
    :goto_1
    and-int/lit8 v1, p4, 0x70

    .line 31
    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    invoke-virtual {p3, p1}, Ll2/t;->h(Z)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-eqz v1, :cond_2

    .line 39
    .line 40
    const/16 v1, 0x20

    .line 41
    .line 42
    goto :goto_2

    .line 43
    :cond_2
    const/16 v1, 0x10

    .line 44
    .line 45
    :goto_2
    or-int/2addr v0, v1

    .line 46
    :cond_3
    and-int/lit16 v1, p4, 0x380

    .line 47
    .line 48
    if-nez v1, :cond_5

    .line 49
    .line 50
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-eqz v1, :cond_4

    .line 55
    .line 56
    const/16 v1, 0x100

    .line 57
    .line 58
    goto :goto_3

    .line 59
    :cond_4
    const/16 v1, 0x80

    .line 60
    .line 61
    :goto_3
    or-int/2addr v0, v1

    .line 62
    :cond_5
    and-int/lit16 v1, v0, 0x2db

    .line 63
    .line 64
    const/16 v2, 0x92

    .line 65
    .line 66
    if-ne v1, v2, :cond_7

    .line 67
    .line 68
    invoke-virtual {p3}, Ll2/t;->A()Z

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    if-nez v1, :cond_6

    .line 73
    .line 74
    goto :goto_4

    .line 75
    :cond_6
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 76
    .line 77
    .line 78
    goto :goto_5

    .line 79
    :cond_7
    :goto_4
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 80
    .line 81
    const/4 v2, 0x0

    .line 82
    if-nez p1, :cond_8

    .line 83
    .line 84
    const v3, -0x4e6aa795

    .line 85
    .line 86
    .line 87
    invoke-virtual {p3, v3}, Ll2/t;->Z(I)V

    .line 88
    .line 89
    .line 90
    const/4 v3, 0x1

    .line 91
    invoke-static {v2, v3, p3}, Lkp/n;->b(IILl2/o;)Le1/n1;

    .line 92
    .line 93
    .line 94
    move-result-object v4

    .line 95
    invoke-static {v1, v4, v2, v3, v2}, Lkp/n;->c(Lx2/s;Le1/n1;ZZZ)Lx2/s;

    .line 96
    .line 97
    .line 98
    move-result-object v1

    .line 99
    and-int/lit16 v0, v0, 0x38e

    .line 100
    .line 101
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 102
    .line 103
    .line 104
    move-result-object v0

    .line 105
    invoke-virtual {p2, p0, v1, p3, v0}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    invoke-virtual {p3, v2}, Ll2/t;->q(Z)V

    .line 109
    .line 110
    .line 111
    goto :goto_5

    .line 112
    :cond_8
    const v3, -0x4e6aa729

    .line 113
    .line 114
    .line 115
    invoke-virtual {p3, v3}, Ll2/t;->Z(I)V

    .line 116
    .line 117
    .line 118
    and-int/lit8 v3, v0, 0xe

    .line 119
    .line 120
    or-int/lit8 v3, v3, 0x30

    .line 121
    .line 122
    and-int/lit16 v0, v0, 0x380

    .line 123
    .line 124
    or-int/2addr v0, v3

    .line 125
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    invoke-virtual {p2, p0, v1, p3, v0}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    invoke-virtual {p3, v2}, Ll2/t;->q(Z)V

    .line 133
    .line 134
    .line 135
    :goto_5
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 136
    .line 137
    .line 138
    move-result-object p3

    .line 139
    if-eqz p3, :cond_9

    .line 140
    .line 141
    new-instance v0, Lvv/l;

    .line 142
    .line 143
    invoke-direct {v0, p0, p1, p2, p4}, Lvv/l;-><init>(Lvv/m0;ZLt2/b;I)V

    .line 144
    .line 145
    .line 146
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 147
    .line 148
    :cond_9
    return-void
.end method

.method public static final b(Lx2/s;Lay0/k;ILay0/k;JLjava/lang/Iterable;Lg4/p0;Ll2/o;I)V
    .locals 20

    .line 1
    move/from16 v9, p9

    .line 2
    .line 3
    const-string v0, "onValueChange"

    .line 4
    .line 5
    move-object/from16 v13, p3

    .line 6
    .line 7
    invoke-static {v13, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v0, "range"

    .line 11
    .line 12
    move-object/from16 v7, p6

    .line 13
    .line 14
    invoke-static {v7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    move-object/from16 v0, p8

    .line 18
    .line 19
    check-cast v0, Ll2/t;

    .line 20
    .line 21
    const v1, -0x39910b24

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 25
    .line 26
    .line 27
    invoke-static/range {p2 .. p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 28
    .line 29
    .line 30
    move-result-object v12

    .line 31
    invoke-static {v7}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 32
    .line 33
    .line 34
    move-result-object v16

    .line 35
    and-int/lit8 v1, v9, 0xe

    .line 36
    .line 37
    const/high16 v2, 0x40000

    .line 38
    .line 39
    or-int/2addr v1, v2

    .line 40
    and-int/lit8 v2, v9, 0x70

    .line 41
    .line 42
    or-int/2addr v1, v2

    .line 43
    and-int/lit16 v2, v9, 0x380

    .line 44
    .line 45
    or-int/2addr v1, v2

    .line 46
    and-int/lit16 v2, v9, 0x1c00

    .line 47
    .line 48
    or-int/2addr v1, v2

    .line 49
    const v2, 0xe000

    .line 50
    .line 51
    .line 52
    and-int/2addr v2, v9

    .line 53
    or-int/2addr v1, v2

    .line 54
    const/high16 v2, 0x380000

    .line 55
    .line 56
    and-int/2addr v2, v9

    .line 57
    or-int v19, v1, v2

    .line 58
    .line 59
    move-object/from16 v10, p0

    .line 60
    .line 61
    move-object/from16 v11, p1

    .line 62
    .line 63
    move-wide/from16 v14, p4

    .line 64
    .line 65
    move-object/from16 v17, p7

    .line 66
    .line 67
    move-object/from16 v18, v0

    .line 68
    .line 69
    invoke-static/range {v10 .. v19}, Llp/dc;->b(Lx2/s;Lay0/k;Ljava/lang/Integer;Lay0/k;JLjava/util/List;Lg4/p0;Ll2/o;I)V

    .line 70
    .line 71
    .line 72
    invoke-virtual/range {v18 .. v18}, Ll2/t;->s()Ll2/u1;

    .line 73
    .line 74
    .line 75
    move-result-object v10

    .line 76
    if-nez v10, :cond_0

    .line 77
    .line 78
    return-void

    .line 79
    :cond_0
    new-instance v0, Ljn/n;

    .line 80
    .line 81
    move-object/from16 v1, p0

    .line 82
    .line 83
    move-object/from16 v2, p1

    .line 84
    .line 85
    move/from16 v3, p2

    .line 86
    .line 87
    move-object/from16 v4, p3

    .line 88
    .line 89
    move-wide/from16 v5, p4

    .line 90
    .line 91
    move-object/from16 v8, p7

    .line 92
    .line 93
    invoke-direct/range {v0 .. v9}, Ljn/n;-><init>(Lx2/s;Lay0/k;ILay0/k;JLjava/lang/Iterable;Lg4/p0;I)V

    .line 94
    .line 95
    .line 96
    iput-object v0, v10, Ll2/u1;->d:Lay0/n;

    .line 97
    .line 98
    return-void
.end method
