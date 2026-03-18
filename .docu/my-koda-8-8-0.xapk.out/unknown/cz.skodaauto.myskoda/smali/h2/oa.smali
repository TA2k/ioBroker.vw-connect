.class public abstract Lh2/oa;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/e0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lgz0/e0;

    .line 2
    .line 3
    const/16 v1, 0x14

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lgz0/e0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Ll2/e0;

    .line 9
    .line 10
    invoke-direct {v1, v0}, Ll2/e0;-><init>(Lay0/a;)V

    .line 11
    .line 12
    .line 13
    sput-object v1, Lh2/oa;->a:Ll2/e0;

    .line 14
    .line 15
    return-void
.end method

.method public static final a(Lx2/s;Le3/n0;JJFFLe1/t;Lt2/b;Ll2/o;II)V
    .locals 1

    .line 1
    and-int/lit8 p11, p12, 0x1

    .line 2
    .line 3
    if-eqz p11, :cond_0

    .line 4
    .line 5
    sget-object p0, Lx2/p;->b:Lx2/p;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p11, p12, 0x2

    .line 8
    .line 9
    if-eqz p11, :cond_1

    .line 10
    .line 11
    sget-object p1, Le3/j0;->a:Le3/i0;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p11, p12, 0x4

    .line 14
    .line 15
    if-eqz p11, :cond_2

    .line 16
    .line 17
    sget-object p2, Lh2/g1;->a:Ll2/u2;

    .line 18
    .line 19
    move-object p3, p10

    .line 20
    check-cast p3, Ll2/t;

    .line 21
    .line 22
    invoke-virtual {p3, p2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object p2

    .line 26
    check-cast p2, Lh2/f1;

    .line 27
    .line 28
    iget-wide p2, p2, Lh2/f1;->p:J

    .line 29
    .line 30
    :cond_2
    and-int/lit8 p11, p12, 0x8

    .line 31
    .line 32
    if-eqz p11, :cond_3

    .line 33
    .line 34
    invoke-static {p2, p3, p10}, Lh2/g1;->b(JLl2/o;)J

    .line 35
    .line 36
    .line 37
    move-result-wide p4

    .line 38
    :cond_3
    and-int/lit8 p11, p12, 0x10

    .line 39
    .line 40
    const/4 v0, 0x0

    .line 41
    if-eqz p11, :cond_4

    .line 42
    .line 43
    int-to-float p6, v0

    .line 44
    :cond_4
    and-int/lit8 p11, p12, 0x20

    .line 45
    .line 46
    if-eqz p11, :cond_5

    .line 47
    .line 48
    int-to-float p7, v0

    .line 49
    :cond_5
    and-int/lit8 p11, p12, 0x40

    .line 50
    .line 51
    if-eqz p11, :cond_6

    .line 52
    .line 53
    const/4 p8, 0x0

    .line 54
    :cond_6
    check-cast p10, Ll2/t;

    .line 55
    .line 56
    sget-object p11, Lh2/oa;->a:Ll2/e0;

    .line 57
    .line 58
    invoke-virtual {p10, p11}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object p12

    .line 62
    check-cast p12, Lt4/f;

    .line 63
    .line 64
    iget p12, p12, Lt4/f;->d:F

    .line 65
    .line 66
    add-float/2addr p6, p12

    .line 67
    sget-object p12, Lh2/p1;->a:Ll2/e0;

    .line 68
    .line 69
    invoke-static {p4, p5, p12}, Lf2/m0;->s(JLl2/e0;)Ll2/t1;

    .line 70
    .line 71
    .line 72
    move-result-object p4

    .line 73
    new-instance p5, Lt4/f;

    .line 74
    .line 75
    invoke-direct {p5, p6}, Lt4/f;-><init>(F)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {p11, p5}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 79
    .line 80
    .line 81
    move-result-object p5

    .line 82
    filled-new-array {p4, p5}, [Ll2/t1;

    .line 83
    .line 84
    .line 85
    move-result-object p11

    .line 86
    move-wide p4, p2

    .line 87
    move-object p3, p1

    .line 88
    new-instance p1, Lh2/la;

    .line 89
    .line 90
    move-object p2, p8

    .line 91
    move p8, p7

    .line 92
    move-object p7, p2

    .line 93
    move-object p2, p0

    .line 94
    invoke-direct/range {p1 .. p9}, Lh2/la;-><init>(Lx2/s;Le3/n0;JFLe1/t;FLt2/b;)V

    .line 95
    .line 96
    .line 97
    const p0, 0x1923bae6

    .line 98
    .line 99
    .line 100
    invoke-static {p0, p10, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    const/16 p1, 0x38

    .line 105
    .line 106
    invoke-static {p11, p0, p10, p1}, Ll2/b;->b([Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 107
    .line 108
    .line 109
    return-void
.end method

.method public static final b(ZLay0/a;Lx2/s;ZLe3/n0;JLe1/t;Lt2/b;Ll2/o;I)V
    .locals 15

    .line 1
    move-object/from16 v0, p9

    .line 2
    .line 3
    move-wide/from16 v3, p5

    .line 4
    .line 5
    invoke-static {v3, v4, v0}, Lh2/g1;->b(JLl2/o;)J

    .line 6
    .line 7
    .line 8
    move-result-wide v1

    .line 9
    const/4 v5, 0x0

    .line 10
    int-to-float v6, v5

    .line 11
    int-to-float v11, v5

    .line 12
    move-object v7, v0

    .line 13
    check-cast v7, Ll2/t;

    .line 14
    .line 15
    const v8, 0x5b159de8

    .line 16
    .line 17
    .line 18
    invoke-virtual {v7, v8}, Ll2/t;->Y(I)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v8

    .line 25
    sget-object v9, Ll2/n;->a:Ll2/x0;

    .line 26
    .line 27
    if-ne v8, v9, :cond_0

    .line 28
    .line 29
    invoke-static {v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->g(Ll2/t;)Li1/l;

    .line 30
    .line 31
    .line 32
    move-result-object v8

    .line 33
    :cond_0
    check-cast v8, Li1/l;

    .line 34
    .line 35
    invoke-virtual {v7, v5}, Ll2/t;->q(Z)V

    .line 36
    .line 37
    .line 38
    move-object v13, v0

    .line 39
    check-cast v13, Ll2/t;

    .line 40
    .line 41
    sget-object v0, Lh2/oa;->a:Ll2/e0;

    .line 42
    .line 43
    invoke-virtual {v13, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v5

    .line 47
    check-cast v5, Lt4/f;

    .line 48
    .line 49
    iget v5, v5, Lt4/f;->d:F

    .line 50
    .line 51
    add-float/2addr v5, v6

    .line 52
    sget-object v6, Lh2/p1;->a:Ll2/e0;

    .line 53
    .line 54
    invoke-static {v1, v2, v6}, Lf2/m0;->s(JLl2/e0;)Ll2/t1;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    new-instance v2, Lt4/f;

    .line 59
    .line 60
    invoke-direct {v2, v5}, Lt4/f;-><init>(F)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v0, v2}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    filled-new-array {v1, v0}, [Ll2/t1;

    .line 68
    .line 69
    .line 70
    move-result-object v14

    .line 71
    new-instance v0, Lh2/na;

    .line 72
    .line 73
    move v7, p0

    .line 74
    move-object/from16 v10, p1

    .line 75
    .line 76
    move-object/from16 v1, p2

    .line 77
    .line 78
    move/from16 v9, p3

    .line 79
    .line 80
    move-object/from16 v2, p4

    .line 81
    .line 82
    move-object/from16 v6, p7

    .line 83
    .line 84
    move-object/from16 v12, p8

    .line 85
    .line 86
    invoke-direct/range {v0 .. v12}, Lh2/na;-><init>(Lx2/s;Le3/n0;JFLe1/t;ZLi1/l;ZLay0/a;FLt2/b;)V

    .line 87
    .line 88
    .line 89
    const p0, 0x59ed78f3

    .line 90
    .line 91
    .line 92
    invoke-static {p0, v13, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    const/16 v0, 0x38

    .line 97
    .line 98
    invoke-static {v14, p0, v13, v0}, Ll2/b;->b([Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 99
    .line 100
    .line 101
    return-void
.end method

.method public static final c(Lay0/a;Lx2/s;ZLe3/n0;JJFFLe1/t;Li1/l;Lt2/b;Ll2/o;II)V
    .locals 14

    .line 1
    move/from16 v0, p15

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x4

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    move v10, v1

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    move/from16 v10, p2

    .line 11
    .line 12
    :goto_0
    and-int/lit8 v1, v0, 0x40

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    if-eqz v1, :cond_1

    .line 16
    .line 17
    int-to-float v1, v2

    .line 18
    goto :goto_1

    .line 19
    :cond_1
    move/from16 v1, p8

    .line 20
    .line 21
    :goto_1
    and-int/lit16 v3, v0, 0x80

    .line 22
    .line 23
    if-eqz v3, :cond_2

    .line 24
    .line 25
    int-to-float v3, v2

    .line 26
    move v12, v3

    .line 27
    goto :goto_2

    .line 28
    :cond_2
    move/from16 v12, p9

    .line 29
    .line 30
    :goto_2
    and-int/lit16 v3, v0, 0x100

    .line 31
    .line 32
    const/4 v4, 0x0

    .line 33
    if-eqz v3, :cond_3

    .line 34
    .line 35
    move-object v8, v4

    .line 36
    goto :goto_3

    .line 37
    :cond_3
    move-object/from16 v8, p10

    .line 38
    .line 39
    :goto_3
    and-int/lit16 v0, v0, 0x200

    .line 40
    .line 41
    if-eqz v0, :cond_4

    .line 42
    .line 43
    goto :goto_4

    .line 44
    :cond_4
    move-object/from16 v4, p11

    .line 45
    .line 46
    :goto_4
    move-object/from16 v0, p13

    .line 47
    .line 48
    check-cast v0, Ll2/t;

    .line 49
    .line 50
    if-nez v4, :cond_6

    .line 51
    .line 52
    const v3, -0x6563c494

    .line 53
    .line 54
    .line 55
    invoke-virtual {v0, v3}, Ll2/t;->Y(I)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v3

    .line 62
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 63
    .line 64
    if-ne v3, v4, :cond_5

    .line 65
    .line 66
    invoke-static {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->g(Ll2/t;)Li1/l;

    .line 67
    .line 68
    .line 69
    move-result-object v3

    .line 70
    :cond_5
    move-object v4, v3

    .line 71
    check-cast v4, Li1/l;

    .line 72
    .line 73
    :goto_5
    invoke-virtual {v0, v2}, Ll2/t;->q(Z)V

    .line 74
    .line 75
    .line 76
    move-object v9, v4

    .line 77
    goto :goto_6

    .line 78
    :cond_6
    const v3, 0x7899accb

    .line 79
    .line 80
    .line 81
    invoke-virtual {v0, v3}, Ll2/t;->Y(I)V

    .line 82
    .line 83
    .line 84
    goto :goto_5

    .line 85
    :goto_6
    move-object/from16 v0, p13

    .line 86
    .line 87
    check-cast v0, Ll2/t;

    .line 88
    .line 89
    sget-object v2, Lh2/oa;->a:Ll2/e0;

    .line 90
    .line 91
    invoke-virtual {v0, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    check-cast v3, Lt4/f;

    .line 96
    .line 97
    iget v3, v3, Lt4/f;->d:F

    .line 98
    .line 99
    add-float v7, v3, v1

    .line 100
    .line 101
    sget-object v1, Lh2/p1;->a:Ll2/e0;

    .line 102
    .line 103
    move-wide/from16 v3, p6

    .line 104
    .line 105
    invoke-static {v3, v4, v1}, Lf2/m0;->s(JLl2/e0;)Ll2/t1;

    .line 106
    .line 107
    .line 108
    move-result-object v1

    .line 109
    new-instance v3, Lt4/f;

    .line 110
    .line 111
    invoke-direct {v3, v7}, Lt4/f;-><init>(F)V

    .line 112
    .line 113
    .line 114
    invoke-virtual {v2, v3}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 115
    .line 116
    .line 117
    move-result-object v2

    .line 118
    filled-new-array {v1, v2}, [Ll2/t1;

    .line 119
    .line 120
    .line 121
    move-result-object v1

    .line 122
    new-instance v2, Lh2/ma;

    .line 123
    .line 124
    move-object v11, p0

    .line 125
    move-object v3, p1

    .line 126
    move-object/from16 v4, p3

    .line 127
    .line 128
    move-wide/from16 v5, p4

    .line 129
    .line 130
    move-object/from16 v13, p12

    .line 131
    .line 132
    invoke-direct/range {v2 .. v13}, Lh2/ma;-><init>(Lx2/s;Le3/n0;JFLe1/t;Li1/l;ZLay0/a;FLt2/b;)V

    .line 133
    .line 134
    .line 135
    const p0, 0x329de4cf

    .line 136
    .line 137
    .line 138
    invoke-static {p0, v0, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    const/16 p1, 0x38

    .line 143
    .line 144
    invoke-static {v1, p0, v0, p1}, Ll2/b;->b([Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 145
    .line 146
    .line 147
    return-void
.end method

.method public static final d(Lx2/s;Le3/n0;JLe1/t;F)Lx2/s;
    .locals 8

    .line 1
    const/4 v0, 0x0

    .line 2
    cmpl-float v0, p5, v0

    .line 3
    .line 4
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 5
    .line 6
    if-lez v0, :cond_0

    .line 7
    .line 8
    const/4 v4, 0x0

    .line 9
    const v7, 0x1e7df

    .line 10
    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    const/4 v3, 0x0

    .line 14
    move-object v6, p1

    .line 15
    move v5, p5

    .line 16
    invoke-static/range {v1 .. v7}, Landroidx/compose/ui/graphics/a;->b(Lx2/s;FFFFLe3/n0;I)Lx2/s;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    move-object v6, p1

    .line 22
    move-object p1, v1

    .line 23
    :goto_0
    invoke-interface {p0, p1}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    if-eqz p4, :cond_1

    .line 28
    .line 29
    iget p1, p4, Le1/t;->a:F

    .line 30
    .line 31
    iget-object p4, p4, Le1/t;->b:Le3/p0;

    .line 32
    .line 33
    invoke-static {v1, p1, p4, v6}, Lkp/g;->b(Lx2/s;FLe3/p0;Le3/n0;)Lx2/s;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    :cond_1
    invoke-interface {p0, v1}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-static {p0, p2, p3, v6}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-static {p0, v6}, Ljp/ba;->c(Lx2/s;Le3/n0;)Lx2/s;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    return-object p0
.end method

.method public static final e(JFLl2/t;)J
    .locals 4

    .line 1
    sget-object v0, Lh2/g1;->a:Ll2/u2;

    .line 2
    .line 3
    invoke-virtual {p3, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lh2/f1;

    .line 8
    .line 9
    sget-object v1, Lh2/g1;->b:Ll2/u2;

    .line 10
    .line 11
    invoke-virtual {p3, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p3

    .line 15
    check-cast p3, Ljava/lang/Boolean;

    .line 16
    .line 17
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 18
    .line 19
    .line 20
    move-result p3

    .line 21
    iget-wide v1, v0, Lh2/f1;->p:J

    .line 22
    .line 23
    invoke-static {p0, p1, v1, v2}, Le3/s;->c(JJ)Z

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    if-eqz v3, :cond_1

    .line 28
    .line 29
    if-eqz p3, :cond_1

    .line 30
    .line 31
    const/4 p0, 0x0

    .line 32
    int-to-float p0, p0

    .line 33
    invoke-static {p2, p0}, Lt4/f;->a(FF)Z

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    if-eqz p0, :cond_0

    .line 38
    .line 39
    return-wide v1

    .line 40
    :cond_0
    const/4 p0, 0x1

    .line 41
    int-to-float p0, p0

    .line 42
    add-float/2addr p2, p0

    .line 43
    float-to-double p0, p2

    .line 44
    invoke-static {p0, p1}, Ljava/lang/Math;->log(D)D

    .line 45
    .line 46
    .line 47
    move-result-wide p0

    .line 48
    double-to-float p0, p0

    .line 49
    const/high16 p1, 0x40900000    # 4.5f

    .line 50
    .line 51
    mul-float/2addr p0, p1

    .line 52
    const/high16 p1, 0x40000000    # 2.0f

    .line 53
    .line 54
    add-float/2addr p0, p1

    .line 55
    const/high16 p1, 0x42c80000    # 100.0f

    .line 56
    .line 57
    div-float/2addr p0, p1

    .line 58
    iget-wide p1, v0, Lh2/f1;->t:J

    .line 59
    .line 60
    invoke-static {p1, p2, p0}, Le3/s;->b(JF)J

    .line 61
    .line 62
    .line 63
    move-result-wide p0

    .line 64
    invoke-static {p0, p1, v1, v2}, Le3/j0;->l(JJ)J

    .line 65
    .line 66
    .line 67
    move-result-wide p0

    .line 68
    :cond_1
    return-wide p0
.end method
