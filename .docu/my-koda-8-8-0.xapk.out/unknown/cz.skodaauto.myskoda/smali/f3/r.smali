.class public final Lf3/r;
.super Lf3/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final r:Lf3/d;


# instance fields
.field public final d:Lf3/t;

.field public final e:F

.field public final f:F

.field public final g:Lf3/s;

.field public final h:[F

.field public final i:[F

.field public final j:[F

.field public final k:Lf3/j;

.field public final l:Lf3/q;

.field public final m:Lf3/n;

.field public final n:Lf3/j;

.field public final o:Lf3/q;

.field public final p:Lf3/n;

.field public final q:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lf3/d;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-direct {v0, v1}, Lf3/d;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lf3/r;->r:Lf3/d;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;[FLf3/t;DFFI)V
    .locals 17

    move-wide/from16 v1, p4

    const-wide/high16 v3, 0x3ff0000000000000L    # 1.0

    cmpg-double v0, v1, v3

    .line 87
    sget-object v3, Lf3/r;->r:Lf3/d;

    if-nez v0, :cond_0

    move-object v11, v3

    goto :goto_0

    .line 88
    :cond_0
    new-instance v4, Lf3/o;

    const/4 v5, 0x0

    invoke-direct {v4, v5, v1, v2}, Lf3/o;-><init>(ID)V

    move-object v11, v4

    :goto_0
    if-nez v0, :cond_1

    :goto_1
    move-object v12, v3

    goto :goto_2

    .line 89
    :cond_1
    new-instance v3, Lf3/o;

    const/4 v0, 0x1

    invoke-direct {v3, v0, v1, v2}, Lf3/o;-><init>(ID)V

    goto :goto_1

    .line 90
    :goto_2
    new-instance v15, Lf3/s;

    const-wide/16 v7, 0x0

    const-wide/16 v9, 0x0

    const-wide/high16 v3, 0x3ff0000000000000L    # 1.0

    const-wide/16 v5, 0x0

    move-object v0, v15

    invoke-direct/range {v0 .. v10}, Lf3/s;-><init>(DDDDD)V

    const/4 v10, 0x0

    move-object/from16 v6, p0

    move-object/from16 v7, p1

    move-object/from16 v8, p2

    move-object/from16 v9, p3

    move/from16 v13, p6

    move/from16 v14, p7

    move/from16 v16, p8

    .line 91
    invoke-direct/range {v6 .. v16}, Lf3/r;-><init>(Ljava/lang/String;[FLf3/t;[FLf3/j;Lf3/j;FFLf3/s;I)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;[FLf3/t;Lf3/s;I)V
    .locals 15

    move-object/from16 v9, p4

    .line 1
    iget-wide v0, v9, Lf3/s;->a:D

    const-wide/high16 v2, -0x3ff8000000000000L    # -3.0

    cmpg-double v4, v0, v2

    if-nez v4, :cond_0

    const/4 v4, 0x1

    goto :goto_0

    :cond_0
    const/4 v4, 0x0

    .line 2
    :goto_0
    iget-wide v5, v9, Lf3/s;->g:D

    iget-wide v7, v9, Lf3/s;->f:D

    const-wide/high16 v10, -0x4000000000000000L    # -2.0

    const-wide/16 v12, 0x0

    if-eqz v4, :cond_1

    .line 3
    new-instance v4, Lf3/p;

    const/4 v14, 0x4

    invoke-direct {v4, v9, v14}, Lf3/p;-><init>(Lf3/s;I)V

    goto :goto_1

    :cond_1
    cmpg-double v4, v0, v10

    if-nez v4, :cond_2

    .line 4
    new-instance v4, Lf3/p;

    const/4 v14, 0x5

    invoke-direct {v4, v9, v14}, Lf3/p;-><init>(Lf3/s;I)V

    goto :goto_1

    :cond_2
    cmpg-double v4, v7, v12

    if-nez v4, :cond_3

    cmpg-double v4, v5, v12

    if-nez v4, :cond_3

    .line 5
    new-instance v4, Lf3/p;

    const/4 v14, 0x6

    invoke-direct {v4, v9, v14}, Lf3/p;-><init>(Lf3/s;I)V

    goto :goto_1

    .line 6
    :cond_3
    new-instance v4, Lf3/p;

    const/4 v14, 0x7

    invoke-direct {v4, v9, v14}, Lf3/p;-><init>(Lf3/s;I)V

    :goto_1
    cmpg-double v2, v0, v2

    if-nez v2, :cond_4

    .line 7
    new-instance v0, Lf3/p;

    const/4 v1, 0x0

    invoke-direct {v0, v9, v1}, Lf3/p;-><init>(Lf3/s;I)V

    :goto_2
    move-object v6, v0

    goto :goto_3

    :cond_4
    cmpg-double v0, v0, v10

    if-nez v0, :cond_5

    .line 8
    new-instance v0, Lf3/p;

    const/4 v1, 0x1

    invoke-direct {v0, v9, v1}, Lf3/p;-><init>(Lf3/s;I)V

    goto :goto_2

    :cond_5
    cmpg-double v0, v7, v12

    if-nez v0, :cond_6

    cmpg-double v0, v5, v12

    if-nez v0, :cond_6

    .line 9
    new-instance v0, Lf3/p;

    const/4 v1, 0x2

    invoke-direct {v0, v9, v1}, Lf3/p;-><init>(Lf3/s;I)V

    goto :goto_2

    .line 10
    :cond_6
    new-instance v0, Lf3/p;

    const/4 v1, 0x3

    invoke-direct {v0, v9, v1}, Lf3/p;-><init>(Lf3/s;I)V

    goto :goto_2

    :goto_3
    const/4 v7, 0x0

    const/high16 v8, 0x3f800000    # 1.0f

    move-object v5, v4

    const/4 v4, 0x0

    move-object v0, p0

    move-object/from16 v1, p1

    move-object/from16 v2, p2

    move-object/from16 v3, p3

    move/from16 v10, p5

    .line 11
    invoke-direct/range {v0 .. v10}, Lf3/r;-><init>(Ljava/lang/String;[FLf3/t;[FLf3/j;Lf3/j;FFLf3/s;I)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;[FLf3/t;[FLf3/j;Lf3/j;FFLf3/s;I)V
    .locals 32

    move-object/from16 v0, p0

    move-object/from16 v1, p2

    move-object/from16 v2, p3

    move-object/from16 v3, p4

    move-object/from16 v4, p5

    move-object/from16 v5, p6

    move/from16 v6, p7

    move/from16 v7, p8

    move/from16 v8, p10

    .line 12
    sget-wide v9, Lf3/b;->a:J

    move-object/from16 v11, p1

    invoke-direct {v0, v9, v10, v11, v8}, Lf3/c;-><init>(JLjava/lang/String;I)V

    .line 13
    iput-object v2, v0, Lf3/r;->d:Lf3/t;

    .line 14
    iput v6, v0, Lf3/r;->e:F

    .line 15
    iput v7, v0, Lf3/r;->f:F

    move-object/from16 v9, p9

    .line 16
    iput-object v9, v0, Lf3/r;->g:Lf3/s;

    .line 17
    iput-object v4, v0, Lf3/r;->k:Lf3/j;

    .line 18
    new-instance v9, Lf3/q;

    const/4 v10, 0x1

    invoke-direct {v9, v0, v10}, Lf3/q;-><init>(Lf3/r;I)V

    iput-object v9, v0, Lf3/r;->l:Lf3/q;

    .line 19
    new-instance v9, Lf3/n;

    const/4 v11, 0x0

    invoke-direct {v9, v0, v11}, Lf3/n;-><init>(Lf3/r;I)V

    iput-object v9, v0, Lf3/r;->m:Lf3/n;

    .line 20
    iput-object v5, v0, Lf3/r;->n:Lf3/j;

    .line 21
    new-instance v9, Lf3/q;

    invoke-direct {v9, v0, v11}, Lf3/q;-><init>(Lf3/r;I)V

    iput-object v9, v0, Lf3/r;->o:Lf3/q;

    .line 22
    new-instance v9, Lf3/n;

    invoke-direct {v9, v0, v10}, Lf3/n;-><init>(Lf3/r;I)V

    iput-object v9, v0, Lf3/r;->p:Lf3/n;

    .line 23
    array-length v9, v1

    const/16 v12, 0x9

    const/4 v13, 0x6

    if-eq v9, v13, :cond_1

    array-length v9, v1

    if-ne v9, v12, :cond_0

    goto :goto_0

    .line 24
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 25
    const-string v1, "The color space\'s primaries must be defined as an array of 6 floats in xyY or 9 floats in XYZ"

    .line 26
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    :goto_0
    cmpl-float v9, v6, v7

    if-gez v9, :cond_10

    .line 27
    new-array v9, v13, [F

    .line 28
    array-length v14, v1

    const/16 v15, 0x8

    const/16 v16, 0x7

    const/16 v17, 0x2

    const/16 v18, 0x3

    const/16 v19, 0x4

    const/16 v20, 0x5

    if-ne v14, v12, :cond_2

    .line 29
    aget v14, v1, v11

    aget v21, v1, v10

    add-float v22, v14, v21

    aget v23, v1, v17

    add-float v22, v22, v23

    div-float v14, v14, v22

    .line 30
    aput v14, v9, v11

    div-float v21, v21, v22

    .line 31
    aput v21, v9, v10

    .line 32
    aget v14, v1, v18

    aget v21, v1, v19

    add-float v22, v14, v21

    aget v23, v1, v20

    add-float v22, v22, v23

    div-float v14, v14, v22

    .line 33
    aput v14, v9, v17

    div-float v21, v21, v22

    .line 34
    aput v21, v9, v18

    .line 35
    aget v14, v1, v13

    aget v21, v1, v16

    add-float v22, v14, v21

    aget v1, v1, v15

    add-float v22, v22, v1

    div-float v14, v14, v22

    .line 36
    aput v14, v9, v19

    div-float v21, v21, v22

    .line 37
    aput v21, v9, v20

    goto :goto_1

    .line 38
    :cond_2
    invoke-static {v1, v11, v9, v11, v13}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 39
    :goto_1
    iput-object v9, v0, Lf3/r;->h:[F

    if-nez v3, :cond_3

    .line 40
    aget v3, v9, v11

    .line 41
    aget v14, v9, v10

    .line 42
    aget v21, v9, v17

    .line 43
    aget v22, v9, v18

    .line 44
    aget v23, v9, v19

    .line 45
    aget v24, v9, v20

    const/high16 p1, 0x3f800000    # 1.0f

    .line 46
    iget v1, v2, Lf3/t;->a:F

    move/from16 p9, v11

    .line 47
    iget v11, v2, Lf3/t;->b:F

    move/from16 v25, v15

    int-to-float v15, v10

    sub-float v26, v15, v3

    div-float v26, v26, v14

    sub-float v27, v15, v21

    div-float v27, v27, v22

    sub-float v28, v15, v23

    div-float v28, v28, v24

    sub-float/2addr v15, v1

    div-float/2addr v15, v11

    div-float v29, v3, v14

    div-float v30, v21, v22

    div-float v31, v23, v24

    div-float/2addr v1, v11

    sub-float v15, v15, v26

    sub-float v30, v30, v29

    mul-float v15, v15, v30

    sub-float v1, v1, v29

    sub-float v27, v27, v26

    mul-float v11, v1, v27

    sub-float/2addr v15, v11

    sub-float v28, v28, v26

    mul-float v28, v28, v30

    sub-float v31, v31, v29

    mul-float v27, v27, v31

    sub-float v28, v28, v27

    div-float v15, v15, v28

    mul-float v31, v31, v15

    sub-float v1, v1, v31

    div-float v1, v1, v30

    sub-float v11, p1, v1

    sub-float/2addr v11, v15

    div-float v26, v11, v14

    div-float v27, v1, v22

    div-float v28, v15, v24

    mul-float v29, v26, v3

    sub-float v3, p1, v3

    sub-float/2addr v3, v14

    mul-float v3, v3, v26

    mul-float v14, v27, v21

    sub-float v21, p1, v21

    sub-float v21, v21, v22

    mul-float v21, v21, v27

    mul-float v22, v28, v23

    sub-float v23, p1, v23

    sub-float v23, v23, v24

    mul-float v23, v23, v28

    .line 48
    new-array v12, v12, [F

    aput v29, v12, p9

    aput v11, v12, v10

    aput v3, v12, v17

    aput v14, v12, v18

    aput v1, v12, v19

    aput v21, v12, v20

    aput v22, v12, v13

    aput v15, v12, v16

    aput v23, v12, v25

    .line 49
    iput-object v12, v0, Lf3/r;->i:[F

    goto :goto_2

    :cond_3
    move/from16 p9, v11

    const/high16 p1, 0x3f800000    # 1.0f

    .line 50
    array-length v1, v3

    if-ne v1, v12, :cond_f

    .line 51
    iput-object v3, v0, Lf3/r;->i:[F

    .line 52
    :goto_2
    iget-object v1, v0, Lf3/r;->i:[F

    invoke-static {v1}, Lf3/k;->f([F)[F

    move-result-object v1

    iput-object v1, v0, Lf3/r;->j:[F

    .line 53
    invoke-static {v9}, Lf3/k;->b([F)F

    move-result v1

    .line 54
    sget-object v3, Lf3/e;->a:[F

    .line 55
    sget-object v3, Lf3/e;->b:[F

    .line 56
    invoke-static {v3}, Lf3/k;->b([F)F

    move-result v3

    div-float/2addr v1, v3

    const v3, 0x3f666666    # 0.9f

    cmpl-float v1, v1, v3

    if-lez v1, :cond_6

    .line 57
    sget-object v1, Lf3/e;->a:[F

    .line 58
    aget v11, v9, p9

    aget v12, v1, p9

    sub-float/2addr v11, v12

    .line 59
    aget v14, v9, v10

    aget v15, v1, v10

    sub-float/2addr v14, v15

    .line 60
    aget v16, v9, v17

    aget v21, v1, v17

    sub-float v16, v16, v21

    .line 61
    aget v22, v9, v18

    aget v23, v1, v18

    sub-float v22, v22, v23

    .line 62
    aget v24, v9, v19

    aget v25, v1, v19

    sub-float v24, v24, v25

    .line 63
    aget v26, v9, v20

    aget v1, v1, v20

    sub-float v26, v26, v1

    const/16 p2, 0x0

    new-array v3, v13, [F

    aput v11, v3, p9

    aput v14, v3, v10

    aput v16, v3, v17

    aput v22, v3, v18

    aput v24, v3, v19

    aput v26, v3, v20

    .line 64
    aget v11, v3, p9

    aget v14, v3, v10

    sub-float v16, v12, v25

    sub-float v22, v15, v1

    mul-float v22, v22, v11

    mul-float v16, v16, v14

    sub-float v22, v22, v16

    cmpg-float v16, v22, p2

    if-ltz v16, :cond_7

    sub-float v16, v12, v21

    sub-float v22, v15, v23

    mul-float v16, v16, v14

    mul-float v22, v22, v11

    sub-float v16, v16, v22

    cmpg-float v11, v16, p2

    if-gez v11, :cond_4

    goto :goto_3

    .line 65
    :cond_4
    aget v11, v3, v17

    aget v14, v3, v18

    sub-float v16, v21, v12

    sub-float v17, v23, v15

    mul-float v17, v17, v11

    mul-float v16, v16, v14

    sub-float v17, v17, v16

    cmpg-float v16, v17, p2

    if-ltz v16, :cond_7

    sub-float v16, v21, v25

    sub-float v17, v23, v1

    mul-float v16, v16, v14

    mul-float v17, v17, v11

    sub-float v16, v16, v17

    cmpg-float v11, v16, p2

    if-gez v11, :cond_5

    goto :goto_3

    .line 66
    :cond_5
    aget v11, v3, v19

    aget v3, v3, v20

    sub-float v14, v25, v21

    sub-float v16, v1, v23

    mul-float v16, v16, v11

    mul-float/2addr v14, v3

    sub-float v16, v16, v14

    cmpg-float v14, v16, p2

    if-ltz v14, :cond_7

    sub-float v25, v25, v12

    sub-float/2addr v1, v15

    mul-float v25, v25, v3

    mul-float/2addr v1, v11

    sub-float v25, v25, v1

    cmpg-float v1, v25, p2

    if-ltz v1, :cond_7

    goto :goto_4

    :cond_6
    const/16 p2, 0x0

    :cond_7
    :goto_3
    cmpg-float v1, v6, p2

    :goto_4
    if-nez v8, :cond_8

    goto/16 :goto_9

    .line 67
    :cond_8
    sget-object v1, Lf3/e;->a:[F

    if-ne v9, v1, :cond_9

    goto :goto_6

    :cond_9
    move/from16 v3, p9

    :goto_5
    if-ge v3, v13, :cond_b

    .line 68
    aget v8, v9, v3

    aget v11, v1, v3

    invoke-static {v8, v11}, Ljava/lang/Float;->compare(FF)I

    move-result v8

    if-eqz v8, :cond_a

    aget v8, v9, v3

    aget v11, v1, v3

    sub-float/2addr v8, v11

    invoke-static {v8}, Ljava/lang/Math;->abs(F)F

    move-result v8

    const v11, 0x3a83126f    # 0.001f

    cmpl-float v8, v8, v11

    if-lez v8, :cond_a

    goto :goto_8

    :cond_a
    add-int/lit8 v3, v3, 0x1

    goto :goto_5

    .line 69
    :cond_b
    :goto_6
    sget-object v1, Lf3/k;->d:Lf3/t;

    invoke-static {v2, v1}, Lf3/k;->d(Lf3/t;Lf3/t;)Z

    move-result v1

    if-nez v1, :cond_c

    goto :goto_8

    :cond_c
    cmpg-float v1, v6, p2

    if-nez v1, :cond_d

    cmpg-float v1, v7, p1

    if-nez v1, :cond_d

    .line 70
    sget-object v1, Lf3/e;->a:[F

    .line 71
    sget-object v1, Lf3/e;->e:Lf3/r;

    const-wide/16 v2, 0x0

    :goto_7
    const-wide/high16 v6, 0x3ff0000000000000L    # 1.0

    cmpg-double v6, v2, v6

    if-gtz v6, :cond_e

    .line 72
    iget-object v6, v1, Lf3/r;->k:Lf3/j;

    .line 73
    invoke-interface {v4, v2, v3}, Lf3/j;->h(D)D

    move-result-wide v7

    .line 74
    invoke-interface {v6, v2, v3}, Lf3/j;->h(D)D

    move-result-wide v11

    sub-double/2addr v7, v11

    .line 75
    invoke-static {v7, v8}, Ljava/lang/Math;->abs(D)D

    move-result-wide v6

    const-wide v8, 0x3f50624dd2f1a9fcL    # 0.001

    cmpg-double v6, v6, v8

    if-gtz v6, :cond_d

    .line 76
    iget-object v6, v1, Lf3/r;->n:Lf3/j;

    .line 77
    invoke-interface {v5, v2, v3}, Lf3/j;->h(D)D

    move-result-wide v11

    .line 78
    invoke-interface {v6, v2, v3}, Lf3/j;->h(D)D

    move-result-wide v6

    sub-double/2addr v11, v6

    .line 79
    invoke-static {v11, v12}, Ljava/lang/Math;->abs(D)D

    move-result-wide v6

    cmpg-double v6, v6, v8

    if-gtz v6, :cond_d

    const-wide v6, 0x3f70101010101010L    # 0.00392156862745098

    add-double/2addr v2, v6

    goto :goto_7

    :cond_d
    :goto_8
    move/from16 v10, p9

    .line 80
    :cond_e
    :goto_9
    iput-boolean v10, v0, Lf3/r;->q:Z

    return-void

    .line 81
    :cond_f
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 82
    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Transform must have 9 entries! Has "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    array-length v2, v3

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    .line 83
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 84
    :cond_10
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 85
    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Invalid range: min="

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v6}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    const-string v2, ", max="

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v7}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    const-string v2, "; min must be strictly < max"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    .line 86
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method


# virtual methods
.method public final a(I)F
    .locals 0

    .line 1
    iget p0, p0, Lf3/r;->f:F

    .line 2
    .line 3
    return p0
.end method

.method public final b(I)F
    .locals 0

    .line 1
    iget p0, p0, Lf3/r;->e:F

    .line 2
    .line 3
    return p0
.end method

.method public final c()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lf3/r;->q:Z

    .line 2
    .line 3
    return p0
.end method

.method public final d(FFF)J
    .locals 3

    .line 1
    float-to-double v0, p1

    .line 2
    iget-object p1, p0, Lf3/r;->p:Lf3/n;

    .line 3
    .line 4
    invoke-virtual {p1, v0, v1}, Lf3/n;->h(D)D

    .line 5
    .line 6
    .line 7
    move-result-wide v0

    .line 8
    double-to-float v0, v0

    .line 9
    float-to-double v1, p2

    .line 10
    invoke-virtual {p1, v1, v2}, Lf3/n;->h(D)D

    .line 11
    .line 12
    .line 13
    move-result-wide v1

    .line 14
    double-to-float p2, v1

    .line 15
    float-to-double v1, p3

    .line 16
    invoke-virtual {p1, v1, v2}, Lf3/n;->h(D)D

    .line 17
    .line 18
    .line 19
    move-result-wide v1

    .line 20
    double-to-float p1, v1

    .line 21
    iget-object p0, p0, Lf3/r;->i:[F

    .line 22
    .line 23
    array-length p3, p0

    .line 24
    const/16 v1, 0x9

    .line 25
    .line 26
    if-ge p3, v1, :cond_0

    .line 27
    .line 28
    const-wide/16 p0, 0x0

    .line 29
    .line 30
    return-wide p0

    .line 31
    :cond_0
    const/4 p3, 0x0

    .line 32
    aget p3, p0, p3

    .line 33
    .line 34
    mul-float/2addr p3, v0

    .line 35
    const/4 v1, 0x3

    .line 36
    aget v1, p0, v1

    .line 37
    .line 38
    mul-float/2addr v1, p2

    .line 39
    add-float/2addr v1, p3

    .line 40
    const/4 p3, 0x6

    .line 41
    aget p3, p0, p3

    .line 42
    .line 43
    mul-float/2addr p3, p1

    .line 44
    add-float/2addr p3, v1

    .line 45
    const/4 v1, 0x1

    .line 46
    aget v1, p0, v1

    .line 47
    .line 48
    mul-float/2addr v1, v0

    .line 49
    const/4 v0, 0x4

    .line 50
    aget v0, p0, v0

    .line 51
    .line 52
    mul-float/2addr v0, p2

    .line 53
    add-float/2addr v0, v1

    .line 54
    const/4 p2, 0x7

    .line 55
    aget p0, p0, p2

    .line 56
    .line 57
    mul-float/2addr p0, p1

    .line 58
    add-float/2addr p0, v0

    .line 59
    invoke-static {p3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 60
    .line 61
    .line 62
    move-result p1

    .line 63
    int-to-long p1, p1

    .line 64
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    int-to-long v0, p0

    .line 69
    const/16 p0, 0x20

    .line 70
    .line 71
    shl-long p0, p1, p0

    .line 72
    .line 73
    const-wide p2, 0xffffffffL

    .line 74
    .line 75
    .line 76
    .line 77
    .line 78
    and-long/2addr p2, v0

    .line 79
    or-long/2addr p0, p2

    .line 80
    return-wide p0
.end method

.method public final e(FFF)F
    .locals 3

    .line 1
    float-to-double v0, p1

    .line 2
    iget-object p1, p0, Lf3/r;->p:Lf3/n;

    .line 3
    .line 4
    invoke-virtual {p1, v0, v1}, Lf3/n;->h(D)D

    .line 5
    .line 6
    .line 7
    move-result-wide v0

    .line 8
    double-to-float v0, v0

    .line 9
    float-to-double v1, p2

    .line 10
    invoke-virtual {p1, v1, v2}, Lf3/n;->h(D)D

    .line 11
    .line 12
    .line 13
    move-result-wide v1

    .line 14
    double-to-float p2, v1

    .line 15
    float-to-double v1, p3

    .line 16
    invoke-virtual {p1, v1, v2}, Lf3/n;->h(D)D

    .line 17
    .line 18
    .line 19
    move-result-wide v1

    .line 20
    double-to-float p1, v1

    .line 21
    const/4 p3, 0x2

    .line 22
    iget-object p0, p0, Lf3/r;->i:[F

    .line 23
    .line 24
    aget p3, p0, p3

    .line 25
    .line 26
    mul-float/2addr p3, v0

    .line 27
    const/4 v0, 0x5

    .line 28
    aget v0, p0, v0

    .line 29
    .line 30
    mul-float/2addr v0, p2

    .line 31
    add-float/2addr v0, p3

    .line 32
    const/16 p2, 0x8

    .line 33
    .line 34
    aget p0, p0, p2

    .line 35
    .line 36
    mul-float/2addr p0, p1

    .line 37
    add-float/2addr p0, v0

    .line 38
    return p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 5

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    const/4 v1, 0x0

    .line 6
    if-eqz p1, :cond_a

    .line 7
    .line 8
    const-class v2, Lf3/r;

    .line 9
    .line 10
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    move-result-object v3

    .line 14
    if-eq v2, v3, :cond_1

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_1
    invoke-super {p0, p1}, Lf3/c;->equals(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    if-nez v2, :cond_2

    .line 22
    .line 23
    return v1

    .line 24
    :cond_2
    check-cast p1, Lf3/r;

    .line 25
    .line 26
    iget-object v2, p1, Lf3/r;->g:Lf3/s;

    .line 27
    .line 28
    iget v3, p1, Lf3/r;->e:F

    .line 29
    .line 30
    iget v4, p0, Lf3/r;->e:F

    .line 31
    .line 32
    invoke-static {v3, v4}, Ljava/lang/Float;->compare(FF)I

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    if-eqz v3, :cond_3

    .line 37
    .line 38
    return v1

    .line 39
    :cond_3
    iget v3, p1, Lf3/r;->f:F

    .line 40
    .line 41
    iget v4, p0, Lf3/r;->f:F

    .line 42
    .line 43
    invoke-static {v3, v4}, Ljava/lang/Float;->compare(FF)I

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    if-eqz v3, :cond_4

    .line 48
    .line 49
    return v1

    .line 50
    :cond_4
    iget-object v3, p0, Lf3/r;->d:Lf3/t;

    .line 51
    .line 52
    iget-object v4, p1, Lf3/r;->d:Lf3/t;

    .line 53
    .line 54
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v3

    .line 58
    if-nez v3, :cond_5

    .line 59
    .line 60
    return v1

    .line 61
    :cond_5
    iget-object v3, p0, Lf3/r;->h:[F

    .line 62
    .line 63
    iget-object v4, p1, Lf3/r;->h:[F

    .line 64
    .line 65
    invoke-static {v3, v4}, Ljava/util/Arrays;->equals([F[F)Z

    .line 66
    .line 67
    .line 68
    move-result v3

    .line 69
    if-nez v3, :cond_6

    .line 70
    .line 71
    return v1

    .line 72
    :cond_6
    iget-object v3, p0, Lf3/r;->g:Lf3/s;

    .line 73
    .line 74
    if-eqz v3, :cond_7

    .line 75
    .line 76
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result p0

    .line 80
    return p0

    .line 81
    :cond_7
    if-nez v2, :cond_8

    .line 82
    .line 83
    return v0

    .line 84
    :cond_8
    iget-object v0, p0, Lf3/r;->k:Lf3/j;

    .line 85
    .line 86
    iget-object v2, p1, Lf3/r;->k:Lf3/j;

    .line 87
    .line 88
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    if-nez v0, :cond_9

    .line 93
    .line 94
    return v1

    .line 95
    :cond_9
    iget-object p0, p0, Lf3/r;->n:Lf3/j;

    .line 96
    .line 97
    iget-object p1, p1, Lf3/r;->n:Lf3/j;

    .line 98
    .line 99
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    move-result p0

    .line 103
    return p0

    .line 104
    :cond_a
    :goto_0
    return v1
.end method

.method public final f(FFFFLf3/c;)J
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Lf3/r;->j:[F

    .line 3
    .line 4
    aget v0, v1, v0

    .line 5
    .line 6
    mul-float/2addr v0, p1

    .line 7
    const/4 v2, 0x3

    .line 8
    aget v2, v1, v2

    .line 9
    .line 10
    mul-float/2addr v2, p2

    .line 11
    add-float/2addr v2, v0

    .line 12
    const/4 v0, 0x6

    .line 13
    aget v0, v1, v0

    .line 14
    .line 15
    mul-float/2addr v0, p3

    .line 16
    add-float/2addr v0, v2

    .line 17
    const/4 v2, 0x1

    .line 18
    aget v2, v1, v2

    .line 19
    .line 20
    mul-float/2addr v2, p1

    .line 21
    const/4 v3, 0x4

    .line 22
    aget v3, v1, v3

    .line 23
    .line 24
    mul-float/2addr v3, p2

    .line 25
    add-float/2addr v3, v2

    .line 26
    const/4 v2, 0x7

    .line 27
    aget v2, v1, v2

    .line 28
    .line 29
    mul-float/2addr v2, p3

    .line 30
    add-float/2addr v2, v3

    .line 31
    const/4 v3, 0x2

    .line 32
    aget v3, v1, v3

    .line 33
    .line 34
    mul-float/2addr v3, p1

    .line 35
    const/4 p1, 0x5

    .line 36
    aget p1, v1, p1

    .line 37
    .line 38
    mul-float/2addr p1, p2

    .line 39
    add-float/2addr p1, v3

    .line 40
    const/16 p2, 0x8

    .line 41
    .line 42
    aget p2, v1, p2

    .line 43
    .line 44
    mul-float/2addr p2, p3

    .line 45
    add-float/2addr p2, p1

    .line 46
    float-to-double v0, v0

    .line 47
    iget-object p0, p0, Lf3/r;->m:Lf3/n;

    .line 48
    .line 49
    invoke-virtual {p0, v0, v1}, Lf3/n;->h(D)D

    .line 50
    .line 51
    .line 52
    move-result-wide v0

    .line 53
    double-to-float p1, v0

    .line 54
    float-to-double v0, v2

    .line 55
    invoke-virtual {p0, v0, v1}, Lf3/n;->h(D)D

    .line 56
    .line 57
    .line 58
    move-result-wide v0

    .line 59
    double-to-float p3, v0

    .line 60
    float-to-double v0, p2

    .line 61
    invoke-virtual {p0, v0, v1}, Lf3/n;->h(D)D

    .line 62
    .line 63
    .line 64
    move-result-wide v0

    .line 65
    double-to-float p0, v0

    .line 66
    invoke-static {p1, p3, p0, p4, p5}, Le3/j0;->b(FFFFLf3/c;)J

    .line 67
    .line 68
    .line 69
    move-result-wide p0

    .line 70
    return-wide p0
.end method

.method public final hashCode()I
    .locals 5

    .line 1
    invoke-super {p0}, Lf3/c;->hashCode()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    mul-int/lit8 v0, v0, 0x1f

    .line 6
    .line 7
    iget-object v1, p0, Lf3/r;->d:Lf3/t;

    .line 8
    .line 9
    invoke-virtual {v1}, Lf3/t;->hashCode()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    add-int/2addr v1, v0

    .line 14
    mul-int/lit8 v1, v1, 0x1f

    .line 15
    .line 16
    iget-object v0, p0, Lf3/r;->h:[F

    .line 17
    .line 18
    invoke-static {v0}, Ljava/util/Arrays;->hashCode([F)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    add-int/2addr v0, v1

    .line 23
    mul-int/lit8 v0, v0, 0x1f

    .line 24
    .line 25
    iget v1, p0, Lf3/r;->e:F

    .line 26
    .line 27
    const/4 v2, 0x0

    .line 28
    cmpg-float v3, v1, v2

    .line 29
    .line 30
    const/4 v4, 0x0

    .line 31
    if-nez v3, :cond_0

    .line 32
    .line 33
    move v1, v4

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    invoke-static {v1}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    :goto_0
    add-int/2addr v0, v1

    .line 40
    mul-int/lit8 v0, v0, 0x1f

    .line 41
    .line 42
    iget v1, p0, Lf3/r;->f:F

    .line 43
    .line 44
    cmpg-float v2, v1, v2

    .line 45
    .line 46
    if-nez v2, :cond_1

    .line 47
    .line 48
    move v1, v4

    .line 49
    goto :goto_1

    .line 50
    :cond_1
    invoke-static {v1}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    :goto_1
    add-int/2addr v0, v1

    .line 55
    mul-int/lit8 v0, v0, 0x1f

    .line 56
    .line 57
    iget-object v1, p0, Lf3/r;->g:Lf3/s;

    .line 58
    .line 59
    if-eqz v1, :cond_2

    .line 60
    .line 61
    invoke-virtual {v1}, Lf3/s;->hashCode()I

    .line 62
    .line 63
    .line 64
    move-result v4

    .line 65
    :cond_2
    add-int/2addr v0, v4

    .line 66
    if-nez v1, :cond_3

    .line 67
    .line 68
    mul-int/lit8 v0, v0, 0x1f

    .line 69
    .line 70
    iget-object v1, p0, Lf3/r;->k:Lf3/j;

    .line 71
    .line 72
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    add-int/2addr v1, v0

    .line 77
    mul-int/lit8 v1, v1, 0x1f

    .line 78
    .line 79
    iget-object p0, p0, Lf3/r;->n:Lf3/j;

    .line 80
    .line 81
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 82
    .line 83
    .line 84
    move-result p0

    .line 85
    add-int/2addr p0, v1

    .line 86
    return p0

    .line 87
    :cond_3
    return v0
.end method
