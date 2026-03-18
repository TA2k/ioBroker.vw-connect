.class public abstract Lxf0/t1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F

.field public static final c:F

.field public static final d:F

.field public static final e:F

.field public static final f:F

.field public static final g:Lxf0/q3;

.field public static final h:Lxf0/q3;


# direct methods
.method static constructor <clinit>()V
    .locals 9

    .line 1
    const/16 v0, 0x2c

    .line 2
    .line 3
    int-to-float v3, v0

    .line 4
    sput v3, Lxf0/t1;->a:F

    .line 5
    .line 6
    const/16 v0, 0xc

    .line 7
    .line 8
    int-to-float v0, v0

    .line 9
    sput v0, Lxf0/t1;->b:F

    .line 10
    .line 11
    const/16 v0, 0x30

    .line 12
    .line 13
    int-to-float v2, v0

    .line 14
    sput v2, Lxf0/t1;->c:F

    .line 15
    .line 16
    const/16 v0, 0xa

    .line 17
    .line 18
    int-to-float v5, v0

    .line 19
    sput v5, Lxf0/t1;->d:F

    .line 20
    .line 21
    const/16 v0, 0x8

    .line 22
    .line 23
    int-to-float v4, v0

    .line 24
    sput v4, Lxf0/t1;->e:F

    .line 25
    .line 26
    const/16 v0, 0x10

    .line 27
    .line 28
    int-to-float v6, v0

    .line 29
    sput v6, Lxf0/t1;->f:F

    .line 30
    .line 31
    new-instance v1, Lxf0/q3;

    .line 32
    .line 33
    move v7, v5

    .line 34
    invoke-direct/range {v1 .. v7}, Lxf0/q3;-><init>(FFFFFF)V

    .line 35
    .line 36
    .line 37
    sput-object v1, Lxf0/t1;->g:Lxf0/q3;

    .line 38
    .line 39
    new-instance v1, Lxf0/q3;

    .line 40
    .line 41
    move v8, v6

    .line 42
    move v6, v4

    .line 43
    move v4, v8

    .line 44
    invoke-direct/range {v1 .. v7}, Lxf0/q3;-><init>(FFFFFF)V

    .line 45
    .line 46
    .line 47
    sput-object v1, Lxf0/t1;->h:Lxf0/q3;

    .line 48
    .line 49
    return-void
.end method

.method public static final a(Ljava/lang/String;Ljava/lang/String;Lay0/k;Lx2/s;ZZZLxf0/i0;Lxf0/i0;Lt1/o0;Lt1/n0;ZIJLl2/o;III)V
    .locals 31

    move-object/from16 v15, p1

    move-object/from16 v3, p2

    move-object/from16 v0, p3

    move/from16 v1, p16

    move/from16 v2, p17

    move/from16 v4, p18

    const-string v5, "placeholder"

    invoke-static {v15, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "onValueChange"

    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    move-object/from16 v5, p15

    check-cast v5, Ll2/t;

    const v6, 0x3e67e056

    invoke-virtual {v5, v6}, Ll2/t;->a0(I)Ll2/t;

    and-int/lit8 v6, v1, 0x6

    if-nez v6, :cond_1

    move-object/from16 v6, p0

    invoke-virtual {v5, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_0

    const/4 v9, 0x4

    goto :goto_0

    :cond_0
    const/4 v9, 0x2

    :goto_0
    or-int/2addr v9, v1

    goto :goto_1

    :cond_1
    move-object/from16 v6, p0

    move v9, v1

    :goto_1
    and-int/lit8 v10, v1, 0x30

    if-nez v10, :cond_3

    invoke-virtual {v5, v15}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_2

    const/16 v10, 0x20

    goto :goto_2

    :cond_2
    const/16 v10, 0x10

    :goto_2
    or-int/2addr v9, v10

    :cond_3
    and-int/lit16 v10, v1, 0x180

    if-nez v10, :cond_5

    invoke-virtual {v5, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_4

    const/16 v10, 0x100

    goto :goto_3

    :cond_4
    const/16 v10, 0x80

    :goto_3
    or-int/2addr v9, v10

    :cond_5
    invoke-virtual {v5, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v10

    const/16 v16, 0x800

    const/16 v17, 0x400

    if-eqz v10, :cond_6

    move/from16 v10, v16

    goto :goto_4

    :cond_6
    move/from16 v10, v17

    :goto_4
    or-int/2addr v9, v10

    or-int/lit16 v10, v9, 0x6000

    and-int/lit8 v18, v4, 0x20

    if-eqz v18, :cond_8

    const v10, 0x36000

    or-int/2addr v10, v9

    :cond_7
    move/from16 v9, p5

    goto :goto_6

    :cond_8
    const/high16 v9, 0x30000

    and-int/2addr v9, v1

    if-nez v9, :cond_7

    move/from16 v9, p5

    invoke-virtual {v5, v9}, Ll2/t;->h(Z)Z

    move-result v19

    if-eqz v19, :cond_9

    const/high16 v19, 0x20000

    goto :goto_5

    :cond_9
    const/high16 v19, 0x10000

    :goto_5
    or-int v10, v10, v19

    :goto_6
    and-int/lit8 v19, v4, 0x40

    const/high16 v20, 0x180000

    if-eqz v19, :cond_a

    or-int v10, v10, v20

    move/from16 v7, p6

    goto :goto_8

    :cond_a
    and-int v20, v1, v20

    move/from16 v7, p6

    if-nez v20, :cond_c

    invoke-virtual {v5, v7}, Ll2/t;->h(Z)Z

    move-result v20

    if-eqz v20, :cond_b

    const/high16 v20, 0x100000

    goto :goto_7

    :cond_b
    const/high16 v20, 0x80000

    :goto_7
    or-int v10, v10, v20

    :cond_c
    :goto_8
    and-int/lit16 v11, v4, 0x80

    if-eqz v11, :cond_d

    const/high16 v21, 0xc00000

    or-int v10, v10, v21

    move-object/from16 v12, p7

    goto :goto_a

    :cond_d
    move-object/from16 v12, p7

    invoke-virtual {v5, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v22

    if-eqz v22, :cond_e

    const/high16 v22, 0x800000

    goto :goto_9

    :cond_e
    const/high16 v22, 0x400000

    :goto_9
    or-int v10, v10, v22

    :goto_a
    and-int/lit16 v13, v4, 0x100

    if-eqz v13, :cond_f

    const/high16 v23, 0x6000000

    or-int v10, v10, v23

    move-object/from16 v14, p8

    goto :goto_c

    :cond_f
    move-object/from16 v14, p8

    invoke-virtual {v5, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v24

    if-eqz v24, :cond_10

    const/high16 v24, 0x4000000

    goto :goto_b

    :cond_10
    const/high16 v24, 0x2000000

    :goto_b
    or-int v10, v10, v24

    :goto_c
    and-int/lit16 v8, v4, 0x200

    const/high16 v25, 0x30000000

    if-eqz v8, :cond_11

    or-int v10, v10, v25

    move-object/from16 v1, p9

    goto :goto_e

    :cond_11
    and-int v25, v1, v25

    move-object/from16 v1, p9

    if-nez v25, :cond_13

    invoke-virtual {v5, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v25

    if-eqz v25, :cond_12

    const/high16 v25, 0x20000000

    goto :goto_d

    :cond_12
    const/high16 v25, 0x10000000

    :goto_d
    or-int v10, v10, v25

    :cond_13
    :goto_e
    and-int/lit16 v1, v4, 0x400

    if-nez v1, :cond_14

    move-object/from16 v1, p10

    invoke-virtual {v5, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v25

    if-eqz v25, :cond_15

    const/16 v25, 0x4

    goto :goto_f

    :cond_14
    move-object/from16 v1, p10

    :cond_15
    const/16 v25, 0x2

    :goto_f
    or-int v25, v2, v25

    and-int/lit16 v1, v4, 0x800

    if-eqz v1, :cond_16

    or-int/lit8 v20, v25, 0x30

    move/from16 p15, v1

    :goto_10
    move/from16 v1, v20

    goto :goto_12

    :cond_16
    move/from16 p15, v1

    move/from16 v1, p11

    invoke-virtual {v5, v1}, Ll2/t;->h(Z)Z

    move-result v26

    if-eqz v26, :cond_17

    const/16 v20, 0x20

    goto :goto_11

    :cond_17
    const/16 v20, 0x10

    :goto_11
    or-int v20, v25, v20

    goto :goto_10

    :goto_12
    and-int/lit16 v3, v4, 0x1000

    if-eqz v3, :cond_19

    or-int/lit16 v1, v1, 0x180

    move/from16 v20, v1

    :cond_18
    move/from16 v1, p12

    goto :goto_14

    :cond_19
    move/from16 v20, v1

    and-int/lit16 v1, v2, 0x180

    if-nez v1, :cond_18

    move/from16 v1, p12

    invoke-virtual {v5, v1}, Ll2/t;->e(I)Z

    move-result v21

    if-eqz v21, :cond_1a

    const/16 v22, 0x100

    goto :goto_13

    :cond_1a
    const/16 v22, 0x80

    :goto_13
    or-int v20, v20, v22

    :goto_14
    and-int/lit16 v1, v4, 0x2000

    if-nez v1, :cond_1b

    move-wide/from16 v1, p13

    invoke-virtual {v5, v1, v2}, Ll2/t;->f(J)Z

    move-result v21

    if-eqz v21, :cond_1c

    goto :goto_15

    :cond_1b
    move-wide/from16 v1, p13

    :cond_1c
    move/from16 v16, v17

    :goto_15
    or-int v1, v20, v16

    const v2, 0x12492493

    and-int/2addr v2, v10

    move/from16 v16, v3

    const v3, 0x12492492

    const/16 v17, 0x1

    if-ne v2, v3, :cond_1e

    and-int/lit16 v1, v1, 0x493

    const/16 v2, 0x492

    if-eq v1, v2, :cond_1d

    goto :goto_16

    :cond_1d
    const/4 v1, 0x0

    goto :goto_17

    :cond_1e
    :goto_16
    move/from16 v1, v17

    :goto_17
    and-int/lit8 v2, v10, 0x1

    invoke-virtual {v5, v2, v1}, Ll2/t;->O(IZ)Z

    move-result v1

    if-eqz v1, :cond_2e

    invoke-virtual {v5}, Ll2/t;->T()V

    and-int/lit8 v1, p16, 0x1

    if-eqz v1, :cond_20

    invoke-virtual {v5}, Ll2/t;->y()Z

    move-result v1

    if-eqz v1, :cond_1f

    goto :goto_18

    .line 2
    :cond_1f
    invoke-virtual {v5}, Ll2/t;->R()V

    move-object/from16 v13, p10

    move/from16 v8, p11

    move-wide/from16 v1, p13

    move v11, v7

    move/from16 v19, v9

    move-object v4, v12

    move/from16 v7, p4

    move-object/from16 v12, p9

    move/from16 v9, p12

    goto/16 :goto_1e

    :cond_20
    :goto_18
    if-eqz v18, :cond_21

    const/4 v9, 0x0

    :cond_21
    if-eqz v19, :cond_22

    const/4 v7, 0x0

    :cond_22
    if-eqz v11, :cond_23

    .line 3
    sget-object v1, Lxf0/m1;->k:Lxf0/m1;

    goto :goto_19

    :cond_23
    move-object v1, v12

    :goto_19
    if-eqz v13, :cond_24

    .line 4
    sget-object v2, Lxf0/p1;->k:Lxf0/p1;

    move-object v14, v2

    :cond_24
    if-eqz v8, :cond_25

    .line 5
    sget-object v2, Lt1/o0;->e:Lt1/o0;

    goto :goto_1a

    :cond_25
    move-object/from16 v2, p9

    :goto_1a
    and-int/lit16 v3, v4, 0x400

    if-eqz v3, :cond_26

    .line 6
    new-instance v3, Lt1/n0;

    const/16 v8, 0x3f

    const/4 v10, 0x0

    invoke-direct {v3, v10, v10, v10, v8}, Lt1/n0;-><init>(Lay0/k;Lay0/k;Lay0/k;I)V

    goto :goto_1b

    :cond_26
    move-object/from16 v3, p10

    :goto_1b
    if-eqz p15, :cond_27

    const/4 v8, 0x0

    goto :goto_1c

    :cond_27
    move/from16 v8, p11

    :goto_1c
    if-eqz v16, :cond_28

    move/from16 v10, v17

    goto :goto_1d

    :cond_28
    move/from16 v10, p12

    :goto_1d
    and-int/lit16 v11, v4, 0x2000

    if-eqz v11, :cond_29

    .line 7
    sget-object v11, Lj91/h;->a:Ll2/u2;

    .line 8
    invoke-virtual {v5, v11}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v11

    .line 9
    check-cast v11, Lj91/e;

    .line 10
    invoke-virtual {v11}, Lj91/e;->q()J

    move-result-wide v11

    move-object v4, v1

    move-object v13, v3

    move/from16 v19, v9

    move v9, v10

    move-wide/from16 v29, v11

    move-object v12, v2

    move v11, v7

    move-wide/from16 v1, v29

    move/from16 v7, v17

    goto :goto_1e

    :cond_29
    move-object v4, v1

    move-object v12, v2

    move-object v13, v3

    move v11, v7

    move/from16 v19, v9

    move v9, v10

    move/from16 v7, v17

    move-wide/from16 v1, p13

    .line 11
    :goto_1e
    invoke-virtual {v5}, Ll2/t;->r()V

    .line 12
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v3

    .line 13
    sget-object v10, Ll2/n;->a:Ll2/x0;

    if-ne v3, v10, :cond_2a

    .line 14
    sget-object v3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v3}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    move-result-object v3

    .line 15
    invoke-virtual {v5, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 16
    :cond_2a
    check-cast v3, Ll2/b1;

    if-eqz v19, :cond_2b

    const v6, 0x43f18a12

    .line 17
    invoke-virtual {v5, v6}, Ll2/t;->Y(I)V

    .line 18
    sget-object v6, Lj91/h;->a:Ll2/u2;

    .line 19
    invoke-virtual {v5, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v6

    .line 20
    check-cast v6, Lj91/e;

    .line 21
    invoke-virtual {v6}, Lj91/e;->h()J

    move-result-wide v20

    :goto_1f
    const/4 v6, 0x0

    .line 22
    invoke-virtual {v5, v6}, Ll2/t;->q(Z)V

    goto :goto_20

    :cond_2b
    const v6, 0x43f19069

    .line 23
    invoke-virtual {v5, v6}, Ll2/t;->Y(I)V

    .line 24
    sget-object v6, Lj91/h;->a:Ll2/u2;

    .line 25
    invoke-virtual {v5, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v6

    .line 26
    check-cast v6, Lj91/e;

    .line 27
    invoke-virtual {v6}, Lj91/e;->c()J

    move-result-wide v20

    goto :goto_1f

    .line 28
    :goto_20
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v6

    if-ne v6, v10, :cond_2c

    .line 29
    invoke-static {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->g(Ll2/t;)Li1/l;

    move-result-object v6

    .line 30
    :cond_2c
    check-cast v6, Li1/l;

    if-eqz v19, :cond_2d

    const/4 v10, 0x2

    :goto_21
    int-to-float v10, v10

    move/from16 v16, v10

    goto :goto_22

    :cond_2d
    const/4 v10, 0x0

    goto :goto_21

    :goto_22
    const/16 v10, 0x16

    int-to-float v10, v10

    .line 31
    invoke-static {v10, v10, v10, v10}, Ls1/f;->c(FFFF)Ls1/e;

    move-result-object v18

    move-object/from16 p4, v3

    move/from16 v3, v17

    int-to-float v3, v3

    .line 32
    invoke-static {v10, v10, v10, v10}, Ls1/f;->c(FFFF)Ls1/e;

    move-result-object v10

    .line 33
    invoke-static {v3, v1, v2, v10, v0}, Lkp/g;->a(FJLe3/n0;Lx2/s;)Lx2/s;

    move-result-object v17

    .line 34
    new-instance v0, Lxf0/q1;

    move-wide/from16 v29, v20

    move-wide/from16 v20, v1

    move-wide/from16 v1, v29

    move-object/from16 v3, p0

    move-object/from16 v10, p2

    move-object/from16 v27, v5

    move v5, v8

    move-object v8, v6

    move-object v6, v14

    move-object/from16 v14, p4

    invoke-direct/range {v0 .. v15}, Lxf0/q1;-><init>(JLjava/lang/String;Lxf0/i0;ZLxf0/i0;ZLi1/l;ILay0/k;ZLt1/o0;Lt1/n0;Ll2/b1;Ljava/lang/String;)V

    move-object v3, v6

    move-object v6, v0

    move-object v0, v3

    move-wide/from16 v22, v1

    move v2, v9

    move-wide/from16 v8, v22

    move v1, v7

    move v3, v11

    move-object/from16 v22, v12

    move-object/from16 v23, v13

    const v7, 0x11e8f2b1

    move-object/from16 v10, v27

    invoke-static {v7, v10, v6}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    move-result-object v15

    move-object/from16 v6, v17

    const/high16 v17, 0xc00000

    move-object/from16 v7, v18

    const/16 v18, 0x58

    const-wide/16 v10, 0x0

    const/4 v12, 0x0

    const/4 v14, 0x0

    move/from16 v13, v16

    move-object/from16 v16, v27

    .line 35
    invoke-static/range {v6 .. v18}, Lh2/oa;->a(Lx2/s;Le3/n0;JJFFLe1/t;Lt2/b;Ll2/o;II)V

    move-object v9, v0

    move v13, v2

    move v7, v3

    move-object v8, v4

    move v12, v5

    move/from16 v6, v19

    move-wide/from16 v14, v20

    move-object/from16 v10, v22

    move-object/from16 v11, v23

    move v5, v1

    goto :goto_23

    :cond_2e
    move-object/from16 v27, v5

    .line 36
    invoke-virtual/range {v27 .. v27}, Ll2/t;->R()V

    move/from16 v5, p4

    move-object/from16 v10, p9

    move-object/from16 v11, p10

    move/from16 v13, p12

    move v6, v9

    move-object v8, v12

    move-object v9, v14

    move/from16 v12, p11

    move-wide/from16 v14, p13

    .line 37
    :goto_23
    invoke-virtual/range {v27 .. v27}, Ll2/t;->s()Ll2/u1;

    move-result-object v0

    if-eqz v0, :cond_2f

    move-object v1, v0

    new-instance v0, Lxf0/s1;

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    move-object/from16 v4, p3

    move/from16 v16, p16

    move/from16 v17, p17

    move/from16 v18, p18

    move-object/from16 v28, v1

    move-object/from16 v1, p0

    invoke-direct/range {v0 .. v18}, Lxf0/s1;-><init>(Ljava/lang/String;Ljava/lang/String;Lay0/k;Lx2/s;ZZZLxf0/i0;Lxf0/i0;Lt1/o0;Lt1/n0;ZIJIII)V

    move-object/from16 v1, v28

    .line 38
    iput-object v0, v1, Ll2/u1;->d:Lay0/n;

    :cond_2f
    return-void
.end method

.method public static final b(ILxf0/q3;Lx2/s;Lay0/a;Ll2/o;II)V
    .locals 22

    .line 1
    move/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    iget v0, v2, Lxf0/q3;->b:F

    .line 6
    .line 7
    iget v3, v2, Lxf0/q3;->a:F

    .line 8
    .line 9
    move-object/from16 v9, p4

    .line 10
    .line 11
    check-cast v9, Ll2/t;

    .line 12
    .line 13
    const v4, -0x5f6559b6

    .line 14
    .line 15
    .line 16
    invoke-virtual {v9, v4}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v9, v1}, Ll2/t;->e(I)Z

    .line 20
    .line 21
    .line 22
    move-result v4

    .line 23
    const/4 v5, 0x2

    .line 24
    const/4 v6, 0x4

    .line 25
    if-eqz v4, :cond_0

    .line 26
    .line 27
    move v4, v6

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    move v4, v5

    .line 30
    :goto_0
    or-int v4, p5, v4

    .line 31
    .line 32
    or-int/lit16 v7, v4, 0x180

    .line 33
    .line 34
    and-int/lit8 v8, p6, 0x8

    .line 35
    .line 36
    if-eqz v8, :cond_1

    .line 37
    .line 38
    or-int/lit16 v4, v4, 0xd80

    .line 39
    .line 40
    move v7, v4

    .line 41
    move-object/from16 v4, p3

    .line 42
    .line 43
    goto :goto_2

    .line 44
    :cond_1
    move-object/from16 v4, p3

    .line 45
    .line 46
    invoke-virtual {v9, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v10

    .line 50
    if-eqz v10, :cond_2

    .line 51
    .line 52
    const/16 v10, 0x800

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_2
    const/16 v10, 0x400

    .line 56
    .line 57
    :goto_1
    or-int/2addr v7, v10

    .line 58
    :goto_2
    and-int/lit16 v10, v7, 0x493

    .line 59
    .line 60
    const/16 v11, 0x492

    .line 61
    .line 62
    const/4 v12, 0x1

    .line 63
    const/4 v13, 0x0

    .line 64
    if-eq v10, v11, :cond_3

    .line 65
    .line 66
    move v10, v12

    .line 67
    goto :goto_3

    .line 68
    :cond_3
    move v10, v13

    .line 69
    :goto_3
    and-int/lit8 v11, v7, 0x1

    .line 70
    .line 71
    invoke-virtual {v9, v11, v10}, Ll2/t;->O(IZ)Z

    .line 72
    .line 73
    .line 74
    move-result v10

    .line 75
    if-eqz v10, :cond_b

    .line 76
    .line 77
    if-eqz v8, :cond_4

    .line 78
    .line 79
    const/16 v19, 0x0

    .line 80
    .line 81
    goto :goto_4

    .line 82
    :cond_4
    move-object/from16 v19, v4

    .line 83
    .line 84
    :goto_4
    const v4, -0x1b75808e

    .line 85
    .line 86
    .line 87
    invoke-virtual {v9, v4}, Ll2/t;->Y(I)V

    .line 88
    .line 89
    .line 90
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 91
    .line 92
    invoke-static {v4, v3, v0}, Landroidx/compose/foundation/layout/d;->o(Lx2/s;FF)Lx2/s;

    .line 93
    .line 94
    .line 95
    move-result-object v8

    .line 96
    iget v11, v2, Lxf0/q3;->c:F

    .line 97
    .line 98
    iget v14, v2, Lxf0/q3;->d:F

    .line 99
    .line 100
    iget v15, v2, Lxf0/q3;->e:F

    .line 101
    .line 102
    iget v10, v2, Lxf0/q3;->f:F

    .line 103
    .line 104
    invoke-static {v8, v11, v14, v15, v10}, Landroidx/compose/foundation/layout/a;->p(Lx2/s;FFFF)Lx2/s;

    .line 105
    .line 106
    .line 107
    move-result-object v14

    .line 108
    if-nez v19, :cond_5

    .line 109
    .line 110
    const v0, -0x640edaf7

    .line 111
    .line 112
    .line 113
    invoke-virtual {v9, v0}, Ll2/t;->Y(I)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {v9, v13}, Ll2/t;->q(Z)V

    .line 117
    .line 118
    .line 119
    const/4 v10, 0x0

    .line 120
    goto :goto_5

    .line 121
    :cond_5
    const v8, -0x640edaf6

    .line 122
    .line 123
    .line 124
    invoke-virtual {v9, v8}, Ll2/t;->Y(I)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v8

    .line 131
    sget-object v10, Ll2/n;->a:Ll2/x0;

    .line 132
    .line 133
    if-ne v8, v10, :cond_6

    .line 134
    .line 135
    invoke-static {v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->g(Ll2/t;)Li1/l;

    .line 136
    .line 137
    .line 138
    move-result-object v8

    .line 139
    :cond_6
    move-object v15, v8

    .line 140
    check-cast v15, Li1/l;

    .line 141
    .line 142
    new-instance v8, Lt4/f;

    .line 143
    .line 144
    invoke-direct {v8, v0}, Lt4/f;-><init>(F)V

    .line 145
    .line 146
    .line 147
    new-instance v0, Lt4/f;

    .line 148
    .line 149
    invoke-direct {v0, v3}, Lt4/f;-><init>(F)V

    .line 150
    .line 151
    .line 152
    invoke-static {v8, v0}, Ljp/vc;->e(Lt4/f;Ljava/lang/Comparable;)Ljava/lang/Comparable;

    .line 153
    .line 154
    .line 155
    move-result-object v0

    .line 156
    check-cast v0, Lt4/f;

    .line 157
    .line 158
    iget v0, v0, Lt4/f;->d:F

    .line 159
    .line 160
    int-to-float v3, v5

    .line 161
    div-float/2addr v0, v3

    .line 162
    const-wide/16 v10, 0x0

    .line 163
    .line 164
    invoke-static {v10, v11, v0, v6, v13}, Lh2/w7;->a(JFIZ)Lh2/x7;

    .line 165
    .line 166
    .line 167
    move-result-object v16

    .line 168
    new-instance v0, Ld4/i;

    .line 169
    .line 170
    invoke-direct {v0, v13}, Ld4/i;-><init>(I)V

    .line 171
    .line 172
    .line 173
    const/16 v20, 0x8

    .line 174
    .line 175
    const/16 v17, 0x1

    .line 176
    .line 177
    move-object/from16 v18, v0

    .line 178
    .line 179
    invoke-static/range {v14 .. v20}, Landroidx/compose/foundation/a;->d(Lx2/s;Li1/l;Le1/s0;ZLd4/i;Lay0/a;I)Lx2/s;

    .line 180
    .line 181
    .line 182
    move-result-object v10

    .line 183
    invoke-virtual {v9, v13}, Ll2/t;->q(Z)V

    .line 184
    .line 185
    .line 186
    :goto_5
    if-nez v10, :cond_7

    .line 187
    .line 188
    goto :goto_6

    .line 189
    :cond_7
    move-object v14, v10

    .line 190
    :goto_6
    invoke-virtual {v9, v13}, Ll2/t;->q(Z)V

    .line 191
    .line 192
    .line 193
    sget-object v0, Lx2/c;->h:Lx2/j;

    .line 194
    .line 195
    invoke-static {v0, v13}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 196
    .line 197
    .line 198
    move-result-object v0

    .line 199
    iget-wide v5, v9, Ll2/t;->T:J

    .line 200
    .line 201
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 202
    .line 203
    .line 204
    move-result v3

    .line 205
    invoke-virtual {v9}, Ll2/t;->m()Ll2/p1;

    .line 206
    .line 207
    .line 208
    move-result-object v5

    .line 209
    invoke-static {v9, v14}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 210
    .line 211
    .line 212
    move-result-object v6

    .line 213
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 214
    .line 215
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 216
    .line 217
    .line 218
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 219
    .line 220
    invoke-virtual {v9}, Ll2/t;->c0()V

    .line 221
    .line 222
    .line 223
    iget-boolean v10, v9, Ll2/t;->S:Z

    .line 224
    .line 225
    if-eqz v10, :cond_8

    .line 226
    .line 227
    invoke-virtual {v9, v8}, Ll2/t;->l(Lay0/a;)V

    .line 228
    .line 229
    .line 230
    goto :goto_7

    .line 231
    :cond_8
    invoke-virtual {v9}, Ll2/t;->m0()V

    .line 232
    .line 233
    .line 234
    :goto_7
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 235
    .line 236
    invoke-static {v8, v0, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 237
    .line 238
    .line 239
    sget-object v0, Lv3/j;->f:Lv3/h;

    .line 240
    .line 241
    invoke-static {v0, v5, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 242
    .line 243
    .line 244
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 245
    .line 246
    iget-boolean v5, v9, Ll2/t;->S:Z

    .line 247
    .line 248
    if-nez v5, :cond_9

    .line 249
    .line 250
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object v5

    .line 254
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 255
    .line 256
    .line 257
    move-result-object v8

    .line 258
    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 259
    .line 260
    .line 261
    move-result v5

    .line 262
    if-nez v5, :cond_a

    .line 263
    .line 264
    :cond_9
    invoke-static {v3, v9, v3, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 265
    .line 266
    .line 267
    :cond_a
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 268
    .line 269
    invoke-static {v0, v6, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 270
    .line 271
    .line 272
    and-int/lit8 v0, v7, 0xe

    .line 273
    .line 274
    invoke-static {v1, v0, v9}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 275
    .line 276
    .line 277
    move-result-object v0

    .line 278
    const/16 v3, 0x18

    .line 279
    .line 280
    int-to-float v3, v3

    .line 281
    invoke-static {v4, v3}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 282
    .line 283
    .line 284
    move-result-object v6

    .line 285
    const/16 v10, 0x1b0

    .line 286
    .line 287
    const/16 v11, 0x8

    .line 288
    .line 289
    const/4 v5, 0x0

    .line 290
    const-wide/16 v7, 0x0

    .line 291
    .line 292
    move-object/from16 v21, v4

    .line 293
    .line 294
    move-object v4, v0

    .line 295
    move-object/from16 v0, v21

    .line 296
    .line 297
    invoke-static/range {v4 .. v11}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 298
    .line 299
    .line 300
    invoke-virtual {v9, v12}, Ll2/t;->q(Z)V

    .line 301
    .line 302
    .line 303
    move-object v3, v0

    .line 304
    move-object/from16 v4, v19

    .line 305
    .line 306
    goto :goto_8

    .line 307
    :cond_b
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 308
    .line 309
    .line 310
    move-object/from16 v3, p2

    .line 311
    .line 312
    :goto_8
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 313
    .line 314
    .line 315
    move-result-object v8

    .line 316
    if-eqz v8, :cond_c

    .line 317
    .line 318
    new-instance v0, Lc71/c;

    .line 319
    .line 320
    const/16 v7, 0x16

    .line 321
    .line 322
    move/from16 v5, p5

    .line 323
    .line 324
    move/from16 v6, p6

    .line 325
    .line 326
    invoke-direct/range {v0 .. v7}, Lc71/c;-><init>(ILjava/lang/Object;Lx2/s;Lay0/a;III)V

    .line 327
    .line 328
    .line 329
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 330
    .line 331
    :cond_c
    return-void
.end method
