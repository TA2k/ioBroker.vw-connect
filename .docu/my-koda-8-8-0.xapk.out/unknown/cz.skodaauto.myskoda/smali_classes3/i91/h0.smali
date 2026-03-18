.class public abstract Li91/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x8

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Li91/h0;->a:F

    .line 5
    .line 6
    const/16 v0, 0x10

    .line 7
    .line 8
    int-to-float v0, v0

    .line 9
    sput v0, Li91/h0;->b:F

    .line 10
    .line 11
    return-void
.end method

.method public static final a(Ljava/lang/String;Lx2/s;Lay0/a;ZZZLjava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;III)V
    .locals 30

    move-object/from16 v7, p0

    move/from16 v11, p11

    move/from16 v12, p12

    move/from16 v13, p13

    const-string v0, "text"

    invoke-static {v7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    move-object/from16 v0, p10

    check-cast v0, Ll2/t;

    const v1, 0x7cef1a15

    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    and-int/lit8 v1, v11, 0x6

    if-nez v1, :cond_1

    invoke-virtual {v0, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    const/4 v1, 0x4

    goto :goto_0

    :cond_0
    const/4 v1, 0x2

    :goto_0
    or-int/2addr v1, v11

    goto :goto_1

    :cond_1
    move v1, v11

    :goto_1
    and-int/lit8 v3, v13, 0x2

    if-eqz v3, :cond_3

    or-int/lit8 v1, v1, 0x30

    :cond_2
    move-object/from16 v5, p1

    goto :goto_3

    :cond_3
    and-int/lit8 v5, v11, 0x30

    if-nez v5, :cond_2

    move-object/from16 v5, p1

    invoke-virtual {v0, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_4

    const/16 v6, 0x20

    goto :goto_2

    :cond_4
    const/16 v6, 0x10

    :goto_2
    or-int/2addr v1, v6

    :goto_3
    and-int/lit8 v6, v13, 0x4

    if-eqz v6, :cond_6

    or-int/lit16 v1, v1, 0x180

    :cond_5
    move-object/from16 v8, p2

    goto :goto_5

    :cond_6
    and-int/lit16 v8, v11, 0x180

    if-nez v8, :cond_5

    move-object/from16 v8, p2

    invoke-virtual {v0, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_7

    const/16 v9, 0x100

    goto :goto_4

    :cond_7
    const/16 v9, 0x80

    :goto_4
    or-int/2addr v1, v9

    :goto_5
    and-int/lit8 v9, v13, 0x8

    if-eqz v9, :cond_9

    or-int/lit16 v1, v1, 0xc00

    :cond_8
    move/from16 v15, p3

    goto :goto_7

    :cond_9
    and-int/lit16 v15, v11, 0xc00

    if-nez v15, :cond_8

    move/from16 v15, p3

    invoke-virtual {v0, v15}, Ll2/t;->h(Z)Z

    move-result v16

    if-eqz v16, :cond_a

    const/16 v16, 0x800

    goto :goto_6

    :cond_a
    const/16 v16, 0x400

    :goto_6
    or-int v1, v1, v16

    :goto_7
    and-int/lit8 v16, v13, 0x10

    if-eqz v16, :cond_c

    or-int/lit16 v1, v1, 0x6000

    :cond_b
    move/from16 v10, p4

    goto :goto_9

    :cond_c
    and-int/lit16 v10, v11, 0x6000

    if-nez v10, :cond_b

    move/from16 v10, p4

    invoke-virtual {v0, v10}, Ll2/t;->h(Z)Z

    move-result v17

    if-eqz v17, :cond_d

    const/16 v17, 0x4000

    goto :goto_8

    :cond_d
    const/16 v17, 0x2000

    :goto_8
    or-int v1, v1, v17

    :goto_9
    and-int/lit8 v17, v13, 0x20

    const/high16 v18, 0x30000

    if-eqz v17, :cond_e

    or-int v1, v1, v18

    move/from16 v14, p5

    goto :goto_b

    :cond_e
    and-int v18, v11, v18

    move/from16 v14, p5

    if-nez v18, :cond_10

    invoke-virtual {v0, v14}, Ll2/t;->h(Z)Z

    move-result v19

    if-eqz v19, :cond_f

    const/high16 v19, 0x20000

    goto :goto_a

    :cond_f
    const/high16 v19, 0x10000

    :goto_a
    or-int v1, v1, v19

    :cond_10
    :goto_b
    and-int/lit8 v19, v13, 0x40

    const/high16 v20, 0x180000

    if-eqz v19, :cond_11

    or-int v1, v1, v20

    move-object/from16 v4, p6

    goto :goto_d

    :cond_11
    and-int v20, v11, v20

    move-object/from16 v4, p6

    if-nez v20, :cond_13

    invoke-virtual {v0, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v21

    if-eqz v21, :cond_12

    const/high16 v21, 0x100000

    goto :goto_c

    :cond_12
    const/high16 v21, 0x80000

    :goto_c
    or-int v1, v1, v21

    :cond_13
    :goto_d
    and-int/lit16 v2, v13, 0x80

    const/high16 v22, 0xc00000

    if-eqz v2, :cond_15

    or-int v1, v1, v22

    :cond_14
    move/from16 v22, v1

    move-object/from16 v1, p7

    goto :goto_f

    :cond_15
    and-int v22, v11, v22

    if-nez v22, :cond_14

    move/from16 v22, v1

    move-object/from16 v1, p7

    invoke-virtual {v0, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v23

    if-eqz v23, :cond_16

    const/high16 v23, 0x800000

    goto :goto_e

    :cond_16
    const/high16 v23, 0x400000

    :goto_e
    or-int v22, v22, v23

    :goto_f
    and-int/lit16 v1, v13, 0x100

    const/high16 v23, 0x6000000

    if-eqz v1, :cond_18

    or-int v22, v22, v23

    :cond_17
    move/from16 v23, v1

    move-object/from16 v1, p8

    goto :goto_11

    :cond_18
    and-int v23, v11, v23

    if-nez v23, :cond_17

    move/from16 v23, v1

    move-object/from16 v1, p8

    invoke-virtual {v0, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v24

    if-eqz v24, :cond_19

    const/high16 v24, 0x4000000

    goto :goto_10

    :cond_19
    const/high16 v24, 0x2000000

    :goto_10
    or-int v22, v22, v24

    :goto_11
    const/high16 v24, 0x30000000

    or-int v22, v22, v24

    or-int/lit16 v1, v12, 0x1b6

    move/from16 v24, v1

    and-int/lit16 v1, v13, 0x2000

    if-eqz v1, :cond_1a

    const/16 v18, 0xdb6

    move/from16 v25, v1

    :goto_12
    move/from16 v1, v18

    goto :goto_14

    :cond_1a
    move/from16 v25, v1

    and-int/lit16 v1, v12, 0xc00

    if-nez v1, :cond_1c

    move-object/from16 v1, p9

    invoke-virtual {v0, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v26

    if-eqz v26, :cond_1b

    const/16 v18, 0x800

    goto :goto_13

    :cond_1b
    const/16 v18, 0x400

    :goto_13
    or-int v18, v24, v18

    goto :goto_12

    :cond_1c
    move-object/from16 v1, p9

    move/from16 v1, v24

    :goto_14
    const v18, 0x12492493

    move/from16 v24, v2

    and-int v2, v22, v18

    move/from16 p10, v3

    const v3, 0x12492492

    const/16 v18, 0x1

    const/4 v4, 0x0

    if-ne v2, v3, :cond_1e

    and-int/lit16 v1, v1, 0x493

    const/16 v2, 0x492

    if-eq v1, v2, :cond_1d

    goto :goto_15

    :cond_1d
    move v1, v4

    goto :goto_16

    :cond_1e
    :goto_15
    move/from16 v1, v18

    :goto_16
    and-int/lit8 v2, v22, 0x1

    invoke-virtual {v0, v2, v1}, Ll2/t;->O(IZ)Z

    move-result v1

    if-eqz v1, :cond_30

    if-eqz p10, :cond_1f

    .line 2
    sget-object v1, Lx2/p;->b:Lx2/p;

    goto :goto_17

    :cond_1f
    move-object v1, v5

    :goto_17
    const/4 v2, 0x0

    if-eqz v6, :cond_20

    move-object v8, v2

    :cond_20
    if-eqz v9, :cond_21

    move v10, v4

    goto :goto_18

    :cond_21
    move v10, v15

    :goto_18
    if-eqz v16, :cond_22

    move/from16 v5, v18

    goto :goto_19

    :cond_22
    move/from16 v5, p4

    :goto_19
    if-eqz v17, :cond_23

    move/from16 v27, v4

    goto :goto_1a

    :cond_23
    move/from16 v27, v14

    :goto_1a
    if-eqz v19, :cond_24

    move-object v3, v2

    goto :goto_1b

    :cond_24
    move-object/from16 v3, p6

    :goto_1b
    if-eqz v24, :cond_25

    move-object v6, v2

    goto :goto_1c

    :cond_25
    move-object/from16 v6, p7

    :goto_1c
    move-object v9, v2

    if-eqz v23, :cond_26

    goto :goto_1d

    :cond_26
    move-object/from16 v2, p8

    :goto_1d
    if-eqz v25, :cond_27

    move-object/from16 v29, v9

    move-object v9, v6

    move-object/from16 v6, v29

    goto :goto_1e

    :cond_27
    move-object v9, v6

    move-object/from16 v6, p9

    :goto_1e
    if-eqz v5, :cond_28

    if-eqz v10, :cond_28

    const v14, -0x65ec5987

    .line 3
    invoke-virtual {v0, v14}, Ll2/t;->Y(I)V

    .line 4
    sget-object v14, Lj91/h;->a:Ll2/u2;

    .line 5
    invoke-virtual {v0, v14}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v14

    .line 6
    check-cast v14, Lj91/e;

    .line 7
    invoke-virtual {v14}, Lj91/e;->e()J

    move-result-wide v14

    .line 8
    invoke-virtual {v0, v4}, Ll2/t;->q(Z)V

    goto :goto_1f

    :cond_28
    if-eqz v5, :cond_29

    if-nez v10, :cond_29

    const v14, -0x65ec51c8

    .line 9
    invoke-virtual {v0, v14}, Ll2/t;->Y(I)V

    .line 10
    sget-object v14, Lj91/h;->a:Ll2/u2;

    .line 11
    invoke-virtual {v0, v14}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v14

    .line 12
    check-cast v14, Lj91/e;

    .line 13
    invoke-virtual {v14}, Lj91/e;->q()J

    move-result-wide v14

    .line 14
    invoke-virtual {v0, v4}, Ll2/t;->q(Z)V

    goto :goto_1f

    :cond_29
    const v14, -0x579d71c0

    .line 15
    invoke-virtual {v0, v14}, Ll2/t;->Y(I)V

    .line 16
    sget-object v14, Lj91/h;->a:Ll2/u2;

    .line 17
    invoke-virtual {v0, v14}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v14

    .line 18
    check-cast v14, Lj91/e;

    .line 19
    invoke-virtual {v14}, Lj91/e;->r()J

    move-result-wide v14

    .line 20
    invoke-virtual {v0, v4}, Ll2/t;->q(Z)V

    :goto_1f
    const/16 v16, 0x0

    const/16 v17, 0xe

    const/16 v19, 0x0

    const/16 v22, 0x0

    move-object/from16 p5, v0

    move-wide/from16 p1, v14

    move/from16 p6, v16

    move/from16 p7, v17

    move-object/from16 p3, v19

    move-object/from16 p4, v22

    .line 21
    invoke-static/range {p1 .. p7}, Lb1/a1;->a(JLc1/f1;Ljava/lang/String;Ll2/o;II)Ll2/t2;

    move-result-object v0

    move-object/from16 v14, p5

    .line 22
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Le3/s;

    move v15, v5

    .line 23
    iget-wide v4, v0, Le3/s;->a:J

    if-eqz v15, :cond_2a

    if-eqz v10, :cond_2a

    const v0, -0xde89390    # -2.999253E30f

    .line 24
    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 25
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 26
    invoke-virtual {v14, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v0

    .line 27
    check-cast v0, Lj91/e;

    .line 28
    invoke-virtual {v0}, Lj91/e;->e()J

    move-result-wide v16

    const/4 v0, 0x0

    .line 29
    invoke-virtual {v14, v0}, Ll2/t;->q(Z)V

    goto :goto_20

    :cond_2a
    if-eqz v15, :cond_2b

    if-nez v10, :cond_2b

    const v0, -0xde88bd0    # -2.9998527E30f

    .line 30
    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 31
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 32
    invoke-virtual {v14, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v0

    .line 33
    check-cast v0, Lj91/e;

    .line 34
    invoke-virtual {v0}, Lj91/e;->t()J

    move-result-wide v16

    const/4 v0, 0x0

    .line 35
    invoke-virtual {v14, v0}, Ll2/t;->q(Z)V

    goto :goto_20

    :cond_2b
    const v0, 0x50d78b47

    .line 36
    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 37
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 38
    invoke-virtual {v14, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v0

    .line 39
    check-cast v0, Lj91/e;

    .line 40
    invoke-virtual {v0}, Lj91/e;->p()J

    move-result-wide v16

    const/4 v0, 0x0

    .line 41
    invoke-virtual {v14, v0}, Ll2/t;->q(Z)V

    :goto_20
    const/4 v0, 0x0

    const/16 v19, 0xe

    const/16 v22, 0x0

    const/16 v23, 0x0

    move/from16 p6, v0

    move-object/from16 p5, v14

    move-wide/from16 p1, v16

    move/from16 p7, v19

    move-object/from16 p3, v22

    move-object/from16 p4, v23

    .line 42
    invoke-static/range {p1 .. p7}, Lb1/a1;->a(JLc1/f1;Ljava/lang/String;Ll2/o;II)Ll2/t2;

    move-result-object v0

    .line 43
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Le3/s;

    move-object/from16 p8, v2

    move-object/from16 v16, v3

    .line 44
    iget-wide v2, v0, Le3/s;->a:J

    if-eqz v15, :cond_2c

    if-eqz v10, :cond_2c

    const v0, 0x142007f8

    .line 45
    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 46
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 47
    invoke-virtual {v14, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v0

    .line 48
    check-cast v0, Lj91/e;

    .line 49
    iget-object v0, v0, Lj91/e;->s:Ll2/j1;

    .line 50
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Le3/s;

    move-wide/from16 v22, v4

    .line 51
    iget-wide v4, v0, Le3/s;->a:J

    const/4 v0, 0x0

    .line 52
    invoke-virtual {v14, v0}, Ll2/t;->q(Z)V

    goto :goto_21

    :cond_2c
    move-wide/from16 v22, v4

    if-eqz v15, :cond_2d

    if-eqz v27, :cond_2d

    const v0, 0x1420115a

    .line 53
    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 54
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 55
    invoke-virtual {v14, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v0

    .line 56
    check-cast v0, Lj91/e;

    .line 57
    invoke-virtual {v0}, Lj91/e;->h()J

    move-result-wide v4

    const/4 v0, 0x0

    .line 58
    invoke-virtual {v14, v0}, Ll2/t;->q(Z)V

    goto :goto_21

    :cond_2d
    const/4 v0, 0x0

    const v4, 0x6fe2cfca

    .line 59
    invoke-virtual {v14, v4}, Ll2/t;->Y(I)V

    .line 60
    sget-object v4, Lj91/h;->a:Ll2/u2;

    .line 61
    invoke-virtual {v14, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v4

    .line 62
    check-cast v4, Lj91/e;

    .line 63
    invoke-virtual {v4}, Lj91/e;->c()J

    move-result-wide v4

    .line 64
    invoke-virtual {v14, v0}, Ll2/t;->q(Z)V

    :goto_21
    const/4 v0, 0x0

    const/16 v17, 0xe

    const/16 v19, 0x0

    const/16 v24, 0x0

    move/from16 p6, v0

    move-wide/from16 p1, v4

    move-object/from16 p5, v14

    move/from16 p7, v17

    move-object/from16 p3, v19

    move-object/from16 p4, v24

    .line 65
    invoke-static/range {p1 .. p7}, Lb1/a1;->a(JLc1/f1;Ljava/lang/String;Ll2/o;II)Ll2/t2;

    move-result-object v0

    .line 66
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Le3/s;

    .line 67
    iget-wide v4, v0, Le3/s;->a:J

    if-eqz v27, :cond_2e

    move-wide/from16 v24, v4

    const/4 v0, 0x2

    int-to-float v4, v0

    :goto_22
    move/from16 v21, v4

    move v5, v15

    goto :goto_23

    :cond_2e
    move-wide/from16 v24, v4

    const/4 v0, 0x2

    const/4 v4, 0x0

    int-to-float v4, v4

    goto :goto_22

    .line 68
    :goto_23
    invoke-static {}, Ls1/f;->a()Ls1/e;

    move-result-object v15

    if-eqz v10, :cond_2f

    if-eqz v5, :cond_2f

    :goto_24
    int-to-float v0, v0

    .line 69
    invoke-static {v2, v3, v0}, Lkp/h;->a(JF)Le1/t;

    move-result-object v0

    move-object/from16 v17, v0

    const/16 v0, 0x20

    goto :goto_25

    :cond_2f
    move/from16 v0, v18

    goto :goto_24

    :goto_25
    int-to-float v0, v0

    .line 70
    invoke-static {v1, v0}, Landroidx/compose/foundation/layout/d;->h(Lx2/s;F)Lx2/s;

    move-result-object v18

    .line 71
    new-instance v0, Li91/e0;

    move-object/from16 v2, p8

    move-object/from16 v28, v1

    move-object v4, v8

    move-object v1, v9

    move-object/from16 v3, v16

    move-wide/from16 v8, v22

    invoke-direct/range {v0 .. v10}, Li91/e0;-><init>(Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/String;Lay0/a;ZLjava/lang/String;Ljava/lang/String;JZ)V

    move-object v9, v1

    const v1, -0xfb16590

    invoke-static {v1, v14, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    move-result-object v23

    move-object/from16 v22, v17

    move-wide/from16 v16, v24

    const/high16 v25, 0xc00000

    const/16 v26, 0x18

    move-object/from16 v24, v14

    move-object/from16 v14, v18

    const-wide/16 v18, 0x0

    const/16 v20, 0x0

    .line 72
    invoke-static/range {v14 .. v26}, Lh2/oa;->a(Lx2/s;Le3/n0;JJFFLe1/t;Lt2/b;Ll2/o;II)V

    move-object v7, v3

    move-object v3, v4

    move-object v8, v9

    move v4, v10

    move-object v9, v2

    move-object v10, v6

    move/from16 v6, v27

    move-object/from16 v2, v28

    goto :goto_26

    :cond_30
    move-object/from16 v24, v0

    .line 73
    invoke-virtual/range {v24 .. v24}, Ll2/t;->R()V

    move-object/from16 v7, p6

    move-object/from16 v9, p8

    move-object/from16 v10, p9

    move-object v2, v5

    move-object v3, v8

    move v6, v14

    move v4, v15

    move/from16 v5, p4

    move-object/from16 v8, p7

    .line 74
    :goto_26
    invoke-virtual/range {v24 .. v24}, Ll2/t;->s()Ll2/u1;

    move-result-object v14

    if-eqz v14, :cond_31

    new-instance v0, Li91/f0;

    move-object/from16 v1, p0

    invoke-direct/range {v0 .. v13}, Li91/f0;-><init>(Ljava/lang/String;Lx2/s;Lay0/a;ZZZLjava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/String;III)V

    .line 75
    iput-object v0, v14, Ll2/u1;->d:Lay0/n;

    :cond_31
    return-void
.end method

.method public static final b(Lx2/s;Lt2/b;Ll2/o;II)V
    .locals 10

    .line 1
    move-object v7, p2

    .line 2
    check-cast v7, Ll2/t;

    .line 3
    .line 4
    const p2, 0x638f0753

    .line 5
    .line 6
    .line 7
    invoke-virtual {v7, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 p2, p4, 0x1

    .line 11
    .line 12
    const/4 v0, 0x4

    .line 13
    if-eqz p2, :cond_0

    .line 14
    .line 15
    or-int/lit8 v1, p3, 0x6

    .line 16
    .line 17
    goto :goto_1

    .line 18
    :cond_0
    invoke-virtual {v7, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_1

    .line 23
    .line 24
    move v1, v0

    .line 25
    goto :goto_0

    .line 26
    :cond_1
    const/4 v1, 0x2

    .line 27
    :goto_0
    or-int/2addr v1, p3

    .line 28
    :goto_1
    and-int/lit8 v2, v1, 0x13

    .line 29
    .line 30
    const/16 v3, 0x12

    .line 31
    .line 32
    const/4 v4, 0x1

    .line 33
    if-eq v2, v3, :cond_2

    .line 34
    .line 35
    move v2, v4

    .line 36
    goto :goto_2

    .line 37
    :cond_2
    const/4 v2, 0x0

    .line 38
    :goto_2
    and-int/2addr v1, v4

    .line 39
    invoke-virtual {v7, v1, v2}, Ll2/t;->O(IZ)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_4

    .line 44
    .line 45
    if-eqz p2, :cond_3

    .line 46
    .line 47
    sget-object p0, Lx2/p;->b:Lx2/p;

    .line 48
    .line 49
    :cond_3
    sget-object p2, Lk1/j;->a:Lk1/c;

    .line 50
    .line 51
    sget p2, Li91/h0;->a:F

    .line 52
    .line 53
    sget-object v1, Lx2/c;->p:Lx2/h;

    .line 54
    .line 55
    invoke-static {p2, v1}, Lk1/j;->h(FLx2/h;)Lk1/h;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    sget p2, Li91/h0;->b:F

    .line 60
    .line 61
    invoke-static {p2}, Lk1/j;->g(F)Lk1/h;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    const/high16 p2, 0x3f800000    # 1.0f

    .line 66
    .line 67
    invoke-static {p0, p2}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 68
    .line 69
    .line 70
    move-result-object p2

    .line 71
    new-instance v3, Ldl/g;

    .line 72
    .line 73
    invoke-direct {v3, p1, v0}, Ldl/g;-><init>(Lt2/b;I)V

    .line 74
    .line 75
    .line 76
    const v0, 0x6291ece

    .line 77
    .line 78
    .line 79
    invoke-static {v0, v7, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 80
    .line 81
    .line 82
    move-result-object v6

    .line 83
    const v8, 0x1801b0

    .line 84
    .line 85
    .line 86
    const/16 v9, 0x38

    .line 87
    .line 88
    const/4 v3, 0x0

    .line 89
    const/4 v4, 0x0

    .line 90
    const/4 v5, 0x0

    .line 91
    move-object v0, p2

    .line 92
    invoke-static/range {v0 .. v9}, Lk1/d;->b(Lx2/s;Lk1/g;Lk1/i;Lx2/i;IILt2/b;Ll2/o;II)V

    .line 93
    .line 94
    .line 95
    :goto_3
    move-object v1, p0

    .line 96
    goto :goto_4

    .line 97
    :cond_4
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 98
    .line 99
    .line 100
    goto :goto_3

    .line 101
    :goto_4
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    if-eqz p0, :cond_5

    .line 106
    .line 107
    new-instance v0, Lew/a;

    .line 108
    .line 109
    const/4 v5, 0x1

    .line 110
    move-object v2, p1

    .line 111
    move v3, p3

    .line 112
    move v4, p4

    .line 113
    invoke-direct/range {v0 .. v5}, Lew/a;-><init>(Lx2/s;Lt2/b;III)V

    .line 114
    .line 115
    .line 116
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 117
    .line 118
    :cond_5
    return-void
.end method

.method public static final c(Lx2/s;FLt2/b;Ll2/o;II)V
    .locals 16

    .line 1
    move-object/from16 v3, p2

    .line 2
    .line 3
    move/from16 v4, p4

    .line 4
    .line 5
    move-object/from16 v0, p3

    .line 6
    .line 7
    check-cast v0, Ll2/t;

    .line 8
    .line 9
    const v1, 0x6dcae651

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 v1, p5, 0x1

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    or-int/lit8 v2, v4, 0x6

    .line 20
    .line 21
    move v5, v2

    .line 22
    move-object/from16 v2, p0

    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_0
    and-int/lit8 v2, v4, 0x6

    .line 26
    .line 27
    if-nez v2, :cond_2

    .line 28
    .line 29
    move-object/from16 v2, p0

    .line 30
    .line 31
    invoke-virtual {v0, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v5

    .line 35
    if-eqz v5, :cond_1

    .line 36
    .line 37
    const/4 v5, 0x4

    .line 38
    goto :goto_0

    .line 39
    :cond_1
    const/4 v5, 0x2

    .line 40
    :goto_0
    or-int/2addr v5, v4

    .line 41
    goto :goto_1

    .line 42
    :cond_2
    move-object/from16 v2, p0

    .line 43
    .line 44
    move v5, v4

    .line 45
    :goto_1
    and-int/lit8 v6, p5, 0x2

    .line 46
    .line 47
    if-eqz v6, :cond_4

    .line 48
    .line 49
    or-int/lit8 v5, v5, 0x30

    .line 50
    .line 51
    :cond_3
    move/from16 v7, p1

    .line 52
    .line 53
    goto :goto_3

    .line 54
    :cond_4
    and-int/lit8 v7, v4, 0x30

    .line 55
    .line 56
    if-nez v7, :cond_3

    .line 57
    .line 58
    move/from16 v7, p1

    .line 59
    .line 60
    invoke-virtual {v0, v7}, Ll2/t;->d(F)Z

    .line 61
    .line 62
    .line 63
    move-result v8

    .line 64
    if-eqz v8, :cond_5

    .line 65
    .line 66
    const/16 v8, 0x20

    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_5
    const/16 v8, 0x10

    .line 70
    .line 71
    :goto_2
    or-int/2addr v5, v8

    .line 72
    :goto_3
    and-int/lit16 v8, v4, 0x180

    .line 73
    .line 74
    if-nez v8, :cond_7

    .line 75
    .line 76
    invoke-virtual {v0, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v8

    .line 80
    if-eqz v8, :cond_6

    .line 81
    .line 82
    const/16 v8, 0x100

    .line 83
    .line 84
    goto :goto_4

    .line 85
    :cond_6
    const/16 v8, 0x80

    .line 86
    .line 87
    :goto_4
    or-int/2addr v5, v8

    .line 88
    :cond_7
    and-int/lit16 v8, v5, 0x93

    .line 89
    .line 90
    const/16 v9, 0x92

    .line 91
    .line 92
    const/4 v10, 0x0

    .line 93
    const/4 v11, 0x1

    .line 94
    if-eq v8, v9, :cond_8

    .line 95
    .line 96
    move v8, v11

    .line 97
    goto :goto_5

    .line 98
    :cond_8
    move v8, v10

    .line 99
    :goto_5
    and-int/lit8 v9, v5, 0x1

    .line 100
    .line 101
    invoke-virtual {v0, v9, v8}, Ll2/t;->O(IZ)Z

    .line 102
    .line 103
    .line 104
    move-result v8

    .line 105
    if-eqz v8, :cond_e

    .line 106
    .line 107
    sget-object v8, Lx2/p;->b:Lx2/p;

    .line 108
    .line 109
    if-eqz v1, :cond_9

    .line 110
    .line 111
    move-object v2, v8

    .line 112
    :cond_9
    if-eqz v6, :cond_a

    .line 113
    .line 114
    int-to-float v1, v10

    .line 115
    goto :goto_6

    .line 116
    :cond_a
    move v1, v7

    .line 117
    :goto_6
    sget-object v6, Lk1/j;->a:Lk1/c;

    .line 118
    .line 119
    sget v6, Li91/h0;->a:F

    .line 120
    .line 121
    invoke-static {v6}, Lk1/j;->g(F)Lk1/h;

    .line 122
    .line 123
    .line 124
    move-result-object v6

    .line 125
    invoke-static {v10, v11, v0}, Lkp/n;->b(IILl2/o;)Le1/n1;

    .line 126
    .line 127
    .line 128
    move-result-object v7

    .line 129
    invoke-static {v2, v7, v10, v11, v10}, Lkp/n;->c(Lx2/s;Le1/n1;ZZZ)Lx2/s;

    .line 130
    .line 131
    .line 132
    move-result-object v7

    .line 133
    const/high16 v9, 0x3f800000    # 1.0f

    .line 134
    .line 135
    invoke-static {v7, v9}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 136
    .line 137
    .line 138
    move-result-object v7

    .line 139
    sget-object v9, Lx2/c;->m:Lx2/i;

    .line 140
    .line 141
    const/4 v10, 0x6

    .line 142
    invoke-static {v6, v9, v0, v10}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 143
    .line 144
    .line 145
    move-result-object v6

    .line 146
    iget-wide v12, v0, Ll2/t;->T:J

    .line 147
    .line 148
    invoke-static {v12, v13}, Ljava/lang/Long;->hashCode(J)I

    .line 149
    .line 150
    .line 151
    move-result v9

    .line 152
    invoke-virtual {v0}, Ll2/t;->m()Ll2/p1;

    .line 153
    .line 154
    .line 155
    move-result-object v12

    .line 156
    invoke-static {v0, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 157
    .line 158
    .line 159
    move-result-object v7

    .line 160
    sget-object v13, Lv3/k;->m1:Lv3/j;

    .line 161
    .line 162
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 163
    .line 164
    .line 165
    sget-object v13, Lv3/j;->b:Lv3/i;

    .line 166
    .line 167
    invoke-virtual {v0}, Ll2/t;->c0()V

    .line 168
    .line 169
    .line 170
    iget-boolean v14, v0, Ll2/t;->S:Z

    .line 171
    .line 172
    if-eqz v14, :cond_b

    .line 173
    .line 174
    invoke-virtual {v0, v13}, Ll2/t;->l(Lay0/a;)V

    .line 175
    .line 176
    .line 177
    goto :goto_7

    .line 178
    :cond_b
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 179
    .line 180
    .line 181
    :goto_7
    sget-object v13, Lv3/j;->g:Lv3/h;

    .line 182
    .line 183
    invoke-static {v13, v6, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 184
    .line 185
    .line 186
    sget-object v6, Lv3/j;->f:Lv3/h;

    .line 187
    .line 188
    invoke-static {v6, v12, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 189
    .line 190
    .line 191
    sget-object v6, Lv3/j;->j:Lv3/h;

    .line 192
    .line 193
    iget-boolean v12, v0, Ll2/t;->S:Z

    .line 194
    .line 195
    if-nez v12, :cond_c

    .line 196
    .line 197
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v12

    .line 201
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 202
    .line 203
    .line 204
    move-result-object v13

    .line 205
    invoke-static {v12, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 206
    .line 207
    .line 208
    move-result v12

    .line 209
    if-nez v12, :cond_d

    .line 210
    .line 211
    :cond_c
    invoke-static {v9, v0, v9, v6}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 212
    .line 213
    .line 214
    :cond_d
    sget-object v6, Lv3/j;->d:Lv3/h;

    .line 215
    .line 216
    invoke-static {v6, v7, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 217
    .line 218
    .line 219
    invoke-static {v8, v1}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 220
    .line 221
    .line 222
    move-result-object v6

    .line 223
    invoke-static {v0, v6}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 224
    .line 225
    .line 226
    shr-int/2addr v5, v10

    .line 227
    and-int/lit8 v5, v5, 0xe

    .line 228
    .line 229
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 230
    .line 231
    .line 232
    move-result-object v5

    .line 233
    invoke-virtual {v3, v0, v5}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    invoke-static {v8, v1}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 237
    .line 238
    .line 239
    move-result-object v5

    .line 240
    invoke-static {v0, v5}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 241
    .line 242
    .line 243
    invoke-virtual {v0, v11}, Ll2/t;->q(Z)V

    .line 244
    .line 245
    .line 246
    move-object v15, v2

    .line 247
    move v2, v1

    .line 248
    move-object v1, v15

    .line 249
    goto :goto_8

    .line 250
    :cond_e
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 251
    .line 252
    .line 253
    move-object v1, v2

    .line 254
    move v2, v7

    .line 255
    :goto_8
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 256
    .line 257
    .line 258
    move-result-object v6

    .line 259
    if-eqz v6, :cond_f

    .line 260
    .line 261
    new-instance v0, Li91/g0;

    .line 262
    .line 263
    move/from16 v5, p5

    .line 264
    .line 265
    invoke-direct/range {v0 .. v5}, Li91/g0;-><init>(Lx2/s;FLt2/b;II)V

    .line 266
    .line 267
    .line 268
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 269
    .line 270
    :cond_f
    return-void
.end method
