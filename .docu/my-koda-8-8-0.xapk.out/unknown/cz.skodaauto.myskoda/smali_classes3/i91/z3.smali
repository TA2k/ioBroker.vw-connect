.class public abstract Li91/z3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lg4/g;Lx2/s;Lg4/p0;JJJLr4/k;JIZILay0/k;Ll2/o;II)V
    .locals 30

    move-object/from16 v0, p0

    move/from16 v1, p17

    move/from16 v2, p18

    const-string v3, "text"

    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    move-object/from16 v3, p16

    check-cast v3, Ll2/t;

    const v4, -0x8f183dc

    invoke-virtual {v3, v4}, Ll2/t;->a0(I)Ll2/t;

    and-int/lit8 v4, v1, 0x6

    if-nez v4, :cond_1

    invoke-virtual {v3, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_0

    const/4 v4, 0x4

    goto :goto_0

    :cond_0
    const/4 v4, 0x2

    :goto_0
    or-int/2addr v4, v1

    goto :goto_1

    :cond_1
    move v4, v1

    :goto_1
    and-int/lit8 v7, v1, 0x30

    if-nez v7, :cond_3

    move-object/from16 v7, p1

    invoke-virtual {v3, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_2

    const/16 v10, 0x20

    goto :goto_2

    :cond_2
    const/16 v10, 0x10

    :goto_2
    or-int/2addr v4, v10

    goto :goto_3

    :cond_3
    move-object/from16 v7, p1

    :goto_3
    and-int/lit16 v10, v1, 0x180

    if-nez v10, :cond_5

    move-object/from16 v10, p2

    invoke-virtual {v3, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v13

    if-eqz v13, :cond_4

    const/16 v13, 0x100

    goto :goto_4

    :cond_4
    const/16 v13, 0x80

    :goto_4
    or-int/2addr v4, v13

    goto :goto_5

    :cond_5
    move-object/from16 v10, p2

    :goto_5
    and-int/lit16 v13, v1, 0xc00

    move-wide/from16 v5, p3

    if-nez v13, :cond_7

    invoke-virtual {v3, v5, v6}, Ll2/t;->f(J)Z

    move-result v16

    if-eqz v16, :cond_6

    const/16 v16, 0x800

    goto :goto_6

    :cond_6
    const/16 v16, 0x400

    :goto_6
    or-int v4, v4, v16

    :cond_7
    and-int/lit16 v8, v1, 0x6000

    const/16 v17, 0x2000

    const/16 v18, 0x4000

    move-wide/from16 v9, p5

    if-nez v8, :cond_9

    invoke-virtual {v3, v9, v10}, Ll2/t;->f(J)Z

    move-result v19

    if-eqz v19, :cond_8

    move/from16 v19, v18

    goto :goto_7

    :cond_8
    move/from16 v19, v17

    :goto_7
    or-int v4, v4, v19

    :cond_9
    const/high16 v19, 0x30000

    and-int v20, v1, v19

    const/4 v8, 0x0

    const/high16 v22, 0x20000

    const/high16 v23, 0x10000

    if-nez v20, :cond_b

    invoke-virtual {v3, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v20

    if-eqz v20, :cond_a

    move/from16 v20, v22

    goto :goto_8

    :cond_a
    move/from16 v20, v23

    :goto_8
    or-int v4, v4, v20

    :cond_b
    const/high16 v20, 0x180000

    and-int v24, v1, v20

    const/high16 v25, 0x80000

    const/high16 v26, 0x100000

    if-nez v24, :cond_d

    invoke-virtual {v3, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v24

    if-eqz v24, :cond_c

    move/from16 v24, v26

    goto :goto_9

    :cond_c
    move/from16 v24, v25

    :goto_9
    or-int v4, v4, v24

    :cond_d
    const/high16 v24, 0xc00000

    and-int v24, v1, v24

    if-nez v24, :cond_f

    invoke-virtual {v3, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v24

    if-eqz v24, :cond_e

    const/high16 v24, 0x800000

    goto :goto_a

    :cond_e
    const/high16 v24, 0x400000

    :goto_a
    or-int v4, v4, v24

    :cond_f
    const/high16 v24, 0x6000000

    and-int v24, v1, v24

    move-wide/from16 v11, p7

    if-nez v24, :cond_11

    invoke-virtual {v3, v11, v12}, Ll2/t;->f(J)Z

    move-result v27

    if-eqz v27, :cond_10

    const/high16 v27, 0x4000000

    goto :goto_b

    :cond_10
    const/high16 v27, 0x2000000

    :goto_b
    or-int v4, v4, v27

    :cond_11
    const/high16 v27, 0x30000000

    and-int v27, v1, v27

    if-nez v27, :cond_13

    invoke-virtual {v3, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_12

    const/high16 v8, 0x20000000

    goto :goto_c

    :cond_12
    const/high16 v8, 0x10000000

    :goto_c
    or-int/2addr v4, v8

    :cond_13
    and-int/lit8 v8, v2, 0x6

    if-nez v8, :cond_15

    move-object/from16 v8, p9

    invoke-virtual {v3, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v27

    if-eqz v27, :cond_14

    const/4 v13, 0x4

    goto :goto_d

    :cond_14
    const/4 v13, 0x2

    :goto_d
    or-int/2addr v13, v2

    goto :goto_e

    :cond_15
    move-object/from16 v8, p9

    move v13, v2

    :goto_e
    and-int/lit8 v27, v2, 0x30

    move-wide/from16 v14, p10

    if-nez v27, :cond_17

    invoke-virtual {v3, v14, v15}, Ll2/t;->f(J)Z

    move-result v28

    if-eqz v28, :cond_16

    const/16 v16, 0x20

    goto :goto_f

    :cond_16
    const/16 v16, 0x10

    :goto_f
    or-int v13, v13, v16

    :cond_17
    and-int/lit16 v0, v2, 0x180

    if-nez v0, :cond_19

    move/from16 v0, p12

    invoke-virtual {v3, v0}, Ll2/t;->e(I)Z

    move-result v16

    if-eqz v16, :cond_18

    const/16 v24, 0x100

    goto :goto_10

    :cond_18
    const/16 v24, 0x80

    :goto_10
    or-int v13, v13, v24

    goto :goto_11

    :cond_19
    move/from16 v0, p12

    :goto_11
    and-int/lit16 v0, v2, 0xc00

    if-nez v0, :cond_1b

    move/from16 v0, p13

    invoke-virtual {v3, v0}, Ll2/t;->h(Z)Z

    move-result v16

    if-eqz v16, :cond_1a

    const/16 v27, 0x800

    goto :goto_12

    :cond_1a
    const/16 v27, 0x400

    :goto_12
    or-int v13, v13, v27

    goto :goto_13

    :cond_1b
    move/from16 v0, p13

    :goto_13
    and-int/lit16 v0, v2, 0x6000

    move/from16 v16, v0

    const/4 v0, 0x1

    if-nez v16, :cond_1d

    invoke-virtual {v3, v0}, Ll2/t;->e(I)Z

    move-result v16

    if-eqz v16, :cond_1c

    move/from16 v17, v18

    :cond_1c
    or-int v13, v13, v17

    :cond_1d
    and-int v16, v2, v19

    move/from16 v0, p14

    if-nez v16, :cond_1f

    invoke-virtual {v3, v0}, Ll2/t;->e(I)Z

    move-result v16

    if-eqz v16, :cond_1e

    goto :goto_14

    :cond_1e
    move/from16 v22, v23

    :goto_14
    or-int v13, v13, v22

    :cond_1f
    and-int v16, v2, v20

    move-object/from16 v0, p15

    if-nez v16, :cond_21

    invoke-virtual {v3, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v16

    if-eqz v16, :cond_20

    move/from16 v25, v26

    :cond_20
    or-int v13, v13, v25

    :cond_21
    const v16, 0x12492493

    and-int v0, v4, v16

    const v1, 0x12492492

    if-ne v0, v1, :cond_23

    const v0, 0x92493

    and-int/2addr v0, v13

    const v1, 0x92492

    if-eq v0, v1, :cond_22

    goto :goto_15

    :cond_22
    const/4 v0, 0x0

    goto :goto_16

    :cond_23
    :goto_15
    const/4 v0, 0x1

    :goto_16
    and-int/lit8 v1, v4, 0x1

    invoke-virtual {v3, v1, v0}, Ll2/t;->O(IZ)Z

    move-result v0

    if-eqz v0, :cond_26

    invoke-virtual {v3}, Ll2/t;->T()V

    and-int/lit8 v0, p17, 0x1

    if-eqz v0, :cond_25

    invoke-virtual {v3}, Ll2/t;->y()Z

    move-result v0

    if-eqz v0, :cond_24

    goto :goto_17

    .line 2
    :cond_24
    invoke-virtual {v3}, Ll2/t;->R()V

    :cond_25
    :goto_17
    invoke-virtual {v3}, Ll2/t;->r()V

    and-int/lit8 v0, v4, 0x7e

    shr-int/lit8 v1, v4, 0x3

    and-int/lit16 v1, v1, 0x380

    or-int/2addr v0, v1

    const v1, 0xe000

    and-int v16, v4, v1

    or-int v0, v0, v16

    const/high16 v16, 0x70000

    and-int v17, v4, v16

    or-int v0, v0, v17

    const/high16 v17, 0x380000

    and-int v17, v4, v17

    or-int v0, v0, v17

    const/high16 v17, 0x1c00000

    and-int v18, v4, v17

    or-int v0, v0, v18

    const/high16 v18, 0xe000000

    and-int v19, v4, v18

    or-int v0, v0, v19

    const/high16 v19, 0x70000000

    and-int v19, v4, v19

    or-int v19, v0, v19

    and-int/lit16 v0, v13, 0x1ffe

    shr-int/lit8 v20, v13, 0x3

    and-int v1, v20, v1

    or-int/2addr v0, v1

    shl-int/lit8 v1, v13, 0x3

    and-int v13, v1, v16

    or-int/2addr v0, v13

    and-int v1, v1, v17

    or-int/2addr v0, v1

    shl-int/lit8 v1, v4, 0x12

    and-int v1, v1, v18

    or-int v20, v0, v1

    const v21, 0x10008

    const/4 v14, 0x1

    const/4 v15, 0x0

    move-object/from16 v0, p0

    move-object/from16 v17, p2

    move/from16 v13, p14

    move-object/from16 v16, p15

    move-object/from16 v18, v3

    move-wide v2, v5

    move-object v1, v7

    move-wide v4, v9

    move-wide v6, v11

    move-wide/from16 v9, p10

    move/from16 v11, p12

    move/from16 v12, p13

    .line 3
    invoke-static/range {v0 .. v21}, Lh2/rb;->c(Lg4/g;Lx2/s;JJJLr4/k;JIZIILjava/util/Map;Lay0/k;Lg4/p0;Ll2/o;III)V

    goto :goto_18

    :cond_26
    move-object/from16 v18, v3

    .line 4
    invoke-virtual/range {v18 .. v18}, Ll2/t;->R()V

    .line 5
    :goto_18
    invoke-virtual/range {v18 .. v18}, Ll2/t;->s()Ll2/u1;

    move-result-object v0

    if-eqz v0, :cond_27

    move-object v1, v0

    new-instance v0, Lf2/s0;

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    move-wide/from16 v4, p3

    move-wide/from16 v6, p5

    move-wide/from16 v8, p7

    move-object/from16 v10, p9

    move-wide/from16 v11, p10

    move/from16 v13, p12

    move/from16 v14, p13

    move/from16 v15, p14

    move-object/from16 v16, p15

    move/from16 v17, p17

    move/from16 v18, p18

    move-object/from16 v29, v1

    move-object/from16 v1, p0

    invoke-direct/range {v0 .. v18}, Lf2/s0;-><init>(Lg4/g;Lx2/s;Lg4/p0;JJJLr4/k;JIZILay0/k;II)V

    move-object/from16 v1, v29

    .line 6
    iput-object v0, v1, Ll2/u1;->d:Lay0/n;

    :cond_27
    return-void
.end method

.method public static final b(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIILay0/k;Ll2/o;II)V
    .locals 35

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move/from16 v0, p18

    move/from16 v3, p19

    const-string v4, "text"

    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v4, "style"

    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    move-object/from16 v4, p17

    check-cast v4, Ll2/t;

    const v5, -0x74f770d8

    invoke-virtual {v4, v5}, Ll2/t;->a0(I)Ll2/t;

    and-int/lit8 v5, v0, 0x6

    if-nez v5, :cond_1

    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_0

    const/4 v5, 0x4

    goto :goto_0

    :cond_0
    const/4 v5, 0x2

    :goto_0
    or-int/2addr v5, v0

    goto :goto_1

    :cond_1
    move v5, v0

    :goto_1
    and-int/lit8 v8, v0, 0x30

    if-nez v8, :cond_3

    invoke-virtual {v4, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_2

    const/16 v8, 0x20

    goto :goto_2

    :cond_2
    const/16 v8, 0x10

    :goto_2
    or-int/2addr v5, v8

    :cond_3
    and-int/lit16 v8, v0, 0x180

    if-nez v8, :cond_5

    move-object/from16 v8, p2

    invoke-virtual {v4, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v13

    if-eqz v13, :cond_4

    const/16 v13, 0x100

    goto :goto_3

    :cond_4
    const/16 v13, 0x80

    :goto_3
    or-int/2addr v5, v13

    goto :goto_4

    :cond_5
    move-object/from16 v8, p2

    :goto_4
    and-int/lit16 v13, v0, 0xc00

    move-wide/from16 v6, p3

    if-nez v13, :cond_7

    invoke-virtual {v4, v6, v7}, Ll2/t;->f(J)Z

    move-result v16

    if-eqz v16, :cond_6

    const/16 v16, 0x800

    goto :goto_5

    :cond_6
    const/16 v16, 0x400

    :goto_5
    or-int v5, v5, v16

    :cond_7
    and-int/lit16 v9, v0, 0x6000

    const/16 v17, 0x2000

    const/16 v18, 0x4000

    move-wide/from16 v10, p5

    if-nez v9, :cond_9

    invoke-virtual {v4, v10, v11}, Ll2/t;->f(J)Z

    move-result v20

    if-eqz v20, :cond_8

    move/from16 v20, v18

    goto :goto_6

    :cond_8
    move/from16 v20, v17

    :goto_6
    or-int v5, v5, v20

    :cond_9
    const/high16 v20, 0x30000

    and-int v21, v0, v20

    const/4 v9, 0x0

    const/high16 v23, 0x20000

    const/high16 v24, 0x10000

    if-nez v21, :cond_b

    invoke-virtual {v4, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v21

    if-eqz v21, :cond_a

    move/from16 v21, v23

    goto :goto_7

    :cond_a
    move/from16 v21, v24

    :goto_7
    or-int v5, v5, v21

    :cond_b
    const/high16 v21, 0x180000

    and-int v25, v0, v21

    const/high16 v26, 0x80000

    const/high16 v27, 0x100000

    move-object/from16 v12, p7

    if-nez v25, :cond_d

    invoke-virtual {v4, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v28

    if-eqz v28, :cond_c

    move/from16 v28, v27

    goto :goto_8

    :cond_c
    move/from16 v28, v26

    :goto_8
    or-int v5, v5, v28

    :cond_d
    const/high16 v28, 0xc00000

    and-int v28, v0, v28

    if-nez v28, :cond_f

    invoke-virtual {v4, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_e

    const/high16 v9, 0x800000

    goto :goto_9

    :cond_e
    const/high16 v9, 0x400000

    :goto_9
    or-int/2addr v5, v9

    :cond_f
    const/high16 v9, 0x6000000

    and-int/2addr v9, v0

    move-wide/from16 v13, p8

    if-nez v9, :cond_11

    invoke-virtual {v4, v13, v14}, Ll2/t;->f(J)Z

    move-result v29

    if-eqz v29, :cond_10

    const/high16 v29, 0x4000000

    goto :goto_a

    :cond_10
    const/high16 v29, 0x2000000

    :goto_a
    or-int v5, v5, v29

    :cond_11
    const/high16 v29, 0x30000000

    and-int v29, v0, v29

    move-object/from16 v9, p10

    if-nez v29, :cond_13

    invoke-virtual {v4, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v30

    if-eqz v30, :cond_12

    const/high16 v30, 0x20000000

    goto :goto_b

    :cond_12
    const/high16 v30, 0x10000000

    :goto_b
    or-int v5, v5, v30

    :cond_13
    and-int/lit8 v30, v3, 0x6

    move-object/from16 v15, p11

    if-nez v30, :cond_15

    invoke-virtual {v4, v15}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v31

    if-eqz v31, :cond_14

    const/16 v28, 0x4

    goto :goto_c

    :cond_14
    const/16 v28, 0x2

    :goto_c
    or-int v28, v3, v28

    goto :goto_d

    :cond_15
    move/from16 v28, v3

    :goto_d
    and-int/lit8 v31, v3, 0x30

    move/from16 p17, v5

    move-wide/from16 v5, p12

    if-nez v31, :cond_17

    invoke-virtual {v4, v5, v6}, Ll2/t;->f(J)Z

    move-result v7

    if-eqz v7, :cond_16

    const/16 v16, 0x20

    goto :goto_e

    :cond_16
    const/16 v16, 0x10

    :goto_e
    or-int v28, v28, v16

    :cond_17
    and-int/lit16 v7, v3, 0x180

    if-nez v7, :cond_19

    move/from16 v7, p14

    invoke-virtual {v4, v7}, Ll2/t;->e(I)Z

    move-result v16

    if-eqz v16, :cond_18

    const/16 v19, 0x100

    goto :goto_f

    :cond_18
    const/16 v19, 0x80

    :goto_f
    or-int v28, v28, v19

    goto :goto_10

    :cond_19
    move/from16 v7, p14

    :goto_10
    and-int/lit16 v0, v3, 0xc00

    move/from16 v16, v0

    const/4 v0, 0x1

    if-nez v16, :cond_1b

    invoke-virtual {v4, v0}, Ll2/t;->h(Z)Z

    move-result v16

    if-eqz v16, :cond_1a

    const/16 v29, 0x800

    goto :goto_11

    :cond_1a
    const/16 v29, 0x400

    :goto_11
    or-int v28, v28, v29

    :cond_1b
    and-int/lit16 v0, v3, 0x6000

    if-nez v0, :cond_1d

    move/from16 v0, p15

    invoke-virtual {v4, v0}, Ll2/t;->e(I)Z

    move-result v19

    if-eqz v19, :cond_1c

    move/from16 v17, v18

    :cond_1c
    or-int v28, v28, v17

    goto :goto_12

    :cond_1d
    move/from16 v0, p15

    :goto_12
    and-int v17, v3, v20

    const/4 v0, 0x1

    if-nez v17, :cond_1f

    invoke-virtual {v4, v0}, Ll2/t;->e(I)Z

    move-result v16

    if-eqz v16, :cond_1e

    goto :goto_13

    :cond_1e
    move/from16 v23, v24

    :goto_13
    or-int v28, v28, v23

    :cond_1f
    and-int v16, v3, v21

    move-object/from16 v0, p16

    if-nez v16, :cond_21

    invoke-virtual {v4, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v17

    if-eqz v17, :cond_20

    move/from16 v26, v27

    :cond_20
    or-int v28, v28, v26

    :cond_21
    const v17, 0x12492493

    and-int v0, p17, v17

    const v3, 0x12492492

    if-ne v0, v3, :cond_23

    const v0, 0x92493

    and-int v0, v28, v0

    const v3, 0x92492

    if-eq v0, v3, :cond_22

    goto :goto_14

    :cond_22
    const/4 v0, 0x0

    goto :goto_15

    :cond_23
    :goto_14
    const/4 v0, 0x1

    :goto_15
    and-int/lit8 v3, p17, 0x1

    invoke-virtual {v4, v3, v0}, Ll2/t;->O(IZ)Z

    move-result v0

    if-eqz v0, :cond_25

    .line 2
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 3
    invoke-virtual {v4, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v0

    .line 4
    check-cast v0, Lj91/f;

    .line 5
    invoke-virtual {v0}, Lj91/f;->n()Lg4/p0;

    move-result-object v0

    .line 6
    invoke-virtual {v2, v0}, Lg4/p0;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_24

    .line 7
    sget-object v0, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    invoke-virtual {v1, v0}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    move-result-object v0

    const-string v3, "toUpperCase(...)"

    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    goto :goto_16

    :cond_24
    move-object v0, v1

    :goto_16
    shr-int/lit8 v3, p17, 0x3

    and-int/lit16 v3, v3, 0x3f0

    const v16, 0xe000

    and-int v16, p17, v16

    or-int v3, v3, v16

    const/high16 v16, 0x70000

    and-int v16, p17, v16

    or-int v3, v3, v16

    const/high16 v16, 0x380000

    and-int v16, p17, v16

    or-int v3, v3, v16

    const/high16 v16, 0x1c00000

    and-int v17, p17, v16

    or-int v3, v3, v17

    const/high16 v17, 0xe000000

    and-int v17, p17, v17

    or-int v3, v3, v17

    const/high16 v17, 0x70000000

    and-int v17, p17, v17

    or-int v22, v3, v17

    const v3, 0x3ffffe

    and-int v3, v28, v3

    shl-int/lit8 v17, p17, 0x12

    and-int v16, v17, v16

    or-int v23, v3, v16

    const/16 v24, 0x8

    const/16 v16, 0x1

    const/16 v18, 0x1

    move/from16 v17, p15

    move-object/from16 v19, p16

    move-object/from16 v20, v2

    move-object/from16 v21, v4

    move-object v3, v8

    move-object v8, v12

    move-object v12, v15

    move-object v2, v0

    move v15, v7

    move-wide/from16 v33, v10

    move-object v11, v9

    move-wide v9, v13

    move-wide v13, v5

    move-wide/from16 v6, v33

    move-wide/from16 v4, p3

    .line 8
    invoke-static/range {v2 .. v24}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    goto :goto_17

    :cond_25
    move-object/from16 v21, v4

    .line 9
    invoke-virtual/range {v21 .. v21}, Ll2/t;->R()V

    .line 10
    :goto_17
    invoke-virtual/range {v21 .. v21}, Ll2/t;->s()Ll2/u1;

    move-result-object v0

    if-eqz v0, :cond_26

    move-object v2, v0

    new-instance v0, Li91/m4;

    move-object/from16 v3, p2

    move-wide/from16 v4, p3

    move-wide/from16 v6, p5

    move-object/from16 v8, p7

    move-wide/from16 v9, p8

    move-object/from16 v11, p10

    move-object/from16 v12, p11

    move-wide/from16 v13, p12

    move/from16 v15, p14

    move/from16 v16, p15

    move-object/from16 v17, p16

    move/from16 v18, p18

    move/from16 v19, p19

    move-object/from16 v32, v2

    move-object/from16 v2, p1

    invoke-direct/range {v0 .. v19}, Li91/m4;-><init>(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIILay0/k;II)V

    move-object/from16 v2, v32

    .line 11
    iput-object v0, v2, Ll2/u1;->d:Lay0/n;

    :cond_26
    return-void
.end method

.method public static final c(Lg4/g;Lx2/s;Lg4/p0;JJJLr4/k;JIZILay0/k;Ll2/o;III)V
    .locals 21

    move-object/from16 v0, p0

    move/from16 v1, p17

    move/from16 v2, p18

    move/from16 v3, p19

    const-string v4, "text"

    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    move-object/from16 v4, p16

    check-cast v4, Ll2/t;

    const v5, 0x3f82b9e7

    invoke-virtual {v4, v5}, Ll2/t;->a0(I)Ll2/t;

    and-int/lit8 v5, v1, 0x6

    if-nez v5, :cond_1

    invoke-virtual {v4, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_0

    const/4 v5, 0x4

    goto :goto_0

    :cond_0
    const/4 v5, 0x2

    :goto_0
    or-int/2addr v5, v1

    goto :goto_1

    :cond_1
    move v5, v1

    :goto_1
    and-int/lit8 v8, v3, 0x2

    if-eqz v8, :cond_3

    or-int/lit8 v5, v5, 0x30

    :cond_2
    move-object/from16 v9, p1

    goto :goto_3

    :cond_3
    and-int/lit8 v9, v1, 0x30

    if-nez v9, :cond_2

    move-object/from16 v9, p1

    invoke-virtual {v4, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_4

    const/16 v10, 0x20

    goto :goto_2

    :cond_4
    const/16 v10, 0x10

    :goto_2
    or-int/2addr v5, v10

    :goto_3
    and-int/lit16 v10, v1, 0x180

    if-nez v10, :cond_7

    and-int/lit8 v10, v3, 0x4

    if-nez v10, :cond_5

    move-object/from16 v10, p2

    invoke-virtual {v4, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v13

    if-eqz v13, :cond_6

    const/16 v13, 0x100

    goto :goto_4

    :cond_5
    move-object/from16 v10, p2

    :cond_6
    const/16 v13, 0x80

    :goto_4
    or-int/2addr v5, v13

    goto :goto_5

    :cond_7
    move-object/from16 v10, p2

    :goto_5
    and-int/lit8 v13, v3, 0x8

    if-eqz v13, :cond_9

    or-int/lit16 v5, v5, 0xc00

    :cond_8
    move-wide/from16 v14, p3

    goto :goto_7

    :cond_9
    and-int/lit16 v14, v1, 0xc00

    if-nez v14, :cond_8

    move-wide/from16 v14, p3

    invoke-virtual {v4, v14, v15}, Ll2/t;->f(J)Z

    move-result v16

    if-eqz v16, :cond_a

    const/16 v16, 0x800

    goto :goto_6

    :cond_a
    const/16 v16, 0x400

    :goto_6
    or-int v5, v5, v16

    :goto_7
    const v16, 0x6db6000

    or-int v16, v5, v16

    and-int/lit16 v6, v3, 0x200

    const/4 v7, 0x0

    if-eqz v6, :cond_c

    const v6, 0x36db6000

    or-int v16, v5, v6

    :cond_b
    :goto_8
    move/from16 v5, v16

    goto :goto_a

    :cond_c
    const/high16 v5, 0x30000000

    and-int/2addr v5, v1

    if-nez v5, :cond_b

    invoke-virtual {v4, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_d

    const/high16 v5, 0x20000000

    goto :goto_9

    :cond_d
    const/high16 v5, 0x10000000

    :goto_9
    or-int v16, v16, v5

    goto :goto_8

    :goto_a
    and-int/lit16 v6, v3, 0x400

    if-eqz v6, :cond_e

    or-int/lit8 v16, v2, 0x6

    move-object/from16 v7, p9

    move/from16 v11, v16

    goto :goto_c

    :cond_e
    and-int/lit8 v16, v2, 0x6

    move-object/from16 v7, p9

    if-nez v16, :cond_10

    invoke-virtual {v4, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v18

    if-eqz v18, :cond_f

    const/16 v17, 0x4

    goto :goto_b

    :cond_f
    const/16 v17, 0x2

    :goto_b
    or-int v17, v2, v17

    move/from16 v11, v17

    goto :goto_c

    :cond_10
    move v11, v2

    :goto_c
    or-int/lit8 v17, v11, 0x30

    and-int/lit16 v12, v3, 0x1000

    if-eqz v12, :cond_11

    or-int/lit16 v11, v11, 0x1b0

    move v0, v11

    move/from16 v11, p12

    goto :goto_f

    :cond_11
    and-int/lit16 v11, v2, 0x180

    if-nez v11, :cond_13

    move/from16 v11, p12

    invoke-virtual {v4, v11}, Ll2/t;->e(I)Z

    move-result v19

    if-eqz v19, :cond_12

    const/16 v18, 0x100

    goto :goto_d

    :cond_12
    const/16 v18, 0x80

    :goto_d
    or-int v17, v17, v18

    :goto_e
    move/from16 v0, v17

    goto :goto_f

    :cond_13
    move/from16 v11, p12

    goto :goto_e

    :goto_f
    or-int/lit16 v1, v0, 0xc00

    move/from16 v17, v1

    and-int/lit16 v1, v3, 0x4000

    if-eqz v1, :cond_15

    or-int/lit16 v0, v0, 0x6c00

    move/from16 v17, v0

    :cond_14
    move/from16 v0, p14

    goto :goto_11

    :cond_15
    and-int/lit16 v0, v2, 0x6000

    if-nez v0, :cond_14

    move/from16 v0, p14

    invoke-virtual {v4, v0}, Ll2/t;->e(I)Z

    move-result v18

    if-eqz v18, :cond_16

    const/16 v18, 0x4000

    goto :goto_10

    :cond_16
    const/16 v18, 0x2000

    :goto_10
    or-int v17, v17, v18

    :goto_11
    const v18, 0x8000

    and-int v18, v3, v18

    const/high16 v19, 0x30000

    if-eqz v18, :cond_18

    :goto_12
    or-int v17, v17, v19

    :cond_17
    move/from16 v0, v17

    goto :goto_13

    :cond_18
    and-int v19, v2, v19

    move-object/from16 v0, p15

    if-nez v19, :cond_17

    invoke-virtual {v4, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v19

    if-eqz v19, :cond_19

    const/high16 v19, 0x20000

    goto :goto_12

    :cond_19
    const/high16 v19, 0x10000

    goto :goto_12

    :goto_13
    const v17, 0x12492493

    move/from16 v19, v1

    and-int v1, v5, v17

    const v2, 0x12492492

    const/16 v17, 0x1

    if-ne v1, v2, :cond_1b

    const v1, 0x12493

    and-int/2addr v1, v0

    const v2, 0x12492

    if-eq v1, v2, :cond_1a

    goto :goto_14

    :cond_1a
    const/4 v1, 0x0

    goto :goto_15

    :cond_1b
    :goto_14
    move/from16 v1, v17

    :goto_15
    and-int/lit8 v2, v5, 0x1

    invoke-virtual {v4, v2, v1}, Ll2/t;->O(IZ)Z

    move-result v1

    if-eqz v1, :cond_27

    invoke-virtual {v4}, Ll2/t;->T()V

    and-int/lit8 v1, p17, 0x1

    if-eqz v1, :cond_1e

    invoke-virtual {v4}, Ll2/t;->y()Z

    move-result v1

    if-eqz v1, :cond_1c

    goto :goto_16

    .line 2
    :cond_1c
    invoke-virtual {v4}, Ll2/t;->R()V

    and-int/lit8 v1, v3, 0x4

    if-eqz v1, :cond_1d

    and-int/lit16 v5, v5, -0x381

    :cond_1d
    move/from16 v13, p13

    move-object/from16 v17, v4

    move/from16 v16, v5

    move-object v1, v9

    move-object v2, v10

    move v12, v11

    move-wide v3, v14

    move-wide/from16 v5, p5

    move-wide/from16 v10, p10

    move/from16 v14, p14

    move-object/from16 v15, p15

    move-object v9, v7

    move-wide/from16 v7, p7

    goto/16 :goto_1c

    :cond_1e
    :goto_16
    if-eqz v8, :cond_1f

    .line 3
    sget-object v1, Lx2/p;->b:Lx2/p;

    goto :goto_17

    :cond_1f
    move-object v1, v9

    :goto_17
    and-int/lit8 v2, v3, 0x4

    if-eqz v2, :cond_20

    .line 4
    sget-object v2, Lh2/rb;->a:Ll2/e0;

    .line 5
    invoke-virtual {v4, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lg4/p0;

    and-int/lit16 v5, v5, -0x381

    goto :goto_18

    :cond_20
    move-object v2, v10

    :goto_18
    if-eqz v13, :cond_21

    .line 6
    sget-wide v8, Le3/s;->i:J

    move-wide v14, v8

    .line 7
    :cond_21
    sget-wide v8, Lt4/o;->c:J

    if-eqz v6, :cond_22

    const/16 v16, 0x0

    goto :goto_19

    :cond_22
    move-object/from16 v16, v7

    :goto_19
    if-eqz v12, :cond_23

    move/from16 v11, v17

    :cond_23
    if-eqz v19, :cond_24

    const v6, 0x7fffffff

    goto :goto_1a

    :cond_24
    move/from16 v6, p14

    :goto_1a
    if-eqz v18, :cond_26

    .line 8
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v7

    .line 9
    sget-object v10, Ll2/n;->a:Ll2/x0;

    if-ne v7, v10, :cond_25

    .line 10
    new-instance v7, Li70/q;

    const/16 v10, 0xb

    invoke-direct {v7, v10}, Li70/q;-><init>(I)V

    .line 11
    invoke-virtual {v4, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 12
    :cond_25
    check-cast v7, Lay0/k;

    move v12, v11

    move/from16 v13, v17

    move-object/from16 v17, v4

    move-wide v10, v8

    move-wide v3, v14

    move v14, v6

    move-object v15, v7

    :goto_1b
    move-wide v7, v10

    move-object/from16 v9, v16

    move/from16 v16, v5

    move-wide v5, v7

    goto :goto_1c

    :cond_26
    move v12, v11

    move/from16 v13, v17

    move-object/from16 v17, v4

    move-wide v10, v8

    move-wide v3, v14

    move-object/from16 v15, p15

    move v14, v6

    goto :goto_1b

    .line 13
    :goto_1c
    invoke-virtual/range {v17 .. v17}, Ll2/t;->r()V

    const v18, 0x7ffffffe

    and-int v16, v16, v18

    move-object/from16 p1, v1

    and-int/lit8 v1, v0, 0xe

    or-int/lit16 v1, v1, 0x6000

    and-int/lit8 v18, v0, 0x70

    or-int v1, v1, v18

    move/from16 p2, v1

    and-int/lit16 v1, v0, 0x380

    or-int v1, p2, v1

    move/from16 p2, v1

    and-int/lit16 v1, v0, 0x1c00

    or-int v1, p2, v1

    shl-int/lit8 v0, v0, 0x3

    const/high16 v18, 0x70000

    and-int v18, v0, v18

    or-int v1, v1, v18

    const/high16 v18, 0x380000

    and-int v0, v0, v18

    or-int v18, v1, v0

    move-object/from16 v0, v17

    move/from16 v17, v16

    move-object/from16 v16, v0

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    .line 14
    invoke-static/range {v0 .. v18}, Li91/z3;->a(Lg4/g;Lx2/s;Lg4/p0;JJJLr4/k;JIZILay0/k;Ll2/o;II)V

    move-object/from16 v17, v16

    move-object/from16 v16, v15

    move v15, v14

    move v14, v13

    move v13, v12

    move-wide v11, v10

    move-object v10, v9

    move-wide v8, v7

    move-wide v6, v5

    move-wide v4, v3

    move-object v3, v2

    move-object v2, v1

    goto :goto_1d

    :cond_27
    move-object/from16 v16, v4

    .line 15
    invoke-virtual/range {v16 .. v16}, Ll2/t;->R()V

    move-object v2, v9

    move-object v3, v10

    move v13, v11

    move-wide v4, v14

    move-object/from16 v17, v16

    move-wide/from16 v8, p7

    move-wide/from16 v11, p10

    move/from16 v14, p13

    move/from16 v15, p14

    move-object/from16 v16, p15

    move-object v10, v7

    move-wide/from16 v6, p5

    .line 16
    :goto_1d
    invoke-virtual/range {v17 .. v17}, Ll2/t;->s()Ll2/u1;

    move-result-object v0

    if-eqz v0, :cond_28

    move-object v1, v0

    new-instance v0, Li91/k4;

    move/from16 v17, p17

    move/from16 v18, p18

    move/from16 v19, p19

    move-object/from16 v20, v1

    move-object/from16 v1, p0

    invoke-direct/range {v0 .. v19}, Li91/k4;-><init>(Lg4/g;Lx2/s;Lg4/p0;JJJLr4/k;JIZILay0/k;III)V

    move-object/from16 v1, v20

    .line 17
    iput-object v0, v1, Ll2/u1;->d:Lay0/n;

    :cond_28
    return-void
.end method

.method public static final d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V
    .locals 26

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move/from16 v2, p19

    move/from16 v3, p20

    move/from16 v4, p21

    const-string v5, "text"

    invoke-static {v0, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "style"

    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    move-object/from16 v5, p18

    check-cast v5, Ll2/t;

    const v6, -0x5991115

    invoke-virtual {v5, v6}, Ll2/t;->a0(I)Ll2/t;

    and-int/lit8 v6, v2, 0x6

    if-nez v6, :cond_1

    invoke-virtual {v5, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_0

    const/4 v6, 0x4

    goto :goto_0

    :cond_0
    const/4 v6, 0x2

    :goto_0
    or-int/2addr v6, v2

    goto :goto_1

    :cond_1
    move v6, v2

    :goto_1
    and-int/lit8 v9, v2, 0x30

    if-nez v9, :cond_3

    invoke-virtual {v5, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_2

    const/16 v9, 0x20

    goto :goto_2

    :cond_2
    const/16 v9, 0x10

    :goto_2
    or-int/2addr v6, v9

    :cond_3
    and-int/lit8 v9, v4, 0x4

    if-eqz v9, :cond_5

    or-int/lit16 v6, v6, 0x180

    :cond_4
    move-object/from16 v12, p2

    goto :goto_4

    :cond_5
    and-int/lit16 v12, v2, 0x180

    if-nez v12, :cond_4

    move-object/from16 v12, p2

    invoke-virtual {v5, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v13

    if-eqz v13, :cond_6

    const/16 v13, 0x100

    goto :goto_3

    :cond_6
    const/16 v13, 0x80

    :goto_3
    or-int/2addr v6, v13

    :goto_4
    and-int/lit8 v13, v4, 0x8

    if-eqz v13, :cond_8

    or-int/lit16 v6, v6, 0xc00

    :cond_7
    move-wide/from16 v14, p3

    goto :goto_6

    :cond_8
    and-int/lit16 v14, v2, 0xc00

    if-nez v14, :cond_7

    move-wide/from16 v14, p3

    invoke-virtual {v5, v14, v15}, Ll2/t;->f(J)Z

    move-result v16

    if-eqz v16, :cond_9

    const/16 v16, 0x800

    goto :goto_5

    :cond_9
    const/16 v16, 0x400

    :goto_5
    or-int v6, v6, v16

    :goto_6
    const v16, 0x36000

    or-int v16, v6, v16

    and-int/lit8 v17, v4, 0x40

    if-eqz v17, :cond_b

    const v16, 0x1b6000

    or-int v16, v6, v16

    :cond_a
    move-object/from16 v6, p7

    goto :goto_8

    :cond_b
    const/high16 v6, 0x180000

    and-int/2addr v6, v2

    if-nez v6, :cond_a

    move-object/from16 v6, p7

    invoke-virtual {v5, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v18

    if-eqz v18, :cond_c

    const/high16 v18, 0x100000

    goto :goto_7

    :cond_c
    const/high16 v18, 0x80000

    :goto_7
    or-int v16, v16, v18

    :goto_8
    const/high16 v18, 0x6c00000

    or-int v18, v16, v18

    and-int/lit16 v7, v4, 0x200

    if-eqz v7, :cond_d

    const/high16 v18, 0x36c00000

    or-int v18, v16, v18

    move-object/from16 v8, p10

    goto :goto_a

    :cond_d
    const/high16 v16, 0x30000000

    and-int v16, v2, v16

    move-object/from16 v8, p10

    if-nez v16, :cond_f

    invoke-virtual {v5, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v19

    if-eqz v19, :cond_e

    const/high16 v19, 0x20000000

    goto :goto_9

    :cond_e
    const/high16 v19, 0x10000000

    :goto_9
    or-int v18, v18, v19

    :cond_f
    :goto_a
    and-int/lit16 v10, v4, 0x400

    if-eqz v10, :cond_10

    or-int/lit8 v16, v3, 0x6

    move-object/from16 v11, p11

    :goto_b
    move/from16 v0, v16

    goto :goto_d

    :cond_10
    and-int/lit8 v20, v3, 0x6

    move-object/from16 v11, p11

    if-nez v20, :cond_12

    invoke-virtual {v5, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v21

    if-eqz v21, :cond_11

    const/16 v16, 0x4

    goto :goto_c

    :cond_11
    const/16 v16, 0x2

    :goto_c
    or-int v16, v3, v16

    goto :goto_b

    :cond_12
    move v0, v3

    :goto_d
    or-int/lit8 v16, v0, 0x30

    and-int/lit16 v1, v4, 0x1000

    if-eqz v1, :cond_13

    or-int/lit16 v0, v0, 0x1b0

    goto :goto_10

    :cond_13
    and-int/lit16 v0, v3, 0x180

    if-nez v0, :cond_15

    move/from16 v0, p14

    invoke-virtual {v5, v0}, Ll2/t;->e(I)Z

    move-result v21

    if-eqz v21, :cond_14

    const/16 v19, 0x100

    goto :goto_e

    :cond_14
    const/16 v19, 0x80

    :goto_e
    or-int v16, v16, v19

    :goto_f
    move/from16 v0, v16

    goto :goto_10

    :cond_15
    move/from16 v0, p14

    goto :goto_f

    :goto_10
    move/from16 v16, v1

    or-int/lit16 v1, v0, 0xc00

    move/from16 v19, v1

    and-int/lit16 v1, v4, 0x4000

    if-eqz v1, :cond_17

    or-int/lit16 v0, v0, 0x6c00

    move/from16 v19, v0

    :cond_16
    move/from16 v0, p16

    goto :goto_12

    :cond_17
    and-int/lit16 v0, v3, 0x6000

    if-nez v0, :cond_16

    move/from16 v0, p16

    invoke-virtual {v5, v0}, Ll2/t;->e(I)Z

    move-result v20

    if-eqz v20, :cond_18

    const/16 v20, 0x4000

    goto :goto_11

    :cond_18
    const/16 v20, 0x2000

    :goto_11
    or-int v19, v19, v20

    :goto_12
    const v20, 0x8000

    and-int v20, v4, v20

    const/high16 v21, 0x30000

    if-eqz v20, :cond_1a

    or-int v19, v19, v21

    :cond_19
    :goto_13
    move/from16 v0, v19

    goto :goto_15

    :cond_1a
    and-int v22, v3, v21

    move-object/from16 v0, p17

    if-nez v22, :cond_19

    invoke-virtual {v5, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v22

    if-eqz v22, :cond_1b

    const/high16 v22, 0x20000

    goto :goto_14

    :cond_1b
    const/high16 v22, 0x10000

    :goto_14
    or-int v19, v19, v22

    goto :goto_13

    :goto_15
    const v19, 0x12492493

    move/from16 v22, v1

    and-int v1, v18, v19

    const v2, 0x12492492

    const/16 v23, 0x1

    if-ne v1, v2, :cond_1d

    const v1, 0x12493

    and-int/2addr v1, v0

    const v2, 0x12492

    if-eq v1, v2, :cond_1c

    goto :goto_16

    :cond_1c
    const/4 v1, 0x0

    goto :goto_17

    :cond_1d
    :goto_16
    move/from16 v1, v23

    :goto_17
    and-int/lit8 v2, v18, 0x1

    invoke-virtual {v5, v2, v1}, Ll2/t;->O(IZ)Z

    move-result v1

    if-eqz v1, :cond_27

    if-eqz v9, :cond_1e

    .line 2
    sget-object v1, Lx2/p;->b:Lx2/p;

    move-object v2, v1

    goto :goto_18

    :cond_1e
    move-object v2, v12

    :goto_18
    if-eqz v13, :cond_1f

    .line 3
    sget-wide v12, Le3/s;->i:J

    move-wide v3, v12

    goto :goto_19

    :cond_1f
    move-wide v3, v14

    .line 4
    :goto_19
    sget-wide v12, Lt4/o;->c:J

    const/4 v1, 0x0

    if-eqz v17, :cond_20

    move v6, v7

    move-object v7, v1

    goto :goto_1a

    :cond_20
    move/from16 v25, v7

    move-object v7, v6

    move/from16 v6, v25

    :goto_1a
    if-eqz v6, :cond_21

    move v6, v10

    move-object v10, v1

    goto :goto_1b

    :cond_21
    move v6, v10

    move-object v10, v8

    :goto_1b
    if-eqz v6, :cond_22

    move-object v11, v1

    :cond_22
    if-eqz v16, :cond_23

    move/from16 v14, v23

    goto :goto_1c

    :cond_23
    move/from16 v14, p14

    :goto_1c
    if-eqz v22, :cond_24

    const v1, 0x7fffffff

    move v15, v1

    goto :goto_1d

    :cond_24
    move/from16 v15, p16

    :goto_1d
    if-eqz v20, :cond_26

    .line 5
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v1

    .line 6
    sget-object v6, Ll2/n;->a:Ll2/x0;

    if-ne v1, v6, :cond_25

    .line 7
    new-instance v1, Li70/q;

    const/16 v6, 0xc

    invoke-direct {v1, v6}, Li70/q;-><init>(I)V

    .line 8
    invoke-virtual {v5, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 9
    :cond_25
    check-cast v1, Lay0/k;

    move-object/from16 v16, v1

    goto :goto_1e

    :cond_26
    move-object/from16 v16, p17

    :goto_1e
    const v1, 0x7ffffffe

    and-int v18, v18, v1

    and-int/lit8 v1, v0, 0xe

    or-int v1, v1, v21

    and-int/lit8 v6, v0, 0x70

    or-int/2addr v1, v6

    and-int/lit16 v6, v0, 0x380

    or-int/2addr v1, v6

    and-int/lit16 v6, v0, 0x1c00

    or-int/2addr v1, v6

    const v6, 0xe000

    and-int/2addr v6, v0

    or-int/2addr v1, v6

    shl-int/lit8 v0, v0, 0x3

    const/high16 v6, 0x380000

    and-int/2addr v0, v6

    or-int v19, v1, v0

    move-wide v8, v12

    move-object/from16 v17, v5

    move-wide v5, v12

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    .line 10
    invoke-static/range {v0 .. v19}, Li91/z3;->b(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIILay0/k;Ll2/o;II)V

    move-object v8, v7

    move-object v12, v11

    move-object/from16 v18, v16

    move-object/from16 v0, v17

    move/from16 v16, v23

    move-object v11, v10

    move/from16 v17, v15

    move-wide v9, v5

    move v15, v14

    move-wide v4, v3

    move-wide v6, v9

    move-wide v13, v6

    move-object v3, v2

    goto :goto_1f

    :cond_27
    move-object/from16 v17, v5

    .line 11
    invoke-virtual/range {v17 .. v17}, Ll2/t;->R()V

    move-wide/from16 v9, p8

    move/from16 v16, p15

    move-object/from16 v18, p17

    move-object v3, v12

    move-wide v4, v14

    move-object/from16 v0, v17

    move-wide/from16 v13, p12

    move/from16 v15, p14

    move/from16 v17, p16

    move-object v12, v11

    move-object v11, v8

    move-object v8, v6

    move-wide/from16 v6, p5

    .line 12
    :goto_1f
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    move-result-object v0

    if-eqz v0, :cond_28

    move-object v1, v0

    new-instance v0, Li91/l4;

    move-object/from16 v2, p1

    move/from16 v19, p19

    move/from16 v20, p20

    move/from16 v21, p21

    move-object/from16 v24, v1

    move-object/from16 v1, p0

    invoke-direct/range {v0 .. v21}, Li91/l4;-><init>(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;III)V

    move-object/from16 v1, v24

    .line 13
    iput-object v0, v1, Ll2/u1;->d:Lay0/n;

    :cond_28
    return-void
.end method

.method public static final e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "defaultTestTag"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    if-nez p0, :cond_1

    .line 7
    .line 8
    if-nez p1, :cond_0

    .line 9
    .line 10
    return-object p2

    .line 11
    :cond_0
    new-instance p0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const/16 p1, 0x5f

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    :cond_1
    return-object p0
.end method
