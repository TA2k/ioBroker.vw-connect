.class public abstract Lt1/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic a:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x28

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    invoke-static {v0, v0}, Lkp/c9;->a(FF)J

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public static final a(Ljava/lang/String;Lay0/k;Lx2/s;ZZLg4/p0;Lt1/o0;Lt1/n0;ZIILl4/d0;Lay0/k;Li1/l;Le3/p0;Lt2/b;Ll2/o;III)V
    .locals 30

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move-object/from16 v7, p6

    move/from16 v9, p8

    move/from16 v0, p18

    move/from16 v3, p19

    .line 1
    move-object/from16 v4, p16

    check-cast v4, Ll2/t;

    const v5, 0x78d0d0fc

    invoke-virtual {v4, v5}, Ll2/t;->a0(I)Ll2/t;

    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_0

    const/4 v5, 0x4

    goto :goto_0

    :cond_0
    const/4 v5, 0x2

    :goto_0
    or-int v5, p17, v5

    invoke-virtual {v4, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_1

    const/16 v10, 0x20

    goto :goto_1

    :cond_1
    const/16 v10, 0x10

    :goto_1
    or-int/2addr v5, v10

    move-object/from16 v10, p2

    invoke-virtual {v4, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v13

    if-eqz v13, :cond_2

    const/16 v13, 0x100

    goto :goto_2

    :cond_2
    const/16 v13, 0x80

    :goto_2
    or-int/2addr v5, v13

    move/from16 v13, p3

    invoke-virtual {v4, v13}, Ll2/t;->h(Z)Z

    move-result v16

    const/16 v17, 0x400

    const/16 v18, 0x800

    if-eqz v16, :cond_3

    move/from16 v16, v18

    goto :goto_3

    :cond_3
    move/from16 v16, v17

    :goto_3
    or-int v5, v5, v16

    move/from16 v8, p4

    invoke-virtual {v4, v8}, Ll2/t;->h(Z)Z

    move-result v16

    const/16 v19, 0x2000

    const/16 v20, 0x4000

    if-eqz v16, :cond_4

    move/from16 v16, v20

    goto :goto_4

    :cond_4
    move/from16 v16, v19

    :goto_4
    or-int v5, v5, v16

    move-object/from16 v11, p5

    invoke-virtual {v4, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v21

    if-eqz v21, :cond_5

    const/high16 v21, 0x20000

    goto :goto_5

    :cond_5
    const/high16 v21, 0x10000

    :goto_5
    or-int v5, v5, v21

    invoke-virtual {v4, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v21

    if-eqz v21, :cond_6

    const/high16 v21, 0x100000

    goto :goto_6

    :cond_6
    const/high16 v21, 0x80000

    :goto_6
    or-int v5, v5, v21

    move-object/from16 v14, p7

    invoke-virtual {v4, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v22

    if-eqz v22, :cond_7

    const/high16 v22, 0x800000

    goto :goto_7

    :cond_7
    const/high16 v22, 0x400000

    :goto_7
    or-int v5, v5, v22

    const/high16 v22, 0x6000000

    and-int v22, p17, v22

    if-nez v22, :cond_9

    invoke-virtual {v4, v9}, Ll2/t;->h(Z)Z

    move-result v22

    if-eqz v22, :cond_8

    const/high16 v22, 0x4000000

    goto :goto_8

    :cond_8
    const/high16 v22, 0x2000000

    :goto_8
    or-int v5, v5, v22

    :cond_9
    const/high16 v22, 0x30000000

    and-int v22, p17, v22

    move/from16 v12, p9

    if-nez v22, :cond_b

    invoke-virtual {v4, v12}, Ll2/t;->e(I)Z

    move-result v23

    if-eqz v23, :cond_a

    const/high16 v23, 0x20000000

    goto :goto_9

    :cond_a
    const/high16 v23, 0x10000000

    :goto_9
    or-int v5, v5, v23

    :cond_b
    and-int/lit16 v15, v3, 0x400

    if-eqz v15, :cond_c

    or-int/lit8 v24, v0, 0x6

    move/from16 v6, p10

    goto :goto_b

    :cond_c
    move/from16 v6, p10

    invoke-virtual {v4, v6}, Ll2/t;->e(I)Z

    move-result v24

    if-eqz v24, :cond_d

    const/16 v24, 0x4

    goto :goto_a

    :cond_d
    const/16 v24, 0x2

    :goto_a
    or-int v24, v0, v24

    :goto_b
    and-int/lit16 v6, v3, 0x800

    if-eqz v6, :cond_e

    or-int/lit8 v16, v24, 0x30

    move/from16 v26, v6

    :goto_c
    move/from16 v6, v16

    goto :goto_e

    :cond_e
    move/from16 v26, v6

    move-object/from16 v6, p11

    invoke-virtual {v4, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v27

    if-eqz v27, :cond_f

    const/16 v16, 0x20

    goto :goto_d

    :cond_f
    const/16 v16, 0x10

    :goto_d
    or-int v16, v24, v16

    goto :goto_c

    :goto_e
    and-int/lit16 v8, v3, 0x1000

    if-eqz v8, :cond_11

    or-int/lit16 v6, v6, 0x180

    :cond_10
    move-object/from16 v3, p12

    goto :goto_10

    :cond_11
    and-int/lit16 v3, v0, 0x180

    if-nez v3, :cond_10

    move-object/from16 v3, p12

    invoke-virtual {v4, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v16

    if-eqz v16, :cond_12

    const/16 v21, 0x100

    goto :goto_f

    :cond_12
    const/16 v21, 0x80

    :goto_f
    or-int v6, v6, v21

    :goto_10
    and-int/lit16 v3, v0, 0xc00

    if-nez v3, :cond_14

    move-object/from16 v3, p13

    invoke-virtual {v4, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v16

    if-eqz v16, :cond_13

    move/from16 v17, v18

    :cond_13
    or-int v6, v6, v17

    :goto_11
    move-object/from16 v0, p14

    goto :goto_12

    :cond_14
    move-object/from16 v3, p13

    goto :goto_11

    :goto_12
    invoke-virtual {v4, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v16

    if-eqz v16, :cond_15

    move/from16 v19, v20

    :cond_15
    or-int v6, v6, v19

    const v16, 0x12492493

    and-int v0, v5, v16

    const v3, 0x12492492

    const/16 v16, 0x0

    const/16 v17, 0x1

    if-ne v0, v3, :cond_17

    const v0, 0x12493

    and-int/2addr v0, v6

    const v3, 0x12492

    if-eq v0, v3, :cond_16

    goto :goto_13

    :cond_16
    move/from16 v0, v16

    goto :goto_14

    :cond_17
    :goto_13
    move/from16 v0, v17

    :goto_14
    and-int/lit8 v3, v5, 0x1

    invoke-virtual {v4, v3, v0}, Ll2/t;->O(IZ)Z

    move-result v0

    if-eqz v0, :cond_29

    invoke-virtual {v4}, Ll2/t;->T()V

    and-int/lit8 v0, p17, 0x1

    sget-object v3, Ll2/n;->a:Ll2/x0;

    if-eqz v0, :cond_19

    invoke-virtual {v4}, Ll2/t;->y()Z

    move-result v0

    if-eqz v0, :cond_18

    goto :goto_16

    .line 2
    :cond_18
    invoke-virtual {v4}, Ll2/t;->R()V

    move-object/from16 v14, p11

    move-object/from16 v15, p12

    :goto_15
    move/from16 v0, p10

    goto :goto_1b

    :cond_19
    :goto_16
    if-eqz v15, :cond_1a

    move/from16 v0, v17

    goto :goto_17

    :cond_1a
    move/from16 v0, p10

    :goto_17
    if-eqz v26, :cond_1b

    .line 3
    sget-object v15, Ll4/c0;->d:Lj9/d;

    goto :goto_18

    :cond_1b
    move-object/from16 v15, p11

    :goto_18
    if-eqz v8, :cond_1d

    .line 4
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v8

    if-ne v8, v3, :cond_1c

    .line 5
    new-instance v8, Lsb/a;

    move/from16 p10, v0

    const/16 v0, 0xe

    invoke-direct {v8, v0}, Lsb/a;-><init>(I)V

    .line 6
    invoke-virtual {v4, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    goto :goto_19

    :cond_1c
    move/from16 p10, v0

    .line 7
    :goto_19
    move-object v0, v8

    check-cast v0, Lay0/k;

    goto :goto_1a

    :cond_1d
    move/from16 p10, v0

    move-object/from16 v0, p12

    :goto_1a
    move-object v14, v15

    move-object v15, v0

    goto :goto_15

    .line 8
    :goto_1b
    invoke-virtual {v4}, Ll2/t;->r()V

    .line 9
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v8

    if-ne v8, v3, :cond_1e

    .line 10
    new-instance v8, Ll4/v;

    const-wide/16 v10, 0x0

    move/from16 p10, v0

    const/4 v0, 0x6

    invoke-direct {v8, v10, v11, v1, v0}, Ll4/v;-><init>(JLjava/lang/String;I)V

    invoke-static {v8}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    move-result-object v8

    .line 11
    invoke-virtual {v4, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    goto :goto_1c

    :cond_1e
    move/from16 p10, v0

    .line 12
    :goto_1c
    check-cast v8, Ll2/b1;

    .line 13
    invoke-interface {v8}, Ll2/t2;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ll4/v;

    .line 14
    iget-wide v10, v0, Ll4/v;->b:J

    .line 15
    iget-object v0, v0, Ll4/v;->c:Lg4/o0;

    move/from16 p16, v6

    .line 16
    new-instance v6, Ll4/v;

    new-instance v12, Lg4/g;

    invoke-direct {v12, v1}, Lg4/g;-><init>(Ljava/lang/String;)V

    invoke-direct {v6, v12, v10, v11, v0}, Ll4/v;-><init>(Lg4/g;JLg4/o0;)V

    .line 17
    invoke-virtual {v4, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v0

    .line 18
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v10

    if-nez v0, :cond_1f

    if-ne v10, v3, :cond_20

    .line 19
    :cond_1f
    new-instance v10, Lo51/c;

    const/16 v0, 0x15

    invoke-direct {v10, v0, v6, v8}, Lo51/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 20
    invoke-virtual {v4, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 21
    :cond_20
    check-cast v10, Lay0/a;

    invoke-static {v10, v4}, Ll2/l0;->g(Lay0/a;Ll2/o;)V

    and-int/lit8 v0, v5, 0xe

    const/4 v10, 0x4

    if-ne v0, v10, :cond_21

    move/from16 v0, v17

    goto :goto_1d

    :cond_21
    move/from16 v0, v16

    .line 22
    :goto_1d
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v10

    if-nez v0, :cond_22

    if-ne v10, v3, :cond_23

    .line 23
    :cond_22
    invoke-static {v1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    move-result-object v10

    .line 24
    invoke-virtual {v4, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 25
    :cond_23
    check-cast v10, Ll2/b1;

    .line 26
    invoke-virtual {v7, v9}, Lt1/o0;->b(Z)Ll4/j;

    move-result-object v21

    xor-int/lit8 v18, v9, 0x1

    if-eqz v9, :cond_24

    move/from16 v20, v17

    goto :goto_1e

    :cond_24
    move/from16 v20, p10

    :goto_1e
    if-eqz v9, :cond_25

    move/from16 v19, v17

    goto :goto_1f

    :cond_25
    move/from16 v19, p9

    .line 27
    :goto_1f
    invoke-virtual {v4, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v0

    and-int/lit8 v11, v5, 0x70

    const/16 v12, 0x20

    if-ne v11, v12, :cond_26

    move/from16 v16, v17

    :cond_26
    or-int v0, v0, v16

    .line 28
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v11

    if-nez v0, :cond_27

    if-ne v11, v3, :cond_28

    .line 29
    :cond_27
    new-instance v11, Lkv0/e;

    const/16 v0, 0xf

    invoke-direct {v11, v2, v8, v10, v0}, Lkv0/e;-><init>(Ljava/lang/Object;Ll2/b1;Ll2/b1;I)V

    .line 30
    invoke-virtual {v4, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 31
    :cond_28
    check-cast v11, Lay0/k;

    and-int/lit16 v0, v5, 0x380

    shr-int/lit8 v3, v5, 0x6

    and-int/lit16 v3, v3, 0x1c00

    or-int/2addr v0, v3

    shl-int/lit8 v3, p16, 0x9

    const v8, 0xe000

    and-int v10, v3, v8

    or-int/2addr v0, v10

    const/high16 v10, 0x70000

    and-int/2addr v10, v3

    or-int/2addr v0, v10

    const/high16 v10, 0x380000

    and-int/2addr v10, v3

    or-int/2addr v0, v10

    const/high16 v10, 0x1c00000

    and-int/2addr v3, v10

    or-int v27, v0, v3

    shr-int/lit8 v0, v5, 0xf

    and-int/lit16 v0, v0, 0x380

    and-int/lit16 v3, v5, 0x1c00

    or-int/2addr v0, v3

    and-int v3, v5, v8

    or-int/2addr v0, v3

    const/high16 v3, 0x30000

    or-int v28, v0, v3

    move-object/from16 v12, p2

    move/from16 v24, p4

    move-object/from16 v22, p7

    move-object/from16 v16, p13

    move-object/from16 v17, p14

    move-object/from16 v25, p15

    move-object/from16 v26, v4

    move-object v10, v6

    move/from16 v23, v13

    move-object/from16 v13, p5

    .line 32
    invoke-static/range {v10 .. v28}, Lt1/l0;->g(Ll4/v;Lay0/k;Lx2/s;Lg4/p0;Ll4/d0;Lay0/k;Li1/l;Le3/p0;ZIILl4/j;Lt1/n0;ZZLt2/b;Ll2/o;II)V

    move-object v12, v14

    move-object v13, v15

    :goto_20
    move/from16 v11, p10

    goto :goto_21

    :cond_29
    move-object/from16 v26, v4

    .line 33
    invoke-virtual/range {v26 .. v26}, Ll2/t;->R()V

    move-object/from16 v12, p11

    move-object/from16 v13, p12

    goto :goto_20

    .line 34
    :goto_21
    invoke-virtual/range {v26 .. v26}, Ll2/t;->s()Ll2/u1;

    move-result-object v0

    if-eqz v0, :cond_2a

    move-object v3, v0

    new-instance v0, Lt1/g;

    const/16 v20, 0x1

    move/from16 v4, p3

    move/from16 v5, p4

    move-object/from16 v6, p5

    move-object/from16 v8, p7

    move/from16 v10, p9

    move-object/from16 v14, p13

    move-object/from16 v15, p14

    move-object/from16 v16, p15

    move/from16 v17, p17

    move/from16 v18, p18

    move/from16 v19, p19

    move-object/from16 v29, v3

    move-object/from16 v3, p2

    invoke-direct/range {v0 .. v20}, Lt1/g;-><init>(Ljava/lang/Object;Lay0/k;Lx2/s;ZZLg4/p0;Lt1/o0;Lt1/n0;ZIILl4/d0;Lay0/k;Li1/l;Le3/p0;Lt2/b;IIII)V

    move-object/from16 v3, v29

    .line 35
    iput-object v0, v3, Ll2/u1;->d:Lay0/n;

    :cond_2a
    return-void
.end method

.method public static final b(Ll4/v;Lay0/k;Lx2/s;ZZLg4/p0;Lt1/o0;Lt1/n0;ZIILl4/d0;Lay0/k;Li1/l;Le3/p0;Lt2/b;Ll2/o;III)V
    .locals 28

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v2, p6

    move/from16 v3, p8

    move/from16 v4, p17

    move/from16 v5, p18

    .line 1
    move-object/from16 v6, p16

    check-cast v6, Ll2/t;

    const v7, -0x39e1fa71

    invoke-virtual {v6, v7}, Ll2/t;->a0(I)Ll2/t;

    and-int/lit8 v7, v4, 0x6

    if-nez v7, :cond_1

    invoke-virtual {v6, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_0

    const/4 v7, 0x4

    goto :goto_0

    :cond_0
    const/4 v7, 0x2

    :goto_0
    or-int/2addr v7, v4

    goto :goto_1

    :cond_1
    move v7, v4

    :goto_1
    and-int/lit8 v10, v4, 0x30

    if-nez v10, :cond_3

    invoke-virtual {v6, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_2

    const/16 v10, 0x20

    goto :goto_2

    :cond_2
    const/16 v10, 0x10

    :goto_2
    or-int/2addr v7, v10

    :cond_3
    and-int/lit16 v10, v4, 0x180

    if-nez v10, :cond_5

    move-object/from16 v10, p2

    invoke-virtual {v6, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v13

    if-eqz v13, :cond_4

    const/16 v13, 0x100

    goto :goto_3

    :cond_4
    const/16 v13, 0x80

    :goto_3
    or-int/2addr v7, v13

    goto :goto_4

    :cond_5
    move-object/from16 v10, p2

    :goto_4
    and-int/lit16 v13, v4, 0xc00

    if-nez v13, :cond_7

    move/from16 v13, p3

    invoke-virtual {v6, v13}, Ll2/t;->h(Z)Z

    move-result v16

    if-eqz v16, :cond_6

    const/16 v16, 0x800

    goto :goto_5

    :cond_6
    const/16 v16, 0x400

    :goto_5
    or-int v7, v7, v16

    goto :goto_6

    :cond_7
    move/from16 v13, p3

    :goto_6
    and-int/lit16 v8, v4, 0x6000

    const/16 v16, 0x2000

    const/16 v17, 0x4000

    if-nez v8, :cond_9

    move/from16 v8, p4

    invoke-virtual {v6, v8}, Ll2/t;->h(Z)Z

    move-result v18

    if-eqz v18, :cond_8

    move/from16 v18, v17

    goto :goto_7

    :cond_8
    move/from16 v18, v16

    :goto_7
    or-int v7, v7, v18

    goto :goto_8

    :cond_9
    move/from16 v8, p4

    :goto_8
    const/high16 v18, 0x30000

    and-int v19, v4, v18

    const/high16 v20, 0x10000

    const/high16 v21, 0x20000

    move-object/from16 v11, p5

    if-nez v19, :cond_b

    invoke-virtual {v6, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v22

    if-eqz v22, :cond_a

    move/from16 v22, v21

    goto :goto_9

    :cond_a
    move/from16 v22, v20

    :goto_9
    or-int v7, v7, v22

    :cond_b
    const/high16 v22, 0x180000

    and-int v22, v4, v22

    if-nez v22, :cond_d

    invoke-virtual {v6, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v22

    if-eqz v22, :cond_c

    const/high16 v22, 0x100000

    goto :goto_a

    :cond_c
    const/high16 v22, 0x80000

    :goto_a
    or-int v7, v7, v22

    :cond_d
    const/high16 v22, 0xc00000

    and-int v22, v4, v22

    move-object/from16 v14, p7

    if-nez v22, :cond_f

    invoke-virtual {v6, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v23

    if-eqz v23, :cond_e

    const/high16 v23, 0x800000

    goto :goto_b

    :cond_e
    const/high16 v23, 0x400000

    :goto_b
    or-int v7, v7, v23

    :cond_f
    const/high16 v23, 0x6000000

    and-int v23, v4, v23

    if-nez v23, :cond_11

    invoke-virtual {v6, v3}, Ll2/t;->h(Z)Z

    move-result v23

    if-eqz v23, :cond_10

    const/high16 v23, 0x4000000

    goto :goto_c

    :cond_10
    const/high16 v23, 0x2000000

    :goto_c
    or-int v7, v7, v23

    :cond_11
    const/high16 v23, 0x30000000

    and-int v23, v4, v23

    move/from16 v12, p9

    if-nez v23, :cond_13

    invoke-virtual {v6, v12}, Ll2/t;->e(I)Z

    move-result v24

    if-eqz v24, :cond_12

    const/high16 v24, 0x20000000

    goto :goto_d

    :cond_12
    const/high16 v24, 0x10000000

    :goto_d
    or-int v7, v7, v24

    :cond_13
    move/from16 v9, p19

    and-int/lit16 v15, v9, 0x400

    if-eqz v15, :cond_14

    or-int/lit8 v25, v5, 0x6

    move/from16 v4, p10

    goto :goto_f

    :cond_14
    and-int/lit8 v25, v5, 0x6

    move/from16 v4, p10

    if-nez v25, :cond_16

    invoke-virtual {v6, v4}, Ll2/t;->e(I)Z

    move-result v25

    if-eqz v25, :cond_15

    const/16 v25, 0x4

    goto :goto_e

    :cond_15
    const/16 v25, 0x2

    :goto_e
    or-int v25, v5, v25

    goto :goto_f

    :cond_16
    move/from16 v25, v5

    :goto_f
    and-int/lit8 v26, v5, 0x30

    move-object/from16 v4, p11

    if-nez v26, :cond_18

    invoke-virtual {v6, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v26

    if-eqz v26, :cond_17

    const/16 v19, 0x20

    goto :goto_10

    :cond_17
    const/16 v19, 0x10

    :goto_10
    or-int v25, v25, v19

    :cond_18
    move/from16 v4, v25

    or-int/lit16 v4, v4, 0x180

    move/from16 v19, v4

    and-int/lit16 v4, v5, 0xc00

    if-nez v4, :cond_1a

    move-object/from16 v4, p13

    invoke-virtual {v6, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v25

    if-eqz v25, :cond_19

    const/16 v22, 0x800

    goto :goto_11

    :cond_19
    const/16 v22, 0x400

    :goto_11
    or-int v19, v19, v22

    goto :goto_12

    :cond_1a
    move-object/from16 v4, p13

    :goto_12
    and-int/lit16 v4, v5, 0x6000

    if-nez v4, :cond_1c

    move-object/from16 v4, p14

    invoke-virtual {v6, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v22

    if-eqz v22, :cond_1b

    move/from16 v16, v17

    :cond_1b
    or-int v19, v19, v16

    goto :goto_13

    :cond_1c
    move-object/from16 v4, p14

    :goto_13
    and-int v16, v5, v18

    move-object/from16 v4, p15

    if-nez v16, :cond_1e

    invoke-virtual {v6, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v16

    if-eqz v16, :cond_1d

    move/from16 v20, v21

    :cond_1d
    or-int v19, v19, v20

    :cond_1e
    const v16, 0x12492493

    and-int v4, v7, v16

    const v5, 0x12492492

    const/16 v16, 0x0

    const/16 v17, 0x1

    if-ne v4, v5, :cond_20

    const v4, 0x12493

    and-int v4, v19, v4

    const v5, 0x12492

    if-eq v4, v5, :cond_1f

    goto :goto_14

    :cond_1f
    move/from16 v4, v16

    goto :goto_15

    :cond_20
    :goto_14
    move/from16 v4, v17

    :goto_15
    and-int/lit8 v5, v7, 0x1

    invoke-virtual {v6, v5, v4}, Ll2/t;->O(IZ)Z

    move-result v4

    if-eqz v4, :cond_2b

    invoke-virtual {v6}, Ll2/t;->T()V

    and-int/lit8 v4, p17, 0x1

    sget-object v5, Ll2/n;->a:Ll2/x0;

    if-eqz v4, :cond_22

    invoke-virtual {v6}, Ll2/t;->y()Z

    move-result v4

    if-eqz v4, :cond_21

    goto :goto_17

    .line 2
    :cond_21
    invoke-virtual {v6}, Ll2/t;->R()V

    move-object/from16 v4, p12

    :goto_16
    move/from16 v20, p10

    goto :goto_1a

    :cond_22
    :goto_17
    if-eqz v15, :cond_23

    move/from16 v4, v17

    goto :goto_18

    :cond_23
    move/from16 v4, p10

    .line 3
    :goto_18
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v15

    if-ne v15, v5, :cond_24

    .line 4
    new-instance v15, Lsb/a;

    move/from16 p10, v4

    const/16 v4, 0xe

    invoke-direct {v15, v4}, Lsb/a;-><init>(I)V

    .line 5
    invoke-virtual {v6, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    goto :goto_19

    :cond_24
    move/from16 p10, v4

    .line 6
    :goto_19
    move-object v4, v15

    check-cast v4, Lay0/k;

    goto :goto_16

    .line 7
    :goto_1a
    invoke-virtual {v6}, Ll2/t;->r()V

    .line 8
    invoke-virtual {v2, v3}, Lt1/o0;->b(Z)Ll4/j;

    move-result-object v11

    xor-int/lit8 v8, v3, 0x1

    if-eqz v3, :cond_25

    move/from16 v10, v17

    goto :goto_1b

    :cond_25
    move/from16 v10, v20

    :goto_1b
    if-eqz v3, :cond_26

    move/from16 v9, v17

    goto :goto_1c

    :cond_26
    move v9, v12

    :goto_1c
    and-int/lit8 v15, v7, 0xe

    const/4 v2, 0x4

    if-ne v15, v2, :cond_27

    move/from16 v2, v17

    goto :goto_1d

    :cond_27
    move/from16 v2, v16

    :goto_1d
    and-int/lit8 v15, v7, 0x70

    move/from16 p10, v2

    const/16 v2, 0x20

    if-ne v15, v2, :cond_28

    move/from16 v16, v17

    :cond_28
    or-int v2, p10, v16

    .line 9
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v15

    if-nez v2, :cond_29

    if-ne v15, v5, :cond_2a

    .line 10
    :cond_29
    new-instance v15, Lod0/n;

    const/16 v2, 0x15

    invoke-direct {v15, v2, v0, v1}, Lod0/n;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 11
    invoke-virtual {v6, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 12
    :cond_2a
    check-cast v15, Lay0/k;

    and-int/lit16 v2, v7, 0x38e

    shr-int/lit8 v5, v7, 0x6

    and-int/lit16 v5, v5, 0x1c00

    or-int/2addr v2, v5

    shl-int/lit8 v5, v19, 0x9

    const v16, 0xe000

    and-int v17, v5, v16

    or-int v2, v2, v17

    const/high16 v17, 0x70000

    and-int v18, v5, v17

    or-int v2, v2, v18

    const/high16 v18, 0x380000

    and-int v18, v5, v18

    or-int v2, v2, v18

    const/high16 v18, 0x1c00000

    and-int v5, v5, v18

    or-int/2addr v2, v5

    shr-int/lit8 v5, v7, 0xf

    and-int/lit16 v5, v5, 0x380

    and-int/lit16 v0, v7, 0x1c00

    or-int/2addr v0, v5

    and-int v5, v7, v16

    or-int/2addr v0, v5

    and-int v5, v19, v17

    or-int v18, v0, v5

    move-object/from16 v0, p0

    move-object/from16 v3, p5

    move-object/from16 v7, p14

    move/from16 v17, v2

    move-object v5, v4

    move-object/from16 v16, v6

    move-object v12, v14

    move-object v1, v15

    move-object/from16 v2, p2

    move/from16 v14, p4

    move-object/from16 v4, p11

    move-object/from16 v6, p13

    move-object/from16 v15, p15

    .line 13
    invoke-static/range {v0 .. v18}, Lt1/l0;->g(Ll4/v;Lay0/k;Lx2/s;Lg4/p0;Ll4/d0;Lay0/k;Li1/l;Le3/p0;ZIILl4/j;Lt1/n0;ZZLt2/b;Ll2/o;II)V

    move-object v13, v5

    move/from16 v11, v20

    goto :goto_1e

    :cond_2b
    move-object/from16 v16, v6

    .line 14
    invoke-virtual/range {v16 .. v16}, Ll2/t;->R()V

    move/from16 v11, p10

    move-object/from16 v13, p12

    .line 15
    :goto_1e
    invoke-virtual/range {v16 .. v16}, Ll2/t;->s()Ll2/u1;

    move-result-object v0

    if-eqz v0, :cond_2c

    move-object v1, v0

    new-instance v0, Lt1/g;

    const/16 v20, 0x0

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    move/from16 v4, p3

    move/from16 v5, p4

    move-object/from16 v6, p5

    move-object/from16 v7, p6

    move-object/from16 v8, p7

    move/from16 v9, p8

    move/from16 v10, p9

    move-object/from16 v12, p11

    move-object/from16 v14, p13

    move-object/from16 v15, p14

    move-object/from16 v16, p15

    move/from16 v17, p17

    move/from16 v18, p18

    move/from16 v19, p19

    move-object/from16 v27, v1

    move-object/from16 v1, p0

    invoke-direct/range {v0 .. v20}, Lt1/g;-><init>(Ljava/lang/Object;Lay0/k;Lx2/s;ZZLg4/p0;Lt1/o0;Lt1/n0;ZIILl4/d0;Lay0/k;Li1/l;Le3/p0;Lt2/b;IIII)V

    move-object/from16 v1, v27

    .line 16
    iput-object v0, v1, Ll2/u1;->d:Lay0/n;

    :cond_2c
    return-void
.end method
