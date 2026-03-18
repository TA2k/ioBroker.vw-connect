.class public abstract Lh2/j6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F

.field public static final c:J


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const/16 v0, 0x30

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Lh2/j6;->a:F

    .line 5
    .line 6
    const/16 v0, 0x18

    .line 7
    .line 8
    int-to-float v0, v0

    .line 9
    sput v0, Lh2/j6;->b:F

    .line 10
    .line 11
    const/high16 v0, 0x3f000000    # 0.5f

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    invoke-static {v0, v1}, Le3/j0;->i(FF)J

    .line 15
    .line 16
    .line 17
    move-result-wide v0

    .line 18
    sput-wide v0, Lh2/j6;->c:J

    .line 19
    .line 20
    return-void
.end method

.method public static final a(Lay0/a;Lx2/s;Lh2/r8;FZLe3/n0;JJFJLay0/n;Lay0/n;Lh2/k6;Lt2/b;Ll2/o;III)V
    .locals 35

    move-object/from16 v1, p0

    move-object/from16 v3, p2

    move-wide/from16 v13, p6

    move/from16 v8, p18

    move/from16 v9, p19

    move/from16 v10, p20

    .line 1
    move-object/from16 v11, p17

    check-cast v11, Ll2/t;

    const v0, 0x7188eb30

    invoke-virtual {v11, v0}, Ll2/t;->a0(I)Ll2/t;

    and-int/lit8 v0, v8, 0x6

    if-nez v0, :cond_1

    invoke-virtual {v11, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, v8

    goto :goto_1

    :cond_1
    move v0, v8

    :goto_1
    and-int/lit8 v4, v10, 0x2

    if-eqz v4, :cond_3

    or-int/lit8 v0, v0, 0x30

    :cond_2
    move-object/from16 v5, p1

    goto :goto_3

    :cond_3
    and-int/lit8 v5, v8, 0x30

    if-nez v5, :cond_2

    move-object/from16 v5, p1

    invoke-virtual {v11, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_4

    const/16 v6, 0x20

    goto :goto_2

    :cond_4
    const/16 v6, 0x10

    :goto_2
    or-int/2addr v0, v6

    :goto_3
    and-int/lit16 v6, v8, 0x180

    if-nez v6, :cond_6

    invoke-virtual {v11, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_5

    const/16 v6, 0x100

    goto :goto_4

    :cond_5
    const/16 v6, 0x80

    :goto_4
    or-int/2addr v0, v6

    :cond_6
    or-int/lit16 v0, v0, 0x6c00

    const/high16 v6, 0x30000

    and-int/2addr v6, v8

    if-nez v6, :cond_9

    and-int/lit8 v6, v10, 0x20

    if-nez v6, :cond_7

    move-object/from16 v6, p5

    invoke-virtual {v11, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_8

    const/high16 v7, 0x20000

    goto :goto_5

    :cond_7
    move-object/from16 v6, p5

    :cond_8
    const/high16 v7, 0x10000

    :goto_5
    or-int/2addr v0, v7

    goto :goto_6

    :cond_9
    move-object/from16 v6, p5

    :goto_6
    const/high16 v7, 0x180000

    and-int/2addr v7, v8

    if-nez v7, :cond_b

    invoke-virtual {v11, v13, v14}, Ll2/t;->f(J)Z

    move-result v7

    if-eqz v7, :cond_a

    const/high16 v7, 0x100000

    goto :goto_7

    :cond_a
    const/high16 v7, 0x80000

    :goto_7
    or-int/2addr v0, v7

    :cond_b
    const/high16 v7, 0xc00000

    and-int/2addr v7, v8

    if-nez v7, :cond_d

    and-int/lit16 v7, v10, 0x80

    move-wide/from16 v2, p8

    if-nez v7, :cond_c

    invoke-virtual {v11, v2, v3}, Ll2/t;->f(J)Z

    move-result v7

    if-eqz v7, :cond_c

    const/high16 v7, 0x800000

    goto :goto_8

    :cond_c
    const/high16 v7, 0x400000

    :goto_8
    or-int/2addr v0, v7

    goto :goto_9

    :cond_d
    move-wide/from16 v2, p8

    :goto_9
    and-int/lit16 v7, v10, 0x100

    const/high16 v16, 0x6000000

    if-eqz v7, :cond_e

    or-int v0, v0, v16

    move/from16 v12, p10

    goto :goto_b

    :cond_e
    and-int v16, v8, v16

    move/from16 v12, p10

    if-nez v16, :cond_10

    invoke-virtual {v11, v12}, Ll2/t;->d(F)Z

    move-result v17

    if-eqz v17, :cond_f

    const/high16 v17, 0x4000000

    goto :goto_a

    :cond_f
    const/high16 v17, 0x2000000

    :goto_a
    or-int v0, v0, v17

    :cond_10
    :goto_b
    const/high16 v17, 0x30000000

    and-int v17, v8, v17

    if-nez v17, :cond_11

    const/high16 v17, 0x10000000

    or-int v0, v0, v17

    :cond_11
    and-int/lit8 v17, v9, 0x6

    if-nez v17, :cond_13

    move/from16 v17, v7

    move-object/from16 v7, p13

    invoke-virtual {v11, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v18

    if-eqz v18, :cond_12

    const/16 v18, 0x4

    goto :goto_c

    :cond_12
    const/16 v18, 0x2

    :goto_c
    or-int v18, v9, v18

    goto :goto_d

    :cond_13
    move/from16 v17, v7

    move-object/from16 v7, p13

    move/from16 v18, v9

    :goto_d
    and-int/lit8 v19, v9, 0x30

    if-nez v19, :cond_14

    or-int/lit8 v18, v18, 0x10

    :cond_14
    move/from16 v15, v18

    or-int/lit16 v15, v15, 0x180

    move/from16 v18, v0

    and-int/lit16 v0, v9, 0xc00

    if-nez v0, :cond_16

    move-object/from16 v0, p16

    invoke-virtual {v11, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v19

    if-eqz v19, :cond_15

    const/16 v19, 0x800

    goto :goto_e

    :cond_15
    const/16 v19, 0x400

    :goto_e
    or-int v15, v15, v19

    goto :goto_f

    :cond_16
    move-object/from16 v0, p16

    :goto_f
    const v19, 0x12492493

    and-int v0, v18, v19

    const v2, 0x12492492

    const/4 v3, 0x0

    const/16 v21, 0x1

    if-ne v0, v2, :cond_18

    and-int/lit16 v0, v15, 0x493

    const/16 v2, 0x492

    if-eq v0, v2, :cond_17

    goto :goto_10

    :cond_17
    move v0, v3

    goto :goto_11

    :cond_18
    :goto_10
    move/from16 v0, v21

    :goto_11
    and-int/lit8 v2, v18, 0x1

    invoke-virtual {v11, v2, v0}, Ll2/t;->O(IZ)Z

    move-result v0

    if-eqz v0, :cond_40

    invoke-virtual {v11}, Ll2/t;->T()V

    and-int/lit8 v0, v8, 0x1

    const v2, -0x70000001

    const v19, -0x1c00001

    const v20, -0x70001

    if-eqz v0, :cond_1c

    invoke-virtual {v11}, Ll2/t;->y()Z

    move-result v0

    if-eqz v0, :cond_19

    goto :goto_13

    .line 2
    :cond_19
    invoke-virtual {v11}, Ll2/t;->R()V

    and-int/lit8 v0, v10, 0x20

    if-eqz v0, :cond_1a

    and-int v0, v18, v20

    goto :goto_12

    :cond_1a
    move/from16 v0, v18

    :goto_12
    and-int/lit16 v4, v10, 0x80

    if-eqz v4, :cond_1b

    and-int v0, v0, v19

    :cond_1b
    and-int/2addr v0, v2

    and-int/lit8 v2, v15, -0x71

    move/from16 v10, p3

    move/from16 v15, p4

    move-wide/from16 v22, p8

    move-wide/from16 v19, p11

    move-object/from16 v24, p14

    move-object/from16 v25, p15

    move-object/from16 v18, v6

    move/from16 v17, v12

    move-object v12, v5

    goto :goto_17

    :cond_1c
    :goto_13
    if-eqz v4, :cond_1d

    .line 3
    sget-object v0, Lx2/p;->b:Lx2/p;

    goto :goto_14

    :cond_1d
    move-object v0, v5

    .line 4
    :goto_14
    sget v4, Lh2/v;->d:F

    and-int/lit8 v5, v10, 0x20

    if-eqz v5, :cond_1e

    .line 5
    sget-object v5, Lh2/v;->a:Lh2/v;

    .line 6
    sget-object v5, Lk2/h0;->a:Lk2/f0;

    .line 7
    invoke-static {v5, v11}, Lh2/i8;->b(Lk2/f0;Ll2/o;)Le3/n0;

    move-result-object v5

    and-int v6, v18, v20

    move/from16 v18, v6

    goto :goto_15

    :cond_1e
    move-object v5, v6

    :goto_15
    and-int/lit16 v6, v10, 0x80

    if-eqz v6, :cond_1f

    .line 8
    invoke-static {v13, v14, v11}, Lh2/g1;->b(JLl2/o;)J

    move-result-wide v22

    and-int v18, v18, v19

    goto :goto_16

    :cond_1f
    move-wide/from16 v22, p8

    :goto_16
    if-eqz v17, :cond_20

    int-to-float v6, v3

    move v12, v6

    .line 9
    :cond_20
    sget-object v6, Lk2/e0;->a:Lk2/l;

    move/from16 v19, v2

    .line 10
    invoke-static {v6, v11}, Lh2/g1;->d(Lk2/l;Ll2/o;)J

    move-result-wide v2

    const v6, 0x3ea3d70a    # 0.32f

    invoke-static {v2, v3, v6}, Le3/s;->b(JF)J

    move-result-wide v2

    and-int v6, v18, v19

    .line 11
    sget-object v18, Lh2/h1;->m:Lh2/h1;

    and-int/lit8 v15, v15, -0x71

    .line 12
    new-instance v19, Lh2/k6;

    invoke-direct/range {v19 .. v19}, Lh2/k6;-><init>()V

    move v10, v4

    move/from16 v17, v12

    move-object/from16 v24, v18

    move-object/from16 v25, v19

    move-object v12, v0

    move-wide/from16 v19, v2

    move-object/from16 v18, v5

    move v0, v6

    move v2, v15

    move/from16 v15, v21

    const/4 v3, 0x0

    .line 13
    :goto_17
    invoke-virtual {v11}, Ll2/t;->r()V

    .line 14
    sget-object v4, Lk2/w;->d:Lk2/w;

    invoke-static {v4, v11}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    move-result-object v6

    .line 15
    invoke-static {v4, v11}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    move-result-object v4

    .line 16
    sget-object v5, Lk2/w;->g:Lk2/w;

    invoke-static {v5, v11}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    move-result-object v5

    and-int/lit16 v3, v0, 0x380

    xor-int/lit16 v3, v3, 0x180

    move/from16 p3, v2

    const/16 v2, 0x100

    if-le v3, v2, :cond_22

    move-object/from16 v2, p2

    .line 17
    invoke-virtual {v11, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v26

    if-nez v26, :cond_21

    goto :goto_18

    :cond_21
    move/from16 v26, v3

    goto :goto_19

    :cond_22
    move-object/from16 v2, p2

    :goto_18
    and-int/lit16 v2, v0, 0x180

    move/from16 v26, v3

    const/16 v3, 0x100

    if-ne v2, v3, :cond_23

    :goto_19
    move/from16 v2, v21

    goto :goto_1a

    :cond_23
    const/4 v2, 0x0

    :goto_1a
    invoke-virtual {v11, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v3

    or-int/2addr v2, v3

    invoke-virtual {v11, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v3

    or-int/2addr v2, v3

    invoke-virtual {v11, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v3

    or-int/2addr v2, v3

    .line 18
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v3

    .line 19
    sget-object v7, Ll2/n;->a:Ll2/x0;

    if-nez v2, :cond_25

    if-ne v3, v7, :cond_24

    goto :goto_1b

    :cond_24
    move/from16 v27, p3

    move-object v2, v3

    move-object v9, v7

    move/from16 v8, v26

    move-object/from16 v3, p2

    goto :goto_1c

    .line 20
    :cond_25
    :goto_1b
    new-instance v2, Lh2/w;

    move-object v3, v7

    const/4 v7, 0x1

    move/from16 v27, p3

    move-object v9, v3

    move/from16 v8, v26

    move-object/from16 v3, p2

    invoke-direct/range {v2 .. v7}, Lh2/w;-><init>(Lh2/r8;Lc1/f1;Lc1/f1;Lc1/f1;I)V

    .line 21
    invoke-virtual {v11, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 22
    :goto_1c
    check-cast v2, Lay0/a;

    invoke-static {v2, v11}, Ll2/l0;->g(Lay0/a;Ll2/o;)V

    .line 23
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v9, :cond_26

    .line 24
    invoke-static {v11}, Ll2/l0;->h(Ll2/o;)Lvy0/b0;

    move-result-object v2

    .line 25
    invoke-virtual {v11, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 26
    :cond_26
    check-cast v2, Lvy0/b0;

    const/16 v4, 0x100

    if-le v8, v4, :cond_27

    .line 27
    invoke-virtual {v11, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_28

    :cond_27
    and-int/lit16 v5, v0, 0x180

    if-ne v5, v4, :cond_29

    :cond_28
    move/from16 v4, v21

    goto :goto_1d

    :cond_29
    const/4 v4, 0x0

    :goto_1d
    invoke-virtual {v11, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v4, v5

    and-int/lit8 v5, v0, 0xe

    const/4 v6, 0x4

    if-ne v5, v6, :cond_2a

    move/from16 v6, v21

    goto :goto_1e

    :cond_2a
    const/4 v6, 0x0

    :goto_1e
    or-int/2addr v4, v6

    .line 28
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v6

    if-nez v4, :cond_2b

    if-ne v6, v9, :cond_2c

    .line 29
    :cond_2b
    new-instance v6, Lh2/a6;

    invoke-direct {v6, v3, v2, v1}, Lh2/a6;-><init>(Lh2/r8;Lvy0/b0;Lay0/a;)V

    .line 30
    invoke-virtual {v11, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 31
    :cond_2c
    check-cast v6, Lay0/a;

    .line 32
    invoke-virtual {v11, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v4

    const/16 v7, 0x100

    if-le v8, v7, :cond_2e

    invoke-virtual {v11, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v26

    if-nez v26, :cond_2d

    goto :goto_1f

    :cond_2d
    move/from16 p1, v4

    goto :goto_20

    :cond_2e
    :goto_1f
    move/from16 p1, v4

    and-int/lit16 v4, v0, 0x180

    if-ne v4, v7, :cond_2f

    :goto_20
    move/from16 v4, v21

    goto :goto_21

    :cond_2f
    const/4 v4, 0x0

    :goto_21
    or-int v4, p1, v4

    const/4 v7, 0x4

    if-ne v5, v7, :cond_30

    move/from16 v7, v21

    goto :goto_22

    :cond_30
    const/4 v7, 0x0

    :goto_22
    or-int/2addr v4, v7

    .line 33
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v7

    if-nez v4, :cond_31

    if-ne v7, v9, :cond_32

    .line 34
    :cond_31
    new-instance v7, Laa/o;

    const/16 v4, 0x16

    invoke-direct {v7, v2, v3, v1, v4}, Laa/o;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 35
    invoke-virtual {v11, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 36
    :cond_32
    check-cast v7, Lay0/k;

    .line 37
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v4

    if-ne v4, v9, :cond_33

    const/4 v4, 0x0

    .line 38
    invoke-static {v4}, Lc1/d;->a(F)Lc1/c;

    move-result-object v4

    .line 39
    invoke-virtual {v11, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 40
    :cond_33
    check-cast v4, Lc1/c;

    move-object/from16 p1, v6

    const/16 v6, 0x100

    if-le v8, v6, :cond_34

    .line 41
    invoke-virtual {v11, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v26

    if-nez v26, :cond_35

    :cond_34
    and-int/lit16 v1, v0, 0x180

    if-ne v1, v6, :cond_36

    :cond_35
    move/from16 v1, v21

    goto :goto_23

    :cond_36
    const/4 v1, 0x0

    :goto_23
    invoke-virtual {v11, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v26

    or-int v1, v1, v26

    invoke-virtual {v11, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v26

    or-int v1, v1, v26

    const/4 v6, 0x4

    if-ne v5, v6, :cond_37

    move/from16 v5, v21

    goto :goto_24

    :cond_37
    const/4 v5, 0x0

    :goto_24
    or-int/2addr v1, v5

    .line 42
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v5

    if-nez v1, :cond_38

    if-ne v5, v9, :cond_39

    :cond_38
    move v6, v0

    goto :goto_25

    :cond_39
    move v6, v0

    move-object v3, v4

    goto :goto_26

    .line 43
    :goto_25
    new-instance v0, Lal/i;

    const/4 v5, 0x3

    move-object v1, v3

    move-object v3, v4

    move-object/from16 v4, p0

    invoke-direct/range {v0 .. v5}, Lal/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 44
    invoke-virtual {v11, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    move-object v5, v0

    .line 45
    :goto_26
    move-object/from16 v26, v5

    check-cast v26, Lay0/a;

    .line 46
    new-instance v0, Lh2/f6;

    move-object/from16 v4, p2

    move/from16 v29, v6

    move/from16 v30, v8

    move-object/from16 v31, v9

    move-object/from16 v28, v11

    move-object v9, v12

    move v11, v15

    move-object/from16 v12, v18

    move-wide/from16 v15, v22

    move-object/from16 v5, v25

    move-object/from16 v18, p13

    move-object v6, v3

    move-object v8, v7

    move-object/from16 v3, p1

    move-object v7, v2

    move-wide/from16 v1, v19

    move-object/from16 v19, v24

    move-object/from16 v20, p16

    invoke-direct/range {v0 .. v20}, Lh2/f6;-><init>(JLay0/a;Lh2/r8;Lh2/k6;Lc1/c;Lvy0/b0;Lay0/k;Lx2/s;FZLe3/n0;JJFLay0/n;Lay0/n;Lt2/b;)V

    move-wide v13, v1

    move-object v8, v4

    move-object v3, v5

    move-object v4, v6

    const v1, 0x3c33c970

    move-object/from16 v6, v28

    invoke-static {v1, v6, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    move-result-object v5

    shr-int/lit8 v0, v29, 0x12

    and-int/lit8 v0, v0, 0x70

    or-int/lit16 v0, v0, 0x6000

    move/from16 v2, v27

    and-int/lit16 v1, v2, 0x380

    or-int/2addr v0, v1

    or-int/lit16 v7, v0, 0x1000

    move-wide v1, v15

    move-object/from16 v0, v26

    move/from16 v15, v29

    .line 47
    invoke-static/range {v0 .. v7}, Lh2/r;->n(Lay0/a;JLh2/k6;Lc1/c;Lt2/b;Ll2/o;I)V

    move-object v0, v6

    .line 48
    iget-object v4, v8, Lh2/r8;->e:Li2/p;

    .line 49
    invoke-virtual {v4}, Li2/p;->d()Li2/u0;

    move-result-object v4

    sget-object v5, Lh2/s8;->e:Lh2/s8;

    .line 50
    iget-object v4, v4, Li2/u0;->a:Ljava/util/Map;

    .line 51
    invoke-interface {v4, v5}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_3f

    const v4, 0x2c9c96f2

    .line 52
    invoke-virtual {v0, v4}, Ll2/t;->Y(I)V

    move/from16 v4, v30

    const/16 v6, 0x100

    if-le v4, v6, :cond_3a

    .line 53
    invoke-virtual {v0, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_3c

    :cond_3a
    and-int/lit16 v4, v15, 0x180

    if-ne v4, v6, :cond_3b

    goto :goto_27

    :cond_3b
    const/16 v21, 0x0

    .line 54
    :cond_3c
    :goto_27
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v4

    if-nez v21, :cond_3d

    move-object/from16 v5, v31

    if-ne v4, v5, :cond_3e

    .line 55
    :cond_3d
    new-instance v4, Lh2/i0;

    const/16 v5, 0x8

    const/4 v6, 0x0

    invoke-direct {v4, v8, v6, v5}, Lh2/i0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 56
    invoke-virtual {v0, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 57
    :cond_3e
    check-cast v4, Lay0/n;

    invoke-static {v4, v8, v0}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    const/4 v4, 0x0

    .line 58
    invoke-virtual {v0, v4}, Ll2/t;->q(Z)V

    goto :goto_28

    :cond_3f
    const/4 v4, 0x0

    const v5, 0x2c9d8732

    .line 59
    invoke-virtual {v0, v5}, Ll2/t;->Y(I)V

    .line 60
    invoke-virtual {v0, v4}, Ll2/t;->q(Z)V

    :goto_28
    move-object/from16 v16, v3

    move v4, v10

    move v5, v11

    move-object v6, v12

    move-wide v12, v13

    move/from16 v11, v17

    move-object/from16 v15, v19

    move-wide/from16 v33, v1

    move-object v2, v9

    move-wide/from16 v9, v33

    goto :goto_29

    :cond_40
    move-object/from16 v8, p2

    move-object v0, v11

    .line 61
    invoke-virtual {v0}, Ll2/t;->R()V

    move/from16 v4, p3

    move-wide/from16 v9, p8

    move-object/from16 v15, p14

    move-object/from16 v16, p15

    move-object v2, v5

    move v11, v12

    move/from16 v5, p4

    move-wide/from16 v12, p11

    .line 62
    :goto_29
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    move-result-object v0

    if-eqz v0, :cond_41

    move-object v1, v0

    new-instance v0, Lh2/b6;

    move-object/from16 v14, p13

    move-object/from16 v17, p16

    move/from16 v18, p18

    move/from16 v19, p19

    move/from16 v20, p20

    move-object/from16 v32, v1

    move-object v3, v8

    move-object/from16 v1, p0

    move-wide/from16 v7, p6

    invoke-direct/range {v0 .. v20}, Lh2/b6;-><init>(Lay0/a;Lx2/s;Lh2/r8;FZLe3/n0;JJFJLay0/n;Lay0/n;Lh2/k6;Lt2/b;III)V

    move-object/from16 v1, v32

    .line 63
    iput-object v0, v1, Ll2/u1;->d:Lay0/n;

    :cond_41
    return-void
.end method

.method public static final b(Lc1/c;Lvy0/b0;Lay0/a;Lay0/k;Lx2/s;Lh2/r8;FZLe3/n0;JJFLay0/n;Lay0/n;Lt2/b;Ll2/o;I)V
    .locals 37

    move-object/from16 v1, p0

    move-object/from16 v9, p3

    move-object/from16 v10, p4

    move-object/from16 v3, p5

    move/from16 v11, p6

    move/from16 v8, p7

    .line 1
    move-object/from16 v12, p17

    check-cast v12, Ll2/t;

    const v0, -0x23aaf70

    invoke-virtual {v12, v0}, Ll2/t;->a0(I)Ll2/t;

    invoke-virtual {v12, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/16 v0, 0x20

    goto :goto_0

    :cond_0
    const/16 v0, 0x10

    :goto_0
    or-int v0, p18, v0

    move-object/from16 v7, p1

    invoke-virtual {v12, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_1

    const/16 v5, 0x100

    goto :goto_1

    :cond_1
    const/16 v5, 0x80

    :goto_1
    or-int/2addr v0, v5

    move-object/from16 v5, p2

    invoke-virtual {v12, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v14

    const/16 v16, 0x400

    if-eqz v14, :cond_2

    const/16 v14, 0x800

    goto :goto_2

    :cond_2
    move/from16 v14, v16

    :goto_2
    or-int/2addr v0, v14

    invoke-virtual {v12, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v14

    const/16 v17, 0x2000

    if-eqz v14, :cond_3

    const/16 v14, 0x4000

    goto :goto_3

    :cond_3
    move/from16 v14, v17

    :goto_3
    or-int/2addr v0, v14

    invoke-virtual {v12, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v14

    const/high16 v18, 0x10000

    const/high16 v19, 0x20000

    if-eqz v14, :cond_4

    move/from16 v14, v19

    goto :goto_4

    :cond_4
    move/from16 v14, v18

    :goto_4
    or-int/2addr v0, v14

    invoke-virtual {v12, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_5

    const/high16 v14, 0x100000

    goto :goto_5

    :cond_5
    const/high16 v14, 0x80000

    :goto_5
    or-int/2addr v0, v14

    invoke-virtual {v12, v11}, Ll2/t;->d(F)Z

    move-result v14

    if-eqz v14, :cond_6

    const/high16 v14, 0x800000

    goto :goto_6

    :cond_6
    const/high16 v14, 0x400000

    :goto_6
    or-int/2addr v0, v14

    invoke-virtual {v12, v8}, Ll2/t;->h(Z)Z

    move-result v14

    if-eqz v14, :cond_7

    const/high16 v14, 0x4000000

    goto :goto_7

    :cond_7
    const/high16 v14, 0x2000000

    :goto_7
    or-int/2addr v0, v14

    move-object/from16 v14, p8

    invoke-virtual {v12, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v21

    if-eqz v21, :cond_8

    const/high16 v21, 0x20000000

    goto :goto_8

    :cond_8
    const/high16 v21, 0x10000000

    :goto_8
    or-int v21, v0, v21

    move-wide/from16 v13, p9

    invoke-virtual {v12, v13, v14}, Ll2/t;->f(J)Z

    move-result v22

    if-eqz v22, :cond_9

    const/16 v22, 0x4

    :goto_9
    move-wide/from16 v4, p11

    goto :goto_a

    :cond_9
    const/16 v22, 0x2

    goto :goto_9

    :goto_a
    invoke-virtual {v12, v4, v5}, Ll2/t;->f(J)Z

    move-result v25

    if-eqz v25, :cond_a

    const/16 v25, 0x20

    goto :goto_b

    :cond_a
    const/16 v25, 0x10

    :goto_b
    or-int v22, v22, v25

    move/from16 v15, p13

    invoke-virtual {v12, v15}, Ll2/t;->d(F)Z

    move-result v25

    if-eqz v25, :cond_b

    const/16 v20, 0x100

    goto :goto_c

    :cond_b
    const/16 v20, 0x80

    :goto_c
    or-int v20, v22, v20

    move-object/from16 v0, p14

    invoke-virtual {v12, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v23

    if-eqz v23, :cond_c

    const/16 v16, 0x800

    :cond_c
    or-int v16, v20, v16

    move-object/from16 v2, p15

    invoke-virtual {v12, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v20

    if-eqz v20, :cond_d

    const/16 v17, 0x4000

    :cond_d
    or-int v16, v16, v17

    move-object/from16 v6, p16

    invoke-virtual {v12, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v20

    if-eqz v20, :cond_e

    move/from16 v18, v19

    :cond_e
    or-int v16, v16, v18

    const v18, 0x12492493

    and-int v0, v21, v18

    const v2, 0x12492492

    const/4 v4, 0x1

    if-ne v0, v2, :cond_10

    const v0, 0x12493

    and-int v0, v16, v0

    const v2, 0x12492

    if-eq v0, v2, :cond_f

    goto :goto_d

    :cond_f
    const/4 v0, 0x0

    goto :goto_e

    :cond_10
    :goto_d
    move v0, v4

    :goto_e
    and-int/lit8 v2, v21, 0x1

    invoke-virtual {v12, v2, v0}, Ll2/t;->O(IZ)Z

    move-result v0

    if-eqz v0, :cond_2d

    invoke-virtual {v12}, Ll2/t;->T()V

    and-int/lit8 v0, p18, 0x1

    if-eqz v0, :cond_12

    invoke-virtual {v12}, Ll2/t;->y()Z

    move-result v0

    if-eqz v0, :cond_11

    goto :goto_f

    .line 2
    :cond_11
    invoke-virtual {v12}, Ll2/t;->R()V

    :cond_12
    :goto_f
    invoke-virtual {v12}, Ll2/t;->r()V

    const v0, 0x7f120592

    .line 3
    invoke-static {v12, v0}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    move-result-object v0

    .line 4
    sget-object v2, Lx2/c;->e:Lx2/j;

    sget-object v5, Landroidx/compose/foundation/layout/b;->a:Landroidx/compose/foundation/layout/b;

    invoke-virtual {v5, v10, v2}, Landroidx/compose/foundation/layout/b;->a(Lx2/s;Lx2/e;)Lx2/s;

    move-result-object v2

    const/4 v5, 0x0

    .line 5
    invoke-static {v2, v5, v11, v4}, Landroidx/compose/foundation/layout/d;->t(Lx2/s;FFI)Lx2/s;

    move-result-object v2

    const/high16 v5, 0x3f800000    # 1.0f

    .line 6
    invoke-static {v2, v5}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    move-result-object v2

    const/high16 v19, 0x380000

    .line 7
    sget-object v5, Lx2/p;->b:Lx2/p;

    sget-object v4, Ll2/n;->a:Ll2/x0;

    const/high16 v23, 0x180000

    if-eqz v8, :cond_18

    const v6, -0x5e4bf1b7

    .line 8
    invoke-virtual {v12, v6}, Ll2/t;->Y(I)V

    and-int v6, v21, v19

    xor-int v6, v6, v23

    const/high16 v7, 0x100000

    if-le v6, v7, :cond_13

    .line 9
    invoke-virtual {v12, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_14

    :cond_13
    and-int v6, v21, v23

    if-ne v6, v7, :cond_15

    :cond_14
    const/4 v6, 0x1

    goto :goto_10

    :cond_15
    const/4 v6, 0x0

    .line 10
    :goto_10
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v7

    if-nez v6, :cond_16

    if-ne v7, v4, :cond_17

    .line 11
    :cond_16
    sget-object v6, Lg1/w1;->d:Lg1/w1;

    .line 12
    sget v6, Lh2/m8;->a:F

    .line 13
    new-instance v7, Lh2/l8;

    invoke-direct {v7, v3, v9}, Lh2/l8;-><init>(Lh2/r8;Lay0/k;)V

    .line 14
    invoke-virtual {v12, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 15
    :cond_17
    check-cast v7, Lo3/a;

    const/4 v6, 0x0

    .line 16
    invoke-static {v5, v7, v6}, Landroidx/compose/ui/input/nestedscroll/a;->a(Lx2/s;Lo3/a;Lo3/d;)Lx2/s;

    move-result-object v5

    const/4 v6, 0x0

    .line 17
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    goto :goto_11

    :cond_18
    const/4 v6, 0x0

    const v7, -0x5e4bb908

    .line 18
    invoke-virtual {v12, v7}, Ll2/t;->Y(I)V

    .line 19
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 20
    :goto_11
    invoke-interface {v2, v5}, Lx2/s;->g(Lx2/s;)Lx2/s;

    move-result-object v2

    .line 21
    iget-object v5, v3, Lh2/r8;->e:Li2/p;

    iget-object v6, v3, Lh2/r8;->e:Li2/p;

    .line 22
    sget-object v28, Lg1/w1;->d:Lg1/w1;

    and-int v7, v21, v19

    xor-int v7, v7, v23

    const/high16 v8, 0x100000

    if-le v7, v8, :cond_19

    invoke-virtual {v12, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v17

    if-nez v17, :cond_1a

    :cond_19
    and-int v10, v21, v23

    if-ne v10, v8, :cond_1b

    :cond_1a
    const/4 v8, 0x1

    goto :goto_12

    :cond_1b
    const/4 v8, 0x0

    .line 23
    :goto_12
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v10

    if-nez v8, :cond_1c

    if-ne v10, v4, :cond_1d

    .line 24
    :cond_1c
    new-instance v10, Lh2/y5;

    const/4 v8, 0x0

    invoke-direct {v10, v3, v8}, Lh2/y5;-><init>(Ljava/lang/Object;I)V

    .line 25
    invoke-virtual {v12, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 26
    :cond_1d
    check-cast v10, Lay0/n;

    invoke-static {v2, v5, v10}, Landroidx/compose/material3/internal/a;->b(Lx2/s;Li2/p;Lay0/n;)Lx2/s;

    move-result-object v26

    .line 27
    iget-object v2, v6, Li2/p;->f:Li2/o;

    if-eqz p7, :cond_1e

    .line 28
    invoke-virtual {v3}, Lh2/r8;->e()Z

    move-result v5

    if-eqz v5, :cond_1e

    const/16 v29, 0x1

    goto :goto_13

    :cond_1e
    const/16 v29, 0x0

    .line 29
    :goto_13
    iget-object v5, v6, Li2/p;->l:Ll2/j1;

    .line 30
    invoke-virtual {v5}, Ll2/j1;->getValue()Ljava/lang/Object;

    move-result-object v5

    if-eqz v5, :cond_1f

    const/16 v31, 0x1

    goto :goto_14

    :cond_1f
    const/16 v31, 0x0

    :goto_14
    const v10, 0xe000

    and-int v5, v21, v10

    const/16 v8, 0x4000

    if-ne v5, v8, :cond_20

    const/4 v5, 0x1

    goto :goto_15

    :cond_20
    const/4 v5, 0x0

    .line 31
    :goto_15
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v8

    if-nez v5, :cond_21

    if-ne v8, v4, :cond_22

    .line 32
    :cond_21
    new-instance v8, Lh2/g6;

    const/4 v5, 0x0

    invoke-direct {v8, v9, v5}, Lh2/g6;-><init>(Lay0/k;Lkotlin/coroutines/Continuation;)V

    .line 33
    invoke-virtual {v12, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 34
    :cond_22
    move-object/from16 v33, v8

    check-cast v33, Lay0/o;

    const/16 v34, 0x0

    const/16 v35, 0xa8

    const/16 v30, 0x0

    const/16 v32, 0x0

    move-object/from16 v27, v2

    .line 35
    invoke-static/range {v26 .. v35}, Lg1/f1;->a(Lx2/s;Lg1/i1;Lg1/w1;ZLi1/l;ZLg1/e1;Lay0/o;ZI)Lx2/s;

    move-result-object v2

    .line 36
    invoke-virtual {v12, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v5

    .line 37
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v8

    if-nez v5, :cond_23

    if-ne v8, v4, :cond_24

    .line 38
    :cond_23
    new-instance v8, Lac0/r;

    const/16 v5, 0x14

    invoke-direct {v8, v0, v5}, Lac0/r;-><init>(Ljava/lang/String;I)V

    .line 39
    invoke-virtual {v12, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 40
    :cond_24
    check-cast v8, Lay0/k;

    const/4 v0, 0x0

    .line 41
    invoke-static {v2, v0, v8}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    move-result-object v2

    .line 42
    iget-object v5, v6, Li2/p;->j:Ll2/f1;

    .line 43
    invoke-virtual {v5}, Ll2/f1;->o()F

    move-result v5

    float-to-int v6, v5

    if-gez v6, :cond_25

    move v6, v0

    .line 44
    :cond_25
    new-instance v5, Lk1/b0;

    invoke-direct {v5, v6}, Lk1/b0;-><init>(I)V

    .line 45
    new-instance v6, Le1/u;

    const/4 v8, 0x4

    invoke-direct {v6, v5, v8}, Le1/u;-><init>(Ljava/lang/Object;I)V

    invoke-static {v2, v6}, Lx2/a;->a(Lx2/s;Lay0/o;)Lx2/s;

    move-result-object v2

    const/high16 v8, 0x100000

    if-le v7, v8, :cond_26

    .line 46
    invoke-virtual {v12, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_27

    :cond_26
    and-int v5, v21, v23

    if-ne v5, v8, :cond_28

    :cond_27
    const/4 v6, 0x1

    goto :goto_16

    :cond_28
    move v6, v0

    :goto_16
    and-int/lit8 v5, v21, 0x70

    const/16 v7, 0x20

    if-eq v5, v7, :cond_2a

    invoke-virtual {v12, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_29

    goto :goto_17

    :cond_29
    move v5, v0

    goto :goto_18

    :cond_2a
    :goto_17
    const/4 v5, 0x1

    :goto_18
    or-int v0, v6, v5

    .line 47
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v5

    if-nez v0, :cond_2b

    if-ne v5, v4, :cond_2c

    .line 48
    :cond_2b
    new-instance v5, Let/g;

    const/16 v0, 0x13

    invoke-direct {v5, v0, v3, v1}, Let/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 49
    invoke-virtual {v12, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 50
    :cond_2c
    check-cast v5, Lay0/k;

    invoke-static {v2, v5}, Landroidx/compose/ui/graphics/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    move-result-object v0

    .line 51
    new-instance v2, Lh2/z;

    const/4 v4, 0x1

    invoke-direct {v2, v3, v4}, Lh2/z;-><init>(Lh2/r8;I)V

    invoke-static {v0, v2}, Landroidx/compose/ui/graphics/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    move-result-object v17

    .line 52
    new-instance v0, Lh2/i6;

    move-object/from16 v7, p1

    move-object/from16 v6, p2

    move/from16 v8, p7

    move-object/from16 v4, p14

    move-object/from16 v5, p16

    move-object v2, v1

    move-object/from16 v1, p15

    invoke-direct/range {v0 .. v8}, Lh2/i6;-><init>(Lay0/n;Lc1/c;Lh2/r8;Lay0/n;Lt2/b;Lay0/a;Lvy0/b0;Z)V

    const v1, 0x2b6fbd6b

    invoke-static {v1, v12, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    move-result-object v0

    shr-int/lit8 v1, v21, 0x18

    and-int/lit8 v1, v1, 0x70

    const/high16 v2, 0xc00000

    or-int/2addr v1, v2

    shl-int/lit8 v2, v16, 0x6

    and-int/lit16 v3, v2, 0x380

    or-int/2addr v1, v3

    and-int/lit16 v3, v2, 0x1c00

    or-int/2addr v1, v3

    and-int/2addr v2, v10

    or-int v23, v1, v2

    const/16 v24, 0x60

    const/16 v19, 0x0

    const/16 v20, 0x0

    move-object/from16 v21, v0

    move-object/from16 v22, v12

    move/from16 v18, v15

    move-object/from16 v12, v17

    move-wide/from16 v16, p11

    move-wide v14, v13

    move-object/from16 v13, p8

    .line 53
    invoke-static/range {v12 .. v24}, Lh2/oa;->a(Lx2/s;Le3/n0;JJFFLe1/t;Lt2/b;Ll2/o;II)V

    goto :goto_19

    :cond_2d
    move-object/from16 v22, v12

    .line 54
    invoke-virtual/range {v22 .. v22}, Ll2/t;->R()V

    .line 55
    :goto_19
    invoke-virtual/range {v22 .. v22}, Ll2/t;->s()Ll2/u1;

    move-result-object v0

    if-eqz v0, :cond_2e

    move-object v1, v0

    new-instance v0, Lh2/z5;

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    move-object/from16 v5, p4

    move-object/from16 v6, p5

    move/from16 v8, p7

    move-wide/from16 v12, p11

    move/from16 v14, p13

    move-object/from16 v15, p14

    move-object/from16 v16, p15

    move-object/from16 v17, p16

    move/from16 v18, p18

    move-object/from16 v36, v1

    move-object v4, v9

    move v7, v11

    move-object/from16 v1, p0

    move-object/from16 v9, p8

    move-wide/from16 v10, p9

    invoke-direct/range {v0 .. v18}, Lh2/z5;-><init>(Lc1/c;Lvy0/b0;Lay0/a;Lay0/k;Lx2/s;Lh2/r8;FZLe3/n0;JJFLay0/n;Lay0/n;Lt2/b;I)V

    move-object/from16 v1, v36

    .line 56
    iput-object v0, v1, Ll2/u1;->d:Lay0/n;

    :cond_2e
    return-void
.end method

.method public static final c(JLay0/a;ZZLl2/o;I)V
    .locals 17

    .line 1
    move-wide/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v3, p2

    .line 4
    .line 5
    move/from16 v4, p3

    .line 6
    .line 7
    move/from16 v5, p4

    .line 8
    .line 9
    move-object/from16 v9, p5

    .line 10
    .line 11
    check-cast v9, Ll2/t;

    .line 12
    .line 13
    const v0, -0x17578dd7

    .line 14
    .line 15
    .line 16
    invoke-virtual {v9, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v9, v1, v2}, Ll2/t;->f(J)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    const/4 v0, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v0, 0x2

    .line 28
    :goto_0
    or-int v0, p6, v0

    .line 29
    .line 30
    invoke-virtual {v9, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v6

    .line 34
    const/16 v13, 0x20

    .line 35
    .line 36
    if-eqz v6, :cond_1

    .line 37
    .line 38
    move v6, v13

    .line 39
    goto :goto_1

    .line 40
    :cond_1
    const/16 v6, 0x10

    .line 41
    .line 42
    :goto_1
    or-int/2addr v0, v6

    .line 43
    invoke-virtual {v9, v4}, Ll2/t;->h(Z)Z

    .line 44
    .line 45
    .line 46
    move-result v6

    .line 47
    if-eqz v6, :cond_2

    .line 48
    .line 49
    const/16 v6, 0x100

    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_2
    const/16 v6, 0x80

    .line 53
    .line 54
    :goto_2
    or-int/2addr v0, v6

    .line 55
    invoke-virtual {v9, v5}, Ll2/t;->h(Z)Z

    .line 56
    .line 57
    .line 58
    move-result v6

    .line 59
    if-eqz v6, :cond_3

    .line 60
    .line 61
    const/16 v6, 0x800

    .line 62
    .line 63
    goto :goto_3

    .line 64
    :cond_3
    const/16 v6, 0x400

    .line 65
    .line 66
    :goto_3
    or-int/2addr v0, v6

    .line 67
    and-int/lit16 v6, v0, 0x493

    .line 68
    .line 69
    const/16 v7, 0x492

    .line 70
    .line 71
    const/4 v14, 0x1

    .line 72
    if-eq v6, v7, :cond_4

    .line 73
    .line 74
    move v6, v14

    .line 75
    goto :goto_4

    .line 76
    :cond_4
    const/4 v6, 0x0

    .line 77
    :goto_4
    and-int/lit8 v7, v0, 0x1

    .line 78
    .line 79
    invoke-virtual {v9, v7, v6}, Ll2/t;->O(IZ)Z

    .line 80
    .line 81
    .line 82
    move-result v6

    .line 83
    if-eqz v6, :cond_11

    .line 84
    .line 85
    const-wide/16 v6, 0x10

    .line 86
    .line 87
    cmp-long v6, v1, v6

    .line 88
    .line 89
    if-eqz v6, :cond_10

    .line 90
    .line 91
    const v6, -0x55bf0636

    .line 92
    .line 93
    .line 94
    invoke-virtual {v9, v6}, Ll2/t;->Y(I)V

    .line 95
    .line 96
    .line 97
    if-eqz v4, :cond_5

    .line 98
    .line 99
    const/high16 v6, 0x3f800000    # 1.0f

    .line 100
    .line 101
    goto :goto_5

    .line 102
    :cond_5
    const/4 v6, 0x0

    .line 103
    :goto_5
    sget-object v7, Lk2/w;->f:Lk2/w;

    .line 104
    .line 105
    invoke-static {v7, v9}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    .line 106
    .line 107
    .line 108
    move-result-object v7

    .line 109
    const/4 v10, 0x0

    .line 110
    const/16 v11, 0x1c

    .line 111
    .line 112
    const/4 v8, 0x0

    .line 113
    invoke-static/range {v6 .. v11}, Lc1/e;->b(FLc1/a0;Ljava/lang/String;Ll2/o;II)Ll2/t2;

    .line 114
    .line 115
    .line 116
    move-result-object v6

    .line 117
    const v7, 0x7f120149

    .line 118
    .line 119
    .line 120
    invoke-static {v9, v7}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object v7

    .line 124
    sget-object v8, Lx2/p;->b:Lx2/p;

    .line 125
    .line 126
    sget-object v10, Ll2/n;->a:Ll2/x0;

    .line 127
    .line 128
    if-eqz v5, :cond_c

    .line 129
    .line 130
    const v11, -0x55ba773b

    .line 131
    .line 132
    .line 133
    invoke-virtual {v9, v11}, Ll2/t;->Y(I)V

    .line 134
    .line 135
    .line 136
    and-int/lit8 v11, v0, 0x70

    .line 137
    .line 138
    if-ne v11, v13, :cond_6

    .line 139
    .line 140
    move/from16 v16, v14

    .line 141
    .line 142
    goto :goto_6

    .line 143
    :cond_6
    const/16 v16, 0x0

    .line 144
    .line 145
    :goto_6
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v12

    .line 149
    if-nez v16, :cond_7

    .line 150
    .line 151
    if-ne v12, v10, :cond_8

    .line 152
    .line 153
    :cond_7
    new-instance v12, Lcz/r;

    .line 154
    .line 155
    const/4 v15, 0x2

    .line 156
    invoke-direct {v12, v3, v15}, Lcz/r;-><init>(Lay0/a;I)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {v9, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 160
    .line 161
    .line 162
    :cond_8
    check-cast v12, Landroidx/compose/ui/input/pointer/PointerInputEventHandler;

    .line 163
    .line 164
    invoke-static {v8, v3, v12}, Lp3/f0;->b(Lx2/s;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)Lx2/s;

    .line 165
    .line 166
    .line 167
    move-result-object v8

    .line 168
    invoke-virtual {v9, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 169
    .line 170
    .line 171
    move-result v12

    .line 172
    if-ne v11, v13, :cond_9

    .line 173
    .line 174
    move v11, v14

    .line 175
    goto :goto_7

    .line 176
    :cond_9
    const/4 v11, 0x0

    .line 177
    :goto_7
    or-int/2addr v11, v12

    .line 178
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object v12

    .line 182
    if-nez v11, :cond_a

    .line 183
    .line 184
    if-ne v12, v10, :cond_b

    .line 185
    .line 186
    :cond_a
    new-instance v12, Let/g;

    .line 187
    .line 188
    invoke-direct {v12, v7, v3}, Let/g;-><init>(Ljava/lang/String;Lay0/a;)V

    .line 189
    .line 190
    .line 191
    invoke-virtual {v9, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 192
    .line 193
    .line 194
    :cond_b
    check-cast v12, Lay0/k;

    .line 195
    .line 196
    invoke-static {v8, v14, v12}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 197
    .line 198
    .line 199
    move-result-object v8

    .line 200
    const/4 v7, 0x0

    .line 201
    invoke-virtual {v9, v7}, Ll2/t;->q(Z)V

    .line 202
    .line 203
    .line 204
    goto :goto_8

    .line 205
    :cond_c
    const/4 v7, 0x0

    .line 206
    const v11, -0x55b3f66f

    .line 207
    .line 208
    .line 209
    invoke-virtual {v9, v11}, Ll2/t;->Y(I)V

    .line 210
    .line 211
    .line 212
    invoke-virtual {v9, v7}, Ll2/t;->q(Z)V

    .line 213
    .line 214
    .line 215
    :goto_8
    sget-object v7, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 216
    .line 217
    invoke-interface {v7, v8}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 218
    .line 219
    .line 220
    move-result-object v7

    .line 221
    and-int/lit8 v0, v0, 0xe

    .line 222
    .line 223
    const/4 v8, 0x4

    .line 224
    if-ne v0, v8, :cond_d

    .line 225
    .line 226
    goto :goto_9

    .line 227
    :cond_d
    const/4 v14, 0x0

    .line 228
    :goto_9
    invoke-virtual {v9, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 229
    .line 230
    .line 231
    move-result v0

    .line 232
    or-int/2addr v0, v14

    .line 233
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    move-result-object v8

    .line 237
    if-nez v0, :cond_e

    .line 238
    .line 239
    if-ne v8, v10, :cond_f

    .line 240
    .line 241
    :cond_e
    new-instance v8, Lh2/d6;

    .line 242
    .line 243
    invoke-direct {v8, v1, v2, v6}, Lh2/d6;-><init>(JLl2/t2;)V

    .line 244
    .line 245
    .line 246
    invoke-virtual {v9, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 247
    .line 248
    .line 249
    :cond_f
    check-cast v8, Lay0/k;

    .line 250
    .line 251
    const/4 v0, 0x0

    .line 252
    invoke-static {v7, v8, v9, v0}, Lkp/i;->a(Lx2/s;Lay0/k;Ll2/o;I)V

    .line 253
    .line 254
    .line 255
    invoke-virtual {v9, v0}, Ll2/t;->q(Z)V

    .line 256
    .line 257
    .line 258
    goto :goto_a

    .line 259
    :cond_10
    const/4 v0, 0x0

    .line 260
    const v6, -0x55b13247

    .line 261
    .line 262
    .line 263
    invoke-virtual {v9, v6}, Ll2/t;->Y(I)V

    .line 264
    .line 265
    .line 266
    invoke-virtual {v9, v0}, Ll2/t;->q(Z)V

    .line 267
    .line 268
    .line 269
    goto :goto_a

    .line 270
    :cond_11
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 271
    .line 272
    .line 273
    :goto_a
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 274
    .line 275
    .line 276
    move-result-object v7

    .line 277
    if-eqz v7, :cond_12

    .line 278
    .line 279
    new-instance v0, Lh2/x5;

    .line 280
    .line 281
    move/from16 v6, p6

    .line 282
    .line 283
    invoke-direct/range {v0 .. v6}, Lh2/x5;-><init>(JLay0/a;ZZI)V

    .line 284
    .line 285
    .line 286
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 287
    .line 288
    :cond_12
    return-void
.end method

.method public static final d(Le3/k0;F)F
    .locals 4

    .line 1
    iget-wide v0, p0, Le3/k0;->t:J

    .line 2
    .line 3
    const/16 v2, 0x20

    .line 4
    .line 5
    shr-long/2addr v0, v2

    .line 6
    long-to-int v0, v0

    .line 7
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    const/high16 v2, 0x3f800000    # 1.0f

    .line 16
    .line 17
    if-nez v1, :cond_1

    .line 18
    .line 19
    const/4 v1, 0x0

    .line 20
    cmpg-float v3, v0, v1

    .line 21
    .line 22
    if-nez v3, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    invoke-virtual {p0}, Le3/k0;->a()F

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    sget v3, Lh2/j6;->a:F

    .line 30
    .line 31
    mul-float/2addr p0, v3

    .line 32
    invoke-static {p0, v0}, Ljava/lang/Math;->min(FF)F

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    invoke-static {v1, p0, p1}, Llp/wa;->b(FFF)F

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    div-float/2addr p0, v0

    .line 41
    sub-float/2addr v2, p0

    .line 42
    :cond_1
    :goto_0
    return v2
.end method

.method public static final e(Le3/k0;F)F
    .locals 4

    .line 1
    iget-wide v0, p0, Le3/k0;->t:J

    .line 2
    .line 3
    const-wide v2, 0xffffffffL

    .line 4
    .line 5
    .line 6
    .line 7
    .line 8
    and-long/2addr v0, v2

    .line 9
    long-to-int v0, v0

    .line 10
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    const/high16 v2, 0x3f800000    # 1.0f

    .line 19
    .line 20
    if-nez v1, :cond_1

    .line 21
    .line 22
    const/4 v1, 0x0

    .line 23
    cmpg-float v3, v0, v1

    .line 24
    .line 25
    if-nez v3, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    invoke-virtual {p0}, Le3/k0;->a()F

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    sget v3, Lh2/j6;->b:F

    .line 33
    .line 34
    mul-float/2addr p0, v3

    .line 35
    invoke-static {p0, v0}, Ljava/lang/Math;->min(FF)F

    .line 36
    .line 37
    .line 38
    move-result p0

    .line 39
    invoke-static {v1, p0, p1}, Llp/wa;->b(FFF)F

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    div-float/2addr p0, v0

    .line 44
    sub-float/2addr v2, p0

    .line 45
    :cond_1
    :goto_0
    return v2
.end method

.method public static final f(IILl2/o;Z)Lh2/r8;
    .locals 6

    .line 1
    and-int/lit8 p1, p1, 0x1

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    const/4 p3, 0x0

    .line 6
    :cond_0
    move v0, p3

    .line 7
    move-object p1, p2

    .line 8
    check-cast p1, Ll2/t;

    .line 9
    .line 10
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p3

    .line 14
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 15
    .line 16
    if-ne p3, v1, :cond_1

    .line 17
    .line 18
    new-instance p3, Lh10/d;

    .line 19
    .line 20
    const/16 v1, 0xd

    .line 21
    .line 22
    invoke-direct {p3, v1}, Lh10/d;-><init>(I)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p1, p3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    :cond_1
    move-object v1, p3

    .line 29
    check-cast v1, Lay0/k;

    .line 30
    .line 31
    sget-object v2, Lh2/s8;->d:Lh2/s8;

    .line 32
    .line 33
    and-int/lit8 p0, p0, 0xe

    .line 34
    .line 35
    or-int/lit16 v4, p0, 0x180

    .line 36
    .line 37
    const/16 v5, 0x38

    .line 38
    .line 39
    move-object v3, p2

    .line 40
    invoke-static/range {v0 .. v5}, Lh2/m8;->b(ZLay0/k;Lh2/s8;Ll2/o;II)Lh2/r8;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0
.end method
