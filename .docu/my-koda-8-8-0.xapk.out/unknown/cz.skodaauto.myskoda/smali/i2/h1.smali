.class public abstract Li2/h1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F

.field public static final c:F

.field public static final d:F

.field public static final e:F

.field public static final f:F


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const/16 v0, 0x10

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Li2/h1;->a:F

    .line 5
    .line 6
    const/4 v1, 0x4

    .line 7
    int-to-float v1, v1

    .line 8
    sput v1, Li2/h1;->b:F

    .line 9
    .line 10
    const/4 v1, 0x2

    .line 11
    int-to-float v1, v1

    .line 12
    sput v1, Li2/h1;->c:F

    .line 13
    .line 14
    const/16 v1, 0x18

    .line 15
    .line 16
    int-to-float v1, v1

    .line 17
    sput v1, Li2/h1;->d:F

    .line 18
    .line 19
    sput v0, Li2/h1;->e:F

    .line 20
    .line 21
    sput v0, Li2/h1;->f:F

    .line 22
    .line 23
    return-void
.end method

.method public static final a(Li2/i1;Ljava/lang/CharSequence;Lay0/n;Lh2/nb;Lay0/o;Lay0/n;Lay0/n;ZZZLi1/l;Lk1/z0;Lh2/eb;Lay0/n;Ll2/o;II)V
    .locals 44

    move-object/from16 v8, p3

    move-object/from16 v5, p4

    move-object/from16 v6, p5

    move-object/from16 v7, p6

    move/from16 v0, p8

    move/from16 v1, p9

    move-object/from16 v2, p10

    move-object/from16 v3, p11

    move-object/from16 v4, p12

    move-object/from16 v9, p13

    move/from16 v10, p15

    move/from16 v11, p16

    .line 1
    sget-object v12, Ll2/x0;->i:Ll2/x0;

    sget-object v13, Lb1/c;->l:Lb1/c;

    move-object/from16 v14, p14

    check-cast v14, Ll2/t;

    const v15, 0x20979528

    invoke-virtual {v14, v15}, Ll2/t;->a0(I)Ll2/t;

    and-int/lit8 v15, v10, 0x6

    const/16 v16, 0x4

    move-object/from16 v21, v12

    if-nez v15, :cond_1

    invoke-virtual/range {p0 .. p0}, Ljava/lang/Enum;->ordinal()I

    move-result v15

    invoke-virtual {v14, v15}, Ll2/t;->e(I)Z

    move-result v15

    if-eqz v15, :cond_0

    move/from16 v15, v16

    goto :goto_0

    :cond_0
    const/4 v15, 0x2

    :goto_0
    or-int/2addr v15, v10

    goto :goto_1

    :cond_1
    move v15, v10

    :goto_1
    and-int/lit8 v17, v10, 0x30

    const/16 v18, 0x10

    const/16 v19, 0x20

    move-object/from16 v12, p1

    if-nez v17, :cond_3

    invoke-virtual {v14, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v17

    if-eqz v17, :cond_2

    move/from16 v17, v19

    goto :goto_2

    :cond_2
    move/from16 v17, v18

    :goto_2
    or-int v15, v15, v17

    :cond_3
    and-int/lit16 v12, v10, 0x180

    const/16 v17, 0x80

    const/16 v20, 0x100

    if-nez v12, :cond_5

    move-object/from16 v12, p2

    invoke-virtual {v14, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v22

    if-eqz v22, :cond_4

    move/from16 v22, v20

    goto :goto_3

    :cond_4
    move/from16 v22, v17

    :goto_3
    or-int v15, v15, v22

    goto :goto_4

    :cond_5
    move-object/from16 v12, p2

    :goto_4
    and-int/lit16 v12, v10, 0xc00

    const/16 v22, 0x400

    move/from16 v23, v12

    if-nez v23, :cond_7

    invoke-virtual {v14, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v23

    if-eqz v23, :cond_6

    const/16 v23, 0x800

    goto :goto_5

    :cond_6
    move/from16 v23, v22

    :goto_5
    or-int v15, v15, v23

    :cond_7
    and-int/lit16 v12, v10, 0x6000

    const/16 v24, 0x2000

    const/16 v25, 0x4000

    if-nez v12, :cond_9

    invoke-virtual {v14, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_8

    move/from16 v12, v25

    goto :goto_6

    :cond_8
    move/from16 v12, v24

    :goto_6
    or-int/2addr v15, v12

    :cond_9
    const/high16 v12, 0x30000

    and-int v26, v10, v12

    const/high16 v27, 0x10000

    const/high16 v28, 0x20000

    if-nez v26, :cond_b

    invoke-virtual {v14, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v26

    if-eqz v26, :cond_a

    move/from16 v26, v28

    goto :goto_7

    :cond_a
    move/from16 v26, v27

    :goto_7
    or-int v15, v15, v26

    :cond_b
    const/high16 v26, 0x180000

    and-int v29, v10, v26

    const/high16 v30, 0x80000

    const/high16 v31, 0x100000

    move/from16 v32, v12

    const/4 v12, 0x0

    if-nez v29, :cond_d

    invoke-virtual {v14, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v29

    if-eqz v29, :cond_c

    move/from16 v29, v31

    goto :goto_8

    :cond_c
    move/from16 v29, v30

    :goto_8
    or-int v15, v15, v29

    :cond_d
    const/high16 v29, 0xc00000

    and-int v33, v10, v29

    const/high16 v34, 0x400000

    const/high16 v35, 0x800000

    if-nez v33, :cond_f

    invoke-virtual {v14, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v33

    if-eqz v33, :cond_e

    move/from16 v33, v35

    goto :goto_9

    :cond_e
    move/from16 v33, v34

    :goto_9
    or-int v15, v15, v33

    :cond_f
    const/high16 v33, 0x6000000

    and-int v33, v10, v33

    if-nez v33, :cond_11

    invoke-virtual {v14, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v33

    if-eqz v33, :cond_10

    const/high16 v33, 0x4000000

    goto :goto_a

    :cond_10
    const/high16 v33, 0x2000000

    :goto_a
    or-int v15, v15, v33

    :cond_11
    const/high16 v33, 0x30000000

    and-int v33, v10, v33

    if-nez v33, :cond_13

    invoke-virtual {v14, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_12

    const/high16 v12, 0x20000000

    goto :goto_b

    :cond_12
    const/high16 v12, 0x10000000

    :goto_b
    or-int/2addr v15, v12

    :cond_13
    move v12, v15

    and-int/lit8 v15, v11, 0x6

    if-nez v15, :cond_15

    invoke-virtual {v14, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v15

    if-eqz v15, :cond_14

    goto :goto_c

    :cond_14
    const/16 v16, 0x2

    :goto_c
    or-int v15, v11, v16

    goto :goto_d

    :cond_15
    move v15, v11

    :goto_d
    and-int/lit8 v16, v11, 0x30

    move/from16 v6, p7

    if-nez v16, :cond_17

    invoke-virtual {v14, v6}, Ll2/t;->h(Z)Z

    move-result v16

    if-eqz v16, :cond_16

    move/from16 v18, v19

    :cond_16
    or-int v15, v15, v18

    :cond_17
    and-int/lit16 v5, v11, 0x180

    if-nez v5, :cond_19

    invoke-virtual {v14, v0}, Ll2/t;->h(Z)Z

    move-result v5

    if-eqz v5, :cond_18

    move/from16 v17, v20

    :cond_18
    or-int v15, v15, v17

    :cond_19
    and-int/lit16 v5, v11, 0xc00

    if-nez v5, :cond_1b

    invoke-virtual {v14, v1}, Ll2/t;->h(Z)Z

    move-result v5

    if-eqz v5, :cond_1a

    const/16 v22, 0x800

    :cond_1a
    or-int v15, v15, v22

    :cond_1b
    and-int/lit16 v5, v11, 0x6000

    if-nez v5, :cond_1d

    invoke-virtual {v14, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_1c

    move/from16 v24, v25

    :cond_1c
    or-int v15, v15, v24

    :cond_1d
    and-int v5, v11, v32

    if-nez v5, :cond_1f

    invoke-virtual {v14, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_1e

    move/from16 v27, v28

    :cond_1e
    or-int v15, v15, v27

    :cond_1f
    and-int v5, v11, v26

    if-nez v5, :cond_21

    invoke-virtual {v14, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_20

    move/from16 v30, v31

    :cond_20
    or-int v15, v15, v30

    :cond_21
    and-int v5, v11, v29

    if-nez v5, :cond_23

    invoke-virtual {v14, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_22

    move/from16 v34, v35

    :cond_22
    or-int v15, v15, v34

    :cond_23
    move/from16 v22, v15

    const v5, 0x12492493

    and-int/2addr v5, v12

    const v15, 0x12492492

    if-ne v5, v15, :cond_25

    const v5, 0x492493

    and-int v5, v22, v5

    const v15, 0x492492

    if-eq v5, v15, :cond_24

    goto :goto_e

    :cond_24
    const/4 v5, 0x0

    goto :goto_f

    :cond_25
    :goto_e
    const/4 v5, 0x1

    :goto_f
    and-int/lit8 v15, v12, 0x1

    invoke-virtual {v14, v15, v5}, Ll2/t;->O(IZ)Z

    move-result v5

    if-eqz v5, :cond_62

    shr-int/lit8 v5, v22, 0xc

    and-int/lit8 v5, v5, 0xe

    .line 2
    invoke-static {v2, v14, v5}, Llp/n1;->b(Li1/l;Ll2/o;I)Ll2/b1;

    move-result-object v5

    invoke-interface {v5}, Ll2/t2;->getValue()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/Boolean;

    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v25

    if-eqz v25, :cond_26

    .line 3
    sget-object v5, Li2/m0;->d:Li2/m0;

    goto :goto_10

    .line 4
    :cond_26
    invoke-interface/range {p1 .. p1}, Ljava/lang/CharSequence;->length()I

    move-result v5

    if-nez v5, :cond_27

    sget-object v5, Li2/m0;->e:Li2/m0;

    goto :goto_10

    .line 5
    :cond_27
    sget-object v5, Li2/m0;->f:Li2/m0;

    :goto_10
    if-nez v0, :cond_28

    .line 6
    iget-wide v6, v4, Lh2/eb;->z:J

    goto :goto_11

    :cond_28
    if-eqz v1, :cond_29

    .line 7
    iget-wide v6, v4, Lh2/eb;->A:J

    goto :goto_11

    :cond_29
    if-eqz v25, :cond_2a

    .line 8
    iget-wide v6, v4, Lh2/eb;->x:J

    goto :goto_11

    .line 9
    :cond_2a
    iget-wide v6, v4, Lh2/eb;->y:J

    .line 10
    :goto_11
    sget-object v15, Lh2/ec;->a:Ll2/u2;

    .line 11
    invoke-virtual {v14, v15}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v15

    .line 12
    check-cast v15, Lh2/dc;

    .line 13
    iget-object v10, v15, Lh2/dc;->j:Lg4/p0;

    .line 14
    iget-object v15, v15, Lh2/dc;->l:Lg4/p0;

    .line 15
    invoke-virtual {v10}, Lg4/p0;->b()J

    move-result-wide v0

    .line 16
    sget-wide v2, Le3/s;->i:J

    .line 17
    invoke-static {v0, v1, v2, v3}, Le3/s;->c(JJ)Z

    move-result v0

    if-eqz v0, :cond_2b

    invoke-virtual {v15}, Lg4/p0;->b()J

    move-result-wide v0

    invoke-static {v0, v1, v2, v3}, Le3/s;->c(JJ)Z

    move-result v0

    if-eqz v0, :cond_2c

    .line 18
    :cond_2b
    invoke-virtual {v10}, Lg4/p0;->b()J

    move-result-wide v0

    invoke-static {v0, v1, v2, v3}, Le3/s;->c(JJ)Z

    move-result v0

    if-nez v0, :cond_2d

    invoke-virtual {v15}, Lg4/p0;->b()J

    move-result-wide v0

    invoke-static {v0, v1, v2, v3}, Le3/s;->c(JJ)Z

    move-result v0

    if-eqz v0, :cond_2d

    :cond_2c
    const/4 v0, 0x1

    goto :goto_12

    :cond_2d
    const/4 v0, 0x0

    .line 19
    :goto_12
    invoke-virtual {v15}, Lg4/p0;->b()J

    move-result-wide v1

    const-wide/16 v16, 0x10

    if-eqz v0, :cond_2f

    cmp-long v3, v1, v16

    if-eqz v3, :cond_2e

    goto :goto_13

    :cond_2e
    move-wide v1, v6

    .line 20
    :cond_2f
    :goto_13
    invoke-virtual {v10}, Lg4/p0;->b()J

    move-result-wide v18

    if-eqz v0, :cond_31

    cmp-long v3, v18, v16

    if-eqz v3, :cond_30

    goto :goto_14

    :cond_30
    move-wide/from16 v27, v6

    goto :goto_15

    :cond_31
    :goto_14
    move-wide/from16 v27, v18

    :goto_15
    if-eqz p4, :cond_32

    const/4 v3, 0x1

    :goto_16
    move/from16 v29, v0

    goto :goto_17

    :cond_32
    const/4 v3, 0x0

    goto :goto_16

    .line 21
    :goto_17
    const-string v0, "TextFieldInputState"

    const/16 v8, 0x30

    move-wide/from16 v30, v1

    const/4 v1, 0x0

    invoke-static {v5, v0, v14, v8, v1}, Lc1/z1;->f(Ljava/lang/Object;Ljava/lang/String;Ll2/o;II)Lc1/w1;

    move-result-object v0

    iget-object v1, v0, Lc1/w1;->a:Lap0/o;

    iget-object v2, v0, Lc1/w1;->d:Ll2/j1;

    .line 22
    sget-object v5, Lk2/w;->e:Lk2/w;

    invoke-static {v5, v14}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    move-result-object v17

    .line 23
    sget-object v18, Lc1/d;->j:Lc1/b2;

    .line 24
    invoke-virtual {v1}, Lap0/o;->D()Ljava/lang/Object;

    move-result-object v5

    .line 25
    check-cast v5, Li2/m0;

    move/from16 v32, v8

    const v8, -0x559dce72

    invoke-virtual {v14, v8}, Ll2/t;->Y(I)V

    .line 26
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    move-result v5

    const/16 v33, 0x0

    const/high16 v34, 0x3f800000    # 1.0f

    if-eqz v5, :cond_33

    const/4 v8, 0x1

    if-eq v5, v8, :cond_35

    const/4 v8, 0x2

    if-ne v5, v8, :cond_34

    :cond_33
    move/from16 v5, v34

    :goto_18
    const/4 v8, 0x0

    goto :goto_19

    :cond_34
    new-instance v0, La8/r0;

    .line 27
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 28
    throw v0

    :cond_35
    if-eqz v3, :cond_33

    move/from16 v5, v33

    goto :goto_18

    .line 29
    :goto_19
    invoke-virtual {v14, v8}, Ll2/t;->q(Z)V

    .line 30
    invoke-static {v5}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v5

    .line 31
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    move-result-object v8

    .line 32
    check-cast v8, Li2/m0;

    move-object/from16 v19, v0

    const v0, -0x559dce72

    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 33
    invoke-virtual {v8}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    if-eqz v0, :cond_36

    const/4 v8, 0x1

    if-eq v0, v8, :cond_38

    const/4 v8, 0x2

    if-ne v0, v8, :cond_37

    :cond_36
    move/from16 v0, v34

    :goto_1a
    const/4 v8, 0x0

    goto :goto_1b

    :cond_37
    new-instance v0, La8/r0;

    .line 34
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 35
    throw v0

    :cond_38
    if-eqz v3, :cond_36

    move/from16 v0, v33

    goto :goto_1a

    .line 36
    :goto_1b
    invoke-virtual {v14, v8}, Ll2/t;->q(Z)V

    .line 37
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v16

    .line 38
    invoke-virtual/range {v19 .. v19}, Lc1/w1;->f()Lc1/r1;

    const v0, -0x2a50698e

    .line 39
    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 40
    invoke-virtual {v14, v8}, Ll2/t;->q(Z)V

    const/high16 v20, 0x30000

    move-object/from16 v0, v19

    move-object/from16 v19, v14

    move-object v14, v0

    move-object v0, v15

    move-object v15, v5

    .line 41
    invoke-static/range {v14 .. v20}, Lc1/z1;->c(Lc1/w1;Ljava/lang/Object;Ljava/lang/Object;Lc1/a0;Lc1/b2;Ll2/o;I)Lc1/t1;

    move-result-object v39

    move-object/from16 v43, v19

    move-object/from16 v19, v14

    move-object/from16 v14, v43

    .line 42
    sget-object v5, Lk2/w;->g:Lk2/w;

    invoke-static {v5, v14}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    move-result-object v8

    .line 43
    sget-object v15, Lk2/w;->h:Lk2/w;

    invoke-static {v15, v14}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    move-result-object v15

    .line 44
    invoke-virtual {v1}, Lap0/o;->D()Ljava/lang/Object;

    move-result-object v16

    .line 45
    check-cast v16, Li2/m0;

    move-object/from16 v35, v0

    const v0, -0x4128d333

    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 46
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    if-eqz v0, :cond_3c

    move-object/from16 v36, v1

    const/4 v1, 0x1

    if-eq v0, v1, :cond_3a

    const/4 v1, 0x2

    if-ne v0, v1, :cond_39

    :goto_1c
    move/from16 v0, v33

    :goto_1d
    const/4 v1, 0x0

    goto :goto_1f

    :cond_39
    new-instance v0, La8/r0;

    .line 47
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 48
    throw v0

    :cond_3a
    if-eqz v3, :cond_3b

    goto :goto_1c

    :cond_3b
    :goto_1e
    move/from16 v0, v34

    goto :goto_1d

    :cond_3c
    move-object/from16 v36, v1

    goto :goto_1e

    .line 49
    :goto_1f
    invoke-virtual {v14, v1}, Ll2/t;->q(Z)V

    .line 50
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v0

    .line 51
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    move-result-object v1

    .line 52
    check-cast v1, Li2/m0;

    move-object/from16 v16, v0

    const v0, -0x4128d333

    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 53
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    if-eqz v0, :cond_3f

    const/4 v1, 0x1

    if-eq v0, v1, :cond_3e

    const/4 v1, 0x2

    if-ne v0, v1, :cond_3d

    :goto_20
    move/from16 v0, v33

    :goto_21
    const/4 v1, 0x0

    goto :goto_22

    :cond_3d
    new-instance v0, La8/r0;

    .line 54
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 55
    throw v0

    :cond_3e
    if-eqz v3, :cond_3f

    goto :goto_20

    :cond_3f
    move/from16 v0, v34

    goto :goto_21

    .line 56
    :goto_22
    invoke-virtual {v14, v1}, Ll2/t;->q(Z)V

    .line 57
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v0

    .line 58
    invoke-virtual/range {v19 .. v19}, Lc1/w1;->f()Lc1/r1;

    move-result-object v1

    move-object/from16 v17, v0

    const v0, -0x3aa6c997

    .line 59
    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 60
    sget-object v0, Li2/m0;->d:Li2/m0;

    move-object/from16 v37, v2

    sget-object v2, Li2/m0;->e:Li2/m0;

    invoke-interface {v1, v0, v2}, Lc1/r1;->c(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v38

    if-eqz v38, :cond_42

    :cond_40
    move-object v15, v8

    :cond_41
    :goto_23
    const/4 v1, 0x0

    goto :goto_24

    .line 61
    :cond_42
    invoke-interface {v1, v2, v0}, Lc1/r1;->c(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_41

    .line 62
    sget-object v0, Li2/m0;->f:Li2/m0;

    invoke-interface {v1, v0, v2}, Lc1/r1;->c(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_40

    goto :goto_23

    .line 63
    :goto_24
    invoke-virtual {v14, v1}, Ll2/t;->q(Z)V

    move-object/from16 v43, v19

    move-object/from16 v19, v14

    move-object/from16 v14, v43

    move-object/from16 v43, v17

    move-object/from16 v17, v15

    move-object/from16 v15, v16

    move-object/from16 v16, v43

    .line 64
    invoke-static/range {v14 .. v20}, Lc1/z1;->c(Lc1/w1;Ljava/lang/Object;Ljava/lang/Object;Lc1/a0;Lc1/b2;Ll2/o;I)Lc1/t1;

    move-result-object v1

    move-object/from16 v43, v19

    move-object/from16 v19, v14

    move-object/from16 v14, v43

    .line 65
    invoke-virtual/range {v36 .. v36}, Lap0/o;->D()Ljava/lang/Object;

    move-result-object v0

    .line 66
    check-cast v0, Li2/m0;

    const v2, -0x4b028119

    invoke-virtual {v14, v2}, Ll2/t;->Y(I)V

    .line 67
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    if-eqz v0, :cond_43

    const/4 v15, 0x1

    if-eq v0, v15, :cond_45

    const/4 v15, 0x2

    if-ne v0, v15, :cond_44

    :cond_43
    move/from16 v0, v34

    :goto_25
    const/4 v15, 0x0

    goto :goto_26

    :cond_44
    new-instance v0, La8/r0;

    .line 68
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 69
    throw v0

    :cond_45
    if-eqz v3, :cond_43

    move/from16 v0, v33

    goto :goto_25

    .line 70
    :goto_26
    invoke-virtual {v14, v15}, Ll2/t;->q(Z)V

    .line 71
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v15

    .line 72
    invoke-virtual/range {v37 .. v37}, Ll2/j1;->getValue()Ljava/lang/Object;

    move-result-object v0

    .line 73
    check-cast v0, Li2/m0;

    invoke-virtual {v14, v2}, Ll2/t;->Y(I)V

    .line 74
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    if-eqz v0, :cond_46

    const/4 v2, 0x1

    if-eq v0, v2, :cond_48

    const/4 v2, 0x2

    if-ne v0, v2, :cond_47

    :cond_46
    move/from16 v33, v34

    :goto_27
    const/4 v0, 0x0

    goto :goto_28

    :cond_47
    new-instance v0, La8/r0;

    .line 75
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 76
    throw v0

    :cond_48
    if-eqz v3, :cond_46

    goto :goto_27

    .line 77
    :goto_28
    invoke-virtual {v14, v0}, Ll2/t;->q(Z)V

    .line 78
    invoke-static/range {v33 .. v33}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v16

    .line 79
    invoke-virtual/range {v19 .. v19}, Lc1/w1;->f()Lc1/r1;

    const v2, 0x7ebca8cb

    .line 80
    invoke-virtual {v14, v2}, Ll2/t;->Y(I)V

    .line 81
    invoke-virtual {v14, v0}, Ll2/t;->q(Z)V

    move-object/from16 v17, v19

    move-object/from16 v19, v14

    move-object/from16 v14, v17

    move-object/from16 v17, v8

    .line 82
    invoke-static/range {v14 .. v20}, Lc1/z1;->c(Lc1/w1;Ljava/lang/Object;Ljava/lang/Object;Lc1/a0;Lc1/b2;Ll2/o;I)Lc1/t1;

    move-result-object v8

    move-object/from16 v43, v19

    move-object/from16 v19, v14

    move-object/from16 v14, v43

    .line 83
    invoke-static {v5, v14}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    move-result-object v17

    .line 84
    invoke-virtual/range {v37 .. v37}, Ll2/j1;->getValue()Ljava/lang/Object;

    move-result-object v0

    .line 85
    check-cast v0, Li2/m0;

    const v2, -0xc5f552

    invoke-virtual {v14, v2}, Ll2/t;->Y(I)V

    .line 86
    sget-object v3, Li2/f1;->a:[I

    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    aget v0, v3, v0

    const/4 v15, 0x1

    if-ne v0, v15, :cond_49

    move-wide/from16 v15, v30

    :goto_29
    const/4 v0, 0x0

    goto :goto_2a

    :cond_49
    move-wide/from16 v15, v27

    goto :goto_29

    .line 87
    :goto_2a
    invoke-virtual {v14, v0}, Ll2/t;->q(Z)V

    .line 88
    invoke-static/range {v15 .. v16}, Le3/s;->f(J)Lf3/c;

    move-result-object v0

    .line 89
    invoke-virtual {v14, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v5

    .line 90
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v15

    .line 91
    sget-object v2, Ll2/n;->a:Ll2/x0;

    if-nez v5, :cond_4a

    if-ne v15, v2, :cond_4b

    .line 92
    :cond_4a
    new-instance v5, La3/f;

    const/4 v15, 0x7

    invoke-direct {v5, v0, v15}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 93
    new-instance v15, Lc1/b2;

    invoke-direct {v15, v13, v5}, Lc1/b2;-><init>(Lay0/k;Lay0/k;)V

    .line 94
    invoke-virtual {v14, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 95
    :cond_4b
    move-object/from16 v18, v15

    check-cast v18, Lc1/b2;

    .line 96
    invoke-virtual/range {v36 .. v36}, Lap0/o;->D()Ljava/lang/Object;

    move-result-object v0

    .line 97
    check-cast v0, Li2/m0;

    const v5, -0xc5f552

    invoke-virtual {v14, v5}, Ll2/t;->Y(I)V

    .line 98
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    aget v0, v3, v0

    const/4 v15, 0x1

    if-ne v0, v15, :cond_4c

    move-wide/from16 v33, v6

    move-wide/from16 v5, v30

    :goto_2b
    const/4 v0, 0x0

    goto :goto_2c

    :cond_4c
    move-wide/from16 v33, v6

    move-wide/from16 v5, v27

    goto :goto_2b

    .line 99
    :goto_2c
    invoke-virtual {v14, v0}, Ll2/t;->q(Z)V

    .line 100
    new-instance v7, Le3/s;

    invoke-direct {v7, v5, v6}, Le3/s;-><init>(J)V

    .line 101
    invoke-virtual/range {v37 .. v37}, Ll2/j1;->getValue()Ljava/lang/Object;

    move-result-object v5

    .line 102
    check-cast v5, Li2/m0;

    const v6, -0xc5f552

    invoke-virtual {v14, v6}, Ll2/t;->Y(I)V

    .line 103
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    move-result v5

    aget v3, v3, v5

    if-ne v3, v15, :cond_4d

    move-wide/from16 v5, v30

    goto :goto_2d

    :cond_4d
    move-wide/from16 v5, v27

    .line 104
    :goto_2d
    invoke-virtual {v14, v0}, Ll2/t;->q(Z)V

    .line 105
    new-instance v3, Le3/s;

    invoke-direct {v3, v5, v6}, Le3/s;-><init>(J)V

    .line 106
    invoke-virtual/range {v19 .. v19}, Lc1/w1;->f()Lc1/r1;

    const v5, 0x747961b9

    .line 107
    invoke-virtual {v14, v5}, Ll2/t;->Y(I)V

    .line 108
    invoke-virtual {v14, v0}, Ll2/t;->q(Z)V

    move-object/from16 v15, v19

    move-object/from16 v19, v14

    move-object v14, v15

    move-object/from16 v16, v3

    move-object v15, v7

    .line 109
    invoke-static/range {v14 .. v20}, Lc1/z1;->c(Lc1/w1;Ljava/lang/Object;Ljava/lang/Object;Lc1/a0;Lc1/b2;Ll2/o;I)Lc1/t1;

    move-result-object v3

    move-object/from16 v43, v19

    move-object/from16 v19, v14

    move-object/from16 v14, v43

    .line 110
    invoke-virtual/range {v37 .. v37}, Ll2/j1;->getValue()Ljava/lang/Object;

    move-result-object v5

    .line 111
    check-cast v5, Li2/m0;

    const v5, -0x1bb38f5d

    invoke-virtual {v14, v5}, Ll2/t;->Y(I)V

    .line 112
    invoke-virtual {v14, v0}, Ll2/t;->q(Z)V

    .line 113
    invoke-static/range {v33 .. v34}, Le3/s;->f(J)Lf3/c;

    move-result-object v0

    .line 114
    invoke-virtual {v14, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v6

    .line 115
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v7

    if-nez v6, :cond_4e

    if-ne v7, v2, :cond_4f

    .line 116
    :cond_4e
    new-instance v6, La3/f;

    const/4 v7, 0x7

    invoke-direct {v6, v0, v7}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 117
    new-instance v7, Lc1/b2;

    invoke-direct {v7, v13, v6}, Lc1/b2;-><init>(Lay0/k;Lay0/k;)V

    .line 118
    invoke-virtual {v14, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 119
    :cond_4f
    move-object/from16 v18, v7

    check-cast v18, Lc1/b2;

    .line 120
    invoke-virtual/range {v36 .. v36}, Lap0/o;->D()Ljava/lang/Object;

    move-result-object v0

    .line 121
    check-cast v0, Li2/m0;

    invoke-virtual {v14, v5}, Ll2/t;->Y(I)V

    const/4 v0, 0x0

    .line 122
    invoke-virtual {v14, v0}, Ll2/t;->q(Z)V

    .line 123
    new-instance v15, Le3/s;

    move-wide/from16 v6, v33

    invoke-direct {v15, v6, v7}, Le3/s;-><init>(J)V

    .line 124
    invoke-virtual/range {v37 .. v37}, Ll2/j1;->getValue()Ljava/lang/Object;

    move-result-object v13

    .line 125
    check-cast v13, Li2/m0;

    invoke-virtual {v14, v5}, Ll2/t;->Y(I)V

    .line 126
    invoke-virtual {v14, v0}, Ll2/t;->q(Z)V

    .line 127
    new-instance v5, Le3/s;

    invoke-direct {v5, v6, v7}, Le3/s;-><init>(J)V

    .line 128
    invoke-virtual/range {v19 .. v19}, Lc1/w1;->f()Lc1/r1;

    const v6, 0x46fc0e6e

    .line 129
    invoke-virtual {v14, v6}, Ll2/t;->Y(I)V

    .line 130
    invoke-virtual {v14, v0}, Ll2/t;->q(Z)V

    move-object/from16 v16, v19

    move-object/from16 v19, v14

    move-object/from16 v14, v16

    move-object/from16 v16, v5

    .line 131
    invoke-static/range {v14 .. v20}, Lc1/z1;->c(Lc1/w1;Ljava/lang/Object;Ljava/lang/Object;Lc1/a0;Lc1/b2;Ll2/o;I)Lc1/t1;

    move-result-object v13

    move-object/from16 v6, v19

    .line 132
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v2, :cond_50

    .line 133
    new-instance v0, Li2/e1;

    .line 134
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 135
    invoke-virtual {v6, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 136
    :cond_50
    move-object/from16 v17, v0

    check-cast v17, Li2/e1;

    if-nez p4, :cond_51

    const v0, -0x70c16e39

    .line 137
    invoke-virtual {v6, v0}, Ll2/t;->Y(I)V

    const/4 v0, 0x0

    .line 138
    invoke-virtual {v6, v0}, Ll2/t;->q(Z)V

    move v5, v12

    move-object/from16 v3, v21

    const/16 p14, 0x0

    const/16 v7, 0x800

    const/4 v9, 0x0

    goto :goto_2e

    :cond_51
    const/4 v0, 0x0

    const v5, -0x70c16e38

    .line 139
    invoke-virtual {v6, v5}, Ll2/t;->Y(I)V

    .line 140
    new-instance v9, Lh2/i6;

    move-object/from16 v16, p4

    move-object v15, v3

    move v5, v12

    move-object/from16 v3, v21

    move/from16 v14, v29

    move-object/from16 v11, v35

    move-object/from16 v12, v39

    const/16 p14, 0x0

    const/16 v7, 0x800

    invoke-direct/range {v9 .. v17}, Lh2/i6;-><init>(Lg4/p0;Lg4/p0;Lc1/t1;Lc1/t1;ZLc1/t1;Lay0/o;Li2/e1;)V

    const v11, -0x402b4ec0

    invoke-static {v11, v6, v9}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    move-result-object v9

    .line 141
    invoke-virtual {v6, v0}, Ll2/t;->q(Z)V

    :goto_2e
    if-nez p8, :cond_52

    .line 142
    iget-wide v11, v4, Lh2/eb;->D:J

    goto :goto_2f

    :cond_52
    if-eqz p9, :cond_53

    .line 143
    iget-wide v11, v4, Lh2/eb;->E:J

    goto :goto_2f

    :cond_53
    if-eqz v25, :cond_54

    .line 144
    iget-wide v11, v4, Lh2/eb;->B:J

    goto :goto_2f

    .line 145
    :cond_54
    iget-wide v11, v4, Lh2/eb;->C:J

    .line 146
    :goto_2f
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v2, :cond_55

    .line 147
    new-instance v0, Laa/a0;

    const/4 v13, 0x4

    invoke-direct {v0, v1, v13}, Laa/a0;-><init>(Ll2/t2;I)V

    invoke-static {v0, v3}, Ll2/b;->i(Lay0/a;Ll2/n2;)Ll2/h0;

    move-result-object v0

    .line 148
    invoke-virtual {v6, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 149
    :cond_55
    check-cast v0, Ll2/t2;

    if-eqz p5, :cond_56

    .line 150
    invoke-interface/range {p1 .. p1}, Ljava/lang/CharSequence;->length()I

    move-result v13

    if-nez v13, :cond_56

    .line 151
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_56

    const v0, -0x70b07c28

    .line 152
    invoke-virtual {v6, v0}, Ll2/t;->Y(I)V

    .line 153
    new-instance v0, Li2/d1;

    move-object v13, v10

    move-object v10, v4

    move-object v4, v13

    move-object v14, v2

    move-object v13, v3

    move v15, v5

    move-wide v2, v11

    move-object/from16 v5, p5

    move-object/from16 v12, p11

    move-object/from16 v11, p13

    invoke-direct/range {v0 .. v5}, Li2/d1;-><init>(Lc1/t1;JLg4/p0;Lay0/n;)V

    const v1, 0x53c6f2c5

    invoke-static {v1, v6, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    move-result-object v0

    const/4 v1, 0x0

    .line 154
    invoke-virtual {v6, v1}, Ll2/t;->q(Z)V

    move-object/from16 v16, v0

    goto :goto_30

    :cond_56
    move-object/from16 v12, p11

    move-object/from16 v11, p13

    move-object v14, v2

    move-object v13, v3

    move-object v10, v4

    move v15, v5

    const/4 v1, 0x0

    const v0, -0x70aa6c96

    .line 155
    invoke-virtual {v6, v0}, Ll2/t;->Y(I)V

    .line 156
    invoke-virtual {v6, v1}, Ll2/t;->q(Z)V

    move-object/from16 v16, p14

    .line 157
    :goto_30
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v14, :cond_57

    .line 158
    new-instance v0, Laa/a0;

    const/4 v1, 0x5

    invoke-direct {v0, v8, v1}, Laa/a0;-><init>(Ll2/t2;I)V

    invoke-static {v0, v13}, Ll2/b;->i(Lay0/a;Ll2/n2;)Ll2/h0;

    move-result-object v0

    .line 159
    invoke-virtual {v6, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 160
    :cond_57
    check-cast v0, Ll2/t2;

    const v0, -0x709f7ed6

    .line 161
    invoke-virtual {v6, v0}, Ll2/t;->Y(I)V

    const/4 v0, 0x0

    .line 162
    invoke-virtual {v6, v0}, Ll2/t;->q(Z)V

    const v1, -0x7096b376

    .line 163
    invoke-virtual {v6, v1}, Ll2/t;->Y(I)V

    .line 164
    invoke-virtual {v6, v0}, Ll2/t;->q(Z)V

    const v1, -0x7094085f

    .line 165
    invoke-virtual {v6, v1}, Ll2/t;->Y(I)V

    .line 166
    invoke-virtual {v6, v0}, Ll2/t;->q(Z)V

    const v1, -0x708fc380

    .line 167
    invoke-virtual {v6, v1}, Ll2/t;->Y(I)V

    .line 168
    invoke-virtual {v6, v0}, Ll2/t;->q(Z)V

    if-nez p8, :cond_58

    .line 169
    iget-wide v0, v10, Lh2/eb;->H:J

    :goto_31
    move-wide v1, v0

    goto :goto_32

    :cond_58
    if-eqz p9, :cond_59

    .line 170
    iget-wide v0, v10, Lh2/eb;->I:J

    goto :goto_31

    :cond_59
    if-eqz v25, :cond_5a

    .line 171
    iget-wide v0, v10, Lh2/eb;->F:J

    goto :goto_31

    .line 172
    :cond_5a
    iget-wide v0, v10, Lh2/eb;->G:J

    goto :goto_31

    :goto_32
    if-nez p6, :cond_5b

    const v0, -0x708b48fc

    .line 173
    invoke-virtual {v6, v0}, Ll2/t;->Y(I)V

    const/4 v8, 0x0

    .line 174
    invoke-virtual {v6, v8}, Ll2/t;->q(Z)V

    move-object/from16 v0, p14

    goto :goto_33

    :cond_5b
    const/4 v8, 0x0

    const v0, -0x708b48fb

    .line 175
    invoke-virtual {v6, v0}, Ll2/t;->Y(I)V

    .line 176
    new-instance v0, Lh2/u0;

    const/4 v5, 0x2

    move-object/from16 v4, p6

    move-object/from16 v3, v35

    invoke-direct/range {v0 .. v5}, Lh2/u0;-><init>(JLjava/lang/Object;Ljava/lang/Object;I)V

    const v1, 0x31e62e50

    invoke-static {v1, v6, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    move-result-object v0

    .line 177
    invoke-virtual {v6, v8}, Ll2/t;->q(Z)V

    .line 178
    :goto_33
    invoke-virtual/range {p0 .. p0}, Ljava/lang/Enum;->ordinal()I

    move-result v1

    if-eqz v1, :cond_61

    const/4 v2, 0x1

    if-ne v1, v2, :cond_60

    const v1, -0x7075f34a

    .line 179
    invoke-virtual {v6, v1}, Ll2/t;->Y(I)V

    .line 180
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v14, :cond_5c

    .line 181
    new-instance v1, Ld3/e;

    const-wide/16 v3, 0x0

    invoke-direct {v1, v3, v4}, Ld3/e;-><init>(J)V

    .line 182
    invoke-static {v1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    move-result-object v1

    .line 183
    invoke-virtual {v6, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 184
    :cond_5c
    check-cast v1, Ll2/b1;

    .line 185
    new-instance v3, La2/i;

    move-object/from16 v4, p3

    invoke-direct {v3, v1, v4, v12, v11}, La2/i;-><init>(Ll2/b1;Lh2/nb;Lk1/z0;Lay0/n;)V

    const v5, 0x1f7a6892

    invoke-static {v5, v6, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    move-result-object v3

    .line 186
    new-instance v35, La90/r;

    const/16 v36, 0x0

    const/16 v37, 0x10

    .line 187
    const-class v38, Ll2/t2;

    const-string v40, "value"

    const-string v41, "getValue()Ljava/lang/Object;"

    invoke-direct/range {v35 .. v41}, La90/r;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    move/from16 v26, v2

    move-object v2, v9

    move-object/from16 v13, v35

    move-object/from16 v5, v39

    .line 188
    new-instance v9, Li2/g1;

    invoke-direct {v9, v13}, Li2/g1;-><init>(La90/r;)V

    and-int/lit16 v13, v15, 0x1c00

    if-ne v13, v7, :cond_5d

    goto :goto_34

    :cond_5d
    move/from16 v26, v8

    .line 189
    :goto_34
    invoke-virtual {v6, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v7

    or-int v7, v26, v7

    .line 190
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v13

    if-nez v7, :cond_5e

    if-ne v13, v14, :cond_5f

    .line 191
    :cond_5e
    new-instance v13, Let/g;

    invoke-direct {v13, v4, v5, v1}, Let/g;-><init>(Lh2/nb;Lc1/t1;Ll2/b1;)V

    .line 192
    invoke-virtual {v6, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 193
    :cond_5f
    check-cast v13, Lay0/k;

    shr-int/lit8 v1, v15, 0x3

    and-int/lit8 v1, v1, 0x70

    or-int/lit8 v1, v1, 0x6

    shl-int/lit8 v5, v22, 0x15

    const/high16 v7, 0xe000000

    and-int/2addr v5, v7

    or-int/2addr v1, v5

    shl-int/lit8 v5, v15, 0x12

    const/high16 v7, 0x70000000

    and-int/2addr v5, v7

    or-int v15, v1, v5

    const v1, 0xe000

    shr-int/lit8 v5, v22, 0x3

    and-int/2addr v1, v5

    or-int/lit16 v1, v1, 0x180

    move-object/from16 v4, p14

    move-object/from16 v5, p14

    move-object/from16 v19, v6

    move-object/from16 v6, p14

    move-object/from16 v7, v16

    move/from16 v16, v1

    move-object v1, v7

    move-object/from16 v8, p3

    move/from16 v7, p7

    move-object v11, v3

    move-object v10, v13

    move-object/from16 v14, v19

    move-object/from16 v3, p14

    move-object v13, v12

    move-object v12, v0

    move-object/from16 v0, p2

    .line 194
    invoke-static/range {v0 .. v16}, Lh2/c7;->b(Lay0/n;Lay0/o;Lay0/n;Lay0/n;Lay0/n;Lay0/n;Lay0/n;ZLh2/nb;Li2/g1;Lay0/k;Lt2/b;Lay0/n;Lk1/z0;Ll2/o;II)V

    const/4 v0, 0x0

    .line 195
    invoke-virtual {v14, v0}, Ll2/t;->q(Z)V

    goto/16 :goto_35

    :cond_60
    move-object v14, v6

    move v0, v8

    const v1, 0x1d670ac8

    .line 196
    invoke-static {v1, v14, v0}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    move-result-object v0

    .line 197
    throw v0

    :cond_61
    move-object/from16 v3, p14

    move-object v11, v0

    move-object v14, v6

    move v0, v8

    move-object v2, v9

    move-object/from16 v1, v16

    move-object/from16 v5, v39

    const v4, -0x708602aa

    .line 198
    invoke-virtual {v14, v4}, Ll2/t;->Y(I)V

    .line 199
    new-instance v4, Lh2/e;

    const/16 v6, 0x9

    move-object/from16 v7, p13

    invoke-direct {v4, v6, v7}, Lh2/e;-><init>(ILay0/n;)V

    const v6, -0x671b8a8b

    invoke-static {v6, v14, v4}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    move-result-object v10

    .line 200
    new-instance v35, La90/r;

    const/16 v36, 0x0

    const/16 v37, 0xf

    .line 201
    const-class v38, Ll2/t2;

    const-string v40, "value"

    const-string v41, "getValue()Ljava/lang/Object;"

    invoke-direct/range {v35 .. v41}, La90/r;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    move-object/from16 v4, v35

    .line 202
    new-instance v9, Li2/g1;

    invoke-direct {v9, v4}, Li2/g1;-><init>(La90/r;)V

    shr-int/lit8 v4, v15, 0x3

    and-int/lit8 v4, v4, 0x70

    or-int/lit8 v4, v4, 0x6

    shl-int/lit8 v5, v22, 0x15

    const/high16 v6, 0xe000000

    and-int/2addr v5, v6

    or-int/2addr v4, v5

    shl-int/lit8 v5, v15, 0x12

    const/high16 v6, 0x70000000

    and-int/2addr v5, v6

    or-int/2addr v4, v5

    shr-int/lit8 v5, v22, 0x6

    and-int/lit16 v5, v5, 0x1c00

    or-int/lit8 v15, v5, 0x30

    move-object/from16 v19, v14

    move v14, v4

    move-object v4, v3

    move-object v5, v3

    move-object v6, v3

    move-object v0, v2

    move-object v2, v1

    move-object v1, v0

    move-object/from16 v0, p2

    move-object/from16 v8, p3

    move/from16 v7, p7

    move-object/from16 v12, p11

    move-object/from16 v13, v19

    .line 203
    invoke-static/range {v0 .. v15}, Lh2/mb;->b(Lay0/n;Lay0/n;Lay0/o;Lay0/n;Lay0/n;Lay0/n;Lay0/n;ZLh2/nb;Li2/g1;Lt2/b;Lay0/n;Lk1/z0;Ll2/o;II)V

    move-object v14, v13

    const/4 v0, 0x0

    .line 204
    invoke-virtual {v14, v0}, Ll2/t;->q(Z)V

    goto :goto_35

    .line 205
    :cond_62
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 206
    :goto_35
    invoke-virtual {v14}, Ll2/t;->s()Ll2/u1;

    move-result-object v0

    if-eqz v0, :cond_63

    move-object v1, v0

    new-instance v0, Li2/c1;

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    move-object/from16 v4, p3

    move-object/from16 v5, p4

    move-object/from16 v6, p5

    move-object/from16 v7, p6

    move/from16 v8, p7

    move/from16 v9, p8

    move/from16 v10, p9

    move-object/from16 v11, p10

    move-object/from16 v12, p11

    move-object/from16 v13, p12

    move-object/from16 v14, p13

    move/from16 v15, p15

    move/from16 v16, p16

    move-object/from16 v42, v1

    move-object/from16 v1, p0

    invoke-direct/range {v0 .. v16}, Li2/c1;-><init>(Li2/i1;Ljava/lang/CharSequence;Lay0/n;Lh2/nb;Lay0/o;Lay0/n;Lay0/n;ZZZLi1/l;Lk1/z0;Lh2/eb;Lay0/n;II)V

    move-object/from16 v1, v42

    .line 207
    iput-object v0, v1, Ll2/u1;->d:Lay0/n;

    :cond_63
    return-void
.end method

.method public static final b(JLg4/p0;Lay0/n;Ll2/o;I)V
    .locals 12

    .line 1
    move/from16 v5, p5

    .line 2
    .line 3
    move-object/from16 v10, p4

    .line 4
    .line 5
    check-cast v10, Ll2/t;

    .line 6
    .line 7
    const v0, 0x17a3cff9

    .line 8
    .line 9
    .line 10
    invoke-virtual {v10, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v10, p0, p1}, Ll2/t;->f(J)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    const/4 v0, 0x4

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v0, 0x2

    .line 22
    :goto_0
    or-int/2addr v0, v5

    .line 23
    invoke-virtual {v10, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-eqz v1, :cond_1

    .line 28
    .line 29
    const/16 v1, 0x20

    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_1
    const/16 v1, 0x10

    .line 33
    .line 34
    :goto_1
    or-int/2addr v0, v1

    .line 35
    and-int/lit16 v1, v5, 0x180

    .line 36
    .line 37
    if-nez v1, :cond_3

    .line 38
    .line 39
    invoke-virtual {v10, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_2

    .line 44
    .line 45
    const/16 v1, 0x100

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_2
    const/16 v1, 0x80

    .line 49
    .line 50
    :goto_2
    or-int/2addr v0, v1

    .line 51
    :cond_3
    and-int/lit16 v1, v0, 0x93

    .line 52
    .line 53
    const/16 v2, 0x92

    .line 54
    .line 55
    if-eq v1, v2, :cond_4

    .line 56
    .line 57
    const/4 v1, 0x1

    .line 58
    goto :goto_3

    .line 59
    :cond_4
    const/4 v1, 0x0

    .line 60
    :goto_3
    and-int/lit8 v2, v0, 0x1

    .line 61
    .line 62
    invoke-virtual {v10, v2, v1}, Ll2/t;->O(IZ)Z

    .line 63
    .line 64
    .line 65
    move-result v1

    .line 66
    if-eqz v1, :cond_5

    .line 67
    .line 68
    and-int/lit16 v11, v0, 0x3fe

    .line 69
    .line 70
    move-wide v6, p0

    .line 71
    move-object v8, p2

    .line 72
    move-object v9, p3

    .line 73
    invoke-static/range {v6 .. v11}, Li2/a1;->d(JLg4/p0;Lay0/n;Ll2/o;I)V

    .line 74
    .line 75
    .line 76
    goto :goto_4

    .line 77
    :cond_5
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 78
    .line 79
    .line 80
    :goto_4
    invoke-virtual {v10}, Ll2/t;->s()Ll2/u1;

    .line 81
    .line 82
    .line 83
    move-result-object v7

    .line 84
    if-eqz v7, :cond_6

    .line 85
    .line 86
    new-instance v0, Li2/b1;

    .line 87
    .line 88
    const/4 v6, 0x1

    .line 89
    move-wide v1, p0

    .line 90
    move-object v3, p2

    .line 91
    move-object v4, p3

    .line 92
    invoke-direct/range {v0 .. v6}, Li2/b1;-><init>(JLg4/p0;Lay0/n;II)V

    .line 93
    .line 94
    .line 95
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 96
    .line 97
    :cond_6
    return-void
.end method

.method public static final c(Lh2/nb;)Lx2/d;
    .locals 3

    .line 1
    instance-of v0, p0, Lh2/nb;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lh2/nb;->a:Lx2/h;

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 9
    .line 10
    new-instance v1, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    const-string v2, "Unknown position: "

    .line 13
    .line 14
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    throw v0
.end method

.method public static final d(Ll2/o;)F
    .locals 8

    .line 1
    sget-object v0, Lh2/ec;->a:Ll2/u2;

    .line 2
    .line 3
    check-cast p0, Ll2/t;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Lh2/dc;

    .line 10
    .line 11
    iget-object v0, v0, Lh2/dc;->l:Lg4/p0;

    .line 12
    .line 13
    iget-object v0, v0, Lg4/p0;->b:Lg4/t;

    .line 14
    .line 15
    iget-wide v0, v0, Lg4/t;->c:J

    .line 16
    .line 17
    sget-wide v2, Lk2/n0;->l:J

    .line 18
    .line 19
    const-wide v4, 0xff00000000L

    .line 20
    .line 21
    .line 22
    .line 23
    .line 24
    and-long/2addr v4, v0

    .line 25
    const-wide v6, 0x100000000L

    .line 26
    .line 27
    .line 28
    .line 29
    .line 30
    cmp-long v4, v4, v6

    .line 31
    .line 32
    if-nez v4, :cond_0

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    move-wide v0, v2

    .line 36
    :goto_0
    sget-object v2, Lw3/h1;->h:Ll2/u2;

    .line 37
    .line 38
    invoke-virtual {p0, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    check-cast p0, Lt4/c;

    .line 43
    .line 44
    invoke-interface {p0, v0, v1}, Lt4/c;->s(J)F

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    const/4 v0, 0x2

    .line 49
    int-to-float v0, v0

    .line 50
    div-float/2addr p0, v0

    .line 51
    return p0
.end method

.method public static final e(Ll2/o;)F
    .locals 2

    .line 1
    sget-object v0, Lh2/k5;->c:Ll2/u2;

    .line 2
    .line 3
    check-cast p0, Ll2/t;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lt4/f;

    .line 10
    .line 11
    iget p0, p0, Lt4/f;->d:F

    .line 12
    .line 13
    invoke-static {p0}, Ljava/lang/Float;->isNaN(F)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    const/4 v1, 0x0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    int-to-float p0, v1

    .line 21
    :cond_0
    sget v0, Lk2/j0;->d:F

    .line 22
    .line 23
    sub-float/2addr p0, v0

    .line 24
    const/4 v0, 0x2

    .line 25
    int-to-float v0, v0

    .line 26
    div-float/2addr p0, v0

    .line 27
    int-to-float v0, v1

    .line 28
    cmpg-float v1, p0, v0

    .line 29
    .line 30
    if-gez v1, :cond_1

    .line 31
    .line 32
    return v0

    .line 33
    :cond_1
    return p0
.end method
