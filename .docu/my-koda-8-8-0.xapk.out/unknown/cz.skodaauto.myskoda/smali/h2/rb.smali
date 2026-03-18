.class public abstract Lh2/rb;
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
    const/16 v1, 0x15

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
    sput-object v1, Lh2/rb;->a:Ll2/e0;

    .line 14
    .line 15
    return-void
.end method

.method public static final a(Lg4/p0;Lay0/n;Ll2/o;I)V
    .locals 3

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    const v0, 0xe9e0ce

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p3, 0x6

    .line 10
    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    invoke-virtual {p2, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

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
    or-int/2addr v0, p3

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    move v0, p3

    .line 25
    :goto_1
    and-int/lit8 v1, p3, 0x30

    .line 26
    .line 27
    if-nez v1, :cond_3

    .line 28
    .line 29
    invoke-virtual {p2, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_2

    .line 34
    .line 35
    const/16 v1, 0x20

    .line 36
    .line 37
    goto :goto_2

    .line 38
    :cond_2
    const/16 v1, 0x10

    .line 39
    .line 40
    :goto_2
    or-int/2addr v0, v1

    .line 41
    :cond_3
    and-int/lit8 v1, v0, 0x13

    .line 42
    .line 43
    const/16 v2, 0x12

    .line 44
    .line 45
    if-eq v1, v2, :cond_4

    .line 46
    .line 47
    const/4 v1, 0x1

    .line 48
    goto :goto_3

    .line 49
    :cond_4
    const/4 v1, 0x0

    .line 50
    :goto_3
    and-int/lit8 v2, v0, 0x1

    .line 51
    .line 52
    invoke-virtual {p2, v2, v1}, Ll2/t;->O(IZ)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-eqz v1, :cond_5

    .line 57
    .line 58
    sget-object v1, Lh2/rb;->a:Ll2/e0;

    .line 59
    .line 60
    invoke-virtual {p2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    check-cast v2, Lg4/p0;

    .line 65
    .line 66
    invoke-virtual {v2, p0}, Lg4/p0;->d(Lg4/p0;)Lg4/p0;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    invoke-virtual {v1, v2}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    and-int/lit8 v0, v0, 0x70

    .line 75
    .line 76
    const/16 v2, 0x8

    .line 77
    .line 78
    or-int/2addr v0, v2

    .line 79
    invoke-static {v1, p1, p2, v0}, Ll2/b;->a(Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 80
    .line 81
    .line 82
    goto :goto_4

    .line 83
    :cond_5
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 84
    .line 85
    .line 86
    :goto_4
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 87
    .line 88
    .line 89
    move-result-object p2

    .line 90
    if-eqz p2, :cond_6

    .line 91
    .line 92
    new-instance v0, La71/n0;

    .line 93
    .line 94
    const/16 v1, 0x11

    .line 95
    .line 96
    invoke-direct {v0, p3, v1, p0, p1}, La71/n0;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 100
    .line 101
    :cond_6
    return-void
.end method

.method public static final b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V
    .locals 41

    move/from16 v0, p20

    move/from16 v1, p21

    move/from16 v2, p22

    .line 1
    move-object/from16 v3, p19

    check-cast v3, Ll2/t;

    const v4, 0x6bda414b

    invoke-virtual {v3, v4}, Ll2/t;->a0(I)Ll2/t;

    and-int/lit8 v4, v0, 0x6

    if-nez v4, :cond_1

    move-object/from16 v4, p0

    invoke-virtual {v3, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_0

    const/4 v7, 0x4

    goto :goto_0

    :cond_0
    const/4 v7, 0x2

    :goto_0
    or-int/2addr v7, v0

    goto :goto_1

    :cond_1
    move-object/from16 v4, p0

    move v7, v0

    :goto_1
    and-int/lit8 v8, v2, 0x2

    if-eqz v8, :cond_3

    or-int/lit8 v7, v7, 0x30

    :cond_2
    move-object/from16 v11, p1

    goto :goto_3

    :cond_3
    and-int/lit8 v11, v0, 0x30

    if-nez v11, :cond_2

    move-object/from16 v11, p1

    invoke-virtual {v3, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_4

    const/16 v12, 0x20

    goto :goto_2

    :cond_4
    const/16 v12, 0x10

    :goto_2
    or-int/2addr v7, v12

    :goto_3
    and-int/lit8 v12, v2, 0x4

    if-eqz v12, :cond_5

    or-int/lit16 v7, v7, 0x180

    move-wide/from16 v5, p2

    goto :goto_5

    :cond_5
    and-int/lit16 v15, v0, 0x180

    move-wide/from16 v5, p2

    if-nez v15, :cond_7

    invoke-virtual {v3, v5, v6}, Ll2/t;->f(J)Z

    move-result v16

    if-eqz v16, :cond_6

    const/16 v16, 0x100

    goto :goto_4

    :cond_6
    const/16 v16, 0x80

    :goto_4
    or-int v7, v7, v16

    :cond_7
    :goto_5
    or-int/lit16 v9, v7, 0xc00

    and-int/lit8 v17, v2, 0x10

    const/16 v18, 0x2000

    const/16 v19, 0x4000

    if-eqz v17, :cond_8

    or-int/lit16 v9, v7, 0x6c00

    move-wide/from16 v10, p4

    goto :goto_7

    :cond_8
    and-int/lit16 v7, v0, 0x6000

    move-wide/from16 v10, p4

    if-nez v7, :cond_a

    invoke-virtual {v3, v10, v11}, Ll2/t;->f(J)Z

    move-result v20

    if-eqz v20, :cond_9

    move/from16 v20, v19

    goto :goto_6

    :cond_9
    move/from16 v20, v18

    :goto_6
    or-int v9, v9, v20

    :cond_a
    :goto_7
    and-int/lit8 v20, v2, 0x20

    const/4 v7, 0x0

    const/high16 v22, 0x10000

    const/high16 v23, 0x30000

    const/high16 v24, 0x20000

    if-eqz v20, :cond_b

    or-int v9, v9, v23

    goto :goto_9

    :cond_b
    and-int v20, v0, v23

    if-nez v20, :cond_d

    invoke-virtual {v3, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v20

    if-eqz v20, :cond_c

    move/from16 v20, v24

    goto :goto_8

    :cond_c
    move/from16 v20, v22

    :goto_8
    or-int v9, v9, v20

    :cond_d
    :goto_9
    and-int/lit8 v20, v2, 0x40

    const/high16 v25, 0x80000

    const/high16 v26, 0x100000

    const/high16 v27, 0x180000

    if-eqz v20, :cond_e

    or-int v9, v9, v27

    move-object/from16 v13, p6

    goto :goto_b

    :cond_e
    and-int v28, v0, v27

    move-object/from16 v13, p6

    if-nez v28, :cond_10

    invoke-virtual {v3, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v29

    if-eqz v29, :cond_f

    move/from16 v29, v26

    goto :goto_a

    :cond_f
    move/from16 v29, v25

    :goto_a
    or-int v9, v9, v29

    :cond_10
    :goto_b
    and-int/lit16 v14, v2, 0x80

    const/high16 v30, 0x400000

    const/high16 v31, 0x800000

    const/high16 v32, 0xc00000

    if-eqz v14, :cond_11

    or-int v9, v9, v32

    goto :goto_d

    :cond_11
    and-int v14, v0, v32

    if-nez v14, :cond_13

    invoke-virtual {v3, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_12

    move/from16 v14, v31

    goto :goto_c

    :cond_12
    move/from16 v14, v30

    :goto_c
    or-int/2addr v9, v14

    :cond_13
    :goto_d
    and-int/lit16 v14, v2, 0x100

    const/high16 v33, 0x6000000

    if-eqz v14, :cond_15

    or-int v9, v9, v33

    :cond_14
    move/from16 v33, v8

    move-wide/from16 v7, p7

    goto :goto_f

    :cond_15
    and-int v33, v0, v33

    if-nez v33, :cond_14

    move/from16 v33, v8

    move-wide/from16 v7, p7

    invoke-virtual {v3, v7, v8}, Ll2/t;->f(J)Z

    move-result v35

    if-eqz v35, :cond_16

    const/high16 v35, 0x4000000

    goto :goto_e

    :cond_16
    const/high16 v35, 0x2000000

    :goto_e
    or-int v9, v9, v35

    :goto_f
    and-int/lit16 v15, v2, 0x200

    const/high16 v36, 0x30000000

    if-eqz v15, :cond_17

    or-int v9, v9, v36

    move-object/from16 v0, p9

    goto :goto_11

    :cond_17
    and-int v36, v0, v36

    move-object/from16 v0, p9

    if-nez v36, :cond_19

    invoke-virtual {v3, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v36

    if-eqz v36, :cond_18

    const/high16 v36, 0x20000000

    goto :goto_10

    :cond_18
    const/high16 v36, 0x10000000

    :goto_10
    or-int v9, v9, v36

    :cond_19
    :goto_11
    and-int/lit16 v0, v2, 0x400

    if-eqz v0, :cond_1a

    or-int/lit8 v35, v1, 0x6

    move/from16 v36, v0

    move-object/from16 v0, p10

    goto :goto_13

    :cond_1a
    and-int/lit8 v36, v1, 0x6

    if-nez v36, :cond_1c

    move/from16 v36, v0

    move-object/from16 v0, p10

    invoke-virtual {v3, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v37

    if-eqz v37, :cond_1b

    const/16 v35, 0x4

    goto :goto_12

    :cond_1b
    const/16 v35, 0x2

    :goto_12
    or-int v35, v1, v35

    goto :goto_13

    :cond_1c
    move/from16 v36, v0

    move-object/from16 v0, p10

    move/from16 v35, v1

    :goto_13
    and-int/lit16 v0, v2, 0x800

    if-eqz v0, :cond_1e

    or-int/lit8 v35, v35, 0x30

    move-wide/from16 v4, p11

    :cond_1d
    :goto_14
    move/from16 v6, v35

    goto :goto_16

    :cond_1e
    and-int/lit8 v37, v1, 0x30

    move-wide/from16 v4, p11

    if-nez v37, :cond_1d

    invoke-virtual {v3, v4, v5}, Ll2/t;->f(J)Z

    move-result v6

    if-eqz v6, :cond_1f

    const/16 v16, 0x20

    goto :goto_15

    :cond_1f
    const/16 v16, 0x10

    :goto_15
    or-int v35, v35, v16

    goto :goto_14

    :goto_16
    move/from16 v16, v0

    and-int/lit16 v0, v2, 0x1000

    if-eqz v0, :cond_21

    or-int/lit16 v6, v6, 0x180

    move/from16 v21, v0

    :cond_20
    move/from16 v0, p13

    goto :goto_18

    :cond_21
    move/from16 v21, v0

    and-int/lit16 v0, v1, 0x180

    if-nez v0, :cond_20

    move/from16 v0, p13

    invoke-virtual {v3, v0}, Ll2/t;->e(I)Z

    move-result v35

    if-eqz v35, :cond_22

    const/16 v28, 0x100

    goto :goto_17

    :cond_22
    const/16 v28, 0x80

    :goto_17
    or-int v6, v6, v28

    :goto_18
    and-int/lit16 v0, v2, 0x2000

    if-eqz v0, :cond_24

    or-int/lit16 v6, v6, 0xc00

    move/from16 v28, v0

    :cond_23
    move/from16 v0, p14

    goto :goto_1a

    :cond_24
    move/from16 v28, v0

    and-int/lit16 v0, v1, 0xc00

    if-nez v0, :cond_23

    move/from16 v0, p14

    invoke-virtual {v3, v0}, Ll2/t;->h(Z)Z

    move-result v29

    if-eqz v29, :cond_25

    const/16 v29, 0x800

    goto :goto_19

    :cond_25
    const/16 v29, 0x400

    :goto_19
    or-int v6, v6, v29

    :goto_1a
    and-int/lit16 v0, v2, 0x4000

    if-eqz v0, :cond_27

    or-int/lit16 v6, v6, 0x6000

    move/from16 v29, v0

    :cond_26
    move/from16 v0, p15

    goto :goto_1b

    :cond_27
    move/from16 v29, v0

    and-int/lit16 v0, v1, 0x6000

    if-nez v0, :cond_26

    move/from16 v0, p15

    invoke-virtual {v3, v0}, Ll2/t;->e(I)Z

    move-result v35

    if-eqz v35, :cond_28

    move/from16 v18, v19

    :cond_28
    or-int v6, v6, v18

    :goto_1b
    const v18, 0x8000

    and-int v18, v2, v18

    if-eqz v18, :cond_29

    or-int v6, v6, v23

    move/from16 v0, p16

    goto :goto_1d

    :cond_29
    and-int v19, v1, v23

    move/from16 v0, p16

    if-nez v19, :cond_2b

    invoke-virtual {v3, v0}, Ll2/t;->e(I)Z

    move-result v19

    if-eqz v19, :cond_2a

    move/from16 v19, v24

    goto :goto_1c

    :cond_2a
    move/from16 v19, v22

    :goto_1c
    or-int v6, v6, v19

    :cond_2b
    :goto_1d
    and-int v19, v2, v22

    if-eqz v19, :cond_2c

    or-int v6, v6, v27

    move-object/from16 v0, p17

    goto :goto_1e

    :cond_2c
    and-int v22, v1, v27

    move-object/from16 v0, p17

    if-nez v22, :cond_2e

    invoke-virtual {v3, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v22

    if-eqz v22, :cond_2d

    move/from16 v25, v26

    :cond_2d
    or-int v6, v6, v25

    :cond_2e
    :goto_1e
    and-int v22, v1, v32

    if-nez v22, :cond_30

    and-int v22, v2, v24

    move-object/from16 v0, p18

    if-nez v22, :cond_2f

    invoke-virtual {v3, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v22

    if-eqz v22, :cond_2f

    move/from16 v30, v31

    :cond_2f
    or-int v6, v6, v30

    goto :goto_1f

    :cond_30
    move-object/from16 v0, p18

    :goto_1f
    const v22, 0x12492493

    and-int v0, v9, v22

    const v1, 0x12492492

    const/16 v22, 0x1

    if-ne v0, v1, :cond_32

    const v0, 0x492493

    and-int/2addr v0, v6

    const v1, 0x492492

    if-eq v0, v1, :cond_31

    goto :goto_20

    :cond_31
    const/4 v0, 0x0

    goto :goto_21

    :cond_32
    :goto_20
    move/from16 v0, v22

    :goto_21
    and-int/lit8 v1, v9, 0x1

    invoke-virtual {v3, v1, v0}, Ll2/t;->O(IZ)Z

    move-result v0

    if-eqz v0, :cond_47

    invoke-virtual {v3}, Ll2/t;->T()V

    and-int/lit8 v0, p20, 0x1

    const v1, -0x1c00001

    if-eqz v0, :cond_36

    invoke-virtual {v3}, Ll2/t;->y()Z

    move-result v0

    if-eqz v0, :cond_33

    goto :goto_22

    .line 2
    :cond_33
    invoke-virtual {v3}, Ll2/t;->R()V

    and-int v0, p22, v24

    if-eqz v0, :cond_34

    and-int/2addr v6, v1

    :cond_34
    move-object/from16 v0, p1

    move-wide/from16 v25, p2

    move-object/from16 v12, p9

    move-object/from16 v14, p10

    move/from16 v15, p13

    move/from16 v16, p14

    move/from16 v17, p15

    move/from16 v22, p16

    move-object/from16 v34, p17

    :cond_35
    move-object/from16 v1, p18

    goto/16 :goto_2c

    :cond_36
    :goto_22
    if-eqz v33, :cond_37

    .line 3
    sget-object v0, Lx2/p;->b:Lx2/p;

    goto :goto_23

    :cond_37
    move-object/from16 v0, p1

    :goto_23
    if-eqz v12, :cond_38

    .line 4
    sget-wide v25, Le3/s;->i:J

    goto :goto_24

    :cond_38
    move-wide/from16 v25, p2

    :goto_24
    if-eqz v17, :cond_39

    .line 5
    sget-wide v10, Lt4/o;->c:J

    :cond_39
    if-eqz v20, :cond_3a

    const/4 v13, 0x0

    :cond_3a
    if-eqz v14, :cond_3b

    .line 6
    sget-wide v7, Lt4/o;->c:J

    :cond_3b
    if-eqz v15, :cond_3c

    const/4 v12, 0x0

    goto :goto_25

    :cond_3c
    move-object/from16 v12, p9

    :goto_25
    if-eqz v36, :cond_3d

    const/4 v14, 0x0

    goto :goto_26

    :cond_3d
    move-object/from16 v14, p10

    :goto_26
    if-eqz v16, :cond_3e

    .line 7
    sget-wide v4, Lt4/o;->c:J

    :cond_3e
    if-eqz v21, :cond_3f

    move/from16 v15, v22

    goto :goto_27

    :cond_3f
    move/from16 v15, p13

    :goto_27
    if-eqz v28, :cond_40

    move/from16 v16, v22

    goto :goto_28

    :cond_40
    move/from16 v16, p14

    :goto_28
    if-eqz v29, :cond_41

    const v17, 0x7fffffff

    goto :goto_29

    :cond_41
    move/from16 v17, p15

    :goto_29
    if-eqz v18, :cond_42

    goto :goto_2a

    :cond_42
    move/from16 v22, p16

    :goto_2a
    if-eqz v19, :cond_43

    const/16 v34, 0x0

    goto :goto_2b

    :cond_43
    move-object/from16 v34, p17

    :goto_2b
    and-int v18, p22, v24

    if-eqz v18, :cond_35

    move/from16 p19, v1

    .line 8
    sget-object v1, Lh2/rb;->a:Ll2/e0;

    .line 9
    invoke-virtual {v3, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lg4/p0;

    and-int v6, v6, p19

    .line 10
    :goto_2c
    invoke-virtual {v3}, Ll2/t;->r()V

    const v2, -0x21b08752

    invoke-virtual {v3, v2}, Ll2/t;->Y(I)V

    const-wide/16 v18, 0x10

    cmp-long v2, v25, v18

    if-eqz v2, :cond_44

    move-object/from16 p15, v0

    move-object/from16 p1, v1

    move-wide/from16 v20, v25

    const/4 v0, 0x0

    goto :goto_2f

    :cond_44
    const v2, -0x21b0844d

    .line 11
    invoke-virtual {v3, v2}, Ll2/t;->Y(I)V

    .line 12
    invoke-virtual {v1}, Lg4/p0;->b()J

    move-result-wide v20

    cmp-long v2, v20, v18

    if-eqz v2, :cond_45

    move-object/from16 p15, v0

    move-object/from16 p1, v1

    :goto_2d
    const/4 v0, 0x0

    goto :goto_2e

    .line 13
    :cond_45
    sget-object v2, Lh2/p1;->a:Ll2/e0;

    .line 14
    invoke-virtual {v3, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v2

    .line 15
    check-cast v2, Le3/s;

    move-object/from16 p15, v0

    move-object/from16 p1, v1

    .line 16
    iget-wide v0, v2, Le3/s;->a:J

    move-wide/from16 v20, v0

    goto :goto_2d

    .line 17
    :goto_2e
    invoke-virtual {v3, v0}, Ll2/t;->q(Z)V

    :goto_2f
    invoke-virtual {v3, v0}, Ll2/t;->q(Z)V

    if-eqz v14, :cond_46

    .line 18
    iget v0, v14, Lr4/k;->a:I

    goto :goto_30

    :cond_46
    const/high16 v0, -0x80000000

    :goto_30
    const v1, 0xfd6f50

    const/4 v2, 0x0

    move/from16 p11, v0

    move/from16 p14, v1

    move-object/from16 p7, v2

    move-wide/from16 p12, v4

    move-wide/from16 p8, v7

    move-wide/from16 p4, v10

    move-object/from16 p10, v12

    move-object/from16 p6, v13

    move-wide/from16 p2, v20

    .line 19
    invoke-static/range {p1 .. p14}, Lg4/p0;->e(Lg4/p0;JJLk4/x;Lk4/t;JLr4/l;IJI)Lg4/p0;

    move-result-object v0

    move-object/from16 v1, p1

    and-int/lit8 v2, v9, 0x7e

    move-object/from16 p3, v0

    shr-int/lit8 v0, v6, 0x9

    and-int/lit16 v0, v0, 0x1c00

    or-int/2addr v0, v2

    shl-int/lit8 v2, v6, 0x6

    const v6, 0xe000

    and-int/2addr v6, v2

    or-int/2addr v0, v6

    const/high16 v6, 0x70000

    and-int/2addr v6, v2

    or-int/2addr v0, v6

    const/high16 v6, 0x380000

    and-int/2addr v6, v2

    or-int/2addr v0, v6

    const/high16 v6, 0x1c00000

    and-int/2addr v2, v6

    or-int/2addr v0, v2

    shl-int/lit8 v2, v9, 0x12

    const/high16 v6, 0x70000000

    and-int/2addr v2, v6

    or-int/2addr v0, v2

    const/16 v2, 0x100

    const/4 v6, 0x0

    move-object/from16 p1, p0

    move-object/from16 p2, p15

    move/from16 p11, v0

    move/from16 p12, v2

    move-object/from16 p10, v3

    move-object/from16 p9, v6

    move/from16 p5, v15

    move/from16 p6, v16

    move/from16 p7, v17

    move/from16 p8, v22

    move-object/from16 p4, v34

    .line 20
    invoke-static/range {p1 .. p12}, Lt1/l0;->c(Ljava/lang/String;Lx2/s;Lg4/p0;Lay0/k;IZIILe3/t;Ll2/o;II)V

    move-object/from16 v2, p2

    move-object/from16 v0, p10

    move-object/from16 v19, v1

    move-wide v8, v7

    move-object v7, v13

    move-object/from16 v18, v34

    move-wide/from16 v39, v10

    move-object v10, v12

    move-wide v12, v4

    move-wide/from16 v5, v39

    move-object v11, v14

    move v14, v15

    move/from16 v15, v16

    move/from16 v16, v17

    move/from16 v17, v22

    move-wide/from16 v3, v25

    goto :goto_31

    :cond_47
    move-object v0, v3

    .line 21
    invoke-virtual {v0}, Ll2/t;->R()V

    move-object/from16 v2, p1

    move/from16 v14, p13

    move/from16 v15, p14

    move/from16 v16, p15

    move/from16 v17, p16

    move-object/from16 v18, p17

    move-object/from16 v19, p18

    move-wide v8, v7

    move-object v7, v13

    move-wide v12, v4

    move-wide v5, v10

    move-wide/from16 v3, p2

    move-object/from16 v10, p9

    move-object/from16 v11, p10

    .line 22
    :goto_31
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    move-result-object v0

    if-eqz v0, :cond_48

    move-object v1, v0

    new-instance v0, Lf2/t0;

    move/from16 v20, p20

    move/from16 v21, p21

    move/from16 v22, p22

    move-object/from16 v38, v1

    move-object/from16 v1, p0

    invoke-direct/range {v0 .. v22}, Lf2/t0;-><init>(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;III)V

    move-object/from16 v1, v38

    .line 23
    iput-object v0, v1, Ll2/u1;->d:Lay0/n;

    :cond_48
    return-void
.end method

.method public static final c(Lg4/g;Lx2/s;JJJLr4/k;JIZIILjava/util/Map;Lay0/k;Lg4/p0;Ll2/o;III)V
    .locals 60

    move-object/from16 v1, p0

    move/from16 v0, p19

    move/from16 v2, p20

    move/from16 v3, p21

    .line 1
    move-object/from16 v4, p18

    check-cast v4, Ll2/t;

    const v5, 0x116b5779

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
    and-int/lit8 v8, v3, 0x2

    if-eqz v8, :cond_3

    or-int/lit8 v5, v5, 0x30

    :cond_2
    move-object/from16 v11, p1

    goto :goto_3

    :cond_3
    and-int/lit8 v11, v0, 0x30

    if-nez v11, :cond_2

    move-object/from16 v11, p1

    invoke-virtual {v4, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_4

    const/16 v12, 0x20

    goto :goto_2

    :cond_4
    const/16 v12, 0x10

    :goto_2
    or-int/2addr v5, v12

    :goto_3
    and-int/lit8 v12, v3, 0x4

    if-eqz v12, :cond_5

    or-int/lit16 v5, v5, 0x180

    move-wide/from16 v9, p2

    goto :goto_5

    :cond_5
    and-int/lit16 v15, v0, 0x180

    move-wide/from16 v9, p2

    if-nez v15, :cond_7

    invoke-virtual {v4, v9, v10}, Ll2/t;->f(J)Z

    move-result v16

    if-eqz v16, :cond_6

    const/16 v16, 0x100

    goto :goto_4

    :cond_6
    const/16 v16, 0x80

    :goto_4
    or-int v5, v5, v16

    :cond_7
    :goto_5
    or-int/lit16 v6, v5, 0xc00

    and-int/lit8 v17, v3, 0x10

    const/16 v18, 0x2000

    const/16 v19, 0x4000

    if-eqz v17, :cond_8

    or-int/lit16 v6, v5, 0x6c00

    move-wide/from16 v13, p4

    goto :goto_7

    :cond_8
    and-int/lit16 v5, v0, 0x6000

    move-wide/from16 v13, p4

    if-nez v5, :cond_a

    invoke-virtual {v4, v13, v14}, Ll2/t;->f(J)Z

    move-result v21

    if-eqz v21, :cond_9

    move/from16 v21, v19

    goto :goto_6

    :cond_9
    move/from16 v21, v18

    :goto_6
    or-int v6, v6, v21

    :cond_a
    :goto_7
    and-int/lit8 v21, v3, 0x20

    const/high16 v22, 0x10000

    const/4 v5, 0x0

    const/high16 v24, 0x20000

    const/high16 v25, 0x30000

    if-eqz v21, :cond_b

    or-int v6, v6, v25

    goto :goto_9

    :cond_b
    and-int v21, v0, v25

    if-nez v21, :cond_d

    invoke-virtual {v4, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v21

    if-eqz v21, :cond_c

    move/from16 v21, v24

    goto :goto_8

    :cond_c
    move/from16 v21, v22

    :goto_8
    or-int v6, v6, v21

    :cond_d
    :goto_9
    and-int/lit8 v21, v3, 0x40

    const/high16 v26, 0x180000

    if-eqz v21, :cond_e

    or-int v6, v6, v26

    goto :goto_b

    :cond_e
    and-int v21, v0, v26

    if-nez v21, :cond_10

    invoke-virtual {v4, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v21

    if-eqz v21, :cond_f

    const/high16 v21, 0x100000

    goto :goto_a

    :cond_f
    const/high16 v21, 0x80000

    :goto_a
    or-int v6, v6, v21

    :cond_10
    :goto_b
    and-int/lit16 v15, v3, 0x80

    const/high16 v27, 0x400000

    const/high16 v28, 0x800000

    const/high16 v29, 0xc00000

    if-eqz v15, :cond_11

    or-int v6, v6, v29

    goto :goto_d

    :cond_11
    and-int v15, v0, v29

    if-nez v15, :cond_13

    invoke-virtual {v4, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v15

    if-eqz v15, :cond_12

    move/from16 v15, v28

    goto :goto_c

    :cond_12
    move/from16 v15, v27

    :goto_c
    or-int/2addr v6, v15

    :cond_13
    :goto_d
    and-int/lit16 v15, v3, 0x100

    const/high16 v30, 0x2000000

    const/high16 v31, 0x4000000

    const/high16 v32, 0x6000000

    if-eqz v15, :cond_14

    or-int v6, v6, v32

    move/from16 v34, v8

    move-wide/from16 v7, p6

    goto :goto_f

    :cond_14
    and-int v33, v0, v32

    move/from16 v34, v8

    move-wide/from16 v7, p6

    if-nez v33, :cond_16

    invoke-virtual {v4, v7, v8}, Ll2/t;->f(J)Z

    move-result v35

    if-eqz v35, :cond_15

    move/from16 v35, v31

    goto :goto_e

    :cond_15
    move/from16 v35, v30

    :goto_e
    or-int v6, v6, v35

    :cond_16
    :goto_f
    and-int/lit16 v5, v3, 0x200

    const/high16 v36, 0x30000000

    if-eqz v5, :cond_17

    or-int v6, v6, v36

    goto :goto_11

    :cond_17
    and-int v5, v0, v36

    if-nez v5, :cond_19

    const/4 v5, 0x0

    invoke-virtual {v4, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v36

    if-eqz v36, :cond_18

    const/high16 v5, 0x20000000

    goto :goto_10

    :cond_18
    const/high16 v5, 0x10000000

    :goto_10
    or-int/2addr v6, v5

    :cond_19
    :goto_11
    and-int/lit16 v5, v3, 0x400

    if-eqz v5, :cond_1a

    or-int/lit8 v16, v2, 0x6

    move-object/from16 v0, p8

    goto :goto_13

    :cond_1a
    and-int/lit8 v36, v2, 0x6

    move-object/from16 v0, p8

    if-nez v36, :cond_1c

    invoke-virtual {v4, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v36

    if-eqz v36, :cond_1b

    const/16 v16, 0x4

    goto :goto_12

    :cond_1b
    const/16 v16, 0x2

    :goto_12
    or-int v16, v2, v16

    goto :goto_13

    :cond_1c
    move/from16 v16, v2

    :goto_13
    and-int/lit16 v0, v3, 0x800

    if-eqz v0, :cond_1d

    or-int/lit8 v16, v16, 0x30

    move/from16 v21, v0

    move/from16 v37, v5

    move/from16 v36, v6

    move/from16 v0, v16

    move-wide/from16 v5, p9

    goto :goto_16

    :cond_1d
    and-int/lit8 v36, v2, 0x30

    move/from16 v37, v5

    if-nez v36, :cond_1f

    move/from16 v36, v6

    move-wide/from16 v5, p9

    invoke-virtual {v4, v5, v6}, Ll2/t;->f(J)Z

    move-result v38

    if-eqz v38, :cond_1e

    const/16 v21, 0x20

    goto :goto_14

    :cond_1e
    const/16 v21, 0x10

    :goto_14
    or-int v16, v16, v21

    :goto_15
    move/from16 v21, v0

    move/from16 v0, v16

    goto :goto_16

    :cond_1f
    move/from16 v36, v6

    move-wide/from16 v5, p9

    goto :goto_15

    :goto_16
    and-int/lit16 v5, v3, 0x1000

    if-eqz v5, :cond_21

    or-int/lit16 v0, v0, 0x180

    :cond_20
    move/from16 v6, p11

    goto :goto_18

    :cond_21
    and-int/lit16 v6, v2, 0x180

    if-nez v6, :cond_20

    move/from16 v6, p11

    invoke-virtual {v4, v6}, Ll2/t;->e(I)Z

    move-result v16

    if-eqz v16, :cond_22

    const/16 v20, 0x100

    goto :goto_17

    :cond_22
    const/16 v20, 0x80

    :goto_17
    or-int v0, v0, v20

    :goto_18
    move/from16 v16, v5

    and-int/lit16 v5, v3, 0x2000

    if-eqz v5, :cond_23

    or-int/lit16 v0, v0, 0xc00

    goto :goto_1b

    :cond_23
    move/from16 v20, v0

    and-int/lit16 v0, v2, 0xc00

    if-nez v0, :cond_25

    move/from16 v0, p12

    invoke-virtual {v4, v0}, Ll2/t;->h(Z)Z

    move-result v23

    if-eqz v23, :cond_24

    const/16 v23, 0x800

    goto :goto_19

    :cond_24
    const/16 v23, 0x400

    :goto_19
    or-int v20, v20, v23

    :goto_1a
    move/from16 v0, v20

    goto :goto_1b

    :cond_25
    move/from16 v0, p12

    goto :goto_1a

    :goto_1b
    move/from16 v20, v5

    and-int/lit16 v5, v3, 0x4000

    if-eqz v5, :cond_26

    or-int/lit16 v0, v0, 0x6000

    move/from16 v18, v0

    move/from16 v0, p13

    goto :goto_1c

    :cond_26
    move/from16 v23, v0

    and-int/lit16 v0, v2, 0x6000

    if-nez v0, :cond_28

    move/from16 v0, p13

    invoke-virtual {v4, v0}, Ll2/t;->e(I)Z

    move-result v38

    if-eqz v38, :cond_27

    move/from16 v18, v19

    :cond_27
    or-int v18, v23, v18

    goto :goto_1c

    :cond_28
    move/from16 v0, p13

    move/from16 v18, v23

    :goto_1c
    const v19, 0x8000

    and-int v19, v3, v19

    if-eqz v19, :cond_29

    or-int v18, v18, v25

    move/from16 v0, p14

    goto :goto_1d

    :cond_29
    and-int v23, v2, v25

    move/from16 v0, p14

    if-nez v23, :cond_2b

    invoke-virtual {v4, v0}, Ll2/t;->e(I)Z

    move-result v23

    if-eqz v23, :cond_2a

    move/from16 v22, v24

    :cond_2a
    or-int v18, v18, v22

    :cond_2b
    :goto_1d
    or-int v22, v18, v26

    and-int v23, v3, v24

    if-eqz v23, :cond_2c

    const/high16 v22, 0xd80000

    or-int v22, v18, v22

    move-object/from16 v0, p16

    goto :goto_1e

    :cond_2c
    and-int v18, v2, v29

    move-object/from16 v0, p16

    if-nez v18, :cond_2e

    invoke-virtual {v4, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v18

    if-eqz v18, :cond_2d

    move/from16 v27, v28

    :cond_2d
    or-int v22, v22, v27

    :cond_2e
    :goto_1e
    and-int v18, v2, v32

    const/high16 v24, 0x40000

    if-nez v18, :cond_30

    and-int v18, v3, v24

    move-object/from16 v0, p17

    if-nez v18, :cond_2f

    invoke-virtual {v4, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v18

    if-eqz v18, :cond_2f

    move/from16 v30, v31

    :cond_2f
    or-int v22, v22, v30

    goto :goto_1f

    :cond_30
    move-object/from16 v0, p17

    :goto_1f
    const v18, 0x12492493

    and-int v0, v36, v18

    const v2, 0x12492492

    const/16 v18, 0x1

    if-ne v0, v2, :cond_32

    const v0, 0x2492493

    and-int v0, v22, v0

    const v2, 0x2492492

    if-eq v0, v2, :cond_31

    goto :goto_20

    :cond_31
    const/4 v0, 0x0

    goto :goto_21

    :cond_32
    :goto_20
    move/from16 v0, v18

    :goto_21
    and-int/lit8 v2, v36, 0x1

    invoke-virtual {v4, v2, v0}, Ll2/t;->O(IZ)Z

    move-result v0

    if-eqz v0, :cond_4b

    invoke-virtual {v4}, Ll2/t;->T()V

    and-int/lit8 v0, p19, 0x1

    const p18, -0xe000001

    sget-object v2, Ll2/n;->a:Ll2/x0;

    if-eqz v0, :cond_35

    invoke-virtual {v4}, Ll2/t;->y()Z

    move-result v0

    if-eqz v0, :cond_33

    goto :goto_22

    .line 2
    :cond_33
    invoke-virtual {v4}, Ll2/t;->R()V

    and-int v0, p21, v24

    if-eqz v0, :cond_34

    and-int v22, v22, p18

    :cond_34
    move-object/from16 v0, p8

    move/from16 v16, p12

    move/from16 v5, p13

    move/from16 v17, p14

    move-object/from16 v20, p15

    move-object/from16 v3, p16

    move-object/from16 v21, p17

    move-wide v12, v13

    move-wide/from16 v14, p9

    goto/16 :goto_2c

    :cond_35
    :goto_22
    if-eqz v34, :cond_36

    .line 3
    sget-object v0, Lx2/p;->b:Lx2/p;

    move-object v11, v0

    :cond_36
    if-eqz v12, :cond_37

    .line 4
    sget-wide v9, Le3/s;->i:J

    :cond_37
    if-eqz v17, :cond_38

    .line 5
    sget-wide v12, Lt4/o;->c:J

    goto :goto_23

    :cond_38
    move-wide v12, v13

    :goto_23
    if-eqz v15, :cond_39

    .line 6
    sget-wide v7, Lt4/o;->c:J

    :cond_39
    if-eqz v37, :cond_3a

    const/4 v0, 0x0

    goto :goto_24

    :cond_3a
    move-object/from16 v0, p8

    :goto_24
    if-eqz v21, :cond_3b

    .line 7
    sget-wide v14, Lt4/o;->c:J

    goto :goto_25

    :cond_3b
    move-wide/from16 v14, p9

    :goto_25
    if-eqz v16, :cond_3c

    move/from16 v6, v18

    :cond_3c
    if-eqz v20, :cond_3d

    move/from16 v16, v18

    goto :goto_26

    :cond_3d
    move/from16 v16, p12

    :goto_26
    if-eqz v5, :cond_3e

    const v5, 0x7fffffff

    goto :goto_27

    :cond_3e
    move/from16 v5, p13

    :goto_27
    if-eqz v19, :cond_3f

    move/from16 v17, v18

    goto :goto_28

    :cond_3f
    move/from16 v17, p14

    :goto_28
    if-eqz v23, :cond_41

    .line 8
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v3

    if-ne v3, v2, :cond_40

    .line 9
    new-instance v3, Lh10/d;

    move-object/from16 p1, v0

    const/16 v0, 0x13

    invoke-direct {v3, v0}, Lh10/d;-><init>(I)V

    .line 10
    invoke-virtual {v4, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    goto :goto_29

    :cond_40
    move-object/from16 p1, v0

    .line 11
    :goto_29
    move-object v0, v3

    check-cast v0, Lay0/k;

    goto :goto_2a

    :cond_41
    move-object/from16 p1, v0

    move-object/from16 v0, p16

    :goto_2a
    and-int v3, p21, v24

    sget-object v20, Lmx0/t;->d:Lmx0/t;

    if-eqz v3, :cond_42

    .line 12
    sget-object v3, Lh2/rb;->a:Ll2/e0;

    .line 13
    invoke-virtual {v4, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lg4/p0;

    and-int v22, v22, p18

    move-object/from16 v21, v3

    :goto_2b
    move-object v3, v0

    move-object/from16 v0, p1

    goto :goto_2c

    :cond_42
    move-object/from16 v21, p17

    goto :goto_2b

    .line 14
    :goto_2c
    invoke-virtual {v4}, Ll2/t;->r()V

    move-object/from16 p15, v3

    const v3, 0x63f3c35c

    invoke-virtual {v4, v3}, Ll2/t;->Y(I)V

    const-wide/16 v23, 0x10

    cmp-long v3, v9, v23

    if-eqz v3, :cond_43

    move/from16 p17, v5

    move/from16 p16, v6

    move-wide/from16 v25, v9

    const/4 v3, 0x0

    goto :goto_2f

    :cond_43
    const v3, 0x63f3c661

    .line 15
    invoke-virtual {v4, v3}, Ll2/t;->Y(I)V

    .line 16
    invoke-virtual/range {v21 .. v21}, Lg4/p0;->b()J

    move-result-wide v25

    cmp-long v3, v25, v23

    if-eqz v3, :cond_44

    move/from16 p17, v5

    move/from16 p16, v6

    :goto_2d
    const/4 v3, 0x0

    goto :goto_2e

    .line 17
    :cond_44
    sget-object v3, Lh2/p1;->a:Ll2/e0;

    .line 18
    invoke-virtual {v4, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v3

    .line 19
    check-cast v3, Le3/s;

    move/from16 p17, v5

    move/from16 p16, v6

    .line 20
    iget-wide v5, v3, Le3/s;->a:J

    move-wide/from16 v25, v5

    goto :goto_2d

    .line 21
    :goto_2e
    invoke-virtual {v4, v3}, Ll2/t;->q(Z)V

    :goto_2f
    invoke-virtual {v4, v3}, Ll2/t;->q(Z)V

    .line 22
    sget-object v5, Lh2/g1;->a:Ll2/u2;

    .line 23
    invoke-virtual {v4, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v5

    .line 24
    check-cast v5, Lh2/f1;

    .line 25
    iget-wide v5, v5, Lh2/f1;->a:J

    .line 26
    invoke-virtual {v4, v5, v6}, Ll2/t;->f(J)Z

    move-result v19

    .line 27
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v3

    if-nez v19, :cond_45

    if-ne v3, v2, :cond_46

    .line 28
    :cond_45
    new-instance v3, Lg4/m0;

    .line 29
    new-instance v37, Lg4/g0;

    const/16 v55, 0x0

    const v56, 0xeffe

    const-wide/16 v40, 0x0

    const/16 v42, 0x0

    const/16 v43, 0x0

    const/16 v44, 0x0

    const/16 v45, 0x0

    const/16 v46, 0x0

    const-wide/16 v47, 0x0

    const/16 v49, 0x0

    const/16 v50, 0x0

    const/16 v51, 0x0

    const-wide/16 v52, 0x0

    sget-object v54, Lr4/l;->c:Lr4/l;

    move-wide/from16 v38, v5

    invoke-direct/range {v37 .. v56}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;I)V

    move-object/from16 v5, v37

    const/4 v6, 0x0

    .line 30
    invoke-direct {v3, v5, v6, v6, v6}, Lg4/m0;-><init>(Lg4/g0;Lg4/g0;Lg4/g0;Lg4/g0;)V

    .line 31
    invoke-virtual {v4, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 32
    :cond_46
    check-cast v3, Lg4/m0;

    and-int/lit8 v5, v36, 0xe

    const/4 v6, 0x4

    if-ne v5, v6, :cond_47

    goto :goto_30

    :cond_47
    const/16 v18, 0x0

    .line 33
    :goto_30
    invoke-virtual {v4, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v5

    or-int v5, v18, v5

    .line 34
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v6

    if-nez v5, :cond_48

    if-ne v6, v2, :cond_49

    .line 35
    :cond_48
    new-instance v2, Le81/w;

    const/16 v5, 0x14

    invoke-direct {v2, v3, v5}, Le81/w;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v1, v2}, Lg4/g;->c(Lay0/k;)Lg4/g;

    move-result-object v6

    .line 36
    invoke-virtual {v4, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 37
    :cond_49
    check-cast v6, Lg4/g;

    if-eqz v0, :cond_4a

    .line 38
    iget v2, v0, Lr4/k;->a:I

    goto :goto_31

    :cond_4a
    const/high16 v2, -0x80000000

    :goto_31
    const v3, 0xfd6f50

    const/4 v5, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    move/from16 p11, v2

    move/from16 p14, v3

    move-object/from16 p6, v5

    move-wide/from16 p8, v7

    move-wide/from16 p4, v12

    move-wide/from16 p12, v14

    move-object/from16 p7, v18

    move-object/from16 p10, v19

    move-object/from16 p1, v21

    move-wide/from16 p2, v25

    .line 39
    invoke-static/range {p1 .. p14}, Lg4/p0;->e(Lg4/p0;JJLk4/x;Lk4/t;JLr4/l;IJI)Lg4/p0;

    move-result-object v2

    move-object/from16 v3, p1

    and-int/lit8 v5, v36, 0x70

    move-object/from16 p14, v0

    shr-int/lit8 v0, v22, 0xc

    and-int/lit16 v0, v0, 0x1c00

    or-int/2addr v0, v5

    shl-int/lit8 v5, v22, 0x6

    const v18, 0xe000

    and-int v18, v5, v18

    or-int v0, v0, v18

    const/high16 v18, 0x70000

    and-int v18, v5, v18

    or-int v0, v0, v18

    const/high16 v18, 0x380000

    and-int v18, v5, v18

    or-int v0, v0, v18

    const/high16 v18, 0x1c00000

    and-int v18, v5, v18

    or-int v0, v0, v18

    const/high16 v18, 0xe000000

    and-int v5, v5, v18

    or-int/2addr v0, v5

    shr-int/lit8 v5, v36, 0x9

    and-int/lit8 v5, v5, 0xe

    const/16 v18, 0x200

    move-object/from16 p4, p15

    move/from16 p5, p16

    move/from16 p7, p17

    move/from16 p11, v0

    move-object/from16 p3, v2

    move-object/from16 p10, v4

    move/from16 p12, v5

    move-object/from16 p1, v6

    move-object/from16 p2, v11

    move/from16 p6, v16

    move/from16 p8, v17

    move/from16 p13, v18

    move-object/from16 p9, v20

    .line 40
    invoke-static/range {p1 .. p13}, Lt1/l0;->a(Lg4/g;Lx2/s;Lg4/p0;Lay0/k;IZIILjava/util/Map;Ll2/o;III)V

    move-object/from16 v2, p4

    move/from16 v6, p5

    move/from16 v5, p7

    move-object/from16 v0, p10

    move-object/from16 v18, v3

    move-wide v3, v9

    move-object/from16 v9, p14

    move/from16 v58, v17

    move-object/from16 v17, v2

    move-object v2, v11

    move-wide v10, v14

    move/from16 v15, v58

    move v14, v5

    move-wide/from16 v58, v12

    move v12, v6

    move-wide/from16 v5, v58

    move/from16 v13, v16

    move-object/from16 v16, v20

    goto :goto_32

    :cond_4b
    move-object v0, v4

    .line 41
    invoke-virtual {v0}, Ll2/t;->R()V

    move/from16 v15, p14

    move-object/from16 v16, p15

    move-object/from16 v17, p16

    move-object/from16 v18, p17

    move v12, v6

    move-wide v3, v9

    move-object v2, v11

    move-wide v5, v13

    move-object/from16 v9, p8

    move-wide/from16 v10, p9

    move/from16 v13, p12

    move/from16 v14, p13

    .line 42
    :goto_32
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    move-result-object v0

    if-eqz v0, :cond_4c

    move-object/from16 v19, v0

    new-instance v0, Lh2/qb;

    move/from16 v20, p20

    move/from16 v21, p21

    move-object/from16 v57, v19

    move/from16 v19, p19

    invoke-direct/range {v0 .. v21}, Lh2/qb;-><init>(Lg4/g;Lx2/s;JJJLr4/k;JIZIILjava/util/Map;Lay0/k;Lg4/p0;III)V

    move-object v1, v0

    move-object/from16 v0, v57

    .line 43
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    :cond_4c
    return-void
.end method
