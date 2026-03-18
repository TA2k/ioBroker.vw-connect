.class public abstract Li91/m3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F

.field public static final c:F

.field public static final d:Li91/a4;

.field public static final e:Li91/a4;


# direct methods
.method static constructor <clinit>()V
    .locals 9

    .line 1
    const/16 v0, 0x2c

    .line 2
    .line 3
    int-to-float v3, v0

    .line 4
    sput v3, Li91/m3;->a:F

    .line 5
    .line 6
    const/4 v0, 0x4

    .line 7
    int-to-float v0, v0

    .line 8
    sput v0, Li91/m3;->b:F

    .line 9
    .line 10
    const/16 v0, 0x30

    .line 11
    .line 12
    int-to-float v2, v0

    .line 13
    sput v2, Li91/m3;->c:F

    .line 14
    .line 15
    const/16 v0, 0xa

    .line 16
    .line 17
    int-to-float v5, v0

    .line 18
    const/16 v0, 0x8

    .line 19
    .line 20
    int-to-float v4, v0

    .line 21
    const/16 v0, 0x10

    .line 22
    .line 23
    int-to-float v6, v0

    .line 24
    new-instance v1, Li91/a4;

    .line 25
    .line 26
    move v7, v5

    .line 27
    invoke-direct/range {v1 .. v7}, Li91/a4;-><init>(FFFFFF)V

    .line 28
    .line 29
    .line 30
    sput-object v1, Li91/m3;->d:Li91/a4;

    .line 31
    .line 32
    new-instance v1, Li91/a4;

    .line 33
    .line 34
    move v8, v6

    .line 35
    move v6, v4

    .line 36
    move v4, v8

    .line 37
    invoke-direct/range {v1 .. v7}, Li91/a4;-><init>(FFFFFF)V

    .line 38
    .line 39
    .line 40
    sput-object v1, Li91/m3;->e:Li91/a4;

    .line 41
    .line 42
    return-void
.end method

.method public static final a(Ljava/lang/String;Ljava/lang/String;Lay0/k;Lx2/s;ZZLi91/j0;Li91/j0;Lt1/o0;Lt1/n0;Ll2/o;II)V
    .locals 30

    move-object/from16 v12, p1

    move-object/from16 v3, p2

    move/from16 v13, p11

    move/from16 v14, p12

    const-string v0, "placeholder"

    invoke-static {v12, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "onValueChange"

    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    move-object/from16 v15, p10

    check-cast v15, Ll2/t;

    const v0, 0x67c17297

    invoke-virtual {v15, v0}, Ll2/t;->a0(I)Ll2/t;

    and-int/lit8 v0, v13, 0x6

    if-nez v0, :cond_1

    move-object/from16 v0, p0

    invoke-virtual {v15, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_0

    const/4 v2, 0x4

    goto :goto_0

    :cond_0
    const/4 v2, 0x2

    :goto_0
    or-int/2addr v2, v13

    goto :goto_1

    :cond_1
    move-object/from16 v0, p0

    move v2, v13

    :goto_1
    and-int/lit8 v4, v13, 0x30

    if-nez v4, :cond_3

    invoke-virtual {v15, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_2

    const/16 v4, 0x20

    goto :goto_2

    :cond_2
    const/16 v4, 0x10

    :goto_2
    or-int/2addr v2, v4

    :cond_3
    and-int/lit16 v4, v13, 0x180

    if-nez v4, :cond_5

    invoke-virtual {v15, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_4

    const/16 v4, 0x100

    goto :goto_3

    :cond_4
    const/16 v4, 0x80

    :goto_3
    or-int/2addr v2, v4

    :cond_5
    and-int/lit8 v4, v14, 0x8

    if-eqz v4, :cond_7

    or-int/lit16 v2, v2, 0xc00

    :cond_6
    move-object/from16 v5, p3

    goto :goto_5

    :cond_7
    and-int/lit16 v5, v13, 0xc00

    if-nez v5, :cond_6

    move-object/from16 v5, p3

    invoke-virtual {v15, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_8

    const/16 v6, 0x800

    goto :goto_4

    :cond_8
    const/16 v6, 0x400

    :goto_4
    or-int/2addr v2, v6

    :goto_5
    or-int/lit16 v6, v2, 0x6000

    and-int/lit8 v7, v14, 0x20

    if-eqz v7, :cond_a

    const v6, 0x36000

    or-int/2addr v6, v2

    :cond_9
    move/from16 v2, p5

    goto :goto_7

    :cond_a
    const/high16 v2, 0x30000

    and-int/2addr v2, v13

    if-nez v2, :cond_9

    move/from16 v2, p5

    invoke-virtual {v15, v2}, Ll2/t;->h(Z)Z

    move-result v8

    if-eqz v8, :cond_b

    const/high16 v8, 0x20000

    goto :goto_6

    :cond_b
    const/high16 v8, 0x10000

    :goto_6
    or-int/2addr v6, v8

    :goto_7
    const/high16 v8, 0x180000

    or-int/2addr v8, v6

    and-int/lit16 v9, v14, 0x80

    if-eqz v9, :cond_d

    const/high16 v8, 0xd80000

    or-int/2addr v8, v6

    :cond_c
    move-object/from16 v6, p6

    goto :goto_9

    :cond_d
    const/high16 v6, 0xc00000

    and-int/2addr v6, v13

    if-nez v6, :cond_c

    move-object/from16 v6, p6

    invoke-virtual {v15, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_e

    const/high16 v10, 0x800000

    goto :goto_8

    :cond_e
    const/high16 v10, 0x400000

    :goto_8
    or-int/2addr v8, v10

    :goto_9
    and-int/lit16 v10, v14, 0x100

    const/high16 v11, 0x6000000

    if-eqz v10, :cond_10

    or-int/2addr v8, v11

    :cond_f
    move-object/from16 v11, p7

    goto :goto_b

    :cond_10
    and-int/2addr v11, v13

    if-nez v11, :cond_f

    move-object/from16 v11, p7

    invoke-virtual {v15, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v16

    if-eqz v16, :cond_11

    const/high16 v16, 0x4000000

    goto :goto_a

    :cond_11
    const/high16 v16, 0x2000000

    :goto_a
    or-int v8, v8, v16

    :goto_b
    const/high16 v16, 0x30000000

    or-int v8, v8, v16

    const v16, 0x12492493

    and-int v1, v8, v16

    const v0, 0x12492492

    const/16 v16, 0x1

    const/4 v2, 0x0

    if-ne v1, v0, :cond_12

    move v0, v2

    goto :goto_c

    :cond_12
    move/from16 v0, v16

    :goto_c
    and-int/lit8 v1, v8, 0x1

    invoke-virtual {v15, v1, v0}, Ll2/t;->O(IZ)Z

    move-result v0

    if-eqz v0, :cond_1d

    invoke-virtual {v15}, Ll2/t;->T()V

    and-int/lit8 v0, v13, 0x1

    if-eqz v0, :cond_14

    invoke-virtual {v15}, Ll2/t;->y()Z

    move-result v0

    if-eqz v0, :cond_13

    goto :goto_e

    .line 2
    :cond_13
    invoke-virtual {v15}, Ll2/t;->R()V

    move/from16 v28, p5

    move-object/from16 v9, p8

    move-object/from16 v10, p9

    move-object v4, v6

    move/from16 v6, p4

    :goto_d
    move-object v0, v5

    move-object v5, v11

    goto :goto_10

    :cond_14
    :goto_e
    if-eqz v4, :cond_15

    .line 3
    sget-object v0, Lx2/p;->b:Lx2/p;

    move-object v5, v0

    :cond_15
    if-eqz v7, :cond_16

    move v0, v2

    goto :goto_f

    :cond_16
    move/from16 v0, p5

    :goto_f
    if-eqz v9, :cond_17

    .line 4
    sget-object v1, Li91/n2;->h:Li91/n2;

    move-object v6, v1

    :cond_17
    if-eqz v10, :cond_18

    .line 5
    sget-object v1, Li91/p2;->h:Li91/p2;

    move-object v11, v1

    .line 6
    :cond_18
    sget-object v1, Lt1/o0;->e:Lt1/o0;

    .line 7
    new-instance v4, Lt1/n0;

    const/16 v7, 0x3f

    const/4 v8, 0x0

    invoke-direct {v4, v8, v8, v8, v7}, Lt1/n0;-><init>(Lay0/k;Lay0/k;Lay0/k;I)V

    move/from16 v28, v0

    move-object v9, v1

    move-object v10, v4

    move-object v4, v6

    move/from16 v6, v16

    goto :goto_d

    .line 8
    :goto_10
    invoke-virtual {v15}, Ll2/t;->r()V

    .line 9
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v1

    .line 10
    sget-object v7, Ll2/n;->a:Ll2/x0;

    if-ne v1, v7, :cond_19

    .line 11
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    move-result-object v1

    .line 12
    invoke-virtual {v15, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 13
    :cond_19
    move-object v11, v1

    check-cast v11, Ll2/b1;

    if-eqz v28, :cond_1a

    const v1, 0x7d2f8273

    .line 14
    invoke-virtual {v15, v1}, Ll2/t;->Y(I)V

    .line 15
    sget-object v1, Lj91/h;->a:Ll2/u2;

    .line 16
    invoke-virtual {v15, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v1

    .line 17
    check-cast v1, Lj91/e;

    .line 18
    invoke-virtual {v1}, Lj91/e;->h()J

    move-result-wide v17

    .line 19
    :goto_11
    invoke-virtual {v15, v2}, Ll2/t;->q(Z)V

    goto :goto_12

    :cond_1a
    const v1, 0x7d2f88ca

    .line 20
    invoke-virtual {v15, v1}, Ll2/t;->Y(I)V

    .line 21
    sget-object v1, Lj91/h;->a:Ll2/u2;

    .line 22
    invoke-virtual {v15, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v1

    .line 23
    check-cast v1, Lj91/e;

    .line 24
    invoke-virtual {v1}, Lj91/e;->c()J

    move-result-wide v17

    goto :goto_11

    .line 25
    :goto_12
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v7, :cond_1b

    .line 26
    invoke-static {v15}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->g(Ll2/t;)Li1/l;

    move-result-object v1

    .line 27
    :cond_1b
    move-object v7, v1

    check-cast v7, Li1/l;

    if-eqz v28, :cond_1c

    const/4 v1, 0x2

    int-to-float v1, v1

    :goto_13
    move/from16 v22, v1

    move/from16 v1, v16

    goto :goto_14

    :cond_1c
    int-to-float v1, v2

    goto :goto_13

    .line 28
    :goto_14
    invoke-static {}, Ls1/f;->a()Ls1/e;

    move-result-object v16

    int-to-float v1, v1

    .line 29
    sget-object v2, Lj91/h;->a:Ll2/u2;

    .line 30
    invoke-virtual {v15, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v2

    .line 31
    check-cast v2, Lj91/e;

    .line 32
    invoke-virtual {v2}, Lj91/e;->t()J

    move-result-wide v2

    .line 33
    invoke-static {}, Ls1/f;->a()Ls1/e;

    move-result-object v8

    .line 34
    invoke-static {v1, v2, v3, v8, v0}, Lkp/g;->a(FJLe3/n0;Lx2/s;)Lx2/s;

    move-result-object v19

    move-object v1, v0

    .line 35
    new-instance v0, Li91/h3;

    move-object/from16 v3, p0

    move-object/from16 v8, p2

    move-object/from16 v29, v1

    move-wide/from16 v1, v17

    invoke-direct/range {v0 .. v12}, Li91/h3;-><init>(JLjava/lang/String;Li91/j0;Li91/j0;ZLi1/l;Lay0/k;Lt1/o0;Lt1/n0;Ll2/b1;Ljava/lang/String;)V

    const v3, -0x1d6fc40e

    invoke-static {v3, v15, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    move-result-object v24

    const/high16 v26, 0xc00000

    const/16 v27, 0x58

    move-object/from16 v25, v15

    move-object/from16 v15, v19

    const-wide/16 v19, 0x0

    const/16 v21, 0x0

    const/16 v23, 0x0

    .line 36
    invoke-static/range {v15 .. v27}, Lh2/oa;->a(Lx2/s;Le3/n0;JJFFLe1/t;Lt2/b;Ll2/o;II)V

    move-object v7, v4

    move-object v8, v5

    move v5, v6

    move/from16 v6, v28

    move-object/from16 v4, v29

    goto :goto_15

    :cond_1d
    move-object/from16 v25, v15

    .line 37
    invoke-virtual/range {v25 .. v25}, Ll2/t;->R()V

    move-object/from16 v9, p8

    move-object/from16 v10, p9

    move-object v4, v5

    move-object v7, v6

    move-object v8, v11

    move/from16 v5, p4

    move/from16 v6, p5

    .line 38
    :goto_15
    invoke-virtual/range {v25 .. v25}, Ll2/t;->s()Ll2/u1;

    move-result-object v15

    if-eqz v15, :cond_1e

    new-instance v0, Li91/i3;

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    move v11, v13

    move v12, v14

    invoke-direct/range {v0 .. v12}, Li91/i3;-><init>(Ljava/lang/String;Ljava/lang/String;Lay0/k;Lx2/s;ZZLi91/j0;Li91/j0;Lt1/o0;Lt1/n0;II)V

    .line 39
    iput-object v0, v15, Ll2/u1;->d:Lay0/n;

    :cond_1e
    return-void
.end method
