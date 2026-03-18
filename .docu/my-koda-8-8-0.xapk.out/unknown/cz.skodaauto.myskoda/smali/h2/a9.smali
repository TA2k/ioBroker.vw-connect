.class public final Lh2/a9;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lh2/a9;

.field public static final b:F

.field public static final c:F

.field public static final d:Le3/i;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lh2/a9;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lh2/a9;->a:Lh2/a9;

    .line 7
    .line 8
    sget v0, Lk2/i0;->n:F

    .line 9
    .line 10
    sput v0, Lh2/a9;->b:F

    .line 11
    .line 12
    sput v0, Lh2/a9;->c:F

    .line 13
    .line 14
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    sput-object v0, Lh2/a9;->d:Le3/i;

    .line 19
    .line 20
    return-void
.end method

.method public static e(Ll2/o;)Lh2/u8;
    .locals 1

    .line 1
    sget-object v0, Lh2/g1;->a:Ll2/u2;

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
    check-cast p0, Lh2/f1;

    .line 10
    .line 11
    invoke-static {p0}, Lh2/a9;->i(Lh2/f1;)Lh2/u8;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public static f(Lg3/d;JFJ)V
    .locals 9

    .line 1
    invoke-interface {p0, p3}, Lt4/c;->w0(F)F

    .line 2
    .line 3
    .line 4
    move-result p3

    .line 5
    const/high16 v0, 0x40000000    # 2.0f

    .line 6
    .line 7
    div-float v4, p3, v0

    .line 8
    .line 9
    const/4 v7, 0x0

    .line 10
    const/16 v8, 0x78

    .line 11
    .line 12
    move-object v1, p0

    .line 13
    move-wide v5, p1

    .line 14
    move-wide v2, p4

    .line 15
    invoke-static/range {v1 .. v8}, Lg3/d;->u0(Lg3/d;JFJLg3/e;I)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public static g(Lg3/d;[FFFJJJJFFFFFFFLay0/n;Lay0/o;ZLg1/w1;)V
    .locals 28

    move-object/from16 v0, p0

    move-object/from16 v10, p1

    move/from16 v1, p2

    move/from16 v2, p3

    move/from16 v3, p16

    move-object/from16 v11, p19

    .line 1
    sget-object v4, Lg1/w1;->d:Lg1/w1;

    const/4 v12, 0x0

    move-object/from16 v5, p22

    if-ne v5, v4, :cond_0

    const/4 v14, 0x1

    goto :goto_0

    :cond_0
    move v14, v12

    .line 2
    :goto_0
    invoke-interface {v0}, Lg3/d;->getLayoutDirection()Lt4/m;

    move-result-object v4

    sget-object v6, Lt4/m;->e:Lt4/m;

    if-ne v4, v6, :cond_1

    const/4 v15, 0x1

    goto :goto_1

    :cond_1
    move v15, v12

    :goto_1
    if-eqz v15, :cond_2

    if-nez v14, :cond_2

    const/16 v16, 0x1

    :goto_2
    move/from16 v4, p18

    goto :goto_3

    :cond_2
    move/from16 v16, v12

    goto :goto_2

    .line 3
    :goto_3
    invoke-interface {v0, v4}, Lt4/c;->w0(F)F

    move-result v17

    const/16 v18, 0x20

    const-wide v19, 0xffffffffL

    .line 4
    invoke-interface {v0}, Lg3/d;->e()J

    move-result-wide v6

    if-eqz v14, :cond_3

    and-long v6, v6, v19

    :goto_4
    long-to-int v4, v6

    .line 5
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v4

    goto :goto_5

    :cond_3
    shr-long v6, v6, v18

    goto :goto_4

    .line 6
    :goto_5
    invoke-static {v10}, Lmx0/n;->v([F)Ljava/lang/Float;

    move-result-object v6

    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->a(FLjava/lang/Float;)Z

    move-result v6

    if-nez v6, :cond_5

    .line 7
    invoke-static {v10}, Lmx0/n;->K([F)Ljava/lang/Float;

    move-result-object v6

    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->a(FLjava/lang/Float;)Z

    move-result v6

    if-eqz v6, :cond_4

    goto :goto_6

    :cond_4
    move v6, v12

    goto :goto_7

    :cond_5
    :goto_6
    const/4 v6, 0x1

    .line 8
    :goto_7
    invoke-static {v10}, Lmx0/n;->v([F)Ljava/lang/Float;

    move-result-object v7

    invoke-static {v2, v7}, Lkotlin/jvm/internal/m;->a(FLjava/lang/Float;)Z

    move-result v7

    if-nez v7, :cond_7

    .line 9
    invoke-static {v10}, Lmx0/n;->K([F)Ljava/lang/Float;

    move-result-object v7

    invoke-static {v2, v7}, Lkotlin/jvm/internal/m;->a(FLjava/lang/Float;)Z

    move-result v7

    if-eqz v7, :cond_6

    goto :goto_8

    :cond_6
    move v7, v12

    goto :goto_9

    :cond_7
    :goto_8
    const/4 v7, 0x1

    .line 10
    :goto_9
    array-length v8, v10

    const/4 v9, 0x2

    const/16 v21, 0x1

    const/4 v13, 0x0

    if-nez v8, :cond_8

    goto :goto_b

    :cond_8
    if-nez v7, :cond_9

    sub-float v7, v4, v13

    int-to-float v8, v9

    mul-float v8, v8, v17

    sub-float/2addr v7, v8

    mul-float/2addr v7, v2

    add-float/2addr v7, v13

    add-float v7, v7, v17

    :goto_a
    move/from16 v22, v7

    goto :goto_c

    :cond_9
    :goto_b
    invoke-static {v4, v13, v2, v13}, La7/g0;->b(FFFF)F

    move-result v7

    goto :goto_a

    .line 11
    :goto_c
    array-length v2, v10

    if-nez v2, :cond_a

    goto :goto_e

    :cond_a
    if-nez v6, :cond_b

    sub-float v2, v4, v13

    int-to-float v6, v9

    mul-float v6, v6, v17

    sub-float/2addr v2, v6

    mul-float/2addr v2, v1

    add-float/2addr v2, v13

    add-float v2, v2, v17

    :goto_d
    move/from16 v1, p17

    move/from16 v23, v2

    goto :goto_f

    :cond_b
    :goto_e
    invoke-static {v4, v13, v1, v13}, La7/g0;->b(FFFF)F

    move-result v2

    goto :goto_d

    .line 12
    :goto_f
    invoke-interface {v0, v1}, Lt4/c;->w0(F)F

    move-result v24

    int-to-float v1, v12

    .line 13
    invoke-static {v3, v1}, Ljava/lang/Float;->compare(FF)I

    move-result v1

    if-lez v1, :cond_d

    if-eqz v14, :cond_c

    move/from16 v1, p13

    .line 14
    invoke-interface {v0, v1}, Lt4/c;->w0(F)F

    move-result v1

    int-to-float v2, v9

    div-float/2addr v1, v2

    invoke-interface {v0, v3}, Lt4/c;->w0(F)F

    move-result v6

    add-float/2addr v6, v1

    move/from16 v1, p15

    .line 15
    invoke-interface {v0, v1}, Lt4/c;->w0(F)F

    move-result v1

    div-float/2addr v1, v2

    invoke-interface {v0, v3}, Lt4/c;->w0(F)F

    move-result v2

    :goto_10
    add-float/2addr v2, v1

    move/from16 v25, v2

    move/from16 v26, v6

    goto :goto_11

    :cond_c
    move/from16 v1, p12

    .line 16
    invoke-interface {v0, v1}, Lt4/c;->w0(F)F

    move-result v1

    int-to-float v2, v9

    div-float/2addr v1, v2

    invoke-interface {v0, v3}, Lt4/c;->w0(F)F

    move-result v6

    add-float/2addr v6, v1

    move/from16 v1, p14

    .line 17
    invoke-interface {v0, v1}, Lt4/c;->w0(F)F

    move-result v1

    div-float/2addr v1, v2

    invoke-interface {v0, v3}, Lt4/c;->w0(F)F

    move-result v2

    goto :goto_10

    :cond_d
    move/from16 v25, v13

    move/from16 v26, v25

    .line 18
    :goto_11
    invoke-interface {v0}, Lg3/d;->D0()J

    move-result-wide v1

    if-eqz v14, :cond_e

    and-long v1, v1, v19

    :goto_12
    long-to-int v1, v1

    .line 19
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    goto :goto_13

    :cond_e
    shr-long v1, v1, v18

    goto :goto_12

    :goto_13
    add-float v1, v26, v13

    add-float v1, v1, v17

    if-eqz p21, :cond_15

    cmpl-float v1, v23, v1

    if-lez v1, :cond_15

    if-eqz v16, :cond_f

    move/from16 v8, v24

    goto :goto_14

    :cond_f
    move/from16 v8, v17

    :goto_14
    if-eqz v16, :cond_10

    move/from16 v9, v17

    goto :goto_15

    :cond_10
    move/from16 v9, v24

    :goto_15
    sub-float v1, v23, v26

    if-eqz v16, :cond_11

    .line 20
    invoke-interface {v0}, Lg3/d;->e()J

    move-result-wide v2

    shr-long v2, v2, v18

    long-to-int v2, v2

    .line 21
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v2

    sub-float/2addr v2, v1

    .line 22
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v2

    int-to-long v2, v2

    .line 23
    invoke-static {v13}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v6

    :goto_16
    int-to-long v6, v6

    shl-long v2, v2, v18

    and-long v6, v6, v19

    or-long/2addr v2, v6

    goto :goto_17

    .line 24
    :cond_11
    invoke-static {v13}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v2

    int-to-long v2, v2

    .line 25
    invoke-static {v13}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v6

    goto :goto_16

    :goto_17
    if-eqz v14, :cond_12

    .line 26
    invoke-interface {v0}, Lg3/d;->e()J

    move-result-wide v6

    shr-long v6, v6, v18

    long-to-int v6, v6

    .line 27
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v6

    sub-float/2addr v1, v13

    .line 28
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v6

    int-to-long v6, v6

    .line 29
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    move/from16 p18, v13

    int-to-long v12, v1

    shl-long v6, v6, v18

    and-long v12, v12, v19

    or-long/2addr v6, v12

    :goto_18
    move v12, v4

    move-object v1, v5

    move-wide v4, v6

    move-wide/from16 v6, p4

    goto :goto_19

    :cond_12
    move/from16 p18, v13

    sub-float v1, v1, p18

    .line 30
    invoke-interface {v0}, Lg3/d;->e()J

    move-result-wide v6

    and-long v6, v6, v19

    long-to-int v6, v6

    .line 31
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v6

    .line 32
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v12, v1

    .line 33
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v6, v1

    shl-long v12, v12, v18

    and-long v6, v6, v19

    or-long/2addr v6, v12

    goto :goto_18

    .line 34
    :goto_19
    invoke-static/range {v0 .. v9}, Lh2/a9;->h(Lg3/d;Lg1/w1;JJJFF)V

    if-eqz v14, :cond_13

    .line 35
    invoke-interface {v0}, Lg3/d;->D0()J

    move-result-wide v1

    shr-long v1, v1, v18

    long-to-int v1, v1

    .line 36
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v1

    add-float v13, v17, p18

    .line 37
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v1, v1

    .line 38
    invoke-static {v13}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v3

    int-to-long v3, v3

    shl-long v1, v1, v18

    and-long v3, v3, v19

    :goto_1a
    or-long/2addr v1, v3

    goto :goto_1b

    :cond_13
    if-eqz v15, :cond_14

    .line 39
    invoke-interface {v0}, Lg3/d;->e()J

    move-result-wide v1

    shr-long v1, v1, v18

    long-to-int v1, v1

    .line 40
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v1

    sub-float v1, v1, p18

    sub-float v1, v1, v17

    .line 41
    invoke-interface {v0}, Lg3/d;->D0()J

    move-result-wide v2

    and-long v2, v2, v19

    long-to-int v2, v2

    .line 42
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v2

    .line 43
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v3, v1

    .line 44
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v1, v1

    shl-long v3, v3, v18

    and-long v1, v1, v19

    or-long/2addr v1, v3

    goto :goto_1b

    :cond_14
    add-float v13, v17, p18

    .line 45
    invoke-interface {v0}, Lg3/d;->D0()J

    move-result-wide v1

    and-long v1, v1, v19

    long-to-int v1, v1

    .line 46
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v1

    .line 47
    invoke-static {v13}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v2

    int-to-long v2, v2

    .line 48
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v4, v1

    shl-long v1, v2, v18

    and-long v3, v4, v19

    goto :goto_1a

    :goto_1b
    if-eqz v11, :cond_16

    .line 49
    new-instance v3, Ld3/b;

    invoke-direct {v3, v1, v2}, Ld3/b;-><init>(J)V

    .line 50
    invoke-interface {v11, v0, v3}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_1c

    :cond_15
    move v12, v4

    move/from16 p18, v13

    :cond_16
    :goto_1c
    sub-float v4, v12, v25

    sub-float v4, v4, v17

    cmpg-float v1, v22, v4

    if-gez v1, :cond_1f

    if-eqz v16, :cond_17

    move/from16 v8, v17

    goto :goto_1d

    :cond_17
    move/from16 v8, v24

    :goto_1d
    if-eqz v16, :cond_18

    move/from16 v9, v24

    goto :goto_1e

    :cond_18
    move/from16 v9, v17

    :goto_1e
    add-float v1, v22, v25

    sub-float v4, v12, v1

    if-eqz v14, :cond_19

    .line 51
    invoke-static/range {p18 .. p18}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v2

    int-to-long v2, v2

    .line 52
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v5

    :goto_1f
    int-to-long v5, v5

    shl-long v2, v2, v18

    and-long v5, v5, v19

    or-long/2addr v2, v5

    goto :goto_20

    :cond_19
    if-eqz v15, :cond_1a

    .line 53
    invoke-static/range {p18 .. p18}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v2

    int-to-long v2, v2

    .line 54
    invoke-static/range {p18 .. p18}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v5

    goto :goto_1f

    .line 55
    :cond_1a
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v2

    int-to-long v2, v2

    .line 56
    invoke-static/range {p18 .. p18}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v5

    goto :goto_1f

    :goto_20
    if-eqz v14, :cond_1b

    .line 57
    invoke-interface {v0}, Lg3/d;->e()J

    move-result-wide v5

    shr-long v5, v5, v18

    long-to-int v1, v5

    .line 58
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v1

    .line 59
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v5, v1

    .line 60
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v0, v1

    shl-long v4, v5, v18

    :goto_21
    and-long v0, v0, v19

    or-long/2addr v0, v4

    move-wide/from16 v6, p4

    move-wide v4, v0

    move-object/from16 v0, p0

    move-object/from16 v1, p22

    goto :goto_23

    :cond_1b
    if-eqz v15, :cond_1c

    if-nez p21, :cond_1c

    .line 61
    invoke-interface/range {p0 .. p0}, Lg3/d;->e()J

    move-result-wide v4

    shr-long v4, v4, v18

    long-to-int v0, v4

    .line 62
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v0

    sub-float/2addr v0, v1

    .line 63
    invoke-interface/range {p0 .. p0}, Lg3/d;->e()J

    move-result-wide v4

    and-long v4, v4, v19

    long-to-int v1, v4

    .line 64
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v1

    .line 65
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v0

    int-to-long v4, v0

    .line 66
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v0

    :goto_22
    int-to-long v0, v0

    shl-long v4, v4, v18

    goto :goto_21

    .line 67
    :cond_1c
    invoke-interface/range {p0 .. p0}, Lg3/d;->e()J

    move-result-wide v0

    and-long v0, v0, v19

    long-to-int v0, v0

    .line 68
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v0

    .line 69
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v4, v1

    .line 70
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v0

    goto :goto_22

    .line 71
    :goto_23
    invoke-static/range {v0 .. v9}, Lh2/a9;->h(Lg3/d;Lg1/w1;JJJFF)V

    if-eqz v14, :cond_1d

    .line 72
    invoke-interface {v0}, Lg3/d;->D0()J

    move-result-wide v1

    shr-long v1, v1, v18

    long-to-int v1, v1

    .line 73
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v1

    sub-float v4, v12, v17

    .line 74
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v1, v1

    .line 75
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v3

    int-to-long v3, v3

    shl-long v1, v1, v18

    and-long v3, v3, v19

    :goto_24
    or-long/2addr v1, v3

    goto :goto_26

    :cond_1d
    if-eqz v15, :cond_1e

    .line 76
    invoke-interface {v0}, Lg3/d;->D0()J

    move-result-wide v1

    and-long v1, v1, v19

    long-to-int v1, v1

    .line 77
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v1

    .line 78
    invoke-static/range {v17 .. v17}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v2

    int-to-long v2, v2

    .line 79
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    :goto_25
    int-to-long v4, v1

    shl-long v1, v2, v18

    and-long v3, v4, v19

    goto :goto_24

    :cond_1e
    sub-float v4, v12, v17

    .line 80
    invoke-interface {v0}, Lg3/d;->D0()J

    move-result-wide v1

    and-long v1, v1, v19

    long-to-int v1, v1

    .line 81
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v1

    .line 82
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v2

    int-to-long v2, v2

    .line 83
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    goto :goto_25

    :goto_26
    if-eqz v11, :cond_1f

    .line 84
    new-instance v3, Ld3/b;

    invoke-direct {v3, v1, v2}, Ld3/b;-><init>(J)V

    .line 85
    invoke-interface {v11, v0, v3}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_1f
    if-eqz p21, :cond_20

    add-float v1, v23, v26

    move v13, v1

    goto :goto_27

    :cond_20
    move/from16 v13, p18

    :goto_27
    sub-float v27, v22, v25

    if-nez v16, :cond_22

    if-eqz p21, :cond_21

    goto :goto_28

    :cond_21
    move/from16 v8, v17

    goto :goto_29

    :cond_22
    :goto_28
    move/from16 v8, v24

    :goto_29
    if-eqz v16, :cond_23

    if-nez p21, :cond_23

    move/from16 v9, v17

    goto :goto_2a

    :cond_23
    move/from16 v9, v24

    :goto_2a
    if-eqz v16, :cond_24

    if-nez p21, :cond_24

    move/from16 v1, v27

    goto :goto_2b

    :cond_24
    sub-float v1, v27, v13

    :goto_2b
    cmpl-float v2, v1, v8

    if-lez v2, :cond_29

    if-eqz v14, :cond_25

    .line 86
    invoke-static/range {p18 .. p18}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v2

    int-to-long v2, v2

    .line 87
    invoke-static {v13}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v4

    :goto_2c
    int-to-long v4, v4

    shl-long v2, v2, v18

    and-long v4, v4, v19

    or-long/2addr v2, v4

    goto :goto_2d

    :cond_25
    if-eqz v15, :cond_26

    .line 88
    invoke-interface {v0}, Lg3/d;->e()J

    move-result-wide v2

    shr-long v2, v2, v18

    long-to-int v2, v2

    .line 89
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v2

    sub-float v2, v2, v27

    .line 90
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v2

    int-to-long v2, v2

    .line 91
    invoke-static/range {p18 .. p18}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v4

    goto :goto_2c

    .line 92
    :cond_26
    invoke-static {v13}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v2

    int-to-long v2, v2

    .line 93
    invoke-static/range {p18 .. p18}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v4

    goto :goto_2c

    :goto_2d
    if-eqz v14, :cond_27

    .line 94
    invoke-interface {v0}, Lg3/d;->e()J

    move-result-wide v4

    shr-long v4, v4, v18

    long-to-int v4, v4

    .line 95
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v4

    .line 96
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v4

    int-to-long v4, v4

    .line 97
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    :goto_2e
    int-to-long v6, v1

    shl-long v4, v4, v18

    and-long v6, v6, v19

    or-long/2addr v4, v6

    :goto_2f
    move-wide/from16 v6, p6

    move-object/from16 v1, p22

    goto :goto_30

    :cond_27
    if-eqz v15, :cond_28

    if-nez p21, :cond_28

    .line 98
    invoke-interface {v0}, Lg3/d;->e()J

    move-result-wide v4

    and-long v4, v4, v19

    long-to-int v1, v4

    .line 99
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v1

    .line 100
    invoke-static/range {v27 .. v27}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v4

    int-to-long v4, v4

    .line 101
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    goto :goto_2e

    .line 102
    :cond_28
    invoke-interface {v0}, Lg3/d;->e()J

    move-result-wide v4

    and-long v4, v4, v19

    long-to-int v4, v4

    .line 103
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v4

    .line 104
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v5, v1

    .line 105
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v0, v1

    shl-long v4, v5, v18

    and-long v0, v0, v19

    or-long/2addr v4, v0

    move-object/from16 v0, p0

    goto :goto_2f

    .line 106
    :goto_30
    invoke-static/range {v0 .. v9}, Lh2/a9;->h(Lg3/d;Lg1/w1;JJJFF)V

    :cond_29
    add-float v1, p18, v17

    sub-float v4, v12, v17

    sub-float v2, v23, v26

    add-float v23, v23, v26

    sub-float v3, v22, v25

    add-float v22, v22, v25

    .line 107
    array-length v5, v10

    const/4 v6, 0x0

    const/4 v12, 0x0

    :goto_31
    if-ge v12, v5, :cond_31

    aget v7, v10, v12

    add-int/lit8 v8, v6, 0x1

    if-eqz v11, :cond_2b

    if-eqz p21, :cond_2a

    if-nez v6, :cond_2a

    goto :goto_32

    .line 108
    :cond_2a
    array-length v9, v10

    add-int/lit8 v9, v9, -0x1

    if-ne v6, v9, :cond_2b

    :goto_32
    move/from16 p2, v1

    move/from16 p3, v2

    move-object/from16 v1, p20

    goto/16 :goto_37

    .line 109
    :cond_2b
    invoke-static {v1, v4, v7}, Llp/wa;->b(FFF)F

    move-result v6

    if-eqz p21, :cond_2c

    cmpl-float v7, v6, v2

    if-ltz v7, :cond_2c

    cmpg-float v7, v6, v23

    if-gtz v7, :cond_2c

    goto :goto_33

    :cond_2c
    cmpl-float v7, v6, v3

    if-ltz v7, :cond_2d

    cmpg-float v7, v6, v22

    if-gtz v7, :cond_2d

    :goto_33
    goto :goto_32

    :cond_2d
    if-eqz v14, :cond_2e

    .line 110
    invoke-interface {v0}, Lg3/d;->D0()J

    move-result-wide v16

    move/from16 p2, v1

    move/from16 p3, v2

    shr-long v1, v16, v18

    long-to-int v1, v1

    .line 111
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v1

    .line 112
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v1, v1

    .line 113
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v7

    :goto_34
    move-wide/from16 v16, v1

    int-to-long v1, v7

    shl-long v16, v16, v18

    and-long v1, v1, v19

    or-long v1, v16, v1

    goto :goto_35

    :cond_2e
    move/from16 p2, v1

    move/from16 p3, v2

    if-eqz v15, :cond_2f

    .line 114
    invoke-interface {v0}, Lg3/d;->e()J

    move-result-wide v1

    shr-long v1, v1, v18

    long-to-int v1, v1

    .line 115
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v1

    sub-float/2addr v1, v6

    .line 116
    invoke-interface {v0}, Lg3/d;->D0()J

    move-result-wide v16

    move/from16 p4, v1

    and-long v1, v16, v19

    long-to-int v1, v1

    .line 117
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v1

    .line 118
    invoke-static/range {p4 .. p4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v2

    move/from16 p4, v1

    int-to-long v1, v2

    .line 119
    invoke-static/range {p4 .. p4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v7

    goto :goto_34

    .line 120
    :cond_2f
    invoke-interface {v0}, Lg3/d;->D0()J

    move-result-wide v1

    and-long v1, v1, v19

    long-to-int v1, v1

    .line 121
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v1

    .line 122
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v2

    move/from16 p4, v1

    int-to-long v1, v2

    .line 123
    invoke-static/range {p4 .. p4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v7

    goto :goto_34

    .line 124
    :goto_35
    new-instance v7, Ld3/b;

    invoke-direct {v7, v1, v2}, Ld3/b;-><init>(J)V

    cmpl-float v1, v6, v13

    if-ltz v1, :cond_30

    cmpg-float v1, v6, v27

    if-gtz v1, :cond_30

    move-wide/from16 v1, p10

    goto :goto_36

    :cond_30
    move-wide/from16 v1, p8

    .line 125
    :goto_36
    new-instance v6, Le3/s;

    invoke-direct {v6, v1, v2}, Le3/s;-><init>(J)V

    move-object/from16 v1, p20

    .line 126
    invoke-interface {v1, v0, v7, v6}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :goto_37
    add-int/lit8 v12, v12, 0x1

    move/from16 v1, p2

    move/from16 v2, p3

    move v6, v8

    goto/16 :goto_31

    :cond_31
    return-void
.end method

.method public static h(Lg3/d;Lg1/w1;JJJFF)V
    .locals 18

    .line 1
    move-wide/from16 v0, p2

    .line 2
    .line 3
    invoke-static/range {p8 .. p8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 4
    .line 5
    .line 6
    move-result v2

    .line 7
    int-to-long v2, v2

    .line 8
    invoke-static/range {p8 .. p8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 9
    .line 10
    .line 11
    move-result v4

    .line 12
    int-to-long v4, v4

    .line 13
    const/16 v6, 0x20

    .line 14
    .line 15
    shl-long/2addr v2, v6

    .line 16
    const-wide v7, 0xffffffffL

    .line 17
    .line 18
    .line 19
    .line 20
    .line 21
    and-long/2addr v4, v7

    .line 22
    or-long v10, v2, v4

    .line 23
    .line 24
    invoke-static/range {p9 .. p9}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    int-to-long v2, v2

    .line 29
    invoke-static/range {p9 .. p9}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 30
    .line 31
    .line 32
    move-result v4

    .line 33
    int-to-long v4, v4

    .line 34
    shl-long/2addr v2, v6

    .line 35
    and-long/2addr v4, v7

    .line 36
    or-long v12, v2, v4

    .line 37
    .line 38
    sget-object v2, Lg1/w1;->d:Lg1/w1;

    .line 39
    .line 40
    move-object/from16 v3, p1

    .line 41
    .line 42
    if-ne v3, v2, :cond_0

    .line 43
    .line 44
    shr-long v2, p4, v6

    .line 45
    .line 46
    long-to-int v2, v2

    .line 47
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 48
    .line 49
    .line 50
    move-result v2

    .line 51
    and-long v3, p4, v7

    .line 52
    .line 53
    long-to-int v3, v3

    .line 54
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 55
    .line 56
    .line 57
    move-result v3

    .line 58
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    int-to-long v4, v2

    .line 63
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 64
    .line 65
    .line 66
    move-result v2

    .line 67
    int-to-long v2, v2

    .line 68
    shl-long/2addr v4, v6

    .line 69
    and-long/2addr v2, v7

    .line 70
    or-long/2addr v2, v4

    .line 71
    invoke-static {v0, v1, v2, v3}, Ljp/cf;->c(JJ)Ld3/c;

    .line 72
    .line 73
    .line 74
    move-result-object v9

    .line 75
    move-wide v14, v12

    .line 76
    move-wide v12, v10

    .line 77
    move-wide/from16 v16, v14

    .line 78
    .line 79
    invoke-static/range {v9 .. v17}, Ljp/df;->a(Ld3/c;JJJJ)Ld3/d;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    goto :goto_0

    .line 84
    :cond_0
    move-wide v14, v12

    .line 85
    shr-long v2, p4, v6

    .line 86
    .line 87
    long-to-int v2, v2

    .line 88
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 89
    .line 90
    .line 91
    move-result v2

    .line 92
    and-long v3, p4, v7

    .line 93
    .line 94
    long-to-int v3, v3

    .line 95
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 96
    .line 97
    .line 98
    move-result v3

    .line 99
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 100
    .line 101
    .line 102
    move-result v2

    .line 103
    int-to-long v4, v2

    .line 104
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 105
    .line 106
    .line 107
    move-result v2

    .line 108
    int-to-long v2, v2

    .line 109
    shl-long/2addr v4, v6

    .line 110
    and-long/2addr v2, v7

    .line 111
    or-long/2addr v2, v4

    .line 112
    invoke-static {v0, v1, v2, v3}, Ljp/cf;->c(JJ)Ld3/c;

    .line 113
    .line 114
    .line 115
    move-result-object v9

    .line 116
    move-wide/from16 v16, v10

    .line 117
    .line 118
    invoke-static/range {v9 .. v17}, Ljp/df;->a(Ld3/c;JJJJ)Ld3/d;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    :goto_0
    sget-object v2, Lh2/a9;->d:Le3/i;

    .line 123
    .line 124
    invoke-static {v2, v0}, Le3/i;->c(Le3/i;Ld3/d;)V

    .line 125
    .line 126
    .line 127
    const/4 v6, 0x0

    .line 128
    const/16 v7, 0x3c

    .line 129
    .line 130
    const/4 v5, 0x0

    .line 131
    move-object/from16 v1, p0

    .line 132
    .line 133
    move-wide/from16 v3, p6

    .line 134
    .line 135
    invoke-static/range {v1 .. v7}, Lg3/d;->K0(Lg3/d;Le3/i;JFLg3/e;I)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v2}, Le3/i;->k()V

    .line 139
    .line 140
    .line 141
    return-void
.end method

.method public static i(Lh2/f1;)Lh2/u8;
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lh2/f1;->e0:Lh2/u8;

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    new-instance v2, Lh2/u8;

    .line 8
    .line 9
    sget-object v1, Lk2/i0;->i:Lk2/l;

    .line 10
    .line 11
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 12
    .line 13
    .line 14
    move-result-wide v3

    .line 15
    sget-object v1, Lk2/i0;->b:Lk2/l;

    .line 16
    .line 17
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 18
    .line 19
    .line 20
    move-result-wide v5

    .line 21
    sget-object v7, Lk2/i0;->l:Lk2/l;

    .line 22
    .line 23
    invoke-static {v0, v7}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 24
    .line 25
    .line 26
    move-result-wide v8

    .line 27
    invoke-static {v0, v7}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 28
    .line 29
    .line 30
    move-result-wide v10

    .line 31
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 32
    .line 33
    .line 34
    move-result-wide v12

    .line 35
    sget-object v1, Lk2/i0;->e:Lk2/l;

    .line 36
    .line 37
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 38
    .line 39
    .line 40
    move-result-wide v14

    .line 41
    sget v1, Lk2/i0;->f:F

    .line 42
    .line 43
    invoke-static {v14, v15, v1}, Le3/s;->b(JF)J

    .line 44
    .line 45
    .line 46
    move-result-wide v14

    .line 47
    move-object v7, v2

    .line 48
    iget-wide v1, v0, Lh2/f1;->p:J

    .line 49
    .line 50
    invoke-static {v14, v15, v1, v2}, Le3/j0;->l(JJ)J

    .line 51
    .line 52
    .line 53
    move-result-wide v1

    .line 54
    sget-object v14, Lk2/i0;->c:Lk2/l;

    .line 55
    .line 56
    move-wide v15, v1

    .line 57
    invoke-static {v0, v14}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 58
    .line 59
    .line 60
    move-result-wide v1

    .line 61
    move-wide/from16 v17, v3

    .line 62
    .line 63
    sget v3, Lk2/i0;->d:F

    .line 64
    .line 65
    invoke-static {v1, v2, v3}, Le3/s;->b(JF)J

    .line 66
    .line 67
    .line 68
    move-result-wide v1

    .line 69
    sget-object v4, Lk2/i0;->g:Lk2/l;

    .line 70
    .line 71
    move-wide/from16 v19, v1

    .line 72
    .line 73
    invoke-static {v0, v4}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 74
    .line 75
    .line 76
    move-result-wide v1

    .line 77
    move-wide/from16 v21, v5

    .line 78
    .line 79
    sget v5, Lk2/i0;->h:F

    .line 80
    .line 81
    invoke-static {v1, v2, v5}, Le3/s;->b(JF)J

    .line 82
    .line 83
    .line 84
    move-result-wide v1

    .line 85
    move-wide/from16 v23, v1

    .line 86
    .line 87
    invoke-static {v0, v4}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 88
    .line 89
    .line 90
    move-result-wide v1

    .line 91
    invoke-static {v1, v2, v5}, Le3/s;->b(JF)J

    .line 92
    .line 93
    .line 94
    move-result-wide v1

    .line 95
    invoke-static {v0, v14}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 96
    .line 97
    .line 98
    move-result-wide v4

    .line 99
    invoke-static {v4, v5, v3}, Le3/s;->b(JF)J

    .line 100
    .line 101
    .line 102
    move-result-wide v3

    .line 103
    move-wide v5, v1

    .line 104
    move-object v2, v7

    .line 105
    move-wide v7, v8

    .line 106
    move-wide v9, v10

    .line 107
    move-wide v11, v12

    .line 108
    move-wide v13, v15

    .line 109
    move-wide/from16 v15, v19

    .line 110
    .line 111
    move-wide/from16 v19, v5

    .line 112
    .line 113
    move-wide/from16 v5, v21

    .line 114
    .line 115
    move-wide/from16 v21, v3

    .line 116
    .line 117
    move-wide/from16 v3, v17

    .line 118
    .line 119
    move-wide/from16 v17, v23

    .line 120
    .line 121
    invoke-direct/range {v2 .. v22}, Lh2/u8;-><init>(JJJJJJJJJJ)V

    .line 122
    .line 123
    .line 124
    iput-object v2, v0, Lh2/f1;->e0:Lh2/u8;

    .line 125
    .line 126
    return-object v2

    .line 127
    :cond_0
    return-object v1
.end method


# virtual methods
.method public final a(Lh2/u7;Lx2/s;ZLh2/u8;Lay0/n;Lay0/o;FFLl2/o;II)V
    .locals 18

    .line 1
    move/from16 v4, p3

    .line 2
    .line 3
    move-object/from16 v5, p4

    .line 4
    .line 5
    move/from16 v11, p10

    .line 6
    .line 7
    move-object/from16 v9, p9

    .line 8
    .line 9
    check-cast v9, Ll2/t;

    .line 10
    .line 11
    const v0, -0x204b9484

    .line 12
    .line 13
    .line 14
    invoke-virtual {v9, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    and-int/lit8 v0, v11, 0x6

    .line 18
    .line 19
    move-object/from16 v1, p1

    .line 20
    .line 21
    if-nez v0, :cond_1

    .line 22
    .line 23
    invoke-virtual {v9, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    const/4 v0, 0x4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v0, 0x2

    .line 32
    :goto_0
    or-int/2addr v0, v11

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move v0, v11

    .line 35
    :goto_1
    and-int/lit8 v2, p11, 0x2

    .line 36
    .line 37
    if-eqz v2, :cond_3

    .line 38
    .line 39
    or-int/lit8 v0, v0, 0x30

    .line 40
    .line 41
    :cond_2
    move-object/from16 v3, p2

    .line 42
    .line 43
    goto :goto_3

    .line 44
    :cond_3
    and-int/lit8 v3, v11, 0x30

    .line 45
    .line 46
    if-nez v3, :cond_2

    .line 47
    .line 48
    move-object/from16 v3, p2

    .line 49
    .line 50
    invoke-virtual {v9, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v6

    .line 54
    if-eqz v6, :cond_4

    .line 55
    .line 56
    const/16 v6, 0x20

    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_4
    const/16 v6, 0x10

    .line 60
    .line 61
    :goto_2
    or-int/2addr v0, v6

    .line 62
    :goto_3
    and-int/lit16 v6, v11, 0x180

    .line 63
    .line 64
    const/16 v7, 0x100

    .line 65
    .line 66
    if-nez v6, :cond_6

    .line 67
    .line 68
    invoke-virtual {v9, v4}, Ll2/t;->h(Z)Z

    .line 69
    .line 70
    .line 71
    move-result v6

    .line 72
    if-eqz v6, :cond_5

    .line 73
    .line 74
    move v6, v7

    .line 75
    goto :goto_4

    .line 76
    :cond_5
    const/16 v6, 0x80

    .line 77
    .line 78
    :goto_4
    or-int/2addr v0, v6

    .line 79
    :cond_6
    and-int/lit16 v6, v11, 0xc00

    .line 80
    .line 81
    const/16 v8, 0x800

    .line 82
    .line 83
    if-nez v6, :cond_8

    .line 84
    .line 85
    invoke-virtual {v9, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v6

    .line 89
    if-eqz v6, :cond_7

    .line 90
    .line 91
    move v6, v8

    .line 92
    goto :goto_5

    .line 93
    :cond_7
    const/16 v6, 0x400

    .line 94
    .line 95
    :goto_5
    or-int/2addr v0, v6

    .line 96
    :cond_8
    and-int/lit16 v6, v11, 0x6000

    .line 97
    .line 98
    if-nez v6, :cond_b

    .line 99
    .line 100
    and-int/lit8 v6, p11, 0x10

    .line 101
    .line 102
    if-nez v6, :cond_9

    .line 103
    .line 104
    move-object/from16 v6, p5

    .line 105
    .line 106
    invoke-virtual {v9, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 107
    .line 108
    .line 109
    move-result v10

    .line 110
    if-eqz v10, :cond_a

    .line 111
    .line 112
    const/16 v10, 0x4000

    .line 113
    .line 114
    goto :goto_6

    .line 115
    :cond_9
    move-object/from16 v6, p5

    .line 116
    .line 117
    :cond_a
    const/16 v10, 0x2000

    .line 118
    .line 119
    :goto_6
    or-int/2addr v0, v10

    .line 120
    goto :goto_7

    .line 121
    :cond_b
    move-object/from16 v6, p5

    .line 122
    .line 123
    :goto_7
    const/high16 v10, 0x30000

    .line 124
    .line 125
    or-int/2addr v10, v0

    .line 126
    and-int/lit8 v12, p11, 0x40

    .line 127
    .line 128
    if-eqz v12, :cond_d

    .line 129
    .line 130
    const/high16 v10, 0x1b0000

    .line 131
    .line 132
    or-int/2addr v10, v0

    .line 133
    :cond_c
    move/from16 v0, p7

    .line 134
    .line 135
    goto :goto_9

    .line 136
    :cond_d
    const/high16 v0, 0x180000

    .line 137
    .line 138
    and-int/2addr v0, v11

    .line 139
    if-nez v0, :cond_c

    .line 140
    .line 141
    move/from16 v0, p7

    .line 142
    .line 143
    invoke-virtual {v9, v0}, Ll2/t;->d(F)Z

    .line 144
    .line 145
    .line 146
    move-result v13

    .line 147
    if-eqz v13, :cond_e

    .line 148
    .line 149
    const/high16 v13, 0x100000

    .line 150
    .line 151
    goto :goto_8

    .line 152
    :cond_e
    const/high16 v13, 0x80000

    .line 153
    .line 154
    :goto_8
    or-int/2addr v10, v13

    .line 155
    :goto_9
    const/high16 v13, 0xc00000

    .line 156
    .line 157
    or-int/2addr v10, v13

    .line 158
    const/high16 v13, 0x6000000

    .line 159
    .line 160
    and-int/2addr v13, v11

    .line 161
    if-nez v13, :cond_10

    .line 162
    .line 163
    move-object/from16 v13, p0

    .line 164
    .line 165
    invoke-virtual {v9, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 166
    .line 167
    .line 168
    move-result v14

    .line 169
    if-eqz v14, :cond_f

    .line 170
    .line 171
    const/high16 v14, 0x4000000

    .line 172
    .line 173
    goto :goto_a

    .line 174
    :cond_f
    const/high16 v14, 0x2000000

    .line 175
    .line 176
    :goto_a
    or-int/2addr v10, v14

    .line 177
    goto :goto_b

    .line 178
    :cond_10
    move-object/from16 v13, p0

    .line 179
    .line 180
    :goto_b
    const v14, 0x2492493

    .line 181
    .line 182
    .line 183
    and-int/2addr v14, v10

    .line 184
    const v15, 0x2492492

    .line 185
    .line 186
    .line 187
    const/16 v16, 0x0

    .line 188
    .line 189
    const/16 v17, 0x1

    .line 190
    .line 191
    if-eq v14, v15, :cond_11

    .line 192
    .line 193
    move/from16 v14, v17

    .line 194
    .line 195
    goto :goto_c

    .line 196
    :cond_11
    move/from16 v14, v16

    .line 197
    .line 198
    :goto_c
    and-int/lit8 v15, v10, 0x1

    .line 199
    .line 200
    invoke-virtual {v9, v15, v14}, Ll2/t;->O(IZ)Z

    .line 201
    .line 202
    .line 203
    move-result v14

    .line 204
    if-eqz v14, :cond_1f

    .line 205
    .line 206
    invoke-virtual {v9}, Ll2/t;->T()V

    .line 207
    .line 208
    .line 209
    and-int/lit8 v14, v11, 0x1

    .line 210
    .line 211
    const v15, -0xe001

    .line 212
    .line 213
    .line 214
    if-eqz v14, :cond_14

    .line 215
    .line 216
    invoke-virtual {v9}, Ll2/t;->y()Z

    .line 217
    .line 218
    .line 219
    move-result v14

    .line 220
    if-eqz v14, :cond_12

    .line 221
    .line 222
    goto :goto_d

    .line 223
    :cond_12
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 224
    .line 225
    .line 226
    and-int/lit8 v2, p11, 0x10

    .line 227
    .line 228
    if-eqz v2, :cond_13

    .line 229
    .line 230
    and-int/2addr v10, v15

    .line 231
    :cond_13
    move/from16 v8, p8

    .line 232
    .line 233
    move v7, v0

    .line 234
    move-object v2, v3

    .line 235
    move-object v5, v6

    .line 236
    move-object/from16 v6, p6

    .line 237
    .line 238
    goto :goto_10

    .line 239
    :cond_14
    :goto_d
    if-eqz v2, :cond_15

    .line 240
    .line 241
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 242
    .line 243
    goto :goto_e

    .line 244
    :cond_15
    move-object v2, v3

    .line 245
    :goto_e
    and-int/lit8 v3, p11, 0x10

    .line 246
    .line 247
    sget-object v14, Ll2/n;->a:Ll2/x0;

    .line 248
    .line 249
    if-eqz v3, :cond_1c

    .line 250
    .line 251
    and-int/lit16 v3, v10, 0x1c00

    .line 252
    .line 253
    xor-int/lit16 v3, v3, 0xc00

    .line 254
    .line 255
    if-le v3, v8, :cond_16

    .line 256
    .line 257
    invoke-virtual {v9, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 258
    .line 259
    .line 260
    move-result v3

    .line 261
    if-nez v3, :cond_17

    .line 262
    .line 263
    :cond_16
    and-int/lit16 v3, v10, 0xc00

    .line 264
    .line 265
    if-ne v3, v8, :cond_18

    .line 266
    .line 267
    :cond_17
    move/from16 v3, v17

    .line 268
    .line 269
    goto :goto_f

    .line 270
    :cond_18
    move/from16 v3, v16

    .line 271
    .line 272
    :goto_f
    and-int/lit16 v6, v10, 0x380

    .line 273
    .line 274
    if-ne v6, v7, :cond_19

    .line 275
    .line 276
    move/from16 v16, v17

    .line 277
    .line 278
    :cond_19
    or-int v3, v3, v16

    .line 279
    .line 280
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    move-result-object v6

    .line 284
    if-nez v3, :cond_1a

    .line 285
    .line 286
    if-ne v6, v14, :cond_1b

    .line 287
    .line 288
    :cond_1a
    new-instance v6, Lh2/w8;

    .line 289
    .line 290
    const/4 v3, 0x1

    .line 291
    invoke-direct {v6, v5, v4, v3}, Lh2/w8;-><init>(Lh2/u8;ZI)V

    .line 292
    .line 293
    .line 294
    invoke-virtual {v9, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 295
    .line 296
    .line 297
    :cond_1b
    move-object v3, v6

    .line 298
    check-cast v3, Lay0/n;

    .line 299
    .line 300
    and-int/2addr v10, v15

    .line 301
    move-object v6, v3

    .line 302
    :cond_1c
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 303
    .line 304
    .line 305
    move-result-object v3

    .line 306
    if-ne v3, v14, :cond_1d

    .line 307
    .line 308
    sget-object v3, Lh2/i1;->g:Lh2/i1;

    .line 309
    .line 310
    invoke-virtual {v9, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 311
    .line 312
    .line 313
    :cond_1d
    check-cast v3, Lay0/o;

    .line 314
    .line 315
    if-eqz v12, :cond_1e

    .line 316
    .line 317
    sget v0, Lh2/q9;->c:F

    .line 318
    .line 319
    :cond_1e
    sget v7, Lh2/q9;->d:F

    .line 320
    .line 321
    move-object v5, v6

    .line 322
    move v8, v7

    .line 323
    move v7, v0

    .line 324
    move-object v6, v3

    .line 325
    :goto_10
    invoke-virtual {v9}, Ll2/t;->r()V

    .line 326
    .line 327
    .line 328
    and-int/lit8 v0, v10, 0xe

    .line 329
    .line 330
    or-int/lit8 v0, v0, 0x30

    .line 331
    .line 332
    shl-int/lit8 v3, v10, 0x3

    .line 333
    .line 334
    and-int/lit16 v10, v3, 0x380

    .line 335
    .line 336
    or-int/2addr v0, v10

    .line 337
    and-int/lit16 v10, v3, 0x1c00

    .line 338
    .line 339
    or-int/2addr v0, v10

    .line 340
    const v10, 0xe000

    .line 341
    .line 342
    .line 343
    and-int/2addr v10, v3

    .line 344
    or-int/2addr v0, v10

    .line 345
    const/high16 v10, 0x70000

    .line 346
    .line 347
    and-int/2addr v10, v3

    .line 348
    or-int/2addr v0, v10

    .line 349
    const/high16 v10, 0x380000

    .line 350
    .line 351
    and-int/2addr v10, v3

    .line 352
    or-int/2addr v0, v10

    .line 353
    const/high16 v10, 0x1c00000

    .line 354
    .line 355
    and-int/2addr v10, v3

    .line 356
    or-int/2addr v0, v10

    .line 357
    const/high16 v10, 0xe000000

    .line 358
    .line 359
    and-int/2addr v10, v3

    .line 360
    or-int/2addr v0, v10

    .line 361
    const/high16 v10, 0x70000000

    .line 362
    .line 363
    and-int/2addr v3, v10

    .line 364
    or-int v10, v0, v3

    .line 365
    .line 366
    move v3, v4

    .line 367
    move-object v0, v13

    .line 368
    move-object/from16 v4, p4

    .line 369
    .line 370
    invoke-virtual/range {v0 .. v10}, Lh2/a9;->d(Lh2/u7;Lx2/s;ZLh2/u8;Lay0/n;Lay0/o;FFLl2/o;I)V

    .line 371
    .line 372
    .line 373
    move-object v3, v2

    .line 374
    move-object v0, v9

    .line 375
    move v9, v8

    .line 376
    move v8, v7

    .line 377
    move-object v7, v6

    .line 378
    move-object v6, v5

    .line 379
    goto :goto_11

    .line 380
    :cond_1f
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 381
    .line 382
    .line 383
    move-object/from16 v7, p6

    .line 384
    .line 385
    move v8, v0

    .line 386
    move-object v0, v9

    .line 387
    move/from16 v9, p8

    .line 388
    .line 389
    :goto_11
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 390
    .line 391
    .line 392
    move-result-object v13

    .line 393
    if-eqz v13, :cond_20

    .line 394
    .line 395
    new-instance v0, Lh2/x8;

    .line 396
    .line 397
    const/4 v12, 0x2

    .line 398
    move-object/from16 v1, p0

    .line 399
    .line 400
    move-object/from16 v2, p1

    .line 401
    .line 402
    move/from16 v4, p3

    .line 403
    .line 404
    move-object/from16 v5, p4

    .line 405
    .line 406
    move v10, v11

    .line 407
    move/from16 v11, p11

    .line 408
    .line 409
    invoke-direct/range {v0 .. v12}, Lh2/x8;-><init>(Lh2/a9;Ljava/lang/Object;Lx2/s;ZLh2/u8;Lay0/n;Lay0/o;FFIII)V

    .line 410
    .line 411
    .line 412
    iput-object v0, v13, Ll2/u1;->d:Lay0/n;

    .line 413
    .line 414
    :cond_20
    return-void
.end method

.method public final b(Lh2/s9;Lx2/s;ZLh2/u8;Lay0/n;Lay0/o;FFLl2/o;II)V
    .locals 18

    .line 1
    move/from16 v4, p3

    .line 2
    .line 3
    move-object/from16 v5, p4

    .line 4
    .line 5
    move/from16 v12, p10

    .line 6
    .line 7
    move-object/from16 v9, p9

    .line 8
    .line 9
    check-cast v9, Ll2/t;

    .line 10
    .line 11
    const v0, 0x2fab503

    .line 12
    .line 13
    .line 14
    invoke-virtual {v9, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    and-int/lit8 v0, v12, 0x6

    .line 18
    .line 19
    move-object/from16 v1, p1

    .line 20
    .line 21
    if-nez v0, :cond_1

    .line 22
    .line 23
    invoke-virtual {v9, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    const/4 v0, 0x4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v0, 0x2

    .line 32
    :goto_0
    or-int/2addr v0, v12

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move v0, v12

    .line 35
    :goto_1
    and-int/lit8 v2, p11, 0x2

    .line 36
    .line 37
    if-eqz v2, :cond_3

    .line 38
    .line 39
    or-int/lit8 v0, v0, 0x30

    .line 40
    .line 41
    :cond_2
    move-object/from16 v3, p2

    .line 42
    .line 43
    goto :goto_3

    .line 44
    :cond_3
    and-int/lit8 v3, v12, 0x30

    .line 45
    .line 46
    if-nez v3, :cond_2

    .line 47
    .line 48
    move-object/from16 v3, p2

    .line 49
    .line 50
    invoke-virtual {v9, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v6

    .line 54
    if-eqz v6, :cond_4

    .line 55
    .line 56
    const/16 v6, 0x20

    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_4
    const/16 v6, 0x10

    .line 60
    .line 61
    :goto_2
    or-int/2addr v0, v6

    .line 62
    :goto_3
    and-int/lit16 v6, v12, 0x180

    .line 63
    .line 64
    const/16 v7, 0x100

    .line 65
    .line 66
    if-nez v6, :cond_6

    .line 67
    .line 68
    invoke-virtual {v9, v4}, Ll2/t;->h(Z)Z

    .line 69
    .line 70
    .line 71
    move-result v6

    .line 72
    if-eqz v6, :cond_5

    .line 73
    .line 74
    move v6, v7

    .line 75
    goto :goto_4

    .line 76
    :cond_5
    const/16 v6, 0x80

    .line 77
    .line 78
    :goto_4
    or-int/2addr v0, v6

    .line 79
    :cond_6
    and-int/lit16 v6, v12, 0xc00

    .line 80
    .line 81
    const/16 v8, 0x800

    .line 82
    .line 83
    if-nez v6, :cond_8

    .line 84
    .line 85
    invoke-virtual {v9, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v6

    .line 89
    if-eqz v6, :cond_7

    .line 90
    .line 91
    move v6, v8

    .line 92
    goto :goto_5

    .line 93
    :cond_7
    const/16 v6, 0x400

    .line 94
    .line 95
    :goto_5
    or-int/2addr v0, v6

    .line 96
    :cond_8
    and-int/lit16 v6, v12, 0x6000

    .line 97
    .line 98
    if-nez v6, :cond_b

    .line 99
    .line 100
    and-int/lit8 v6, p11, 0x10

    .line 101
    .line 102
    if-nez v6, :cond_9

    .line 103
    .line 104
    move-object/from16 v6, p5

    .line 105
    .line 106
    invoke-virtual {v9, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 107
    .line 108
    .line 109
    move-result v10

    .line 110
    if-eqz v10, :cond_a

    .line 111
    .line 112
    const/16 v10, 0x4000

    .line 113
    .line 114
    goto :goto_6

    .line 115
    :cond_9
    move-object/from16 v6, p5

    .line 116
    .line 117
    :cond_a
    const/16 v10, 0x2000

    .line 118
    .line 119
    :goto_6
    or-int/2addr v0, v10

    .line 120
    goto :goto_7

    .line 121
    :cond_b
    move-object/from16 v6, p5

    .line 122
    .line 123
    :goto_7
    const/high16 v10, 0x30000

    .line 124
    .line 125
    or-int/2addr v10, v0

    .line 126
    and-int/lit8 v11, p11, 0x40

    .line 127
    .line 128
    if-eqz v11, :cond_d

    .line 129
    .line 130
    const/high16 v10, 0x1b0000

    .line 131
    .line 132
    or-int/2addr v10, v0

    .line 133
    :cond_c
    move/from16 v0, p7

    .line 134
    .line 135
    goto :goto_9

    .line 136
    :cond_d
    const/high16 v0, 0x180000

    .line 137
    .line 138
    and-int/2addr v0, v12

    .line 139
    if-nez v0, :cond_c

    .line 140
    .line 141
    move/from16 v0, p7

    .line 142
    .line 143
    invoke-virtual {v9, v0}, Ll2/t;->d(F)Z

    .line 144
    .line 145
    .line 146
    move-result v13

    .line 147
    if-eqz v13, :cond_e

    .line 148
    .line 149
    const/high16 v13, 0x100000

    .line 150
    .line 151
    goto :goto_8

    .line 152
    :cond_e
    const/high16 v13, 0x80000

    .line 153
    .line 154
    :goto_8
    or-int/2addr v10, v13

    .line 155
    :goto_9
    const/high16 v13, 0xc00000

    .line 156
    .line 157
    or-int/2addr v10, v13

    .line 158
    const/high16 v13, 0x6000000

    .line 159
    .line 160
    and-int/2addr v13, v12

    .line 161
    if-nez v13, :cond_10

    .line 162
    .line 163
    move-object/from16 v13, p0

    .line 164
    .line 165
    invoke-virtual {v9, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 166
    .line 167
    .line 168
    move-result v14

    .line 169
    if-eqz v14, :cond_f

    .line 170
    .line 171
    const/high16 v14, 0x4000000

    .line 172
    .line 173
    goto :goto_a

    .line 174
    :cond_f
    const/high16 v14, 0x2000000

    .line 175
    .line 176
    :goto_a
    or-int/2addr v10, v14

    .line 177
    goto :goto_b

    .line 178
    :cond_10
    move-object/from16 v13, p0

    .line 179
    .line 180
    :goto_b
    const v14, 0x2492493

    .line 181
    .line 182
    .line 183
    and-int/2addr v14, v10

    .line 184
    const v15, 0x2492492

    .line 185
    .line 186
    .line 187
    const/16 v16, 0x0

    .line 188
    .line 189
    const/16 v17, 0x1

    .line 190
    .line 191
    if-eq v14, v15, :cond_11

    .line 192
    .line 193
    move/from16 v14, v17

    .line 194
    .line 195
    goto :goto_c

    .line 196
    :cond_11
    move/from16 v14, v16

    .line 197
    .line 198
    :goto_c
    and-int/lit8 v15, v10, 0x1

    .line 199
    .line 200
    invoke-virtual {v9, v15, v14}, Ll2/t;->O(IZ)Z

    .line 201
    .line 202
    .line 203
    move-result v14

    .line 204
    if-eqz v14, :cond_1f

    .line 205
    .line 206
    invoke-virtual {v9}, Ll2/t;->T()V

    .line 207
    .line 208
    .line 209
    and-int/lit8 v14, v12, 0x1

    .line 210
    .line 211
    const v15, -0xe001

    .line 212
    .line 213
    .line 214
    if-eqz v14, :cond_14

    .line 215
    .line 216
    invoke-virtual {v9}, Ll2/t;->y()Z

    .line 217
    .line 218
    .line 219
    move-result v14

    .line 220
    if-eqz v14, :cond_12

    .line 221
    .line 222
    goto :goto_d

    .line 223
    :cond_12
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 224
    .line 225
    .line 226
    and-int/lit8 v2, p11, 0x10

    .line 227
    .line 228
    if-eqz v2, :cond_13

    .line 229
    .line 230
    and-int/2addr v10, v15

    .line 231
    :cond_13
    move/from16 v8, p8

    .line 232
    .line 233
    move v7, v0

    .line 234
    move-object v2, v3

    .line 235
    move-object v5, v6

    .line 236
    move-object/from16 v6, p6

    .line 237
    .line 238
    goto :goto_10

    .line 239
    :cond_14
    :goto_d
    if-eqz v2, :cond_15

    .line 240
    .line 241
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 242
    .line 243
    goto :goto_e

    .line 244
    :cond_15
    move-object v2, v3

    .line 245
    :goto_e
    and-int/lit8 v3, p11, 0x10

    .line 246
    .line 247
    sget-object v14, Ll2/n;->a:Ll2/x0;

    .line 248
    .line 249
    if-eqz v3, :cond_1c

    .line 250
    .line 251
    and-int/lit16 v3, v10, 0x1c00

    .line 252
    .line 253
    xor-int/lit16 v3, v3, 0xc00

    .line 254
    .line 255
    if-le v3, v8, :cond_16

    .line 256
    .line 257
    invoke-virtual {v9, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 258
    .line 259
    .line 260
    move-result v3

    .line 261
    if-nez v3, :cond_17

    .line 262
    .line 263
    :cond_16
    and-int/lit16 v3, v10, 0xc00

    .line 264
    .line 265
    if-ne v3, v8, :cond_18

    .line 266
    .line 267
    :cond_17
    move/from16 v3, v17

    .line 268
    .line 269
    goto :goto_f

    .line 270
    :cond_18
    move/from16 v3, v16

    .line 271
    .line 272
    :goto_f
    and-int/lit16 v6, v10, 0x380

    .line 273
    .line 274
    if-ne v6, v7, :cond_19

    .line 275
    .line 276
    move/from16 v16, v17

    .line 277
    .line 278
    :cond_19
    or-int v3, v3, v16

    .line 279
    .line 280
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    move-result-object v6

    .line 284
    if-nez v3, :cond_1a

    .line 285
    .line 286
    if-ne v6, v14, :cond_1b

    .line 287
    .line 288
    :cond_1a
    new-instance v6, Lh2/w8;

    .line 289
    .line 290
    const/4 v3, 0x0

    .line 291
    invoke-direct {v6, v5, v4, v3}, Lh2/w8;-><init>(Lh2/u8;ZI)V

    .line 292
    .line 293
    .line 294
    invoke-virtual {v9, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 295
    .line 296
    .line 297
    :cond_1b
    move-object v3, v6

    .line 298
    check-cast v3, Lay0/n;

    .line 299
    .line 300
    and-int/2addr v10, v15

    .line 301
    move-object v6, v3

    .line 302
    :cond_1c
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 303
    .line 304
    .line 305
    move-result-object v3

    .line 306
    if-ne v3, v14, :cond_1d

    .line 307
    .line 308
    sget-object v3, Lh2/i1;->h:Lh2/i1;

    .line 309
    .line 310
    invoke-virtual {v9, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 311
    .line 312
    .line 313
    :cond_1d
    check-cast v3, Lay0/o;

    .line 314
    .line 315
    if-eqz v11, :cond_1e

    .line 316
    .line 317
    sget v0, Lh2/q9;->c:F

    .line 318
    .line 319
    :cond_1e
    sget v7, Lh2/q9;->d:F

    .line 320
    .line 321
    move-object v5, v6

    .line 322
    move v8, v7

    .line 323
    move v7, v0

    .line 324
    move-object v6, v3

    .line 325
    :goto_10
    invoke-virtual {v9}, Ll2/t;->r()V

    .line 326
    .line 327
    .line 328
    const v0, 0x30000030

    .line 329
    .line 330
    .line 331
    and-int/lit8 v3, v10, 0xe

    .line 332
    .line 333
    or-int/2addr v0, v3

    .line 334
    shl-int/lit8 v3, v10, 0x3

    .line 335
    .line 336
    and-int/lit16 v11, v3, 0x380

    .line 337
    .line 338
    or-int/2addr v0, v11

    .line 339
    and-int/lit16 v11, v3, 0x1c00

    .line 340
    .line 341
    or-int/2addr v0, v11

    .line 342
    const v11, 0xe000

    .line 343
    .line 344
    .line 345
    and-int/2addr v11, v3

    .line 346
    or-int/2addr v0, v11

    .line 347
    const/high16 v11, 0x70000

    .line 348
    .line 349
    and-int/2addr v11, v3

    .line 350
    or-int/2addr v0, v11

    .line 351
    const/high16 v11, 0x380000

    .line 352
    .line 353
    and-int/2addr v11, v3

    .line 354
    or-int/2addr v0, v11

    .line 355
    const/high16 v11, 0x1c00000

    .line 356
    .line 357
    and-int/2addr v11, v3

    .line 358
    or-int/2addr v0, v11

    .line 359
    const/high16 v11, 0xe000000

    .line 360
    .line 361
    and-int/2addr v3, v11

    .line 362
    or-int/2addr v0, v3

    .line 363
    shr-int/lit8 v3, v10, 0x15

    .line 364
    .line 365
    and-int/lit8 v3, v3, 0x70

    .line 366
    .line 367
    or-int/lit8 v11, v3, 0x6

    .line 368
    .line 369
    move v10, v0

    .line 370
    move v3, v4

    .line 371
    move-object v0, v13

    .line 372
    move-object/from16 v4, p4

    .line 373
    .line 374
    invoke-virtual/range {v0 .. v11}, Lh2/a9;->c(Lh2/s9;Lx2/s;ZLh2/u8;Lay0/n;Lay0/o;FFLl2/o;II)V

    .line 375
    .line 376
    .line 377
    move-object v3, v2

    .line 378
    move-object v0, v9

    .line 379
    move v9, v8

    .line 380
    move v8, v7

    .line 381
    move-object v7, v6

    .line 382
    move-object v6, v5

    .line 383
    goto :goto_11

    .line 384
    :cond_1f
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 385
    .line 386
    .line 387
    move-object/from16 v7, p6

    .line 388
    .line 389
    move v8, v0

    .line 390
    move-object v0, v9

    .line 391
    move/from16 v9, p8

    .line 392
    .line 393
    :goto_11
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 394
    .line 395
    .line 396
    move-result-object v13

    .line 397
    if-eqz v13, :cond_20

    .line 398
    .line 399
    new-instance v0, Lh2/x8;

    .line 400
    .line 401
    const/4 v12, 0x0

    .line 402
    move-object/from16 v1, p0

    .line 403
    .line 404
    move-object/from16 v2, p1

    .line 405
    .line 406
    move/from16 v4, p3

    .line 407
    .line 408
    move-object/from16 v5, p4

    .line 409
    .line 410
    move/from16 v10, p10

    .line 411
    .line 412
    move/from16 v11, p11

    .line 413
    .line 414
    invoke-direct/range {v0 .. v12}, Lh2/x8;-><init>(Lh2/a9;Ljava/lang/Object;Lx2/s;ZLh2/u8;Lay0/n;Lay0/o;FFIII)V

    .line 415
    .line 416
    .line 417
    iput-object v0, v13, Ll2/u1;->d:Lay0/n;

    .line 418
    .line 419
    :cond_20
    return-void
.end method

.method public final c(Lh2/s9;Lx2/s;ZLh2/u8;Lay0/n;Lay0/o;FFLl2/o;II)V
    .locals 22

    .line 1
    move-object/from16 v1, p1

    .line 2
    .line 3
    move-object/from16 v15, p2

    .line 4
    .line 5
    move/from16 v0, p3

    .line 6
    .line 7
    move-object/from16 v2, p4

    .line 8
    .line 9
    move/from16 v3, p10

    .line 10
    .line 11
    move-object/from16 v4, p9

    .line 12
    .line 13
    check-cast v4, Ll2/t;

    .line 14
    .line 15
    const v5, 0x7f37829    # 3.66332E-34f

    .line 16
    .line 17
    .line 18
    invoke-virtual {v4, v5}, Ll2/t;->a0(I)Ll2/t;

    .line 19
    .line 20
    .line 21
    and-int/lit8 v5, v3, 0x6

    .line 22
    .line 23
    const/4 v6, 0x2

    .line 24
    if-nez v5, :cond_1

    .line 25
    .line 26
    invoke-virtual {v4, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v5

    .line 30
    if-eqz v5, :cond_0

    .line 31
    .line 32
    const/4 v5, 0x4

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    move v5, v6

    .line 35
    :goto_0
    or-int/2addr v5, v3

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    move v5, v3

    .line 38
    :goto_1
    and-int/lit8 v8, v3, 0x30

    .line 39
    .line 40
    if-nez v8, :cond_3

    .line 41
    .line 42
    const/high16 v8, 0x7fc00000    # Float.NaN

    .line 43
    .line 44
    invoke-virtual {v4, v8}, Ll2/t;->d(F)Z

    .line 45
    .line 46
    .line 47
    move-result v8

    .line 48
    if-eqz v8, :cond_2

    .line 49
    .line 50
    const/16 v8, 0x20

    .line 51
    .line 52
    goto :goto_2

    .line 53
    :cond_2
    const/16 v8, 0x10

    .line 54
    .line 55
    :goto_2
    or-int/2addr v5, v8

    .line 56
    :cond_3
    and-int/lit16 v8, v3, 0x180

    .line 57
    .line 58
    if-nez v8, :cond_5

    .line 59
    .line 60
    invoke-virtual {v4, v15}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v8

    .line 64
    if-eqz v8, :cond_4

    .line 65
    .line 66
    const/16 v8, 0x100

    .line 67
    .line 68
    goto :goto_3

    .line 69
    :cond_4
    const/16 v8, 0x80

    .line 70
    .line 71
    :goto_3
    or-int/2addr v5, v8

    .line 72
    :cond_5
    and-int/lit16 v8, v3, 0xc00

    .line 73
    .line 74
    if-nez v8, :cond_7

    .line 75
    .line 76
    invoke-virtual {v4, v0}, Ll2/t;->h(Z)Z

    .line 77
    .line 78
    .line 79
    move-result v8

    .line 80
    if-eqz v8, :cond_6

    .line 81
    .line 82
    const/16 v8, 0x800

    .line 83
    .line 84
    goto :goto_4

    .line 85
    :cond_6
    const/16 v8, 0x400

    .line 86
    .line 87
    :goto_4
    or-int/2addr v5, v8

    .line 88
    :cond_7
    and-int/lit16 v8, v3, 0x6000

    .line 89
    .line 90
    if-nez v8, :cond_9

    .line 91
    .line 92
    invoke-virtual {v4, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result v8

    .line 96
    if-eqz v8, :cond_8

    .line 97
    .line 98
    const/16 v8, 0x4000

    .line 99
    .line 100
    goto :goto_5

    .line 101
    :cond_8
    const/16 v8, 0x2000

    .line 102
    .line 103
    :goto_5
    or-int/2addr v5, v8

    .line 104
    :cond_9
    const/high16 v8, 0x30000

    .line 105
    .line 106
    and-int/2addr v8, v3

    .line 107
    move-object/from16 v12, p5

    .line 108
    .line 109
    if-nez v8, :cond_b

    .line 110
    .line 111
    invoke-virtual {v4, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result v8

    .line 115
    if-eqz v8, :cond_a

    .line 116
    .line 117
    const/high16 v8, 0x20000

    .line 118
    .line 119
    goto :goto_6

    .line 120
    :cond_a
    const/high16 v8, 0x10000

    .line 121
    .line 122
    :goto_6
    or-int/2addr v5, v8

    .line 123
    :cond_b
    const/high16 v8, 0x180000

    .line 124
    .line 125
    and-int/2addr v8, v3

    .line 126
    move-object/from16 v13, p6

    .line 127
    .line 128
    if-nez v8, :cond_d

    .line 129
    .line 130
    invoke-virtual {v4, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v8

    .line 134
    if-eqz v8, :cond_c

    .line 135
    .line 136
    const/high16 v8, 0x100000

    .line 137
    .line 138
    goto :goto_7

    .line 139
    :cond_c
    const/high16 v8, 0x80000

    .line 140
    .line 141
    :goto_7
    or-int/2addr v5, v8

    .line 142
    :cond_d
    const/high16 v8, 0xc00000

    .line 143
    .line 144
    and-int/2addr v8, v3

    .line 145
    if-nez v8, :cond_f

    .line 146
    .line 147
    move/from16 v8, p7

    .line 148
    .line 149
    invoke-virtual {v4, v8}, Ll2/t;->d(F)Z

    .line 150
    .line 151
    .line 152
    move-result v16

    .line 153
    if-eqz v16, :cond_e

    .line 154
    .line 155
    const/high16 v16, 0x800000

    .line 156
    .line 157
    goto :goto_8

    .line 158
    :cond_e
    const/high16 v16, 0x400000

    .line 159
    .line 160
    :goto_8
    or-int v5, v5, v16

    .line 161
    .line 162
    goto :goto_9

    .line 163
    :cond_f
    move/from16 v8, p7

    .line 164
    .line 165
    :goto_9
    const/high16 v16, 0x6000000

    .line 166
    .line 167
    and-int v16, v3, v16

    .line 168
    .line 169
    move/from16 v11, p8

    .line 170
    .line 171
    if-nez v16, :cond_11

    .line 172
    .line 173
    invoke-virtual {v4, v11}, Ll2/t;->d(F)Z

    .line 174
    .line 175
    .line 176
    move-result v17

    .line 177
    if-eqz v17, :cond_10

    .line 178
    .line 179
    const/high16 v17, 0x4000000

    .line 180
    .line 181
    goto :goto_a

    .line 182
    :cond_10
    const/high16 v17, 0x2000000

    .line 183
    .line 184
    :goto_a
    or-int v5, v5, v17

    .line 185
    .line 186
    :cond_11
    const/high16 v17, 0x30000000

    .line 187
    .line 188
    and-int v17, v3, v17

    .line 189
    .line 190
    const/4 v10, 0x0

    .line 191
    if-nez v17, :cond_13

    .line 192
    .line 193
    invoke-virtual {v4, v10}, Ll2/t;->h(Z)Z

    .line 194
    .line 195
    .line 196
    move-result v17

    .line 197
    if-eqz v17, :cond_12

    .line 198
    .line 199
    const/high16 v17, 0x20000000

    .line 200
    .line 201
    goto :goto_b

    .line 202
    :cond_12
    const/high16 v17, 0x10000000

    .line 203
    .line 204
    :goto_b
    or-int v5, v5, v17

    .line 205
    .line 206
    :cond_13
    and-int/lit8 v17, p11, 0x6

    .line 207
    .line 208
    if-nez v17, :cond_15

    .line 209
    .line 210
    invoke-virtual {v4, v10}, Ll2/t;->h(Z)Z

    .line 211
    .line 212
    .line 213
    move-result v17

    .line 214
    if-eqz v17, :cond_14

    .line 215
    .line 216
    const/16 v17, 0x4

    .line 217
    .line 218
    goto :goto_c

    .line 219
    :cond_14
    move/from16 v17, v6

    .line 220
    .line 221
    :goto_c
    or-int v17, p11, v17

    .line 222
    .line 223
    goto :goto_d

    .line 224
    :cond_15
    move/from16 v17, p11

    .line 225
    .line 226
    :goto_d
    const v18, 0x12492493

    .line 227
    .line 228
    .line 229
    and-int v7, v5, v18

    .line 230
    .line 231
    const v14, 0x12492492

    .line 232
    .line 233
    .line 234
    const/4 v9, 0x1

    .line 235
    if-ne v7, v14, :cond_17

    .line 236
    .line 237
    and-int/lit8 v7, v17, 0x3

    .line 238
    .line 239
    if-eq v7, v6, :cond_16

    .line 240
    .line 241
    goto :goto_e

    .line 242
    :cond_16
    move v6, v10

    .line 243
    goto :goto_f

    .line 244
    :cond_17
    :goto_e
    move v6, v9

    .line 245
    :goto_f
    and-int/lit8 v7, v5, 0x1

    .line 246
    .line 247
    invoke-virtual {v4, v7, v6}, Ll2/t;->O(IZ)Z

    .line 248
    .line 249
    .line 250
    move-result v6

    .line 251
    if-eqz v6, :cond_25

    .line 252
    .line 253
    invoke-virtual {v2, v0, v10}, Lh2/u8;->b(ZZ)J

    .line 254
    .line 255
    .line 256
    move-result-wide v6

    .line 257
    invoke-virtual {v2, v0, v9}, Lh2/u8;->b(ZZ)J

    .line 258
    .line 259
    .line 260
    move-result-wide v11

    .line 261
    invoke-virtual {v2, v0, v10}, Lh2/u8;->a(ZZ)J

    .line 262
    .line 263
    .line 264
    move-result-wide v13

    .line 265
    move v10, v9

    .line 266
    invoke-virtual {v2, v0, v10}, Lh2/u8;->a(ZZ)J

    .line 267
    .line 268
    .line 269
    move-result-wide v8

    .line 270
    iget-object v10, v1, Lh2/s9;->m:Lg1/w1;

    .line 271
    .line 272
    sget-object v0, Lg1/w1;->d:Lg1/w1;

    .line 273
    .line 274
    const/high16 v2, 0x3f800000    # 1.0f

    .line 275
    .line 276
    if-ne v10, v0, :cond_18

    .line 277
    .line 278
    sget v0, Lh2/q9;->a:F

    .line 279
    .line 280
    invoke-static {v15, v0}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 281
    .line 282
    .line 283
    move-result-object v0

    .line 284
    invoke-static {v0, v2}, Landroidx/compose/foundation/layout/d;->c(Lx2/s;F)Lx2/s;

    .line 285
    .line 286
    .line 287
    move-result-object v0

    .line 288
    goto :goto_10

    .line 289
    :cond_18
    invoke-static {v15, v2}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 290
    .line 291
    .line 292
    move-result-object v0

    .line 293
    sget v2, Lh2/q9;->a:F

    .line 294
    .line 295
    invoke-static {v0, v2}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 296
    .line 297
    .line 298
    move-result-object v0

    .line 299
    :goto_10
    and-int/lit8 v2, v5, 0x70

    .line 300
    .line 301
    const/16 v10, 0x20

    .line 302
    .line 303
    if-ne v2, v10, :cond_19

    .line 304
    .line 305
    const/4 v10, 0x1

    .line 306
    goto :goto_11

    .line 307
    :cond_19
    const/4 v10, 0x0

    .line 308
    :goto_11
    invoke-virtual {v4, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 309
    .line 310
    .line 311
    move-result v20

    .line 312
    or-int v10, v10, v20

    .line 313
    .line 314
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 315
    .line 316
    .line 317
    move-result-object v3

    .line 318
    move/from16 v20, v5

    .line 319
    .line 320
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 321
    .line 322
    if-nez v10, :cond_1a

    .line 323
    .line 324
    if-ne v3, v5, :cond_1b

    .line 325
    .line 326
    :cond_1a
    new-instance v3, Lb50/c;

    .line 327
    .line 328
    const/16 v10, 0x10

    .line 329
    .line 330
    invoke-direct {v3, v1, v10}, Lb50/c;-><init>(Ljava/lang/Object;I)V

    .line 331
    .line 332
    .line 333
    invoke-virtual {v4, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 334
    .line 335
    .line 336
    :cond_1b
    check-cast v3, Lay0/o;

    .line 337
    .line 338
    sget-object v10, Lx2/p;->b:Lx2/p;

    .line 339
    .line 340
    invoke-static {v10, v3}, Landroidx/compose/ui/layout/a;->b(Lx2/s;Lay0/o;)Lx2/s;

    .line 341
    .line 342
    .line 343
    move-result-object v3

    .line 344
    invoke-interface {v0, v3}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 345
    .line 346
    .line 347
    move-result-object v0

    .line 348
    const/16 v10, 0x20

    .line 349
    .line 350
    if-ne v2, v10, :cond_1c

    .line 351
    .line 352
    const/4 v2, 0x1

    .line 353
    goto :goto_12

    .line 354
    :cond_1c
    const/4 v2, 0x0

    .line 355
    :goto_12
    invoke-virtual {v4, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 356
    .line 357
    .line 358
    move-result v3

    .line 359
    or-int/2addr v2, v3

    .line 360
    invoke-virtual {v4, v6, v7}, Ll2/t;->f(J)Z

    .line 361
    .line 362
    .line 363
    move-result v3

    .line 364
    or-int/2addr v2, v3

    .line 365
    invoke-virtual {v4, v11, v12}, Ll2/t;->f(J)Z

    .line 366
    .line 367
    .line 368
    move-result v3

    .line 369
    or-int/2addr v2, v3

    .line 370
    invoke-virtual {v4, v13, v14}, Ll2/t;->f(J)Z

    .line 371
    .line 372
    .line 373
    move-result v3

    .line 374
    or-int/2addr v2, v3

    .line 375
    invoke-virtual {v4, v8, v9}, Ll2/t;->f(J)Z

    .line 376
    .line 377
    .line 378
    move-result v3

    .line 379
    or-int/2addr v2, v3

    .line 380
    const/high16 v3, 0x1c00000

    .line 381
    .line 382
    and-int v3, v20, v3

    .line 383
    .line 384
    const/high16 v10, 0x800000

    .line 385
    .line 386
    if-ne v3, v10, :cond_1d

    .line 387
    .line 388
    const/4 v3, 0x1

    .line 389
    goto :goto_13

    .line 390
    :cond_1d
    const/4 v3, 0x0

    .line 391
    :goto_13
    or-int/2addr v2, v3

    .line 392
    const/high16 v3, 0xe000000

    .line 393
    .line 394
    and-int v3, v20, v3

    .line 395
    .line 396
    const/high16 v10, 0x4000000

    .line 397
    .line 398
    if-ne v3, v10, :cond_1e

    .line 399
    .line 400
    const/4 v3, 0x1

    .line 401
    goto :goto_14

    .line 402
    :cond_1e
    const/4 v3, 0x0

    .line 403
    :goto_14
    or-int/2addr v2, v3

    .line 404
    const/high16 v3, 0x70000

    .line 405
    .line 406
    and-int v3, v20, v3

    .line 407
    .line 408
    const/high16 v10, 0x20000

    .line 409
    .line 410
    if-ne v3, v10, :cond_1f

    .line 411
    .line 412
    const/4 v3, 0x1

    .line 413
    goto :goto_15

    .line 414
    :cond_1f
    const/4 v3, 0x0

    .line 415
    :goto_15
    or-int/2addr v2, v3

    .line 416
    const/high16 v3, 0x380000

    .line 417
    .line 418
    and-int v3, v20, v3

    .line 419
    .line 420
    const/high16 v10, 0x100000

    .line 421
    .line 422
    if-ne v3, v10, :cond_20

    .line 423
    .line 424
    const/4 v3, 0x1

    .line 425
    goto :goto_16

    .line 426
    :cond_20
    const/4 v3, 0x0

    .line 427
    :goto_16
    or-int/2addr v2, v3

    .line 428
    const/high16 v3, 0x70000000

    .line 429
    .line 430
    and-int v3, v20, v3

    .line 431
    .line 432
    const/high16 v10, 0x20000000

    .line 433
    .line 434
    if-ne v3, v10, :cond_21

    .line 435
    .line 436
    const/4 v3, 0x1

    .line 437
    goto :goto_17

    .line 438
    :cond_21
    const/4 v3, 0x0

    .line 439
    :goto_17
    or-int/2addr v2, v3

    .line 440
    and-int/lit8 v3, v17, 0xe

    .line 441
    .line 442
    const/4 v10, 0x4

    .line 443
    if-ne v3, v10, :cond_22

    .line 444
    .line 445
    const/16 v19, 0x1

    .line 446
    .line 447
    goto :goto_18

    .line 448
    :cond_22
    const/16 v19, 0x0

    .line 449
    .line 450
    :goto_18
    or-int v2, v2, v19

    .line 451
    .line 452
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 453
    .line 454
    .line 455
    move-result-object v3

    .line 456
    if-nez v2, :cond_23

    .line 457
    .line 458
    if-ne v3, v5, :cond_24

    .line 459
    .line 460
    :cond_23
    move-object v2, v0

    .line 461
    goto :goto_19

    .line 462
    :cond_24
    move-object/from16 v21, v0

    .line 463
    .line 464
    move-object v15, v4

    .line 465
    goto :goto_1a

    .line 466
    :goto_19
    new-instance v0, Lh2/y8;

    .line 467
    .line 468
    move-object v5, v2

    .line 469
    move-wide v2, v6

    .line 470
    move-wide v6, v13

    .line 471
    const/4 v14, 0x1

    .line 472
    move-object/from16 v13, p6

    .line 473
    .line 474
    move/from16 v10, p7

    .line 475
    .line 476
    move-object v15, v4

    .line 477
    move-object/from16 v21, v5

    .line 478
    .line 479
    move-wide v4, v11

    .line 480
    move-object/from16 v12, p5

    .line 481
    .line 482
    move/from16 v11, p8

    .line 483
    .line 484
    invoke-direct/range {v0 .. v14}, Lh2/y8;-><init>(Ljava/lang/Object;JJJJFFLay0/n;Lay0/o;I)V

    .line 485
    .line 486
    .line 487
    invoke-virtual {v15, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 488
    .line 489
    .line 490
    move-object v3, v0

    .line 491
    :goto_1a
    check-cast v3, Lay0/k;

    .line 492
    .line 493
    move-object/from16 v5, v21

    .line 494
    .line 495
    const/4 v0, 0x0

    .line 496
    invoke-static {v5, v3, v15, v0}, Lkp/i;->a(Lx2/s;Lay0/k;Ll2/o;I)V

    .line 497
    .line 498
    .line 499
    goto :goto_1b

    .line 500
    :cond_25
    move-object v15, v4

    .line 501
    invoke-virtual {v15}, Ll2/t;->R()V

    .line 502
    .line 503
    .line 504
    :goto_1b
    invoke-virtual {v15}, Ll2/t;->s()Ll2/u1;

    .line 505
    .line 506
    .line 507
    move-result-object v13

    .line 508
    if-eqz v13, :cond_26

    .line 509
    .line 510
    new-instance v0, Lh2/x8;

    .line 511
    .line 512
    const/4 v12, 0x1

    .line 513
    move-object/from16 v1, p0

    .line 514
    .line 515
    move-object/from16 v2, p1

    .line 516
    .line 517
    move-object/from16 v3, p2

    .line 518
    .line 519
    move/from16 v4, p3

    .line 520
    .line 521
    move-object/from16 v5, p4

    .line 522
    .line 523
    move-object/from16 v6, p5

    .line 524
    .line 525
    move-object/from16 v7, p6

    .line 526
    .line 527
    move/from16 v8, p7

    .line 528
    .line 529
    move/from16 v9, p8

    .line 530
    .line 531
    move/from16 v10, p10

    .line 532
    .line 533
    move/from16 v11, p11

    .line 534
    .line 535
    invoke-direct/range {v0 .. v12}, Lh2/x8;-><init>(Lh2/a9;Ljava/lang/Object;Lx2/s;ZLh2/u8;Lay0/n;Lay0/o;FFIII)V

    .line 536
    .line 537
    .line 538
    iput-object v0, v13, Ll2/u1;->d:Lay0/n;

    .line 539
    .line 540
    :cond_26
    return-void
.end method

.method public final d(Lh2/u7;Lx2/s;ZLh2/u8;Lay0/n;Lay0/o;FFLl2/o;I)V
    .locals 19

    .line 1
    move-object/from16 v1, p1

    .line 2
    .line 3
    move-object/from16 v15, p2

    .line 4
    .line 5
    move/from16 v0, p3

    .line 6
    .line 7
    move-object/from16 v2, p4

    .line 8
    .line 9
    move/from16 v3, p10

    .line 10
    .line 11
    move-object/from16 v4, p9

    .line 12
    .line 13
    check-cast v4, Ll2/t;

    .line 14
    .line 15
    const v5, -0x667bea28

    .line 16
    .line 17
    .line 18
    invoke-virtual {v4, v5}, Ll2/t;->a0(I)Ll2/t;

    .line 19
    .line 20
    .line 21
    and-int/lit8 v5, v3, 0x6

    .line 22
    .line 23
    if-nez v5, :cond_1

    .line 24
    .line 25
    invoke-virtual {v4, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v5

    .line 29
    if-eqz v5, :cond_0

    .line 30
    .line 31
    const/4 v5, 0x4

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    const/4 v5, 0x2

    .line 34
    :goto_0
    or-int/2addr v5, v3

    .line 35
    goto :goto_1

    .line 36
    :cond_1
    move v5, v3

    .line 37
    :goto_1
    and-int/lit8 v6, v3, 0x30

    .line 38
    .line 39
    if-nez v6, :cond_3

    .line 40
    .line 41
    const/high16 v6, 0x7fc00000    # Float.NaN

    .line 42
    .line 43
    invoke-virtual {v4, v6}, Ll2/t;->d(F)Z

    .line 44
    .line 45
    .line 46
    move-result v6

    .line 47
    if-eqz v6, :cond_2

    .line 48
    .line 49
    const/16 v6, 0x20

    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_2
    const/16 v6, 0x10

    .line 53
    .line 54
    :goto_2
    or-int/2addr v5, v6

    .line 55
    :cond_3
    and-int/lit16 v6, v3, 0x180

    .line 56
    .line 57
    if-nez v6, :cond_5

    .line 58
    .line 59
    invoke-virtual {v4, v15}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v6

    .line 63
    if-eqz v6, :cond_4

    .line 64
    .line 65
    const/16 v6, 0x100

    .line 66
    .line 67
    goto :goto_3

    .line 68
    :cond_4
    const/16 v6, 0x80

    .line 69
    .line 70
    :goto_3
    or-int/2addr v5, v6

    .line 71
    :cond_5
    and-int/lit16 v6, v3, 0xc00

    .line 72
    .line 73
    if-nez v6, :cond_7

    .line 74
    .line 75
    invoke-virtual {v4, v0}, Ll2/t;->h(Z)Z

    .line 76
    .line 77
    .line 78
    move-result v6

    .line 79
    if-eqz v6, :cond_6

    .line 80
    .line 81
    const/16 v6, 0x800

    .line 82
    .line 83
    goto :goto_4

    .line 84
    :cond_6
    const/16 v6, 0x400

    .line 85
    .line 86
    :goto_4
    or-int/2addr v5, v6

    .line 87
    :cond_7
    and-int/lit16 v6, v3, 0x6000

    .line 88
    .line 89
    if-nez v6, :cond_9

    .line 90
    .line 91
    invoke-virtual {v4, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    move-result v6

    .line 95
    if-eqz v6, :cond_8

    .line 96
    .line 97
    const/16 v6, 0x4000

    .line 98
    .line 99
    goto :goto_5

    .line 100
    :cond_8
    const/16 v6, 0x2000

    .line 101
    .line 102
    :goto_5
    or-int/2addr v5, v6

    .line 103
    :cond_9
    const/high16 v6, 0x30000

    .line 104
    .line 105
    and-int/2addr v6, v3

    .line 106
    if-nez v6, :cond_b

    .line 107
    .line 108
    move-object/from16 v6, p5

    .line 109
    .line 110
    invoke-virtual {v4, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    move-result v9

    .line 114
    if-eqz v9, :cond_a

    .line 115
    .line 116
    const/high16 v9, 0x20000

    .line 117
    .line 118
    goto :goto_6

    .line 119
    :cond_a
    const/high16 v9, 0x10000

    .line 120
    .line 121
    :goto_6
    or-int/2addr v5, v9

    .line 122
    goto :goto_7

    .line 123
    :cond_b
    move-object/from16 v6, p5

    .line 124
    .line 125
    :goto_7
    const/high16 v9, 0x180000

    .line 126
    .line 127
    and-int/2addr v9, v3

    .line 128
    move-object/from16 v13, p6

    .line 129
    .line 130
    if-nez v9, :cond_d

    .line 131
    .line 132
    invoke-virtual {v4, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    move-result v9

    .line 136
    if-eqz v9, :cond_c

    .line 137
    .line 138
    const/high16 v9, 0x100000

    .line 139
    .line 140
    goto :goto_8

    .line 141
    :cond_c
    const/high16 v9, 0x80000

    .line 142
    .line 143
    :goto_8
    or-int/2addr v5, v9

    .line 144
    :cond_d
    const/high16 v9, 0xc00000

    .line 145
    .line 146
    and-int/2addr v9, v3

    .line 147
    if-nez v9, :cond_f

    .line 148
    .line 149
    move/from16 v9, p7

    .line 150
    .line 151
    invoke-virtual {v4, v9}, Ll2/t;->d(F)Z

    .line 152
    .line 153
    .line 154
    move-result v12

    .line 155
    if-eqz v12, :cond_e

    .line 156
    .line 157
    const/high16 v12, 0x800000

    .line 158
    .line 159
    goto :goto_9

    .line 160
    :cond_e
    const/high16 v12, 0x400000

    .line 161
    .line 162
    :goto_9
    or-int/2addr v5, v12

    .line 163
    goto :goto_a

    .line 164
    :cond_f
    move/from16 v9, p7

    .line 165
    .line 166
    :goto_a
    const/high16 v12, 0x6000000

    .line 167
    .line 168
    and-int/2addr v12, v3

    .line 169
    if-nez v12, :cond_11

    .line 170
    .line 171
    move/from16 v12, p8

    .line 172
    .line 173
    invoke-virtual {v4, v12}, Ll2/t;->d(F)Z

    .line 174
    .line 175
    .line 176
    move-result v16

    .line 177
    if-eqz v16, :cond_10

    .line 178
    .line 179
    const/high16 v16, 0x4000000

    .line 180
    .line 181
    goto :goto_b

    .line 182
    :cond_10
    const/high16 v16, 0x2000000

    .line 183
    .line 184
    :goto_b
    or-int v5, v5, v16

    .line 185
    .line 186
    goto :goto_c

    .line 187
    :cond_11
    move/from16 v12, p8

    .line 188
    .line 189
    :goto_c
    const v16, 0x2492493

    .line 190
    .line 191
    .line 192
    and-int v10, v5, v16

    .line 193
    .line 194
    const v8, 0x2492492

    .line 195
    .line 196
    .line 197
    const/4 v14, 0x0

    .line 198
    const/4 v11, 0x1

    .line 199
    if-eq v10, v8, :cond_12

    .line 200
    .line 201
    move v8, v11

    .line 202
    goto :goto_d

    .line 203
    :cond_12
    move v8, v14

    .line 204
    :goto_d
    and-int/lit8 v10, v5, 0x1

    .line 205
    .line 206
    invoke-virtual {v4, v10, v8}, Ll2/t;->O(IZ)Z

    .line 207
    .line 208
    .line 209
    move-result v8

    .line 210
    if-eqz v8, :cond_1b

    .line 211
    .line 212
    invoke-virtual {v2, v0, v14}, Lh2/u8;->b(ZZ)J

    .line 213
    .line 214
    .line 215
    move-result-wide v7

    .line 216
    move/from16 v17, v5

    .line 217
    .line 218
    invoke-virtual {v2, v0, v11}, Lh2/u8;->b(ZZ)J

    .line 219
    .line 220
    .line 221
    move-result-wide v5

    .line 222
    invoke-virtual {v2, v0, v14}, Lh2/u8;->a(ZZ)J

    .line 223
    .line 224
    .line 225
    move-result-wide v9

    .line 226
    invoke-virtual {v2, v0, v11}, Lh2/u8;->a(ZZ)J

    .line 227
    .line 228
    .line 229
    move-result-wide v12

    .line 230
    const/high16 v11, 0x3f800000    # 1.0f

    .line 231
    .line 232
    invoke-static {v15, v11}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 233
    .line 234
    .line 235
    move-result-object v11

    .line 236
    sget v14, Lh2/q9;->a:F

    .line 237
    .line 238
    invoke-static {v11, v14}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 239
    .line 240
    .line 241
    move-result-object v11

    .line 242
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 243
    .line 244
    .line 245
    move-result-object v14

    .line 246
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 247
    .line 248
    if-ne v14, v0, :cond_13

    .line 249
    .line 250
    new-instance v14, Lel/a;

    .line 251
    .line 252
    const/16 v2, 0x13

    .line 253
    .line 254
    invoke-direct {v14, v2}, Lel/a;-><init>(I)V

    .line 255
    .line 256
    .line 257
    invoke-virtual {v4, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 258
    .line 259
    .line 260
    :cond_13
    check-cast v14, Lay0/o;

    .line 261
    .line 262
    invoke-static {v11, v14}, Landroidx/compose/ui/layout/a;->b(Lx2/s;Lay0/o;)Lx2/s;

    .line 263
    .line 264
    .line 265
    move-result-object v2

    .line 266
    and-int/lit8 v11, v17, 0x70

    .line 267
    .line 268
    const/16 v14, 0x20

    .line 269
    .line 270
    if-ne v11, v14, :cond_14

    .line 271
    .line 272
    const/4 v11, 0x1

    .line 273
    goto :goto_e

    .line 274
    :cond_14
    const/4 v11, 0x0

    .line 275
    :goto_e
    invoke-virtual {v4, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 276
    .line 277
    .line 278
    move-result v14

    .line 279
    or-int/2addr v11, v14

    .line 280
    invoke-virtual {v4, v7, v8}, Ll2/t;->f(J)Z

    .line 281
    .line 282
    .line 283
    move-result v14

    .line 284
    or-int/2addr v11, v14

    .line 285
    invoke-virtual {v4, v5, v6}, Ll2/t;->f(J)Z

    .line 286
    .line 287
    .line 288
    move-result v14

    .line 289
    or-int/2addr v11, v14

    .line 290
    invoke-virtual {v4, v9, v10}, Ll2/t;->f(J)Z

    .line 291
    .line 292
    .line 293
    move-result v14

    .line 294
    or-int/2addr v11, v14

    .line 295
    invoke-virtual {v4, v12, v13}, Ll2/t;->f(J)Z

    .line 296
    .line 297
    .line 298
    move-result v14

    .line 299
    or-int/2addr v11, v14

    .line 300
    const/high16 v14, 0x1c00000

    .line 301
    .line 302
    and-int v14, v17, v14

    .line 303
    .line 304
    const/high16 v1, 0x800000

    .line 305
    .line 306
    if-ne v14, v1, :cond_15

    .line 307
    .line 308
    const/4 v1, 0x1

    .line 309
    goto :goto_f

    .line 310
    :cond_15
    const/4 v1, 0x0

    .line 311
    :goto_f
    or-int/2addr v1, v11

    .line 312
    const/high16 v11, 0xe000000

    .line 313
    .line 314
    and-int v11, v17, v11

    .line 315
    .line 316
    const/high16 v14, 0x4000000

    .line 317
    .line 318
    if-ne v11, v14, :cond_16

    .line 319
    .line 320
    const/4 v11, 0x1

    .line 321
    goto :goto_10

    .line 322
    :cond_16
    const/4 v11, 0x0

    .line 323
    :goto_10
    or-int/2addr v1, v11

    .line 324
    const/high16 v11, 0x70000

    .line 325
    .line 326
    and-int v11, v17, v11

    .line 327
    .line 328
    const/high16 v14, 0x20000

    .line 329
    .line 330
    if-ne v11, v14, :cond_17

    .line 331
    .line 332
    const/4 v11, 0x1

    .line 333
    goto :goto_11

    .line 334
    :cond_17
    const/4 v11, 0x0

    .line 335
    :goto_11
    or-int/2addr v1, v11

    .line 336
    const/high16 v11, 0x380000

    .line 337
    .line 338
    and-int v11, v17, v11

    .line 339
    .line 340
    const/high16 v14, 0x100000

    .line 341
    .line 342
    if-ne v11, v14, :cond_18

    .line 343
    .line 344
    const/4 v11, 0x1

    .line 345
    goto :goto_12

    .line 346
    :cond_18
    const/4 v11, 0x0

    .line 347
    :goto_12
    or-int/2addr v1, v11

    .line 348
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 349
    .line 350
    .line 351
    move-result-object v11

    .line 352
    if-nez v1, :cond_1a

    .line 353
    .line 354
    if-ne v11, v0, :cond_19

    .line 355
    .line 356
    goto :goto_13

    .line 357
    :cond_19
    move-object/from16 v18, v2

    .line 358
    .line 359
    move-object v15, v4

    .line 360
    goto :goto_14

    .line 361
    :cond_1a
    :goto_13
    new-instance v0, Lh2/y8;

    .line 362
    .line 363
    const/4 v14, 0x0

    .line 364
    move-object/from16 v1, p1

    .line 365
    .line 366
    move/from16 v11, p8

    .line 367
    .line 368
    move-object/from16 v18, v2

    .line 369
    .line 370
    move-object v15, v4

    .line 371
    move-wide v4, v5

    .line 372
    move-wide v2, v7

    .line 373
    move-wide v6, v9

    .line 374
    move-wide v8, v12

    .line 375
    move-object/from16 v12, p5

    .line 376
    .line 377
    move-object/from16 v13, p6

    .line 378
    .line 379
    move/from16 v10, p7

    .line 380
    .line 381
    invoke-direct/range {v0 .. v14}, Lh2/y8;-><init>(Ljava/lang/Object;JJJJFFLay0/n;Lay0/o;I)V

    .line 382
    .line 383
    .line 384
    invoke-virtual {v15, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 385
    .line 386
    .line 387
    move-object v11, v0

    .line 388
    :goto_14
    check-cast v11, Lay0/k;

    .line 389
    .line 390
    move-object/from16 v0, v18

    .line 391
    .line 392
    const/4 v1, 0x0

    .line 393
    invoke-static {v0, v11, v15, v1}, Lkp/i;->a(Lx2/s;Lay0/k;Ll2/o;I)V

    .line 394
    .line 395
    .line 396
    goto :goto_15

    .line 397
    :cond_1b
    move-object v15, v4

    .line 398
    invoke-virtual {v15}, Ll2/t;->R()V

    .line 399
    .line 400
    .line 401
    :goto_15
    invoke-virtual {v15}, Ll2/t;->s()Ll2/u1;

    .line 402
    .line 403
    .line 404
    move-result-object v11

    .line 405
    if-eqz v11, :cond_1c

    .line 406
    .line 407
    new-instance v0, Lh2/z8;

    .line 408
    .line 409
    move-object/from16 v1, p0

    .line 410
    .line 411
    move-object/from16 v2, p1

    .line 412
    .line 413
    move-object/from16 v3, p2

    .line 414
    .line 415
    move/from16 v4, p3

    .line 416
    .line 417
    move-object/from16 v5, p4

    .line 418
    .line 419
    move-object/from16 v6, p5

    .line 420
    .line 421
    move-object/from16 v7, p6

    .line 422
    .line 423
    move/from16 v8, p7

    .line 424
    .line 425
    move/from16 v9, p8

    .line 426
    .line 427
    move/from16 v10, p10

    .line 428
    .line 429
    invoke-direct/range {v0 .. v10}, Lh2/z8;-><init>(Lh2/a9;Lh2/u7;Lx2/s;ZLh2/u8;Lay0/n;Lay0/o;FFI)V

    .line 430
    .line 431
    .line 432
    iput-object v0, v11, Ll2/u1;->d:Lay0/n;

    .line 433
    .line 434
    :cond_1c
    return-void
.end method
