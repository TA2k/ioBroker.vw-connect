.class public abstract Landroidx/compose/ui/graphics/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lx2/s;Lay0/k;)Lx2/s;
    .locals 1

    .line 1
    new-instance v0, Landroidx/compose/ui/graphics/BlockGraphicsLayerElement;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Landroidx/compose/ui/graphics/BlockGraphicsLayerElement;-><init>(Lay0/k;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public static b(Lx2/s;FFFFLe3/n0;I)Lx2/s;
    .locals 19

    .line 1
    move/from16 v0, p6

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    const/high16 v2, 0x3f800000    # 1.0f

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    move v4, v2

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move/from16 v4, p1

    .line 12
    .line 13
    :goto_0
    and-int/lit8 v1, v0, 0x2

    .line 14
    .line 15
    if-eqz v1, :cond_1

    .line 16
    .line 17
    move v5, v2

    .line 18
    goto :goto_1

    .line 19
    :cond_1
    move/from16 v5, p2

    .line 20
    .line 21
    :goto_1
    and-int/lit8 v1, v0, 0x4

    .line 22
    .line 23
    if-eqz v1, :cond_2

    .line 24
    .line 25
    move v6, v2

    .line 26
    goto :goto_2

    .line 27
    :cond_2
    move/from16 v6, p3

    .line 28
    .line 29
    :goto_2
    and-int/lit8 v1, v0, 0x20

    .line 30
    .line 31
    if-eqz v1, :cond_3

    .line 32
    .line 33
    const/4 v1, 0x0

    .line 34
    move v9, v1

    .line 35
    goto :goto_3

    .line 36
    :cond_3
    move/from16 v9, p4

    .line 37
    .line 38
    :goto_3
    sget-wide v11, Le3/q0;->b:J

    .line 39
    .line 40
    and-int/lit16 v0, v0, 0x800

    .line 41
    .line 42
    if-eqz v0, :cond_4

    .line 43
    .line 44
    sget-object v0, Le3/j0;->a:Le3/i0;

    .line 45
    .line 46
    move-object v13, v0

    .line 47
    goto :goto_4

    .line 48
    :cond_4
    move-object/from16 v13, p5

    .line 49
    .line 50
    :goto_4
    sget-wide v15, Le3/y;->a:J

    .line 51
    .line 52
    new-instance v3, Landroidx/compose/ui/graphics/GraphicsLayerElement;

    .line 53
    .line 54
    const/4 v7, 0x0

    .line 55
    const/4 v8, 0x0

    .line 56
    const/4 v10, 0x0

    .line 57
    const/4 v14, 0x0

    .line 58
    move-wide/from16 v17, v15

    .line 59
    .line 60
    invoke-direct/range {v3 .. v18}, Landroidx/compose/ui/graphics/GraphicsLayerElement;-><init>(FFFFFFFJLe3/n0;ZJJ)V

    .line 61
    .line 62
    .line 63
    move-object/from16 v0, p0

    .line 64
    .line 65
    invoke-interface {v0, v3}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    return-object v0
.end method

.method public static c(Lx2/s;FFFFLe3/n0;I)Lx2/s;
    .locals 20

    .line 1
    move/from16 v0, p6

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/high16 v3, 0x3f800000    # 1.0f

    .line 7
    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    move v5, v3

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    move v5, v2

    .line 13
    :goto_0
    and-int/lit8 v1, v0, 0x2

    .line 14
    .line 15
    if-eqz v1, :cond_1

    .line 16
    .line 17
    move v6, v3

    .line 18
    goto :goto_1

    .line 19
    :cond_1
    move v6, v2

    .line 20
    :goto_1
    and-int/lit8 v1, v0, 0x4

    .line 21
    .line 22
    if-eqz v1, :cond_2

    .line 23
    .line 24
    move v7, v3

    .line 25
    goto :goto_2

    .line 26
    :cond_2
    move/from16 v7, p1

    .line 27
    .line 28
    :goto_2
    and-int/lit8 v1, v0, 0x8

    .line 29
    .line 30
    if-eqz v1, :cond_3

    .line 31
    .line 32
    move v8, v2

    .line 33
    goto :goto_3

    .line 34
    :cond_3
    move/from16 v8, p2

    .line 35
    .line 36
    :goto_3
    and-int/lit8 v1, v0, 0x10

    .line 37
    .line 38
    if-eqz v1, :cond_4

    .line 39
    .line 40
    move v9, v2

    .line 41
    goto :goto_4

    .line 42
    :cond_4
    move/from16 v9, p3

    .line 43
    .line 44
    :goto_4
    and-int/lit16 v1, v0, 0x100

    .line 45
    .line 46
    if-eqz v1, :cond_5

    .line 47
    .line 48
    move v11, v2

    .line 49
    goto :goto_5

    .line 50
    :cond_5
    move/from16 v11, p4

    .line 51
    .line 52
    :goto_5
    sget-wide v12, Le3/q0;->b:J

    .line 53
    .line 54
    and-int/lit16 v1, v0, 0x800

    .line 55
    .line 56
    if-eqz v1, :cond_6

    .line 57
    .line 58
    sget-object v1, Le3/j0;->a:Le3/i0;

    .line 59
    .line 60
    move-object v14, v1

    .line 61
    goto :goto_6

    .line 62
    :cond_6
    move-object/from16 v14, p5

    .line 63
    .line 64
    :goto_6
    and-int/lit16 v0, v0, 0x1000

    .line 65
    .line 66
    if-eqz v0, :cond_7

    .line 67
    .line 68
    const/4 v0, 0x0

    .line 69
    :goto_7
    move v15, v0

    .line 70
    goto :goto_8

    .line 71
    :cond_7
    const/4 v0, 0x1

    .line 72
    goto :goto_7

    .line 73
    :goto_8
    sget-wide v16, Le3/y;->a:J

    .line 74
    .line 75
    new-instance v4, Landroidx/compose/ui/graphics/GraphicsLayerElement;

    .line 76
    .line 77
    const/4 v10, 0x0

    .line 78
    move-wide/from16 v18, v16

    .line 79
    .line 80
    invoke-direct/range {v4 .. v19}, Landroidx/compose/ui/graphics/GraphicsLayerElement;-><init>(FFFFFFFJLe3/n0;ZJJ)V

    .line 81
    .line 82
    .line 83
    move-object/from16 v0, p0

    .line 84
    .line 85
    invoke-interface {v0, v4}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    return-object v0
.end method
