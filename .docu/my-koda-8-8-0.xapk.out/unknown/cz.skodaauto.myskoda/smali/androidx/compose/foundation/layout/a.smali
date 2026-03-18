.class public abstract Landroidx/compose/foundation/layout/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(FFI)Lk1/a1;
    .locals 2

    .line 1
    and-int/lit8 v0, p2, 0x1

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    int-to-float p0, v1

    .line 7
    :cond_0
    and-int/lit8 p2, p2, 0x2

    .line 8
    .line 9
    if-eqz p2, :cond_1

    .line 10
    .line 11
    int-to-float p1, v1

    .line 12
    :cond_1
    new-instance p2, Lk1/a1;

    .line 13
    .line 14
    invoke-direct {p2, p0, p1, p0, p1}, Lk1/a1;-><init>(FFFF)V

    .line 15
    .line 16
    .line 17
    return-object p2
.end method

.method public static final b(FFFF)Lk1/a1;
    .locals 1

    .line 1
    new-instance v0, Lk1/a1;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1, p2, p3}, Lk1/a1;-><init>(FFFF)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static c(FFFFI)Lk1/a1;
    .locals 2

    .line 1
    and-int/lit8 v0, p4, 0x1

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    int-to-float p0, v1

    .line 7
    :cond_0
    and-int/lit8 v0, p4, 0x2

    .line 8
    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    int-to-float p1, v1

    .line 12
    :cond_1
    and-int/lit8 v0, p4, 0x4

    .line 13
    .line 14
    if-eqz v0, :cond_2

    .line 15
    .line 16
    int-to-float p2, v1

    .line 17
    :cond_2
    and-int/lit8 p4, p4, 0x8

    .line 18
    .line 19
    if-eqz p4, :cond_3

    .line 20
    .line 21
    int-to-float p3, v1

    .line 22
    :cond_3
    new-instance p4, Lk1/a1;

    .line 23
    .line 24
    invoke-direct {p4, p0, p1, p2, p3}, Lk1/a1;-><init>(FFFF)V

    .line 25
    .line 26
    .line 27
    return-object p4
.end method

.method public static final d(Lx2/s;FZ)Lx2/s;
    .locals 1

    .line 1
    new-instance v0, Landroidx/compose/foundation/layout/AspectRatioElement;

    .line 2
    .line 3
    invoke-direct {v0, p1, p2}, Landroidx/compose/foundation/layout/AspectRatioElement;-><init>(FZ)V

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

.method public static final e(Lk1/z0;Lt4/m;)F
    .locals 1

    .line 1
    sget-object v0, Lt4/m;->d:Lt4/m;

    .line 2
    .line 3
    if-ne p1, v0, :cond_0

    .line 4
    .line 5
    invoke-interface {p0, p1}, Lk1/z0;->a(Lt4/m;)F

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0

    .line 10
    :cond_0
    invoke-interface {p0, p1}, Lk1/z0;->b(Lt4/m;)F

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0
.end method

.method public static final f(Lk1/z0;Lt4/m;)F
    .locals 1

    .line 1
    sget-object v0, Lt4/m;->d:Lt4/m;

    .line 2
    .line 3
    if-ne p1, v0, :cond_0

    .line 4
    .line 5
    invoke-interface {p0, p1}, Lk1/z0;->b(Lt4/m;)F

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0

    .line 10
    :cond_0
    invoke-interface {p0, p1}, Lk1/z0;->a(Lt4/m;)F

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0
.end method

.method public static final g(Lx2/s;Lk1/r0;)Lx2/s;
    .locals 1

    .line 1
    new-instance v0, Landroidx/compose/foundation/layout/IntrinsicHeightElement;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Landroidx/compose/foundation/layout/IntrinsicHeightElement;-><init>(Lk1/r0;)V

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

.method public static final h(JII)Z
    .locals 2

    .line 1
    invoke-static {p0, p1}, Lt4/a;->j(J)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {p0, p1}, Lt4/a;->h(J)I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-gt p2, v1, :cond_0

    .line 10
    .line 11
    if-gt v0, p2, :cond_0

    .line 12
    .line 13
    invoke-static {p0, p1}, Lt4/a;->i(J)I

    .line 14
    .line 15
    .line 16
    move-result p2

    .line 17
    invoke-static {p0, p1}, Lt4/a;->g(J)I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-gt p3, p0, :cond_0

    .line 22
    .line 23
    if-gt p2, p3, :cond_0

    .line 24
    .line 25
    const/4 p0, 0x1

    .line 26
    return p0

    .line 27
    :cond_0
    const/4 p0, 0x0

    .line 28
    return p0
.end method

.method public static final i(Lx2/s;Lay0/k;)Lx2/s;
    .locals 3

    .line 1
    new-instance v0, Landroidx/compose/foundation/layout/OffsetPxElement;

    .line 2
    .line 3
    new-instance v1, Li50/d;

    .line 4
    .line 5
    const/4 v2, 0x6

    .line 6
    invoke-direct {v1, v2, p1}, Li50/d;-><init>(ILay0/k;)V

    .line 7
    .line 8
    .line 9
    invoke-direct {v0, p1, v1}, Landroidx/compose/foundation/layout/OffsetPxElement;-><init>(Lay0/k;Li50/d;)V

    .line 10
    .line 11
    .line 12
    invoke-interface {p0, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method public static final j(Lx2/s;FF)Lx2/s;
    .locals 3

    .line 1
    new-instance v0, Landroidx/compose/foundation/layout/OffsetElement;

    .line 2
    .line 3
    new-instance v1, Ljy/b;

    .line 4
    .line 5
    const/4 v2, 0x6

    .line 6
    invoke-direct {v1, v2}, Ljy/b;-><init>(I)V

    .line 7
    .line 8
    .line 9
    invoke-direct {v0, p1, p2, v1}, Landroidx/compose/foundation/layout/OffsetElement;-><init>(FFLjy/b;)V

    .line 10
    .line 11
    .line 12
    invoke-interface {p0, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method public static k(Lx2/s;FFI)Lx2/s;
    .locals 2

    .line 1
    and-int/lit8 v0, p3, 0x1

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    int-to-float p1, v1

    .line 7
    :cond_0
    and-int/lit8 p3, p3, 0x2

    .line 8
    .line 9
    if-eqz p3, :cond_1

    .line 10
    .line 11
    int-to-float p2, v1

    .line 12
    :cond_1
    invoke-static {p0, p1, p2}, Landroidx/compose/foundation/layout/a;->j(Lx2/s;FF)Lx2/s;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method public static final l(Lx2/s;Lk1/z0;)Lx2/s;
    .locals 3

    .line 1
    new-instance v0, Landroidx/compose/foundation/layout/PaddingValuesElement;

    .line 2
    .line 3
    new-instance v1, Ljy/b;

    .line 4
    .line 5
    const/4 v2, 0x7

    .line 6
    invoke-direct {v1, v2}, Ljy/b;-><init>(I)V

    .line 7
    .line 8
    .line 9
    invoke-direct {v0, p1, v1}, Landroidx/compose/foundation/layout/PaddingValuesElement;-><init>(Lk1/z0;Ljy/b;)V

    .line 10
    .line 11
    .line 12
    invoke-interface {p0, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method public static final m(Lx2/s;F)Lx2/s;
    .locals 6

    .line 1
    new-instance v0, Landroidx/compose/foundation/layout/PaddingElement;

    .line 2
    .line 3
    new-instance v5, Ljy/b;

    .line 4
    .line 5
    const/16 v1, 0xa

    .line 6
    .line 7
    invoke-direct {v5, v1}, Ljy/b;-><init>(I)V

    .line 8
    .line 9
    .line 10
    move v2, p1

    .line 11
    move v3, p1

    .line 12
    move v4, p1

    .line 13
    move v1, p1

    .line 14
    invoke-direct/range {v0 .. v5}, Landroidx/compose/foundation/layout/PaddingElement;-><init>(FFFFLay0/k;)V

    .line 15
    .line 16
    .line 17
    invoke-interface {p0, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method

.method public static final n(Lx2/s;FF)Lx2/s;
    .locals 6

    .line 1
    new-instance v0, Landroidx/compose/foundation/layout/PaddingElement;

    .line 2
    .line 3
    new-instance v5, Ljy/b;

    .line 4
    .line 5
    const/16 v1, 0x9

    .line 6
    .line 7
    invoke-direct {v5, v1}, Ljy/b;-><init>(I)V

    .line 8
    .line 9
    .line 10
    move v3, p1

    .line 11
    move v4, p2

    .line 12
    move v1, p1

    .line 13
    move v2, p2

    .line 14
    invoke-direct/range {v0 .. v5}, Landroidx/compose/foundation/layout/PaddingElement;-><init>(FFFFLay0/k;)V

    .line 15
    .line 16
    .line 17
    invoke-interface {p0, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method

.method public static o(Lx2/s;FFI)Lx2/s;
    .locals 2

    .line 1
    and-int/lit8 v0, p3, 0x1

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    int-to-float p1, v1

    .line 7
    :cond_0
    and-int/lit8 p3, p3, 0x2

    .line 8
    .line 9
    if-eqz p3, :cond_1

    .line 10
    .line 11
    int-to-float p2, v1

    .line 12
    :cond_1
    invoke-static {p0, p1, p2}, Landroidx/compose/foundation/layout/a;->n(Lx2/s;FF)Lx2/s;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method public static final p(Lx2/s;FFFF)Lx2/s;
    .locals 6

    .line 1
    new-instance v0, Landroidx/compose/foundation/layout/PaddingElement;

    .line 2
    .line 3
    new-instance v5, Ljy/b;

    .line 4
    .line 5
    const/16 v1, 0x8

    .line 6
    .line 7
    invoke-direct {v5, v1}, Ljy/b;-><init>(I)V

    .line 8
    .line 9
    .line 10
    move v1, p1

    .line 11
    move v2, p2

    .line 12
    move v3, p3

    .line 13
    move v4, p4

    .line 14
    invoke-direct/range {v0 .. v5}, Landroidx/compose/foundation/layout/PaddingElement;-><init>(FFFFLay0/k;)V

    .line 15
    .line 16
    .line 17
    invoke-interface {p0, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method

.method public static q(Lx2/s;FFFFI)Lx2/s;
    .locals 2

    .line 1
    and-int/lit8 v0, p5, 0x1

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    int-to-float p1, v1

    .line 7
    :cond_0
    and-int/lit8 v0, p5, 0x2

    .line 8
    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    int-to-float p2, v1

    .line 12
    :cond_1
    and-int/lit8 v0, p5, 0x4

    .line 13
    .line 14
    if-eqz v0, :cond_2

    .line 15
    .line 16
    int-to-float p3, v1

    .line 17
    :cond_2
    and-int/lit8 p5, p5, 0x8

    .line 18
    .line 19
    if-eqz p5, :cond_3

    .line 20
    .line 21
    int-to-float p4, v1

    .line 22
    :cond_3
    invoke-static {p0, p1, p2, p3, p4}, Landroidx/compose/foundation/layout/a;->p(Lx2/s;FFFF)Lx2/s;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method

.method public static final r(Lx2/s;)Lx2/s;
    .locals 1

    .line 1
    sget-object v0, Lk1/r0;->d:Lk1/r0;

    .line 2
    .line 3
    new-instance v0, Landroidx/compose/foundation/layout/IntrinsicWidthElement;

    .line 4
    .line 5
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    invoke-interface {p0, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method
