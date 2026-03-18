.class public abstract Landroidx/compose/foundation/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Lx2/s;Le3/b0;)Lx2/s;
    .locals 6

    .line 1
    new-instance v0, Landroidx/compose/foundation/BackgroundElement;

    .line 2
    .line 3
    const-wide/16 v1, 0x0

    .line 4
    .line 5
    const/4 v5, 0x1

    .line 6
    sget-object v4, Le3/j0;->a:Le3/i0;

    .line 7
    .line 8
    move-object v3, p1

    .line 9
    invoke-direct/range {v0 .. v5}, Landroidx/compose/foundation/BackgroundElement;-><init>(JLe3/b0;Le3/n0;I)V

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

.method public static final b(Lx2/s;JLe3/n0;)Lx2/s;
    .locals 6

    .line 1
    new-instance v0, Landroidx/compose/foundation/BackgroundElement;

    .line 2
    .line 3
    const/4 v3, 0x0

    .line 4
    const/4 v5, 0x2

    .line 5
    move-wide v1, p1

    .line 6
    move-object v4, p3

    .line 7
    invoke-direct/range {v0 .. v5}, Landroidx/compose/foundation/BackgroundElement;-><init>(JLe3/b0;Le3/n0;I)V

    .line 8
    .line 9
    .line 10
    invoke-interface {p0, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public static final c(Lx2/s;Li1/l;Le1/s0;ZLd4/i;Lay0/a;)Lx2/s;
    .locals 8

    .line 1
    const/4 v5, 0x0

    .line 2
    if-eqz p2, :cond_0

    .line 3
    .line 4
    new-instance v0, Landroidx/compose/foundation/ClickableElement;

    .line 5
    .line 6
    const/4 v3, 0x0

    .line 7
    move-object v1, p1

    .line 8
    move-object v2, p2

    .line 9
    move v4, p3

    .line 10
    move-object v6, p4

    .line 11
    move-object v7, p5

    .line 12
    invoke-direct/range {v0 .. v7}, Landroidx/compose/foundation/ClickableElement;-><init>(Li1/l;Le1/s0;ZZLjava/lang/String;Ld4/i;Lay0/a;)V

    .line 13
    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move-object v1, p1

    .line 17
    move-object v2, p2

    .line 18
    move v4, p3

    .line 19
    move-object v6, p4

    .line 20
    move-object v7, p5

    .line 21
    if-nez v2, :cond_1

    .line 22
    .line 23
    new-instance v0, Landroidx/compose/foundation/ClickableElement;

    .line 24
    .line 25
    const/4 v3, 0x0

    .line 26
    const/4 v2, 0x0

    .line 27
    invoke-direct/range {v0 .. v7}, Landroidx/compose/foundation/ClickableElement;-><init>(Li1/l;Le1/s0;ZZLjava/lang/String;Ld4/i;Lay0/a;)V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_1
    if-eqz v1, :cond_2

    .line 32
    .line 33
    invoke-static {v1, v2}, Landroidx/compose/foundation/c;->a(Li1/l;Le1/s0;)Lx2/s;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    new-instance v0, Landroidx/compose/foundation/ClickableElement;

    .line 38
    .line 39
    const/4 v3, 0x0

    .line 40
    const/4 v2, 0x0

    .line 41
    invoke-direct/range {v0 .. v7}, Landroidx/compose/foundation/ClickableElement;-><init>(Li1/l;Le1/s0;ZZLjava/lang/String;Ld4/i;Lay0/a;)V

    .line 42
    .line 43
    .line 44
    invoke-interface {p1, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    goto :goto_0

    .line 49
    :cond_2
    new-instance p1, Landroidx/compose/foundation/b;

    .line 50
    .line 51
    invoke-direct {p1, v2, v4, v6, v7}, Landroidx/compose/foundation/b;-><init>(Le1/s0;ZLd4/i;Lay0/a;)V

    .line 52
    .line 53
    .line 54
    sget-object p2, Lx2/p;->b:Lx2/p;

    .line 55
    .line 56
    invoke-static {p2, p1}, Lx2/a;->a(Lx2/s;Lay0/o;)Lx2/s;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    :goto_0
    invoke-interface {p0, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    return-object p0
.end method

.method public static synthetic d(Lx2/s;Li1/l;Le1/s0;ZLd4/i;Lay0/a;I)Lx2/s;
    .locals 6

    .line 1
    and-int/lit8 v0, p6, 0x4

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const/4 p3, 0x1

    .line 6
    :cond_0
    move v3, p3

    .line 7
    and-int/lit8 p3, p6, 0x10

    .line 8
    .line 9
    if-eqz p3, :cond_1

    .line 10
    .line 11
    const/4 p4, 0x0

    .line 12
    :cond_1
    move-object v0, p0

    .line 13
    move-object v1, p1

    .line 14
    move-object v2, p2

    .line 15
    move-object v4, p4

    .line 16
    move-object v5, p5

    .line 17
    invoke-static/range {v0 .. v5}, Landroidx/compose/foundation/a;->c(Lx2/s;Li1/l;Le1/s0;ZLd4/i;Lay0/a;)Lx2/s;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method

.method public static synthetic e(Lay0/a;)Lx2/s;
    .locals 2

    .line 1
    new-instance v0, Le1/u;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, v1}, Le1/u;-><init>(Ljava/lang/Object;I)V

    .line 5
    .line 6
    .line 7
    sget-object p0, Lx2/p;->b:Lx2/p;

    .line 8
    .line 9
    invoke-static {p0, v0}, Lx2/a;->a(Lx2/s;Lay0/o;)Lx2/s;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public static f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;
    .locals 8

    .line 1
    and-int/lit8 v0, p5, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const/4 p1, 0x1

    .line 6
    :cond_0
    move v4, p1

    .line 7
    and-int/lit8 p1, p5, 0x2

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    if-eqz p1, :cond_1

    .line 11
    .line 12
    move-object v5, v0

    .line 13
    goto :goto_0

    .line 14
    :cond_1
    move-object v5, p2

    .line 15
    :goto_0
    and-int/lit8 p1, p5, 0x4

    .line 16
    .line 17
    if-eqz p1, :cond_2

    .line 18
    .line 19
    move-object v6, v0

    .line 20
    goto :goto_1

    .line 21
    :cond_2
    move-object v6, p3

    .line 22
    :goto_1
    new-instance v0, Landroidx/compose/foundation/ClickableElement;

    .line 23
    .line 24
    const/4 v2, 0x0

    .line 25
    const/4 v3, 0x1

    .line 26
    const/4 v1, 0x0

    .line 27
    move-object v7, p4

    .line 28
    invoke-direct/range {v0 .. v7}, Landroidx/compose/foundation/ClickableElement;-><init>(Li1/l;Le1/s0;ZZLjava/lang/String;Ld4/i;Lay0/a;)V

    .line 29
    .line 30
    .line 31
    invoke-interface {p0, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0
.end method

.method public static final g(Lx2/s;Li1/l;Lay0/a;)Lx2/s;
    .locals 2

    .line 1
    new-instance v0, Landroidx/compose/foundation/CombinedClickableElement;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p2, p1, v1}, Landroidx/compose/foundation/CombinedClickableElement;-><init>(Lay0/a;Li1/l;Z)V

    .line 5
    .line 6
    .line 7
    invoke-interface {p0, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public static h(Lx2/s;Lay0/a;)Lx2/s;
    .locals 3

    .line 1
    new-instance v0, Landroidx/compose/foundation/CombinedClickableElement;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, p1, v2, v1}, Landroidx/compose/foundation/CombinedClickableElement;-><init>(Lay0/a;Li1/l;Z)V

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

.method public static final i(Lx2/s;ZLi1/l;)Lx2/s;
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    new-instance p1, Landroidx/compose/foundation/FocusableElement;

    .line 4
    .line 5
    invoke-direct {p1, p2}, Landroidx/compose/foundation/FocusableElement;-><init>(Li1/l;)V

    .line 6
    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    sget-object p1, Lx2/p;->b:Lx2/p;

    .line 10
    .line 11
    :goto_0
    invoke-interface {p0, p1}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public static j(Lx2/s;Li1/l;)Lx2/s;
    .locals 1

    .line 1
    new-instance v0, Landroidx/compose/foundation/HoverableElement;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Landroidx/compose/foundation/HoverableElement;-><init>(Li1/l;)V

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

.method public static final k(Landroid/view/KeyEvent;)Z
    .locals 4

    .line 1
    invoke-static {p0}, Ln3/c;->b(Landroid/view/KeyEvent;)J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    sget p0, Ln3/a;->r:I

    .line 6
    .line 7
    sget-wide v2, Ln3/a;->h:J

    .line 8
    .line 9
    invoke-static {v0, v1, v2, v3}, Ln3/a;->a(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    if-nez p0, :cond_1

    .line 14
    .line 15
    sget-wide v2, Ln3/a;->k:J

    .line 16
    .line 17
    invoke-static {v0, v1, v2, v3}, Ln3/a;->a(JJ)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-nez p0, :cond_1

    .line 22
    .line 23
    sget-wide v2, Ln3/a;->q:J

    .line 24
    .line 25
    invoke-static {v0, v1, v2, v3}, Ln3/a;->a(JJ)Z

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    if-nez p0, :cond_1

    .line 30
    .line 31
    sget-wide v2, Ln3/a;->j:J

    .line 32
    .line 33
    invoke-static {v0, v1, v2, v3}, Ln3/a;->a(JJ)Z

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    if-eqz p0, :cond_0

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    const/4 p0, 0x0

    .line 41
    return p0

    .line 42
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 43
    return p0
.end method

.method public static final l(Lx2/s;Lg1/q2;Lg1/w1;ZZLg1/j1;Li1/l;ZLe1/j;Lp1/h;)Lx2/s;
    .locals 10

    .line 1
    sget v0, Le1/x;->a:F

    .line 2
    .line 3
    sget-object v0, Lg1/w1;->d:Lg1/w1;

    .line 4
    .line 5
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 6
    .line 7
    if-ne p2, v0, :cond_0

    .line 8
    .line 9
    sget-object v0, Le1/k0;->c:Le1/k0;

    .line 10
    .line 11
    invoke-static {v1, v0}, Ljp/ba;->c(Lx2/s;Le3/n0;)Lx2/s;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    sget-object v0, Le1/k0;->b:Le1/k0;

    .line 17
    .line 18
    invoke-static {v1, v0}, Ljp/ba;->c(Lx2/s;Le3/n0;)Lx2/s;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    :goto_0
    invoke-interface {p0, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    new-instance v0, Landroidx/compose/foundation/ScrollingContainerElement;

    .line 27
    .line 28
    move-object v5, p1

    .line 29
    move-object v4, p2

    .line 30
    move v7, p3

    .line 31
    move v8, p4

    .line 32
    move-object v3, p5

    .line 33
    move-object/from16 v6, p6

    .line 34
    .line 35
    move/from16 v9, p7

    .line 36
    .line 37
    move-object/from16 v1, p8

    .line 38
    .line 39
    move-object/from16 v2, p9

    .line 40
    .line 41
    invoke-direct/range {v0 .. v9}, Landroidx/compose/foundation/ScrollingContainerElement;-><init>(Le1/j;Lg1/u;Lg1/j1;Lg1/w1;Lg1/q2;Li1/l;ZZZ)V

    .line 42
    .line 43
    .line 44
    invoke-interface {p0, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0
.end method
