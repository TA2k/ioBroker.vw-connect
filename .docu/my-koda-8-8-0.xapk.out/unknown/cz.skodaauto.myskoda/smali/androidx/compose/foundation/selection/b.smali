.class public abstract Landroidx/compose/foundation/selection/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lx2/s;ZLi1/l;Le1/s0;ZLd4/i;Lay0/a;)Lx2/s;
    .locals 8

    .line 1
    if-eqz p3, :cond_0

    .line 2
    .line 3
    new-instance v0, Landroidx/compose/foundation/selection/SelectableElement;

    .line 4
    .line 5
    move v1, p1

    .line 6
    move-object v2, p2

    .line 7
    move-object v3, p3

    .line 8
    move v4, p4

    .line 9
    move-object v5, p5

    .line 10
    move-object v6, p6

    .line 11
    invoke-direct/range {v0 .. v6}, Landroidx/compose/foundation/selection/SelectableElement;-><init>(ZLi1/l;Le1/s0;ZLd4/i;Lay0/a;)V

    .line 12
    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move v2, p1

    .line 16
    move-object v3, p2

    .line 17
    move-object p2, p3

    .line 18
    move v5, p4

    .line 19
    move-object v6, p5

    .line 20
    move-object v7, p6

    .line 21
    if-nez p2, :cond_1

    .line 22
    .line 23
    new-instance v1, Landroidx/compose/foundation/selection/SelectableElement;

    .line 24
    .line 25
    const/4 v4, 0x0

    .line 26
    invoke-direct/range {v1 .. v7}, Landroidx/compose/foundation/selection/SelectableElement;-><init>(ZLi1/l;Le1/s0;ZLd4/i;Lay0/a;)V

    .line 27
    .line 28
    .line 29
    move-object v0, v1

    .line 30
    goto :goto_0

    .line 31
    :cond_1
    if-eqz v3, :cond_2

    .line 32
    .line 33
    invoke-static {v3, p2}, Landroidx/compose/foundation/c;->a(Li1/l;Le1/s0;)Lx2/s;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    new-instance v1, Landroidx/compose/foundation/selection/SelectableElement;

    .line 38
    .line 39
    const/4 v4, 0x0

    .line 40
    invoke-direct/range {v1 .. v7}, Landroidx/compose/foundation/selection/SelectableElement;-><init>(ZLi1/l;Le1/s0;ZLd4/i;Lay0/a;)V

    .line 41
    .line 42
    .line 43
    invoke-interface {p1, v1}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    goto :goto_0

    .line 48
    :cond_2
    new-instance p1, Landroidx/compose/foundation/selection/a;

    .line 49
    .line 50
    move p3, v2

    .line 51
    move p4, v5

    .line 52
    move-object p5, v6

    .line 53
    move-object p6, v7

    .line 54
    invoke-direct/range {p1 .. p6}, Landroidx/compose/foundation/selection/a;-><init>(Le1/s0;ZZLd4/i;Lay0/a;)V

    .line 55
    .line 56
    .line 57
    sget-object p2, Lx2/p;->b:Lx2/p;

    .line 58
    .line 59
    invoke-static {p2, p1}, Lx2/a;->a(Lx2/s;Lay0/o;)Lx2/s;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    :goto_0
    invoke-interface {p0, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    return-object p0
.end method

.method public static b(Lx2/s;ZZLd4/i;Lay0/k;)Lx2/s;
    .locals 7

    .line 1
    new-instance v0, Landroidx/compose/foundation/selection/ToggleableElement;

    .line 2
    .line 3
    const/4 v3, 0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    move v1, p1

    .line 6
    move v4, p2

    .line 7
    move-object v5, p3

    .line 8
    move-object v6, p4

    .line 9
    invoke-direct/range {v0 .. v6}, Landroidx/compose/foundation/selection/ToggleableElement;-><init>(ZLi1/l;ZZLd4/i;Lay0/k;)V

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

.method public static final c(Lx2/s;Lf4/a;Li1/l;Lh2/x7;ZLd4/i;Lay0/a;)Lx2/s;
    .locals 8

    .line 1
    if-eqz p3, :cond_0

    .line 2
    .line 3
    new-instance v0, Landroidx/compose/foundation/selection/TriStateToggleableElement;

    .line 4
    .line 5
    move-object v1, p1

    .line 6
    move-object v2, p2

    .line 7
    move-object v3, p3

    .line 8
    move v4, p4

    .line 9
    move-object v5, p5

    .line 10
    move-object v6, p6

    .line 11
    invoke-direct/range {v0 .. v6}, Landroidx/compose/foundation/selection/TriStateToggleableElement;-><init>(Lf4/a;Li1/l;Le1/s0;ZLd4/i;Lay0/a;)V

    .line 12
    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move-object v2, p1

    .line 16
    move-object v3, p2

    .line 17
    move-object p2, p3

    .line 18
    move v5, p4

    .line 19
    move-object v6, p5

    .line 20
    move-object v7, p6

    .line 21
    if-nez p2, :cond_1

    .line 22
    .line 23
    new-instance v1, Landroidx/compose/foundation/selection/TriStateToggleableElement;

    .line 24
    .line 25
    const/4 v4, 0x0

    .line 26
    invoke-direct/range {v1 .. v7}, Landroidx/compose/foundation/selection/TriStateToggleableElement;-><init>(Lf4/a;Li1/l;Le1/s0;ZLd4/i;Lay0/a;)V

    .line 27
    .line 28
    .line 29
    move-object v0, v1

    .line 30
    goto :goto_0

    .line 31
    :cond_1
    if-eqz v3, :cond_2

    .line 32
    .line 33
    invoke-static {v3, p2}, Landroidx/compose/foundation/c;->a(Li1/l;Le1/s0;)Lx2/s;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    new-instance v1, Landroidx/compose/foundation/selection/TriStateToggleableElement;

    .line 38
    .line 39
    const/4 v4, 0x0

    .line 40
    invoke-direct/range {v1 .. v7}, Landroidx/compose/foundation/selection/TriStateToggleableElement;-><init>(Lf4/a;Li1/l;Le1/s0;ZLd4/i;Lay0/a;)V

    .line 41
    .line 42
    .line 43
    invoke-interface {p1, v1}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    goto :goto_0

    .line 48
    :cond_2
    new-instance p1, Landroidx/compose/foundation/selection/c;

    .line 49
    .line 50
    move-object p3, v2

    .line 51
    move p4, v5

    .line 52
    move-object p5, v6

    .line 53
    move-object p6, v7

    .line 54
    invoke-direct/range {p1 .. p6}, Landroidx/compose/foundation/selection/c;-><init>(Le1/s0;Lf4/a;ZLd4/i;Lay0/a;)V

    .line 55
    .line 56
    .line 57
    sget-object p2, Lx2/p;->b:Lx2/p;

    .line 58
    .line 59
    invoke-static {p2, p1}, Lx2/a;->a(Lx2/s;Lay0/o;)Lx2/s;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    :goto_0
    invoke-interface {p0, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    return-object p0
.end method
