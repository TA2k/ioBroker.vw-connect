.class public abstract Ljp/cd;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lo1/d0;IJLp1/m;JLx2/i;Lt4/m;ZILandroidx/collection/b0;)Lp1/d;
    .locals 10

    .line 1
    move-object/from16 v0, p11

    .line 2
    .line 3
    sget-object v2, Lg1/w1;->d:Lg1/w1;

    .line 4
    .line 5
    invoke-virtual {p4, p1}, Lp1/m;->d(I)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v6

    .line 9
    invoke-virtual {v0, p1}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    check-cast v2, Ljava/util/List;

    .line 14
    .line 15
    if-eqz v2, :cond_0

    .line 16
    .line 17
    move-object v3, v2

    .line 18
    goto :goto_1

    .line 19
    :cond_0
    invoke-virtual/range {p0 .. p1}, Lo1/d0;->b(I)Ljava/util/List;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    new-instance v4, Ljava/util/ArrayList;

    .line 28
    .line 29
    invoke-direct {v4, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 30
    .line 31
    .line 32
    const/4 v5, 0x0

    .line 33
    :goto_0
    if-ge v5, v3, :cond_1

    .line 34
    .line 35
    invoke-interface {v2, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v7

    .line 39
    check-cast v7, Lt3/p0;

    .line 40
    .line 41
    invoke-interface {v7, p2, p3}, Lt3/p0;->L(J)Lt3/e1;

    .line 42
    .line 43
    .line 44
    move-result-object v7

    .line 45
    invoke-virtual {v4, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    add-int/lit8 v5, v5, 0x1

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_1
    invoke-virtual {v0, p1, v4}, Landroidx/collection/b0;->h(ILjava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    move-object v3, v4

    .line 55
    :goto_1
    new-instance v0, Lp1/d;

    .line 56
    .line 57
    move v1, p1

    .line 58
    move-wide v4, p5

    .line 59
    move-object/from16 v7, p7

    .line 60
    .line 61
    move-object/from16 v8, p8

    .line 62
    .line 63
    move/from16 v9, p9

    .line 64
    .line 65
    move/from16 v2, p10

    .line 66
    .line 67
    invoke-direct/range {v0 .. v9}, Lp1/d;-><init>(IILjava/util/List;JLjava/lang/Object;Lx2/i;Lt4/m;Z)V

    .line 68
    .line 69
    .line 70
    return-object v0
.end method

.method public static final b(Lm1/f;Ljava/util/List;Lc3/j;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/o;)V
    .locals 8

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "items"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "focusManager"

    .line 12
    .line 13
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "onEvent"

    .line 17
    .line 18
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    move-object v0, p1

    .line 22
    check-cast v0, Ljava/util/Collection;

    .line 23
    .line 24
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    if-nez v0, :cond_0

    .line 29
    .line 30
    new-instance v0, Lc41/j;

    .line 31
    .line 32
    move-object v1, p1

    .line 33
    move-object v3, p2

    .line 34
    move-object v4, p3

    .line 35
    move-object v6, p4

    .line 36
    move-object v7, p5

    .line 37
    move-object v2, p6

    .line 38
    move-object v5, p7

    .line 39
    invoke-direct/range {v0 .. v7}, Lc41/j;-><init>(Ljava/util/List;Lay0/k;Lc3/j;Lay0/k;Lay0/o;Lay0/k;Lay0/k;)V

    .line 40
    .line 41
    .line 42
    new-instance v1, Lt2/b;

    .line 43
    .line 44
    const/4 v2, 0x1

    .line 45
    const v3, -0x150a238e

    .line 46
    .line 47
    .line 48
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 49
    .line 50
    .line 51
    const/4 v0, 0x3

    .line 52
    invoke-static {p0, v1, v0}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 53
    .line 54
    .line 55
    :cond_0
    return-void
.end method
