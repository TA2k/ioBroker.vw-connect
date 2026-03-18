.class public abstract Lb1/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lc1/b2;

.field public static final b:Lc1/f1;

.field public static final c:Lc1/f1;

.field public static final d:Lc1/f1;


# direct methods
.method static constructor <clinit>()V
    .locals 10

    .line 1
    sget-object v0, Lb1/c;->n:Lb1/c;

    .line 2
    .line 3
    sget-object v1, Lb1/c;->o:Lb1/c;

    .line 4
    .line 5
    new-instance v2, Lc1/b2;

    .line 6
    .line 7
    invoke-direct {v2, v0, v1}, Lc1/b2;-><init>(Lay0/k;Lay0/k;)V

    .line 8
    .line 9
    .line 10
    sput-object v2, Lb1/o0;->a:Lc1/b2;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    const/4 v1, 0x5

    .line 14
    const/4 v2, 0x0

    .line 15
    const/high16 v3, 0x43c80000    # 400.0f

    .line 16
    .line 17
    invoke-static {v2, v3, v0, v1}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    sput-object v0, Lb1/o0;->b:Lc1/f1;

    .line 22
    .line 23
    const/4 v0, 0x1

    .line 24
    int-to-long v4, v0

    .line 25
    const/16 v1, 0x20

    .line 26
    .line 27
    shl-long v6, v4, v1

    .line 28
    .line 29
    const-wide v8, 0xffffffffL

    .line 30
    .line 31
    .line 32
    .line 33
    .line 34
    and-long/2addr v4, v8

    .line 35
    or-long/2addr v4, v6

    .line 36
    new-instance v1, Lt4/j;

    .line 37
    .line 38
    invoke-direct {v1, v4, v5}, Lt4/j;-><init>(J)V

    .line 39
    .line 40
    .line 41
    invoke-static {v2, v3, v1, v0}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    sput-object v1, Lb1/o0;->c:Lc1/f1;

    .line 46
    .line 47
    new-instance v1, Lt4/l;

    .line 48
    .line 49
    invoke-direct {v1, v4, v5}, Lt4/l;-><init>(J)V

    .line 50
    .line 51
    .line 52
    invoke-static {v2, v3, v1, v0}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    sput-object v0, Lb1/o0;->d:Lc1/f1;

    .line 57
    .line 58
    return-void
.end method

.method public static final a(Lay0/k;Lc1/a0;Lx2/j;)Lb1/t0;
    .locals 8

    .line 1
    new-instance v0, Lb1/t0;

    .line 2
    .line 3
    new-instance v1, Lb1/i1;

    .line 4
    .line 5
    new-instance v4, Lb1/c0;

    .line 6
    .line 7
    invoke-direct {v4, p0, p1, p2}, Lb1/c0;-><init>(Lay0/k;Lc1/a0;Lx2/j;)V

    .line 8
    .line 9
    .line 10
    const/4 v6, 0x0

    .line 11
    const/16 v7, 0x3b

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    const/4 v3, 0x0

    .line 15
    const/4 v5, 0x0

    .line 16
    invoke-direct/range {v1 .. v7}, Lb1/i1;-><init>(Lb1/v0;Lb1/g1;Lb1/c0;Ljp/x1;Ljava/util/LinkedHashMap;I)V

    .line 17
    .line 18
    .line 19
    invoke-direct {v0, v1}, Lb1/t0;-><init>(Lb1/i1;)V

    .line 20
    .line 21
    .line 22
    return-object v0
.end method

.method public static b(Lc1/f1;I)Lb1/t0;
    .locals 10

    .line 1
    sget-object v0, Lx2/c;->o:Lx2/i;

    .line 2
    .line 3
    sget-object v1, Lx2/c;->m:Lx2/i;

    .line 4
    .line 5
    and-int/lit8 v2, p1, 0x1

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    if-eqz v2, :cond_0

    .line 9
    .line 10
    int-to-long v4, v3

    .line 11
    const/16 p0, 0x20

    .line 12
    .line 13
    shl-long v6, v4, p0

    .line 14
    .line 15
    const-wide v8, 0xffffffffL

    .line 16
    .line 17
    .line 18
    .line 19
    .line 20
    and-long/2addr v4, v8

    .line 21
    or-long/2addr v4, v6

    .line 22
    new-instance p0, Lt4/l;

    .line 23
    .line 24
    invoke-direct {p0, v4, v5}, Lt4/l;-><init>(J)V

    .line 25
    .line 26
    .line 27
    const/4 v2, 0x0

    .line 28
    const/high16 v4, 0x43c80000    # 400.0f

    .line 29
    .line 30
    invoke-static {v2, v4, p0, v3}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    :cond_0
    and-int/lit8 p1, p1, 0x2

    .line 35
    .line 36
    if-eqz p1, :cond_1

    .line 37
    .line 38
    move-object p1, v0

    .line 39
    goto :goto_0

    .line 40
    :cond_1
    move-object p1, v1

    .line 41
    :goto_0
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    if-eqz v1, :cond_2

    .line 46
    .line 47
    sget-object p1, Lx2/c;->e:Lx2/j;

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_2
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result p1

    .line 54
    if-eqz p1, :cond_3

    .line 55
    .line 56
    sget-object p1, Lx2/c;->k:Lx2/j;

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_3
    sget-object p1, Lx2/c;->h:Lx2/j;

    .line 60
    .line 61
    :goto_1
    new-instance v0, Lb1/c;

    .line 62
    .line 63
    const/16 v1, 0x10

    .line 64
    .line 65
    invoke-direct {v0, v3, v1}, Lb1/c;-><init>(II)V

    .line 66
    .line 67
    .line 68
    invoke-static {v0, p0, p1}, Lb1/o0;->a(Lay0/k;Lc1/a0;Lx2/j;)Lb1/t0;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    return-object p0
.end method

.method public static c(Lc1/a0;I)Lb1/t0;
    .locals 8

    .line 1
    and-int/lit8 p1, p1, 0x1

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    if-eqz p1, :cond_0

    .line 5
    .line 6
    const/high16 p0, 0x43c80000    # 400.0f

    .line 7
    .line 8
    const/4 p1, 0x5

    .line 9
    const/4 v1, 0x0

    .line 10
    invoke-static {v0, p0, v1, p1}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    :cond_0
    new-instance p1, Lb1/t0;

    .line 15
    .line 16
    new-instance v1, Lb1/i1;

    .line 17
    .line 18
    new-instance v2, Lb1/v0;

    .line 19
    .line 20
    invoke-direct {v2, v0, p0}, Lb1/v0;-><init>(FLc1/a0;)V

    .line 21
    .line 22
    .line 23
    const/4 v6, 0x0

    .line 24
    const/16 v7, 0x3e

    .line 25
    .line 26
    const/4 v3, 0x0

    .line 27
    const/4 v4, 0x0

    .line 28
    const/4 v5, 0x0

    .line 29
    invoke-direct/range {v1 .. v7}, Lb1/i1;-><init>(Lb1/v0;Lb1/g1;Lb1/c0;Ljp/x1;Ljava/util/LinkedHashMap;I)V

    .line 30
    .line 31
    .line 32
    invoke-direct {p1, v1}, Lb1/t0;-><init>(Lb1/i1;)V

    .line 33
    .line 34
    .line 35
    return-object p1
.end method

.method public static d(Lc1/a0;I)Lb1/u0;
    .locals 8

    .line 1
    and-int/lit8 p1, p1, 0x1

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    if-eqz p1, :cond_0

    .line 5
    .line 6
    const/high16 p0, 0x43c80000    # 400.0f

    .line 7
    .line 8
    const/4 p1, 0x5

    .line 9
    const/4 v1, 0x0

    .line 10
    invoke-static {v0, p0, v1, p1}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    :cond_0
    new-instance p1, Lb1/u0;

    .line 15
    .line 16
    new-instance v1, Lb1/i1;

    .line 17
    .line 18
    new-instance v2, Lb1/v0;

    .line 19
    .line 20
    invoke-direct {v2, v0, p0}, Lb1/v0;-><init>(FLc1/a0;)V

    .line 21
    .line 22
    .line 23
    const/4 v6, 0x0

    .line 24
    const/16 v7, 0x3e

    .line 25
    .line 26
    const/4 v3, 0x0

    .line 27
    const/4 v4, 0x0

    .line 28
    const/4 v5, 0x0

    .line 29
    invoke-direct/range {v1 .. v7}, Lb1/i1;-><init>(Lb1/v0;Lb1/g1;Lb1/c0;Ljp/x1;Ljava/util/LinkedHashMap;I)V

    .line 30
    .line 31
    .line 32
    invoke-direct {p1, v1}, Lb1/u0;-><init>(Lb1/i1;)V

    .line 33
    .line 34
    .line 35
    return-object p1
.end method

.method public static final e(Lay0/k;Lc1/a0;Lx2/j;)Lb1/u0;
    .locals 8

    .line 1
    new-instance v0, Lb1/u0;

    .line 2
    .line 3
    new-instance v1, Lb1/i1;

    .line 4
    .line 5
    new-instance v4, Lb1/c0;

    .line 6
    .line 7
    invoke-direct {v4, p0, p1, p2}, Lb1/c0;-><init>(Lay0/k;Lc1/a0;Lx2/j;)V

    .line 8
    .line 9
    .line 10
    const/4 v6, 0x0

    .line 11
    const/16 v7, 0x3b

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    const/4 v3, 0x0

    .line 15
    const/4 v5, 0x0

    .line 16
    invoke-direct/range {v1 .. v7}, Lb1/i1;-><init>(Lb1/v0;Lb1/g1;Lb1/c0;Ljp/x1;Ljava/util/LinkedHashMap;I)V

    .line 17
    .line 18
    .line 19
    invoke-direct {v0, v1}, Lb1/u0;-><init>(Lb1/i1;)V

    .line 20
    .line 21
    .line 22
    return-object v0
.end method

.method public static f()Lb1/u0;
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    int-to-long v1, v0

    .line 3
    const/16 v3, 0x20

    .line 4
    .line 5
    shl-long v3, v1, v3

    .line 6
    .line 7
    const-wide v5, 0xffffffffL

    .line 8
    .line 9
    .line 10
    .line 11
    .line 12
    and-long/2addr v1, v5

    .line 13
    or-long/2addr v1, v3

    .line 14
    new-instance v3, Lt4/l;

    .line 15
    .line 16
    invoke-direct {v3, v1, v2}, Lt4/l;-><init>(J)V

    .line 17
    .line 18
    .line 19
    const/4 v1, 0x0

    .line 20
    const/high16 v2, 0x43c80000    # 400.0f

    .line 21
    .line 22
    invoke-static {v1, v2, v3, v0}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    sget-object v1, Lx2/c;->l:Lx2/j;

    .line 27
    .line 28
    sget-object v2, Lb1/c;->t:Lb1/c;

    .line 29
    .line 30
    invoke-static {v2, v0, v1}, Lb1/o0;->e(Lay0/k;Lc1/a0;Lx2/j;)Lb1/u0;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    return-object v0
.end method

.method public static g(Lc1/f1;I)Lb1/u0;
    .locals 10

    .line 1
    sget-object v0, Lx2/c;->o:Lx2/i;

    .line 2
    .line 3
    sget-object v1, Lx2/c;->m:Lx2/i;

    .line 4
    .line 5
    and-int/lit8 v2, p1, 0x1

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    if-eqz v2, :cond_0

    .line 9
    .line 10
    int-to-long v4, v3

    .line 11
    const/16 p0, 0x20

    .line 12
    .line 13
    shl-long v6, v4, p0

    .line 14
    .line 15
    const-wide v8, 0xffffffffL

    .line 16
    .line 17
    .line 18
    .line 19
    .line 20
    and-long/2addr v4, v8

    .line 21
    or-long/2addr v4, v6

    .line 22
    new-instance p0, Lt4/l;

    .line 23
    .line 24
    invoke-direct {p0, v4, v5}, Lt4/l;-><init>(J)V

    .line 25
    .line 26
    .line 27
    const/4 v2, 0x0

    .line 28
    const/high16 v4, 0x43c80000    # 400.0f

    .line 29
    .line 30
    invoke-static {v2, v4, p0, v3}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    :cond_0
    and-int/lit8 p1, p1, 0x2

    .line 35
    .line 36
    if-eqz p1, :cond_1

    .line 37
    .line 38
    move-object p1, v0

    .line 39
    goto :goto_0

    .line 40
    :cond_1
    move-object p1, v1

    .line 41
    :goto_0
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    if-eqz v1, :cond_2

    .line 46
    .line 47
    sget-object p1, Lx2/c;->e:Lx2/j;

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_2
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result p1

    .line 54
    if-eqz p1, :cond_3

    .line 55
    .line 56
    sget-object p1, Lx2/c;->k:Lx2/j;

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_3
    sget-object p1, Lx2/c;->h:Lx2/j;

    .line 60
    .line 61
    :goto_1
    new-instance v0, Lb1/c;

    .line 62
    .line 63
    const/16 v1, 0x11

    .line 64
    .line 65
    invoke-direct {v0, v3, v1}, Lb1/c;-><init>(II)V

    .line 66
    .line 67
    .line 68
    invoke-static {v0, p0, p1}, Lb1/o0;->e(Lay0/k;Lc1/a0;Lx2/j;)Lb1/u0;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    return-object p0
.end method

.method public static final h(Lay0/k;Lc1/a0;)Lb1/t0;
    .locals 8

    .line 1
    new-instance v0, Law/o;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-direct {v0, v1, p0}, Law/o;-><init>(ILay0/k;)V

    .line 5
    .line 6
    .line 7
    new-instance p0, Lb1/t0;

    .line 8
    .line 9
    new-instance v1, Lb1/i1;

    .line 10
    .line 11
    new-instance v3, Lb1/g1;

    .line 12
    .line 13
    invoke-direct {v3, v0, p1}, Lb1/g1;-><init>(Lay0/k;Lc1/a0;)V

    .line 14
    .line 15
    .line 16
    const/4 v6, 0x0

    .line 17
    const/16 v7, 0x3d

    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    const/4 v4, 0x0

    .line 21
    const/4 v5, 0x0

    .line 22
    invoke-direct/range {v1 .. v7}, Lb1/i1;-><init>(Lb1/v0;Lb1/g1;Lb1/c0;Ljp/x1;Ljava/util/LinkedHashMap;I)V

    .line 23
    .line 24
    .line 25
    invoke-direct {p0, v1}, Lb1/t0;-><init>(Lb1/i1;)V

    .line 26
    .line 27
    .line 28
    return-object p0
.end method

.method public static i(ILay0/k;)Lb1/t0;
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    int-to-long v1, v0

    .line 3
    const/16 v3, 0x20

    .line 4
    .line 5
    shl-long v3, v1, v3

    .line 6
    .line 7
    const-wide v5, 0xffffffffL

    .line 8
    .line 9
    .line 10
    .line 11
    .line 12
    and-long/2addr v1, v5

    .line 13
    or-long/2addr v1, v3

    .line 14
    new-instance v3, Lt4/j;

    .line 15
    .line 16
    invoke-direct {v3, v1, v2}, Lt4/j;-><init>(J)V

    .line 17
    .line 18
    .line 19
    const/4 v1, 0x0

    .line 20
    const/high16 v2, 0x43c80000    # 400.0f

    .line 21
    .line 22
    invoke-static {v1, v2, v3, v0}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    and-int/lit8 p0, p0, 0x2

    .line 27
    .line 28
    if-eqz p0, :cond_0

    .line 29
    .line 30
    sget-object p1, Lb1/c;->u:Lb1/c;

    .line 31
    .line 32
    :cond_0
    invoke-static {p1, v0}, Lb1/o0;->h(Lay0/k;Lc1/a0;)Lb1/t0;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0
.end method

.method public static final j(Lay0/k;Lc1/a0;)Lb1/u0;
    .locals 8

    .line 1
    new-instance v0, Law/o;

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    invoke-direct {v0, v1, p0}, Law/o;-><init>(ILay0/k;)V

    .line 5
    .line 6
    .line 7
    new-instance p0, Lb1/u0;

    .line 8
    .line 9
    new-instance v1, Lb1/i1;

    .line 10
    .line 11
    new-instance v3, Lb1/g1;

    .line 12
    .line 13
    invoke-direct {v3, v0, p1}, Lb1/g1;-><init>(Lay0/k;Lc1/a0;)V

    .line 14
    .line 15
    .line 16
    const/4 v6, 0x0

    .line 17
    const/16 v7, 0x3d

    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    const/4 v4, 0x0

    .line 21
    const/4 v5, 0x0

    .line 22
    invoke-direct/range {v1 .. v7}, Lb1/i1;-><init>(Lb1/v0;Lb1/g1;Lb1/c0;Ljp/x1;Ljava/util/LinkedHashMap;I)V

    .line 23
    .line 24
    .line 25
    invoke-direct {p0, v1}, Lb1/u0;-><init>(Lb1/i1;)V

    .line 26
    .line 27
    .line 28
    return-object p0
.end method

.method public static k(Lay0/k;)Lb1/u0;
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    int-to-long v1, v0

    .line 3
    const/16 v3, 0x20

    .line 4
    .line 5
    shl-long v3, v1, v3

    .line 6
    .line 7
    const-wide v5, 0xffffffffL

    .line 8
    .line 9
    .line 10
    .line 11
    .line 12
    and-long/2addr v1, v5

    .line 13
    or-long/2addr v1, v3

    .line 14
    new-instance v3, Lt4/j;

    .line 15
    .line 16
    invoke-direct {v3, v1, v2}, Lt4/j;-><init>(J)V

    .line 17
    .line 18
    .line 19
    const/4 v1, 0x0

    .line 20
    const/high16 v2, 0x43c80000    # 400.0f

    .line 21
    .line 22
    invoke-static {v1, v2, v3, v0}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-static {p0, v0}, Lb1/o0;->j(Lay0/k;Lc1/a0;)Lb1/u0;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method
