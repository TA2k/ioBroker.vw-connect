.class public final Lcoil3/compose/internal/ContentPainterElement;
.super Lv3/z0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lv3/z0;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0081\u0008\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001\u00a8\u0006\u0003"
    }
    d2 = {
        "Lcoil3/compose/internal/ContentPainterElement;",
        "Lv3/z0;",
        "Lam/d;",
        "coil-compose-core_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final b:Lmm/g;

.field public final c:Lyl/l;

.field public final d:Lzl/a;

.field public final e:Lay0/k;

.field public final f:Lay0/k;

.field public final g:Lx2/e;

.field public final h:Lt3/k;

.field public final i:Le3/m;

.field public final j:Lzl/l;


# direct methods
.method public constructor <init>(Lmm/g;Lyl/l;Lzl/a;Lay0/k;Lay0/k;Lx2/e;Lt3/k;Le3/m;Lzl/l;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcoil3/compose/internal/ContentPainterElement;->b:Lmm/g;

    .line 5
    .line 6
    iput-object p2, p0, Lcoil3/compose/internal/ContentPainterElement;->c:Lyl/l;

    .line 7
    .line 8
    iput-object p3, p0, Lcoil3/compose/internal/ContentPainterElement;->d:Lzl/a;

    .line 9
    .line 10
    iput-object p4, p0, Lcoil3/compose/internal/ContentPainterElement;->e:Lay0/k;

    .line 11
    .line 12
    iput-object p5, p0, Lcoil3/compose/internal/ContentPainterElement;->f:Lay0/k;

    .line 13
    .line 14
    iput-object p6, p0, Lcoil3/compose/internal/ContentPainterElement;->g:Lx2/e;

    .line 15
    .line 16
    iput-object p7, p0, Lcoil3/compose/internal/ContentPainterElement;->h:Lt3/k;

    .line 17
    .line 18
    iput-object p8, p0, Lcoil3/compose/internal/ContentPainterElement;->i:Le3/m;

    .line 19
    .line 20
    iput-object p9, p0, Lcoil3/compose/internal/ContentPainterElement;->j:Lzl/l;

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto/16 :goto_1

    .line 4
    .line 5
    :cond_0
    instance-of v0, p1, Lcoil3/compose/internal/ContentPainterElement;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    goto/16 :goto_0

    .line 10
    .line 11
    :cond_1
    check-cast p1, Lcoil3/compose/internal/ContentPainterElement;

    .line 12
    .line 13
    iget-object v0, p0, Lcoil3/compose/internal/ContentPainterElement;->b:Lmm/g;

    .line 14
    .line 15
    iget-object v1, p1, Lcoil3/compose/internal/ContentPainterElement;->b:Lmm/g;

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Lmm/g;->equals(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-nez v0, :cond_2

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_2
    iget-object v0, p0, Lcoil3/compose/internal/ContentPainterElement;->c:Lyl/l;

    .line 25
    .line 26
    iget-object v1, p1, Lcoil3/compose/internal/ContentPainterElement;->c:Lyl/l;

    .line 27
    .line 28
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-nez v0, :cond_3

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_3
    iget-object v0, p0, Lcoil3/compose/internal/ContentPainterElement;->d:Lzl/a;

    .line 36
    .line 37
    iget-object v1, p1, Lcoil3/compose/internal/ContentPainterElement;->d:Lzl/a;

    .line 38
    .line 39
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-nez v0, :cond_4

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_4
    iget-object v0, p0, Lcoil3/compose/internal/ContentPainterElement;->e:Lay0/k;

    .line 47
    .line 48
    iget-object v1, p1, Lcoil3/compose/internal/ContentPainterElement;->e:Lay0/k;

    .line 49
    .line 50
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    if-nez v0, :cond_5

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_5
    iget-object v0, p0, Lcoil3/compose/internal/ContentPainterElement;->f:Lay0/k;

    .line 58
    .line 59
    iget-object v1, p1, Lcoil3/compose/internal/ContentPainterElement;->f:Lay0/k;

    .line 60
    .line 61
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v0

    .line 65
    if-nez v0, :cond_6

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_6
    iget-object v0, p0, Lcoil3/compose/internal/ContentPainterElement;->g:Lx2/e;

    .line 69
    .line 70
    iget-object v1, p1, Lcoil3/compose/internal/ContentPainterElement;->g:Lx2/e;

    .line 71
    .line 72
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v0

    .line 76
    if-nez v0, :cond_7

    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_7
    iget-object v0, p0, Lcoil3/compose/internal/ContentPainterElement;->h:Lt3/k;

    .line 80
    .line 81
    iget-object v1, p1, Lcoil3/compose/internal/ContentPainterElement;->h:Lt3/k;

    .line 82
    .line 83
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v0

    .line 87
    if-nez v0, :cond_8

    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_8
    const/high16 v0, 0x3f800000    # 1.0f

    .line 91
    .line 92
    invoke-static {v0, v0}, Ljava/lang/Float;->compare(FF)I

    .line 93
    .line 94
    .line 95
    move-result v0

    .line 96
    if-eqz v0, :cond_9

    .line 97
    .line 98
    goto :goto_0

    .line 99
    :cond_9
    iget-object v0, p0, Lcoil3/compose/internal/ContentPainterElement;->i:Le3/m;

    .line 100
    .line 101
    iget-object v1, p1, Lcoil3/compose/internal/ContentPainterElement;->i:Le3/m;

    .line 102
    .line 103
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    move-result v0

    .line 107
    if-nez v0, :cond_a

    .line 108
    .line 109
    goto :goto_0

    .line 110
    :cond_a
    iget-object p0, p0, Lcoil3/compose/internal/ContentPainterElement;->j:Lzl/l;

    .line 111
    .line 112
    iget-object p1, p1, Lcoil3/compose/internal/ContentPainterElement;->j:Lzl/l;

    .line 113
    .line 114
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    move-result p0

    .line 118
    if-nez p0, :cond_b

    .line 119
    .line 120
    :goto_0
    const/4 p0, 0x0

    .line 121
    return p0

    .line 122
    :cond_b
    :goto_1
    const/4 p0, 0x1

    .line 123
    return p0
.end method

.method public final h()Lx2/r;
    .locals 10

    .line 1
    new-instance v0, Lzl/b;

    .line 2
    .line 3
    iget-object v1, p0, Lcoil3/compose/internal/ContentPainterElement;->d:Lzl/a;

    .line 4
    .line 5
    iget-object v2, p0, Lcoil3/compose/internal/ContentPainterElement;->c:Lyl/l;

    .line 6
    .line 7
    iget-object v3, p0, Lcoil3/compose/internal/ContentPainterElement;->b:Lmm/g;

    .line 8
    .line 9
    invoke-direct {v0, v2, v3, v1}, Lzl/b;-><init>(Lyl/l;Lmm/g;Lzl/a;)V

    .line 10
    .line 11
    .line 12
    new-instance v5, Lzl/h;

    .line 13
    .line 14
    invoke-direct {v5, v0}, Lzl/h;-><init>(Lzl/b;)V

    .line 15
    .line 16
    .line 17
    iget-object v1, p0, Lcoil3/compose/internal/ContentPainterElement;->e:Lay0/k;

    .line 18
    .line 19
    iput-object v1, v5, Lzl/h;->p:Lay0/k;

    .line 20
    .line 21
    iget-object v1, p0, Lcoil3/compose/internal/ContentPainterElement;->f:Lay0/k;

    .line 22
    .line 23
    iput-object v1, v5, Lzl/h;->q:Lay0/k;

    .line 24
    .line 25
    iget-object v1, p0, Lcoil3/compose/internal/ContentPainterElement;->h:Lt3/k;

    .line 26
    .line 27
    iput-object v1, v5, Lzl/h;->r:Lt3/k;

    .line 28
    .line 29
    const/4 v1, 0x1

    .line 30
    iput v1, v5, Lzl/h;->s:I

    .line 31
    .line 32
    iget-object v1, p0, Lcoil3/compose/internal/ContentPainterElement;->j:Lzl/l;

    .line 33
    .line 34
    iput-object v1, v5, Lzl/h;->t:Lzl/l;

    .line 35
    .line 36
    invoke-virtual {v5, v0}, Lzl/h;->m(Lzl/b;)V

    .line 37
    .line 38
    .line 39
    iget-object v0, v3, Lmm/g;->o:Lnm/i;

    .line 40
    .line 41
    instance-of v1, v0, Lzl/n;

    .line 42
    .line 43
    if-eqz v1, :cond_0

    .line 44
    .line 45
    check-cast v0, Lzl/n;

    .line 46
    .line 47
    :goto_0
    move-object v9, v0

    .line 48
    goto :goto_1

    .line 49
    :cond_0
    const/4 v0, 0x0

    .line 50
    goto :goto_0

    .line 51
    :goto_1
    new-instance v4, Lam/d;

    .line 52
    .line 53
    iget-object v6, p0, Lcoil3/compose/internal/ContentPainterElement;->g:Lx2/e;

    .line 54
    .line 55
    iget-object v7, p0, Lcoil3/compose/internal/ContentPainterElement;->h:Lt3/k;

    .line 56
    .line 57
    iget-object v8, p0, Lcoil3/compose/internal/ContentPainterElement;->i:Le3/m;

    .line 58
    .line 59
    invoke-direct/range {v4 .. v9}, Lam/d;-><init>(Lzl/h;Lx2/e;Lt3/k;Le3/m;Lzl/n;)V

    .line 60
    .line 61
    .line 62
    return-object v4
.end method

.method public final hashCode()I
    .locals 5

    .line 1
    iget-object v0, p0, Lcoil3/compose/internal/ContentPainterElement;->b:Lmm/g;

    .line 2
    .line 3
    invoke-virtual {v0}, Lmm/g;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-object v2, p0, Lcoil3/compose/internal/ContentPainterElement;->c:Lyl/l;

    .line 11
    .line 12
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    add-int/2addr v2, v0

    .line 17
    mul-int/2addr v2, v1

    .line 18
    iget-object v0, p0, Lcoil3/compose/internal/ContentPainterElement;->d:Lzl/a;

    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    add-int/2addr v0, v2

    .line 25
    mul-int/2addr v0, v1

    .line 26
    iget-object v2, p0, Lcoil3/compose/internal/ContentPainterElement;->e:Lay0/k;

    .line 27
    .line 28
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    add-int/2addr v2, v0

    .line 33
    mul-int/2addr v2, v1

    .line 34
    const/4 v0, 0x0

    .line 35
    iget-object v3, p0, Lcoil3/compose/internal/ContentPainterElement;->f:Lay0/k;

    .line 36
    .line 37
    if-nez v3, :cond_0

    .line 38
    .line 39
    move v3, v0

    .line 40
    goto :goto_0

    .line 41
    :cond_0
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    :goto_0
    add-int/2addr v2, v3

    .line 46
    mul-int/2addr v2, v1

    .line 47
    const/4 v3, 0x1

    .line 48
    invoke-static {v3, v2, v1}, Lc1/j0;->g(III)I

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    iget-object v4, p0, Lcoil3/compose/internal/ContentPainterElement;->g:Lx2/e;

    .line 53
    .line 54
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 55
    .line 56
    .line 57
    move-result v4

    .line 58
    add-int/2addr v4, v2

    .line 59
    mul-int/2addr v4, v1

    .line 60
    iget-object v2, p0, Lcoil3/compose/internal/ContentPainterElement;->h:Lt3/k;

    .line 61
    .line 62
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    add-int/2addr v2, v4

    .line 67
    mul-int/2addr v2, v1

    .line 68
    const/high16 v4, 0x3f800000    # 1.0f

    .line 69
    .line 70
    invoke-static {v4, v2, v1}, La7/g0;->c(FII)I

    .line 71
    .line 72
    .line 73
    move-result v2

    .line 74
    iget-object v4, p0, Lcoil3/compose/internal/ContentPainterElement;->i:Le3/m;

    .line 75
    .line 76
    if-nez v4, :cond_1

    .line 77
    .line 78
    move v4, v0

    .line 79
    goto :goto_1

    .line 80
    :cond_1
    invoke-virtual {v4}, Le3/m;->hashCode()I

    .line 81
    .line 82
    .line 83
    move-result v4

    .line 84
    :goto_1
    add-int/2addr v2, v4

    .line 85
    mul-int/2addr v2, v1

    .line 86
    invoke-static {v2, v1, v3}, La7/g0;->e(IIZ)I

    .line 87
    .line 88
    .line 89
    move-result v2

    .line 90
    iget-object p0, p0, Lcoil3/compose/internal/ContentPainterElement;->j:Lzl/l;

    .line 91
    .line 92
    if-nez p0, :cond_2

    .line 93
    .line 94
    goto :goto_2

    .line 95
    :cond_2
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    :goto_2
    add-int/2addr v2, v0

    .line 100
    mul-int/2addr v2, v1

    .line 101
    return v2
.end method

.method public final j(Lx2/r;)V
    .locals 9

    .line 1
    check-cast p1, Lam/d;

    .line 2
    .line 3
    iget-object v0, p1, Lam/d;->x:Lzl/h;

    .line 4
    .line 5
    invoke-virtual {v0}, Lzl/h;->g()J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    iget-object v2, p1, Lam/b;->w:Lzl/n;

    .line 10
    .line 11
    new-instance v3, Lzl/b;

    .line 12
    .line 13
    iget-object v4, p0, Lcoil3/compose/internal/ContentPainterElement;->d:Lzl/a;

    .line 14
    .line 15
    iget-object v5, p0, Lcoil3/compose/internal/ContentPainterElement;->c:Lyl/l;

    .line 16
    .line 17
    iget-object v6, p0, Lcoil3/compose/internal/ContentPainterElement;->b:Lmm/g;

    .line 18
    .line 19
    invoke-direct {v3, v5, v6, v4}, Lzl/b;-><init>(Lyl/l;Lmm/g;Lzl/a;)V

    .line 20
    .line 21
    .line 22
    iget-object v4, p1, Lam/d;->x:Lzl/h;

    .line 23
    .line 24
    iget-object v5, p0, Lcoil3/compose/internal/ContentPainterElement;->e:Lay0/k;

    .line 25
    .line 26
    iput-object v5, v4, Lzl/h;->p:Lay0/k;

    .line 27
    .line 28
    iget-object v5, p0, Lcoil3/compose/internal/ContentPainterElement;->f:Lay0/k;

    .line 29
    .line 30
    iput-object v5, v4, Lzl/h;->q:Lay0/k;

    .line 31
    .line 32
    iget-object v5, p0, Lcoil3/compose/internal/ContentPainterElement;->h:Lt3/k;

    .line 33
    .line 34
    iput-object v5, v4, Lzl/h;->r:Lt3/k;

    .line 35
    .line 36
    const/4 v7, 0x1

    .line 37
    iput v7, v4, Lzl/h;->s:I

    .line 38
    .line 39
    iget-object v8, p0, Lcoil3/compose/internal/ContentPainterElement;->j:Lzl/l;

    .line 40
    .line 41
    iput-object v8, v4, Lzl/h;->t:Lzl/l;

    .line 42
    .line 43
    invoke-virtual {v4, v3}, Lzl/h;->m(Lzl/b;)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v4}, Lzl/h;->g()J

    .line 47
    .line 48
    .line 49
    move-result-wide v3

    .line 50
    invoke-static {v0, v1, v3, v4}, Ld3/e;->a(JJ)Z

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    iget-object v1, p0, Lcoil3/compose/internal/ContentPainterElement;->g:Lx2/e;

    .line 55
    .line 56
    iput-object v1, p1, Lam/b;->r:Lx2/e;

    .line 57
    .line 58
    iget-object v1, v6, Lmm/g;->o:Lnm/i;

    .line 59
    .line 60
    instance-of v3, v1, Lzl/n;

    .line 61
    .line 62
    if-eqz v3, :cond_0

    .line 63
    .line 64
    check-cast v1, Lzl/n;

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_0
    const/4 v1, 0x0

    .line 68
    :goto_0
    iput-object v1, p1, Lam/b;->w:Lzl/n;

    .line 69
    .line 70
    iput-object v5, p1, Lam/b;->s:Lt3/k;

    .line 71
    .line 72
    const/high16 v1, 0x3f800000    # 1.0f

    .line 73
    .line 74
    iput v1, p1, Lam/b;->t:F

    .line 75
    .line 76
    iget-object p0, p0, Lcoil3/compose/internal/ContentPainterElement;->i:Le3/m;

    .line 77
    .line 78
    iput-object p0, p1, Lam/b;->u:Le3/m;

    .line 79
    .line 80
    iput-boolean v7, p1, Lam/b;->v:Z

    .line 81
    .line 82
    iget-object p0, p1, Lam/b;->w:Lzl/n;

    .line 83
    .line 84
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    move-result p0

    .line 88
    if-eqz v0, :cond_1

    .line 89
    .line 90
    if-nez p0, :cond_2

    .line 91
    .line 92
    :cond_1
    invoke-static {p1}, Lv3/f;->n(Lv3/y;)V

    .line 93
    .line 94
    .line 95
    :cond_2
    invoke-static {p1}, Lv3/f;->m(Lv3/p;)V

    .line 96
    .line 97
    .line 98
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "ContentPainterElement(request="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lcoil3/compose/internal/ContentPainterElement;->b:Lmm/g;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", imageLoader="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lcoil3/compose/internal/ContentPainterElement;->c:Lyl/l;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", modelEqualityDelegate="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lcoil3/compose/internal/ContentPainterElement;->d:Lzl/a;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", transform="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lcoil3/compose/internal/ContentPainterElement;->e:Lay0/k;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", onState="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Lcoil3/compose/internal/ContentPainterElement;->f:Lay0/k;

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", filterQuality="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    const-string v1, "Low"

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", alignment="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget-object v1, p0, Lcoil3/compose/internal/ContentPainterElement;->g:Lx2/e;

    .line 69
    .line 70
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v1, ", contentScale="

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    iget-object v1, p0, Lcoil3/compose/internal/ContentPainterElement;->h:Lt3/k;

    .line 79
    .line 80
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v1, ", alpha=1.0, colorFilter="

    .line 84
    .line 85
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    iget-object v1, p0, Lcoil3/compose/internal/ContentPainterElement;->i:Le3/m;

    .line 89
    .line 90
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string v1, ", clipToBounds=true, previewHandler="

    .line 94
    .line 95
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    iget-object p0, p0, Lcoil3/compose/internal/ContentPainterElement;->j:Lzl/l;

    .line 99
    .line 100
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    const-string p0, ", contentDescription=null)"

    .line 104
    .line 105
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    return-object p0
.end method
