.class public final Lcoil3/compose/internal/SubcomposeContentPainterElement;
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
        "Lcoil3/compose/internal/SubcomposeContentPainterElement;",
        "Lv3/z0;",
        "Lam/g;",
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
.field public final b:Li3/c;

.field public final c:Lx2/e;

.field public final d:Lt3/k;

.field public final e:F

.field public final f:Z


# direct methods
.method public constructor <init>(Li3/c;Lx2/e;Lt3/k;FZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->b:Li3/c;

    .line 5
    .line 6
    iput-object p2, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->c:Lx2/e;

    .line 7
    .line 8
    iput-object p3, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->d:Lt3/k;

    .line 9
    .line 10
    iput p4, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->e:F

    .line 11
    .line 12
    iput-boolean p5, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->f:Z

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_1

    .line 4
    :cond_0
    instance-of v0, p1, Lcoil3/compose/internal/SubcomposeContentPainterElement;

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_1
    check-cast p1, Lcoil3/compose/internal/SubcomposeContentPainterElement;

    .line 10
    .line 11
    iget-object v0, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->b:Li3/c;

    .line 12
    .line 13
    iget-object v1, p1, Lcoil3/compose/internal/SubcomposeContentPainterElement;->b:Li3/c;

    .line 14
    .line 15
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-nez v0, :cond_2

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_2
    iget-object v0, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->c:Lx2/e;

    .line 23
    .line 24
    iget-object v1, p1, Lcoil3/compose/internal/SubcomposeContentPainterElement;->c:Lx2/e;

    .line 25
    .line 26
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-nez v0, :cond_3

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_3
    iget-object v0, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->d:Lt3/k;

    .line 34
    .line 35
    iget-object v1, p1, Lcoil3/compose/internal/SubcomposeContentPainterElement;->d:Lt3/k;

    .line 36
    .line 37
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-nez v0, :cond_4

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_4
    iget v0, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->e:F

    .line 45
    .line 46
    iget v1, p1, Lcoil3/compose/internal/SubcomposeContentPainterElement;->e:F

    .line 47
    .line 48
    invoke-static {v0, v1}, Ljava/lang/Float;->compare(FF)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    if-eqz v0, :cond_5

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_5
    iget-boolean p0, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->f:Z

    .line 56
    .line 57
    iget-boolean p1, p1, Lcoil3/compose/internal/SubcomposeContentPainterElement;->f:Z

    .line 58
    .line 59
    if-eq p0, p1, :cond_6

    .line 60
    .line 61
    :goto_0
    const/4 p0, 0x0

    .line 62
    return p0

    .line 63
    :cond_6
    :goto_1
    const/4 p0, 0x1

    .line 64
    return p0
.end method

.method public final h()Lx2/r;
    .locals 7

    .line 1
    new-instance v0, Lam/g;

    .line 2
    .line 3
    iget-boolean v5, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->f:Z

    .line 4
    .line 5
    const/4 v6, 0x0

    .line 6
    iget-object v1, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->c:Lx2/e;

    .line 7
    .line 8
    iget-object v2, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->d:Lt3/k;

    .line 9
    .line 10
    iget v3, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->e:F

    .line 11
    .line 12
    const/4 v4, 0x0

    .line 13
    invoke-direct/range {v0 .. v6}, Lam/b;-><init>(Lx2/e;Lt3/k;FLe3/m;ZLzl/n;)V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->b:Li3/c;

    .line 17
    .line 18
    iput-object p0, v0, Lam/g;->x:Li3/c;

    .line 19
    .line 20
    return-object v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->b:Li3/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

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
    iget-object v2, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->c:Lx2/e;

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
    iget-object v0, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->d:Lt3/k;

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
    iget v2, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->e:F

    .line 27
    .line 28
    const/16 v3, 0x3c1

    .line 29
    .line 30
    invoke-static {v2, v0, v3}, La7/g0;->c(FII)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-boolean p0, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->f:Z

    .line 35
    .line 36
    invoke-static {v0, v1, p0}, La7/g0;->e(IIZ)I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    return p0
.end method

.method public final j(Lx2/r;)V
    .locals 5

    .line 1
    check-cast p1, Lam/g;

    .line 2
    .line 3
    iget-object v0, p1, Lam/g;->x:Li3/c;

    .line 4
    .line 5
    invoke-virtual {v0}, Li3/c;->g()J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    iget-object v2, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->b:Li3/c;

    .line 10
    .line 11
    invoke-virtual {v2}, Li3/c;->g()J

    .line 12
    .line 13
    .line 14
    move-result-wide v3

    .line 15
    invoke-static {v0, v1, v3, v4}, Ld3/e;->a(JJ)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    iput-object v2, p1, Lam/g;->x:Li3/c;

    .line 20
    .line 21
    iget-object v1, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->c:Lx2/e;

    .line 22
    .line 23
    iput-object v1, p1, Lam/b;->r:Lx2/e;

    .line 24
    .line 25
    iget-object v1, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->d:Lt3/k;

    .line 26
    .line 27
    iput-object v1, p1, Lam/b;->s:Lt3/k;

    .line 28
    .line 29
    iget v1, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->e:F

    .line 30
    .line 31
    iput v1, p1, Lam/b;->t:F

    .line 32
    .line 33
    const/4 v1, 0x0

    .line 34
    iput-object v1, p1, Lam/b;->u:Le3/m;

    .line 35
    .line 36
    iget-boolean p0, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->f:Z

    .line 37
    .line 38
    iput-boolean p0, p1, Lam/b;->v:Z

    .line 39
    .line 40
    if-nez v0, :cond_0

    .line 41
    .line 42
    invoke-static {p1}, Lv3/f;->n(Lv3/y;)V

    .line 43
    .line 44
    .line 45
    :cond_0
    invoke-static {p1}, Lv3/f;->m(Lv3/p;)V

    .line 46
    .line 47
    .line 48
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "SubcomposeContentPainterElement(painter="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->b:Li3/c;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", alignment="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->c:Lx2/e;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", contentScale="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->d:Lt3/k;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", alpha="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget v1, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->e:F

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", colorFilter=null, clipToBounds="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    const-string v1, ", contentDescription=null)"

    .line 49
    .line 50
    iget-boolean p0, p0, Lcoil3/compose/internal/SubcomposeContentPainterElement;->f:Z

    .line 51
    .line 52
    invoke-static {v0, p0, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0
.end method
