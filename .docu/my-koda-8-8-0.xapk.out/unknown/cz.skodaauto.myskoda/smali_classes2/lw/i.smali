.class public abstract Llw/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkw/e;


# instance fields
.field public final a:Lqw/a;

.field public final b:Lqw/e;

.field public final c:Lmw/e;

.field public final d:Lqw/a;

.field public final e:Lqw/a;

.field public final f:Llw/h;

.field public final g:Ljava/util/ArrayList;

.field public final h:Landroid/graphics/RectF;


# direct methods
.method public constructor <init>(Lqw/a;Lqw/e;Lmw/e;Lqw/a;Lqw/a;Llw/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llw/i;->a:Lqw/a;

    .line 5
    .line 6
    iput-object p2, p0, Llw/i;->b:Lqw/e;

    .line 7
    .line 8
    iput-object p3, p0, Llw/i;->c:Lmw/e;

    .line 9
    .line 10
    iput-object p4, p0, Llw/i;->d:Lqw/a;

    .line 11
    .line 12
    iput-object p5, p0, Llw/i;->e:Lqw/a;

    .line 13
    .line 14
    iput-object p6, p0, Llw/i;->f:Llw/h;

    .line 15
    .line 16
    new-instance p1, Ljava/util/ArrayList;

    .line 17
    .line 18
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 19
    .line 20
    .line 21
    iput-object p1, p0, Llw/i;->g:Ljava/util/ArrayList;

    .line 22
    .line 23
    new-instance p1, Landroid/graphics/RectF;

    .line 24
    .line 25
    invoke-direct {p1}, Landroid/graphics/RectF;-><init>()V

    .line 26
    .line 27
    .line 28
    iput-object p1, p0, Llw/i;->h:Landroid/graphics/RectF;

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public bridge synthetic b(Lkw/g;FLjava/lang/Object;Ld3/a;)V
    .locals 0

    .line 1
    check-cast p3, Lmw/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2, p3, p4}, Llw/i;->n(Lkw/g;FLmw/a;Ld3/a;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public abstract c(Lc1/h2;)V
.end method

.method public abstract d(Lc1/h2;)V
.end method

.method public final e(Lc1/h2;)F
    .locals 0

    .line 1
    iget-object p0, p0, Llw/i;->e:Lqw/a;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    iget p0, p0, Lqw/a;->i:F

    .line 6
    .line 7
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    :goto_0
    if-eqz p0, :cond_1

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Float;->floatValue()F

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    goto :goto_1

    .line 20
    :cond_1
    const/4 p0, 0x0

    .line 21
    :goto_1
    iget-object p1, p1, Lc1/h2;->b:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p1, Lkw/g;

    .line 24
    .line 25
    invoke-interface {p1, p0}, Lpw/f;->c(F)F

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    return p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-eq p0, p1, :cond_1

    .line 2
    .line 3
    instance-of v0, p1, Llw/i;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Llw/i;->g()Llw/f;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    check-cast p1, Llw/i;

    .line 12
    .line 13
    invoke-virtual {p1}, Llw/i;->g()Llw/f;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-eqz v0, :cond_0

    .line 22
    .line 23
    iget-object v0, p0, Llw/i;->a:Lqw/a;

    .line 24
    .line 25
    iget-object v1, p1, Llw/i;->a:Lqw/a;

    .line 26
    .line 27
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_0

    .line 32
    .line 33
    iget-object v0, p0, Llw/i;->b:Lqw/e;

    .line 34
    .line 35
    iget-object v1, p1, Llw/i;->b:Lqw/e;

    .line 36
    .line 37
    invoke-virtual {v0, v1}, Lqw/e;->equals(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-eqz v0, :cond_0

    .line 42
    .line 43
    iget-object v0, p0, Llw/i;->c:Lmw/e;

    .line 44
    .line 45
    iget-object v1, p1, Llw/i;->c:Lmw/e;

    .line 46
    .line 47
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    if-eqz v0, :cond_0

    .line 52
    .line 53
    iget-object v0, p0, Llw/i;->d:Lqw/a;

    .line 54
    .line 55
    iget-object v1, p1, Llw/i;->d:Lqw/a;

    .line 56
    .line 57
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    if-eqz v0, :cond_0

    .line 62
    .line 63
    iget-object v0, p0, Llw/i;->e:Lqw/a;

    .line 64
    .line 65
    iget-object v1, p1, Llw/i;->e:Lqw/a;

    .line 66
    .line 67
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    if-eqz v0, :cond_0

    .line 72
    .line 73
    iget-object p0, p0, Llw/i;->f:Llw/h;

    .line 74
    .line 75
    iget-object p1, p1, Llw/i;->f:Llw/h;

    .line 76
    .line 77
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result p0

    .line 81
    if-eqz p0, :cond_0

    .line 82
    .line 83
    goto :goto_0

    .line 84
    :cond_0
    const/4 p0, 0x0

    .line 85
    return p0

    .line 86
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 87
    return p0
.end method

.method public final f(Lpw/f;)F
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Llw/i;->a:Lqw/a;

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    iget p0, p0, Lqw/a;->i:F

    .line 11
    .line 12
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    :goto_0
    if-eqz p0, :cond_1

    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/lang/Float;->floatValue()F

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    goto :goto_1

    .line 25
    :cond_1
    const/4 p0, 0x0

    .line 26
    :goto_1
    invoke-interface {p1, p0}, Lpw/f;->c(F)F

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    return p0
.end method

.method public abstract g()Llw/f;
.end method

.method public final h(Lkw/g;)F
    .locals 0

    .line 1
    iget-object p0, p0, Llw/i;->d:Lqw/a;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/high16 p0, 0x40800000    # 4.0f

    .line 6
    .line 7
    invoke-interface {p1, p0}, Lpw/f;->c(F)F

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return p0
.end method

.method public hashCode()I
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Llw/i;->a:Lqw/a;

    .line 3
    .line 4
    if-eqz v1, :cond_0

    .line 5
    .line 6
    invoke-virtual {v1}, Lqw/a;->hashCode()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move v1, v0

    .line 12
    :goto_0
    const/16 v2, 0x1f

    .line 13
    .line 14
    mul-int/2addr v1, v2

    .line 15
    invoke-virtual {p0}, Llw/i;->g()Llw/f;

    .line 16
    .line 17
    .line 18
    move-result-object v3

    .line 19
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    add-int/2addr v3, v1

    .line 24
    mul-int/2addr v3, v2

    .line 25
    iget-object v1, p0, Llw/i;->b:Lqw/e;

    .line 26
    .line 27
    invoke-virtual {v1}, Lqw/e;->hashCode()I

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    add-int/2addr v1, v3

    .line 32
    mul-int/lit16 v1, v1, 0x3c1

    .line 33
    .line 34
    const/4 v3, 0x0

    .line 35
    invoke-static {v3, v1, v2}, La7/g0;->c(FII)I

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    iget-object v3, p0, Llw/i;->c:Lmw/e;

    .line 40
    .line 41
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    add-int/2addr v3, v1

    .line 46
    mul-int/2addr v3, v2

    .line 47
    iget-object v1, p0, Llw/i;->d:Lqw/a;

    .line 48
    .line 49
    if-eqz v1, :cond_1

    .line 50
    .line 51
    invoke-virtual {v1}, Lqw/a;->hashCode()I

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    goto :goto_1

    .line 56
    :cond_1
    move v1, v0

    .line 57
    :goto_1
    add-int/2addr v3, v1

    .line 58
    mul-int/2addr v3, v2

    .line 59
    const/high16 v1, 0x40800000    # 4.0f

    .line 60
    .line 61
    invoke-static {v1, v3, v2}, La7/g0;->c(FII)I

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    iget-object v3, p0, Llw/i;->e:Lqw/a;

    .line 66
    .line 67
    if-eqz v3, :cond_2

    .line 68
    .line 69
    invoke-virtual {v3}, Lqw/a;->hashCode()I

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    :cond_2
    add-int/2addr v1, v0

    .line 74
    mul-int/2addr v1, v2

    .line 75
    iget-object p0, p0, Llw/i;->f:Llw/h;

    .line 76
    .line 77
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 78
    .line 79
    .line 80
    move-result p0

    .line 81
    add-int/2addr p0, v1

    .line 82
    mul-int/lit16 p0, p0, 0x3c1

    .line 83
    .line 84
    return p0
.end method

.method public final i(Lkw/g;)F
    .locals 0

    .line 1
    iget-object p0, p0, Llw/i;->d:Lqw/a;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    iget p0, p0, Lqw/a;->i:F

    .line 6
    .line 7
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    :goto_0
    if-eqz p0, :cond_1

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Float;->floatValue()F

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    goto :goto_1

    .line 20
    :cond_1
    const/4 p0, 0x0

    .line 21
    :goto_1
    invoke-interface {p1, p0}, Lpw/f;->c(F)F

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    return p0
.end method

.method public final j(FFFF)Z
    .locals 2

    .line 1
    iget-object p0, p0, Llw/i;->g:Ljava/util/ArrayList;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    :cond_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-eqz v0, :cond_3

    .line 21
    .line 22
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    check-cast v0, Landroid/graphics/RectF;

    .line 27
    .line 28
    invoke-virtual {v0, p1, p2, p3, p4}, Landroid/graphics/RectF;->contains(FFFF)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_2

    .line 33
    .line 34
    invoke-virtual {v0, p1, p2, p3, p4}, Landroid/graphics/RectF;->intersects(FFFF)Z

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    if-eqz v0, :cond_1

    .line 39
    .line 40
    :cond_2
    const/4 p0, 0x0

    .line 41
    return p0

    .line 42
    :cond_3
    :goto_0
    const/4 p0, 0x1

    .line 43
    return p0
.end method

.method public final k(Ljava/lang/Float;Ljava/lang/Float;Ljava/lang/Float;Ljava/lang/Float;)V
    .locals 0

    .line 1
    iget-object p0, p0, Llw/i;->h:Landroid/graphics/RectF;

    .line 2
    .line 3
    invoke-static {p0, p1, p2, p3, p4}, Ljp/ae;->c(Landroid/graphics/RectF;Ljava/lang/Number;Ljava/lang/Number;Ljava/lang/Number;Ljava/lang/Number;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final varargs l([Landroid/graphics/RectF;)V
    .locals 1

    .line 1
    invoke-static {p1}, Lmx0/n;->t([Ljava/lang/Object;)Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    const-string v0, "<this>"

    .line 6
    .line 7
    iget-object p0, p0, Llw/i;->g:Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0}, Ljava/util/ArrayList;->clear()V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public abstract m(Lkw/g;Lkw/i;)V
.end method

.method public n(Lkw/g;FLmw/a;Ld3/a;)V
    .locals 0

    .line 1
    const-string p0, "model"

    .line 2
    .line 3
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "insets"

    .line 7
    .line 8
    invoke-static {p4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method
