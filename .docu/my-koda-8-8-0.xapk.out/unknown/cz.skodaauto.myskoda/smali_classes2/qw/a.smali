.class public final Lqw/a;
.super Lqw/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final i:F


# direct methods
.method public constructor <init>(Lpw/d;FLtw/l;Lpw/c;Lpw/d;F)V
    .locals 7

    .line 1
    const-string v0, "margins"

    .line 2
    .line 3
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "strokeFill"

    .line 7
    .line 8
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    move-object v1, p0

    .line 12
    move-object v2, p1

    .line 13
    move-object v3, p3

    .line 14
    move-object v4, p4

    .line 15
    move-object v5, p5

    .line 16
    move v6, p6

    .line 17
    invoke-direct/range {v1 .. v6}, Lqw/b;-><init>(Lpw/d;Ltw/l;Lpw/c;Lpw/d;F)V

    .line 18
    .line 19
    .line 20
    iput p2, v1, Lqw/a;->i:F

    .line 21
    .line 22
    return-void
.end method

.method public static b(Lqw/a;Lc1/h2;FFF)V
    .locals 11

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iget v0, p0, Lqw/a;->i:F

    .line 5
    .line 6
    iget-object v1, p1, Lc1/h2;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v1, Lkw/g;

    .line 9
    .line 10
    invoke-interface {v1, v0}, Lpw/f;->c(F)F

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    const/high16 v3, 0x3f800000    # 1.0f

    .line 15
    .line 16
    mul-float/2addr v2, v3

    .line 17
    const/4 v4, 0x2

    .line 18
    int-to-float v4, v4

    .line 19
    div-float/2addr v2, v4

    .line 20
    sub-float v8, p4, v2

    .line 21
    .line 22
    invoke-interface {v1, v0}, Lpw/f;->c(F)F

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    mul-float/2addr v0, v3

    .line 27
    div-float/2addr v0, v4

    .line 28
    add-float v10, v0, p4

    .line 29
    .line 30
    move-object v5, p0

    .line 31
    move-object v6, p1

    .line 32
    move v7, p2

    .line 33
    move v9, p3

    .line 34
    invoke-virtual/range {v5 .. v10}, Lqw/b;->a(Lc1/h2;FFFF)V

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method public static c(Lqw/a;Lc1/h2;FFF)V
    .locals 11

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iget v0, p0, Lqw/a;->i:F

    .line 5
    .line 6
    iget-object v1, p1, Lc1/h2;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v1, Lkw/g;

    .line 9
    .line 10
    invoke-interface {v1, v0}, Lpw/f;->c(F)F

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    const/high16 v3, 0x3f800000    # 1.0f

    .line 15
    .line 16
    mul-float/2addr v2, v3

    .line 17
    const/4 v4, 0x2

    .line 18
    int-to-float v4, v4

    .line 19
    div-float/2addr v2, v4

    .line 20
    sub-float v7, p4, v2

    .line 21
    .line 22
    invoke-interface {v1, v0}, Lpw/f;->c(F)F

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    mul-float/2addr v0, v3

    .line 27
    div-float/2addr v0, v4

    .line 28
    add-float v9, v0, p4

    .line 29
    .line 30
    move-object v5, p0

    .line 31
    move-object v6, p1

    .line 32
    move v8, p2

    .line 33
    move v10, p3

    .line 34
    invoke-virtual/range {v5 .. v10}, Lqw/b;->a(Lc1/h2;FFFF)V

    .line 35
    .line 36
    .line 37
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    invoke-super {p0, p1}, Lqw/b;->equals(Ljava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    instance-of v0, p1, Lqw/a;

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    check-cast p1, Lqw/a;

    .line 12
    .line 13
    iget p1, p1, Lqw/a;->i:F

    .line 14
    .line 15
    iget p0, p0, Lqw/a;->i:F

    .line 16
    .line 17
    cmpg-float p0, p0, p1

    .line 18
    .line 19
    if-nez p0, :cond_0

    .line 20
    .line 21
    const/4 p0, 0x1

    .line 22
    return p0

    .line 23
    :cond_0
    const/4 p0, 0x0

    .line 24
    return p0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    invoke-super {p0}, Lqw/b;->hashCode()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    mul-int/lit8 v0, v0, 0x1f

    .line 6
    .line 7
    iget p0, p0, Lqw/a;->i:F

    .line 8
    .line 9
    invoke-static {p0}, Ljava/lang/Float;->hashCode(F)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    add-int/2addr p0, v0

    .line 14
    return p0
.end method
