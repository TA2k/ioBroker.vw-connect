.class public final Lc1/f1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lc1/a0;


# instance fields
.field public final a:F

.field public final b:F

.field public final c:Ljava/lang/Object;


# direct methods
.method public constructor <init>(FFLjava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput p1, p0, Lc1/f1;->a:F

    .line 3
    iput p2, p0, Lc1/f1;->b:F

    .line 4
    iput-object p3, p0, Lc1/f1;->c:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 1

    and-int/lit8 p2, p2, 0x4

    if-eqz p2, :cond_0

    const/4 p1, 0x0

    :cond_0
    const/high16 p2, 0x3f800000    # 1.0f

    const v0, 0x44bb8000    # 1500.0f

    .line 5
    invoke-direct {p0, p2, v0, p1}, Lc1/f1;-><init>(FFLjava/lang/Object;)V

    return-void
.end method


# virtual methods
.method public final a(Lc1/b2;)Lc1/d2;
    .locals 2

    .line 1
    new-instance v0, La0/j;

    .line 2
    .line 3
    iget-object v1, p0, Lc1/f1;->c:Ljava/lang/Object;

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    const/4 p1, 0x0

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    iget-object p1, p1, Lc1/b2;->a:Lay0/k;

    .line 10
    .line 11
    invoke-interface {p1, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    check-cast p1, Lc1/p;

    .line 16
    .line 17
    :goto_0
    iget v1, p0, Lc1/f1;->a:F

    .line 18
    .line 19
    iget p0, p0, Lc1/f1;->b:F

    .line 20
    .line 21
    invoke-direct {v0, v1, p0, p1}, La0/j;-><init>(FFLc1/p;)V

    .line 22
    .line 23
    .line 24
    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    instance-of v0, p1, Lc1/f1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    check-cast p1, Lc1/f1;

    .line 7
    .line 8
    iget v0, p1, Lc1/f1;->a:F

    .line 9
    .line 10
    iget v2, p0, Lc1/f1;->a:F

    .line 11
    .line 12
    cmpg-float v0, v0, v2

    .line 13
    .line 14
    if-nez v0, :cond_0

    .line 15
    .line 16
    iget v0, p1, Lc1/f1;->b:F

    .line 17
    .line 18
    iget v2, p0, Lc1/f1;->b:F

    .line 19
    .line 20
    cmpg-float v0, v0, v2

    .line 21
    .line 22
    if-nez v0, :cond_0

    .line 23
    .line 24
    iget-object p1, p1, Lc1/f1;->c:Ljava/lang/Object;

    .line 25
    .line 26
    iget-object p0, p0, Lc1/f1;->c:Ljava/lang/Object;

    .line 27
    .line 28
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-eqz p0, :cond_0

    .line 33
    .line 34
    const/4 p0, 0x1

    .line 35
    return p0

    .line 36
    :cond_0
    return v1
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lc1/f1;->c:Ljava/lang/Object;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 v0, 0x0

    .line 11
    :goto_0
    const/16 v1, 0x1f

    .line 12
    .line 13
    mul-int/2addr v0, v1

    .line 14
    iget v2, p0, Lc1/f1;->a:F

    .line 15
    .line 16
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    iget p0, p0, Lc1/f1;->b:F

    .line 21
    .line 22
    invoke-static {p0}, Ljava/lang/Float;->hashCode(F)I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    add-int/2addr p0, v0

    .line 27
    return p0
.end method
