.class public final Lu71/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final g:Lu71/b;


# instance fields
.field public final a:I

.field public final b:I

.field public final c:Lu71/a;

.field public final d:F

.field public final e:F

.field public final f:Lu71/a;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lu71/b;

    .line 2
    .line 3
    new-instance v3, Lu71/a;

    .line 4
    .line 5
    const/high16 v1, -0x40800000    # -1.0f

    .line 6
    .line 7
    invoke-direct {v3, v1, v1}, Lu71/a;-><init>(FF)V

    .line 8
    .line 9
    .line 10
    const/high16 v4, -0x40800000    # -1.0f

    .line 11
    .line 12
    const/high16 v5, -0x40800000    # -1.0f

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    const/16 v2, 0x1f

    .line 16
    .line 17
    invoke-direct/range {v0 .. v5}, Lu71/b;-><init>(IILu71/a;FF)V

    .line 18
    .line 19
    .line 20
    sput-object v0, Lu71/b;->g:Lu71/b;

    .line 21
    .line 22
    return-void
.end method

.method public constructor <init>(IILu71/a;FF)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lu71/b;->a:I

    .line 5
    .line 6
    iput p2, p0, Lu71/b;->b:I

    .line 7
    .line 8
    iput-object p3, p0, Lu71/b;->c:Lu71/a;

    .line 9
    .line 10
    iput p4, p0, Lu71/b;->d:F

    .line 11
    .line 12
    iput p5, p0, Lu71/b;->e:F

    .line 13
    .line 14
    new-instance p1, Lu71/a;

    .line 15
    .line 16
    iget p2, p3, Lu71/a;->a:F

    .line 17
    .line 18
    add-float/2addr p2, p4

    .line 19
    iget p3, p3, Lu71/a;->b:F

    .line 20
    .line 21
    add-float/2addr p3, p5

    .line 22
    invoke-direct {p1, p2, p3}, Lu71/a;-><init>(FF)V

    .line 23
    .line 24
    .line 25
    iput-object p1, p0, Lu71/b;->f:Lu71/a;

    .line 26
    .line 27
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lu71/b;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lu71/b;

    .line 12
    .line 13
    iget v1, p0, Lu71/b;->a:I

    .line 14
    .line 15
    iget v3, p1, Lu71/b;->a:I

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget v1, p0, Lu71/b;->b:I

    .line 21
    .line 22
    iget v3, p1, Lu71/b;->b:I

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-object v1, p0, Lu71/b;->c:Lu71/a;

    .line 28
    .line 29
    iget-object v3, p1, Lu71/b;->c:Lu71/a;

    .line 30
    .line 31
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-nez v1, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    iget v1, p0, Lu71/b;->d:F

    .line 39
    .line 40
    iget v3, p1, Lu71/b;->d:F

    .line 41
    .line 42
    invoke-static {v1, v3}, Ljava/lang/Float;->compare(FF)I

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    if-eqz v1, :cond_5

    .line 47
    .line 48
    return v2

    .line 49
    :cond_5
    iget p0, p0, Lu71/b;->e:F

    .line 50
    .line 51
    iget p1, p1, Lu71/b;->e:F

    .line 52
    .line 53
    invoke-static {p0, p1}, Ljava/lang/Float;->compare(FF)I

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    if-eqz p0, :cond_6

    .line 58
    .line 59
    return v2

    .line 60
    :cond_6
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Lu71/b;->a:I

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Integer;->hashCode(I)I

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
    iget v2, p0, Lu71/b;->b:I

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lu71/b;->c:Lu71/a;

    .line 17
    .line 18
    invoke-virtual {v2}, Lu71/a;->hashCode()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v0

    .line 23
    mul-int/2addr v2, v1

    .line 24
    iget v0, p0, Lu71/b;->d:F

    .line 25
    .line 26
    invoke-static {v0, v2, v1}, La7/g0;->c(FII)I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    iget p0, p0, Lu71/b;->e:F

    .line 31
    .line 32
    invoke-static {p0}, Ljava/lang/Float;->hashCode(F)I

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    add-int/2addr p0, v0

    .line 37
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", cellIndexY="

    .line 2
    .line 3
    const-string v1, ", topLeftPointPx="

    .line 4
    .line 5
    iget v2, p0, Lu71/b;->a:I

    .line 6
    .line 7
    iget v3, p0, Lu71/b;->b:I

    .line 8
    .line 9
    const-string v4, "TouchCell(cellIndexX="

    .line 10
    .line 11
    invoke-static {v2, v3, v4, v0, v1}, Lu/w;->j(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iget-object v1, p0, Lu71/b;->c:Lu71/a;

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const-string v1, ", widthPx="

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    iget v1, p0, Lu71/b;->d:F

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v1, ", heightPx="

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v1, ")"

    .line 36
    .line 37
    iget p0, p0, Lu71/b;->e:F

    .line 38
    .line 39
    invoke-static {p0, v1, v0}, Lkx/a;->g(FLjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0
.end method
