.class public final Li2/j1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Li2/v0;


# instance fields
.field public final a:Lx2/f;


# direct methods
.method public constructor <init>(Lx2/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li2/j1;->a:Lx2/f;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lt4/k;JILt4/m;)I
    .locals 0

    .line 1
    const/16 p1, 0x20

    .line 2
    .line 3
    shr-long p1, p2, p1

    .line 4
    .line 5
    long-to-int p1, p1

    .line 6
    if-lt p4, p1, :cond_1

    .line 7
    .line 8
    sub-int/2addr p1, p4

    .line 9
    int-to-float p0, p1

    .line 10
    const/high16 p1, 0x40000000    # 2.0f

    .line 11
    .line 12
    div-float/2addr p0, p1

    .line 13
    sget-object p1, Lt4/m;->d:Lt4/m;

    .line 14
    .line 15
    const/4 p2, 0x0

    .line 16
    if-ne p5, p1, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const/4 p1, -0x1

    .line 20
    int-to-float p1, p1

    .line 21
    mul-float/2addr p2, p1

    .line 22
    :goto_0
    const/4 p1, 0x1

    .line 23
    int-to-float p1, p1

    .line 24
    add-float/2addr p1, p2

    .line 25
    mul-float/2addr p1, p0

    .line 26
    invoke-static {p1}, Ljava/lang/Math;->round(F)I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    return p0

    .line 31
    :cond_1
    iget-object p0, p0, Li2/j1;->a:Lx2/f;

    .line 32
    .line 33
    invoke-virtual {p0, p4, p1, p5}, Lx2/f;->a(IILt4/m;)I

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    sub-int/2addr p1, p4

    .line 38
    const/4 p2, 0x0

    .line 39
    invoke-static {p0, p2, p1}, Lkp/r9;->e(III)I

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    return p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Li2/j1;

    .line 6
    .line 7
    if-nez v1, :cond_1

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_1
    check-cast p1, Li2/j1;

    .line 11
    .line 12
    iget-object p0, p0, Li2/j1;->a:Lx2/f;

    .line 13
    .line 14
    iget-object p1, p1, Li2/j1;->a:Lx2/f;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Lx2/f;->equals(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    if-nez p0, :cond_2

    .line 21
    .line 22
    :goto_0
    const/4 p0, 0x0

    .line 23
    return p0

    .line 24
    :cond_2
    return v0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget-object p0, p0, Li2/j1;->a:Lx2/f;

    .line 2
    .line 3
    iget p0, p0, Lx2/f;->a:F

    .line 4
    .line 5
    invoke-static {p0}, Ljava/lang/Float;->hashCode(F)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    mul-int/lit8 p0, p0, 0x1f

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    invoke-static {v0}, Ljava/lang/Integer;->hashCode(I)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    add-int/2addr v0, p0

    .line 17
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "Horizontal(alignment="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Li2/j1;->a:Lx2/f;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string p0, ", margin=0)"

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method
