.class public final Li2/k1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Li2/w0;


# instance fields
.field public final a:Lx2/i;

.field public final b:I


# direct methods
.method public constructor <init>(Lx2/i;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li2/k1;->a:Lx2/i;

    .line 5
    .line 6
    iput p2, p0, Li2/k1;->b:I

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lt4/k;JI)I
    .locals 2

    .line 1
    const-wide v0, 0xffffffffL

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    and-long p1, p2, v0

    .line 7
    .line 8
    long-to-int p1, p1

    .line 9
    iget p2, p0, Li2/k1;->b:I

    .line 10
    .line 11
    mul-int/lit8 p3, p2, 0x2

    .line 12
    .line 13
    sub-int p3, p1, p3

    .line 14
    .line 15
    if-lt p4, p3, :cond_0

    .line 16
    .line 17
    sub-int/2addr p1, p4

    .line 18
    int-to-float p0, p1

    .line 19
    const/high16 p1, 0x40000000    # 2.0f

    .line 20
    .line 21
    div-float/2addr p0, p1

    .line 22
    const/4 p1, 0x1

    .line 23
    int-to-float p1, p1

    .line 24
    const/4 p2, 0x0

    .line 25
    add-float/2addr p1, p2

    .line 26
    mul-float/2addr p1, p0

    .line 27
    invoke-static {p1}, Ljava/lang/Math;->round(F)I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    return p0

    .line 32
    :cond_0
    iget-object p0, p0, Li2/k1;->a:Lx2/i;

    .line 33
    .line 34
    invoke-virtual {p0, p4, p1}, Lx2/i;->a(II)I

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    sub-int/2addr p1, p2

    .line 39
    sub-int/2addr p1, p4

    .line 40
    invoke-static {p0, p2, p1}, Lkp/r9;->e(III)I

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    return p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_1

    .line 4
    :cond_0
    instance-of v0, p1, Li2/k1;

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_1
    check-cast p1, Li2/k1;

    .line 10
    .line 11
    iget-object v0, p0, Li2/k1;->a:Lx2/i;

    .line 12
    .line 13
    iget-object v1, p1, Li2/k1;->a:Lx2/i;

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Lx2/i;->equals(Ljava/lang/Object;)Z

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
    iget p0, p0, Li2/k1;->b:I

    .line 23
    .line 24
    iget p1, p1, Li2/k1;->b:I

    .line 25
    .line 26
    if-eq p0, p1, :cond_3

    .line 27
    .line 28
    :goto_0
    const/4 p0, 0x0

    .line 29
    return p0

    .line 30
    :cond_3
    :goto_1
    const/4 p0, 0x1

    .line 31
    return p0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget-object v0, p0, Li2/k1;->a:Lx2/i;

    .line 2
    .line 3
    iget v0, v0, Lx2/i;->a:F

    .line 4
    .line 5
    invoke-static {v0}, Ljava/lang/Float;->hashCode(F)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    mul-int/lit8 v0, v0, 0x1f

    .line 10
    .line 11
    iget p0, p0, Li2/k1;->b:I

    .line 12
    .line 13
    invoke-static {p0}, Ljava/lang/Integer;->hashCode(I)I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    add-int/2addr p0, v0

    .line 18
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "Vertical(alignment="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Li2/k1;->a:Lx2/i;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", margin="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget p0, p0, Li2/k1;->b:I

    .line 19
    .line 20
    const/16 v1, 0x29

    .line 21
    .line 22
    invoke-static {v0, p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->m(Ljava/lang/StringBuilder;IC)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method
