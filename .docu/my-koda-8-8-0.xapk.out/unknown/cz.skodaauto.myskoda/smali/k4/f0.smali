.class public final Lk4/f0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lk4/n;

.field public final b:Lk4/x;

.field public final c:I

.field public final d:I

.field public final e:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lk4/n;Lk4/x;IILjava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk4/f0;->a:Lk4/n;

    .line 5
    .line 6
    iput-object p2, p0, Lk4/f0;->b:Lk4/x;

    .line 7
    .line 8
    iput p3, p0, Lk4/f0;->c:I

    .line 9
    .line 10
    iput p4, p0, Lk4/f0;->d:I

    .line 11
    .line 12
    iput-object p5, p0, Lk4/f0;->e:Ljava/lang/Object;

    .line 13
    .line 14
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
    instance-of v1, p1, Lk4/f0;

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
    check-cast p1, Lk4/f0;

    .line 12
    .line 13
    iget-object v1, p0, Lk4/f0;->a:Lk4/n;

    .line 14
    .line 15
    iget-object v3, p1, Lk4/f0;->a:Lk4/n;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Lk4/f0;->b:Lk4/x;

    .line 25
    .line 26
    iget-object v3, p1, Lk4/f0;->b:Lk4/x;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget v1, p0, Lk4/f0;->c:I

    .line 36
    .line 37
    iget v3, p1, Lk4/f0;->c:I

    .line 38
    .line 39
    if-ne v1, v3, :cond_5

    .line 40
    .line 41
    iget v1, p0, Lk4/f0;->d:I

    .line 42
    .line 43
    iget v3, p1, Lk4/f0;->d:I

    .line 44
    .line 45
    if-ne v1, v3, :cond_5

    .line 46
    .line 47
    iget-object p0, p0, Lk4/f0;->e:Ljava/lang/Object;

    .line 48
    .line 49
    iget-object p1, p1, Lk4/f0;->e:Ljava/lang/Object;

    .line 50
    .line 51
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result p0

    .line 55
    if-nez p0, :cond_4

    .line 56
    .line 57
    return v2

    .line 58
    :cond_4
    return v0

    .line 59
    :cond_5
    return v2
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Lk4/f0;->a:Lk4/n;

    .line 3
    .line 4
    if-nez v1, :cond_0

    .line 5
    .line 6
    move v1, v0

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    :goto_0
    const/16 v2, 0x1f

    .line 13
    .line 14
    mul-int/2addr v1, v2

    .line 15
    iget-object v3, p0, Lk4/f0;->b:Lk4/x;

    .line 16
    .line 17
    iget v3, v3, Lk4/x;->d:I

    .line 18
    .line 19
    add-int/2addr v1, v3

    .line 20
    mul-int/2addr v1, v2

    .line 21
    iget v3, p0, Lk4/f0;->c:I

    .line 22
    .line 23
    invoke-static {v3, v1, v2}, Lc1/j0;->g(III)I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    iget v3, p0, Lk4/f0;->d:I

    .line 28
    .line 29
    invoke-static {v3, v1, v2}, Lc1/j0;->g(III)I

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    iget-object p0, p0, Lk4/f0;->e:Ljava/lang/Object;

    .line 34
    .line 35
    if-nez p0, :cond_1

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_1
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    :goto_1
    add-int/2addr v1, v0

    .line 43
    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "TypefaceRequest(fontFamily="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lk4/f0;->a:Lk4/n;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", fontWeight="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lk4/f0;->b:Lk4/x;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", fontStyle="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, "Invalid"

    .line 29
    .line 30
    const/4 v2, 0x1

    .line 31
    iget v3, p0, Lk4/f0;->c:I

    .line 32
    .line 33
    if-nez v3, :cond_0

    .line 34
    .line 35
    const-string v3, "Normal"

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    if-ne v3, v2, :cond_1

    .line 39
    .line 40
    const-string v3, "Italic"

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_1
    move-object v3, v1

    .line 44
    :goto_0
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    const-string v3, ", fontSynthesis="

    .line 48
    .line 49
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    iget v3, p0, Lk4/f0;->d:I

    .line 53
    .line 54
    if-nez v3, :cond_2

    .line 55
    .line 56
    const-string v1, "None"

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_2
    if-ne v3, v2, :cond_3

    .line 60
    .line 61
    const-string v1, "Weight"

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_3
    const/4 v2, 0x2

    .line 65
    if-ne v3, v2, :cond_4

    .line 66
    .line 67
    const-string v1, "Style"

    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_4
    const v2, 0xffff

    .line 71
    .line 72
    .line 73
    if-ne v3, v2, :cond_5

    .line 74
    .line 75
    const-string v1, "All"

    .line 76
    .line 77
    :cond_5
    :goto_1
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    const-string v1, ", resourceLoaderCacheKey="

    .line 81
    .line 82
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    iget-object p0, p0, Lk4/f0;->e:Ljava/lang/Object;

    .line 86
    .line 87
    const/16 v1, 0x29

    .line 88
    .line 89
    invoke-static {v0, p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->n(Ljava/lang/StringBuilder;Ljava/lang/Object;C)Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    return-object p0
.end method
