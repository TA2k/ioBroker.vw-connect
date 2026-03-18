.class public final Lh0/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final h:Landroid/util/Range;


# instance fields
.field public final a:Landroid/util/Size;

.field public final b:Landroid/util/Size;

.field public final c:Lb0/y;

.field public final d:I

.field public final e:Landroid/util/Range;

.field public final f:Lh0/q0;

.field public final g:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Landroid/util/Range;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 5
    .line 6
    .line 7
    move-result-object v1

    .line 8
    invoke-direct {v0, v1, v1}, Landroid/util/Range;-><init>(Ljava/lang/Comparable;Ljava/lang/Comparable;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lh0/k;->h:Landroid/util/Range;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(Landroid/util/Size;Landroid/util/Size;Lb0/y;ILandroid/util/Range;Lh0/q0;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh0/k;->a:Landroid/util/Size;

    .line 5
    .line 6
    iput-object p2, p0, Lh0/k;->b:Landroid/util/Size;

    .line 7
    .line 8
    iput-object p3, p0, Lh0/k;->c:Lb0/y;

    .line 9
    .line 10
    iput p4, p0, Lh0/k;->d:I

    .line 11
    .line 12
    iput-object p5, p0, Lh0/k;->e:Landroid/util/Range;

    .line 13
    .line 14
    iput-object p6, p0, Lh0/k;->f:Lh0/q0;

    .line 15
    .line 16
    iput-boolean p7, p0, Lh0/k;->g:Z

    .line 17
    .line 18
    return-void
.end method

.method public static a(Landroid/util/Size;)Lss/b;
    .locals 2

    .line 1
    new-instance v0, Lss/b;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-direct {v0, v1}, Lss/b;-><init>(I)V

    .line 5
    .line 6
    .line 7
    if-eqz p0, :cond_1

    .line 8
    .line 9
    iput-object p0, v0, Lss/b;->e:Ljava/lang/Object;

    .line 10
    .line 11
    iput-object p0, v0, Lss/b;->f:Ljava/lang/Object;

    .line 12
    .line 13
    const/4 p0, 0x0

    .line 14
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    iput-object p0, v0, Lss/b;->h:Ljava/lang/Object;

    .line 19
    .line 20
    sget-object p0, Lh0/k;->h:Landroid/util/Range;

    .line 21
    .line 22
    if-eqz p0, :cond_0

    .line 23
    .line 24
    iput-object p0, v0, Lss/b;->i:Ljava/lang/Object;

    .line 25
    .line 26
    sget-object p0, Lb0/y;->d:Lb0/y;

    .line 27
    .line 28
    iput-object p0, v0, Lss/b;->g:Ljava/lang/Object;

    .line 29
    .line 30
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 31
    .line 32
    iput-object p0, v0, Lss/b;->k:Ljava/lang/Object;

    .line 33
    .line 34
    return-object v0

    .line 35
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 36
    .line 37
    const-string v0, "Null expectedFrameRateRange"

    .line 38
    .line 39
    invoke-direct {p0, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw p0

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/NullPointerException;

    .line 44
    .line 45
    const-string v0, "Null resolution"

    .line 46
    .line 47
    invoke-direct {p0, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0
.end method


# virtual methods
.method public final b()Lss/b;
    .locals 2

    .line 1
    new-instance v0, Lss/b;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-direct {v0, v1}, Lss/b;-><init>(I)V

    .line 5
    .line 6
    .line 7
    iget-object v1, p0, Lh0/k;->a:Landroid/util/Size;

    .line 8
    .line 9
    iput-object v1, v0, Lss/b;->e:Ljava/lang/Object;

    .line 10
    .line 11
    iget-object v1, p0, Lh0/k;->b:Landroid/util/Size;

    .line 12
    .line 13
    iput-object v1, v0, Lss/b;->f:Ljava/lang/Object;

    .line 14
    .line 15
    iget-object v1, p0, Lh0/k;->c:Lb0/y;

    .line 16
    .line 17
    iput-object v1, v0, Lss/b;->g:Ljava/lang/Object;

    .line 18
    .line 19
    iget v1, p0, Lh0/k;->d:I

    .line 20
    .line 21
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    iput-object v1, v0, Lss/b;->h:Ljava/lang/Object;

    .line 26
    .line 27
    iget-object v1, p0, Lh0/k;->e:Landroid/util/Range;

    .line 28
    .line 29
    iput-object v1, v0, Lss/b;->i:Ljava/lang/Object;

    .line 30
    .line 31
    iget-object v1, p0, Lh0/k;->f:Lh0/q0;

    .line 32
    .line 33
    iput-object v1, v0, Lss/b;->j:Ljava/lang/Object;

    .line 34
    .line 35
    iget-boolean p0, p0, Lh0/k;->g:Z

    .line 36
    .line 37
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    iput-object p0, v0, Lss/b;->k:Ljava/lang/Object;

    .line 42
    .line 43
    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 5

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p1, p0, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lh0/k;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_2

    .line 9
    .line 10
    check-cast p1, Lh0/k;

    .line 11
    .line 12
    iget-object v1, p1, Lh0/k;->f:Lh0/q0;

    .line 13
    .line 14
    iget-object v3, p0, Lh0/k;->a:Landroid/util/Size;

    .line 15
    .line 16
    iget-object v4, p1, Lh0/k;->a:Landroid/util/Size;

    .line 17
    .line 18
    invoke-virtual {v3, v4}, Landroid/util/Size;->equals(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    if-eqz v3, :cond_2

    .line 23
    .line 24
    iget-object v3, p0, Lh0/k;->b:Landroid/util/Size;

    .line 25
    .line 26
    iget-object v4, p1, Lh0/k;->b:Landroid/util/Size;

    .line 27
    .line 28
    invoke-virtual {v3, v4}, Landroid/util/Size;->equals(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v3

    .line 32
    if-eqz v3, :cond_2

    .line 33
    .line 34
    iget-object v3, p0, Lh0/k;->c:Lb0/y;

    .line 35
    .line 36
    iget-object v4, p1, Lh0/k;->c:Lb0/y;

    .line 37
    .line 38
    invoke-virtual {v3, v4}, Lb0/y;->equals(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v3

    .line 42
    if-eqz v3, :cond_2

    .line 43
    .line 44
    iget v3, p0, Lh0/k;->d:I

    .line 45
    .line 46
    iget v4, p1, Lh0/k;->d:I

    .line 47
    .line 48
    if-ne v3, v4, :cond_2

    .line 49
    .line 50
    iget-object v3, p0, Lh0/k;->e:Landroid/util/Range;

    .line 51
    .line 52
    iget-object v4, p1, Lh0/k;->e:Landroid/util/Range;

    .line 53
    .line 54
    invoke-virtual {v3, v4}, Landroid/util/Range;->equals(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v3

    .line 58
    if-eqz v3, :cond_2

    .line 59
    .line 60
    iget-object v3, p0, Lh0/k;->f:Lh0/q0;

    .line 61
    .line 62
    if-nez v3, :cond_1

    .line 63
    .line 64
    if-nez v1, :cond_2

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_1
    invoke-virtual {v3, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-eqz v1, :cond_2

    .line 72
    .line 73
    :goto_0
    iget-boolean p0, p0, Lh0/k;->g:Z

    .line 74
    .line 75
    iget-boolean p1, p1, Lh0/k;->g:Z

    .line 76
    .line 77
    if-ne p0, p1, :cond_2

    .line 78
    .line 79
    return v0

    .line 80
    :cond_2
    return v2
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lh0/k;->a:Landroid/util/Size;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/util/Size;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const v1, 0xf4243

    .line 8
    .line 9
    .line 10
    xor-int/2addr v0, v1

    .line 11
    mul-int/2addr v0, v1

    .line 12
    iget-object v2, p0, Lh0/k;->b:Landroid/util/Size;

    .line 13
    .line 14
    invoke-virtual {v2}, Landroid/util/Size;->hashCode()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    xor-int/2addr v0, v2

    .line 19
    mul-int/2addr v0, v1

    .line 20
    iget-object v2, p0, Lh0/k;->c:Lb0/y;

    .line 21
    .line 22
    invoke-virtual {v2}, Lb0/y;->hashCode()I

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    xor-int/2addr v0, v2

    .line 27
    mul-int/2addr v0, v1

    .line 28
    iget v2, p0, Lh0/k;->d:I

    .line 29
    .line 30
    xor-int/2addr v0, v2

    .line 31
    mul-int/2addr v0, v1

    .line 32
    iget-object v2, p0, Lh0/k;->e:Landroid/util/Range;

    .line 33
    .line 34
    invoke-virtual {v2}, Landroid/util/Range;->hashCode()I

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    xor-int/2addr v0, v2

    .line 39
    mul-int/2addr v0, v1

    .line 40
    iget-object v2, p0, Lh0/k;->f:Lh0/q0;

    .line 41
    .line 42
    if-nez v2, :cond_0

    .line 43
    .line 44
    const/4 v2, 0x0

    .line 45
    goto :goto_0

    .line 46
    :cond_0
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    :goto_0
    xor-int/2addr v0, v2

    .line 51
    mul-int/2addr v0, v1

    .line 52
    iget-boolean p0, p0, Lh0/k;->g:Z

    .line 53
    .line 54
    if-eqz p0, :cond_1

    .line 55
    .line 56
    const/16 p0, 0x4cf

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_1
    const/16 p0, 0x4d5

    .line 60
    .line 61
    :goto_1
    xor-int/2addr p0, v0

    .line 62
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "StreamSpec{resolution="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lh0/k;->a:Landroid/util/Size;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", originalConfiguredResolution="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lh0/k;->b:Landroid/util/Size;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", dynamicRange="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lh0/k;->c:Lb0/y;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", sessionType="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget v1, p0, Lh0/k;->d:I

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", expectedFrameRateRange="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Lh0/k;->e:Landroid/util/Range;

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", implementationOptions="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object v1, p0, Lh0/k;->f:Lh0/q0;

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", zslDisabled="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget-boolean p0, p0, Lh0/k;->g:Z

    .line 69
    .line 70
    const-string v1, "}"

    .line 71
    .line 72
    invoke-static {v0, p0, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    return-object p0
.end method
