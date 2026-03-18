.class public final Lon0/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/String;

.field public final c:Ljava/lang/String;

.field public final d:Ljava/lang/String;

.field public final e:Ljava/net/URL;

.field public final f:Lon0/s;

.field public final g:Z

.field public final h:Ljava/lang/String;

.field public final i:Z


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/net/URL;Lon0/s;ZLjava/lang/String;Z)V
    .locals 1

    .line 1
    const-string v0, "id"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "providerName"

    .line 7
    .line 8
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "termsUrl"

    .line 12
    .line 13
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lon0/r;->a:Ljava/lang/String;

    .line 20
    .line 21
    iput-object p2, p0, Lon0/r;->b:Ljava/lang/String;

    .line 22
    .line 23
    iput-object p3, p0, Lon0/r;->c:Ljava/lang/String;

    .line 24
    .line 25
    iput-object p4, p0, Lon0/r;->d:Ljava/lang/String;

    .line 26
    .line 27
    iput-object p5, p0, Lon0/r;->e:Ljava/net/URL;

    .line 28
    .line 29
    iput-object p6, p0, Lon0/r;->f:Lon0/s;

    .line 30
    .line 31
    iput-boolean p7, p0, Lon0/r;->g:Z

    .line 32
    .line 33
    iput-object p8, p0, Lon0/r;->h:Ljava/lang/String;

    .line 34
    .line 35
    iput-boolean p9, p0, Lon0/r;->i:Z

    .line 36
    .line 37
    return-void
.end method

.method public static a(Lon0/r;Ljava/lang/String;I)Lon0/r;
    .locals 10

    .line 1
    iget-object v1, p0, Lon0/r;->a:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v2, p0, Lon0/r;->b:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v3, p0, Lon0/r;->c:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v4, p0, Lon0/r;->d:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v5, p0, Lon0/r;->e:Ljava/net/URL;

    .line 10
    .line 11
    iget-object v6, p0, Lon0/r;->f:Lon0/s;

    .line 12
    .line 13
    iget-boolean v7, p0, Lon0/r;->g:Z

    .line 14
    .line 15
    and-int/lit16 v0, p2, 0x80

    .line 16
    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    iget-object p1, p0, Lon0/r;->h:Ljava/lang/String;

    .line 20
    .line 21
    :cond_0
    move-object v8, p1

    .line 22
    and-int/lit16 p1, p2, 0x100

    .line 23
    .line 24
    if-eqz p1, :cond_1

    .line 25
    .line 26
    iget-boolean p1, p0, Lon0/r;->i:Z

    .line 27
    .line 28
    :goto_0
    move v9, p1

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    const/4 p1, 0x1

    .line 31
    goto :goto_0

    .line 32
    :goto_1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 33
    .line 34
    .line 35
    const-string p0, "id"

    .line 36
    .line 37
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    const-string p0, "providerName"

    .line 41
    .line 42
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    const-string p0, "termsUrl"

    .line 46
    .line 47
    invoke-static {v5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    new-instance v0, Lon0/r;

    .line 51
    .line 52
    invoke-direct/range {v0 .. v9}, Lon0/r;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/net/URL;Lon0/s;ZLjava/lang/String;Z)V

    .line 53
    .line 54
    .line 55
    return-object v0
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
    instance-of v1, p1, Lon0/r;

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
    check-cast p1, Lon0/r;

    .line 12
    .line 13
    iget-object v1, p0, Lon0/r;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lon0/r;->a:Ljava/lang/String;

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
    iget-object v1, p0, Lon0/r;->b:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lon0/r;->b:Ljava/lang/String;

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
    iget-object v1, p0, Lon0/r;->c:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v3, p1, Lon0/r;->c:Ljava/lang/String;

    .line 38
    .line 39
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-nez v1, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    iget-object v1, p0, Lon0/r;->d:Ljava/lang/String;

    .line 47
    .line 48
    iget-object v3, p1, Lon0/r;->d:Ljava/lang/String;

    .line 49
    .line 50
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-nez v1, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    iget-object v1, p0, Lon0/r;->e:Ljava/net/URL;

    .line 58
    .line 59
    iget-object v3, p1, Lon0/r;->e:Ljava/net/URL;

    .line 60
    .line 61
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-nez v1, :cond_6

    .line 66
    .line 67
    return v2

    .line 68
    :cond_6
    iget-object v1, p0, Lon0/r;->f:Lon0/s;

    .line 69
    .line 70
    iget-object v3, p1, Lon0/r;->f:Lon0/s;

    .line 71
    .line 72
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    if-nez v1, :cond_7

    .line 77
    .line 78
    return v2

    .line 79
    :cond_7
    iget-boolean v1, p0, Lon0/r;->g:Z

    .line 80
    .line 81
    iget-boolean v3, p1, Lon0/r;->g:Z

    .line 82
    .line 83
    if-eq v1, v3, :cond_8

    .line 84
    .line 85
    return v2

    .line 86
    :cond_8
    iget-object v1, p0, Lon0/r;->h:Ljava/lang/String;

    .line 87
    .line 88
    iget-object v3, p1, Lon0/r;->h:Ljava/lang/String;

    .line 89
    .line 90
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v1

    .line 94
    if-nez v1, :cond_9

    .line 95
    .line 96
    return v2

    .line 97
    :cond_9
    iget-boolean p0, p0, Lon0/r;->i:Z

    .line 98
    .line 99
    iget-boolean p1, p1, Lon0/r;->i:Z

    .line 100
    .line 101
    if-eq p0, p1, :cond_a

    .line 102
    .line 103
    return v2

    .line 104
    :cond_a
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lon0/r;->a:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

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
    iget-object v2, p0, Lon0/r;->b:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lon0/r;->c:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v2, p0, Lon0/r;->d:Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Lon0/r;->e:Ljava/net/URL;

    .line 29
    .line 30
    invoke-virtual {v2}, Ljava/net/URL;->hashCode()I

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    add-int/2addr v2, v0

    .line 35
    mul-int/2addr v2, v1

    .line 36
    const/4 v0, 0x0

    .line 37
    iget-object v3, p0, Lon0/r;->f:Lon0/s;

    .line 38
    .line 39
    if-nez v3, :cond_0

    .line 40
    .line 41
    move v3, v0

    .line 42
    goto :goto_0

    .line 43
    :cond_0
    invoke-virtual {v3}, Lon0/s;->hashCode()I

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    :goto_0
    add-int/2addr v2, v3

    .line 48
    mul-int/2addr v2, v1

    .line 49
    iget-boolean v3, p0, Lon0/r;->g:Z

    .line 50
    .line 51
    invoke-static {v2, v1, v3}, La7/g0;->e(IIZ)I

    .line 52
    .line 53
    .line 54
    move-result v2

    .line 55
    iget-object v3, p0, Lon0/r;->h:Ljava/lang/String;

    .line 56
    .line 57
    if-nez v3, :cond_1

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    :goto_1
    add-int/2addr v2, v0

    .line 65
    mul-int/2addr v2, v1

    .line 66
    iget-boolean p0, p0, Lon0/r;->i:Z

    .line 67
    .line 68
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    add-int/2addr p0, v2

    .line 73
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", name="

    .line 2
    .line 3
    const-string v1, ", formattedAddress="

    .line 4
    .line 5
    const-string v2, "ParkingPlace(id="

    .line 6
    .line 7
    iget-object v3, p0, Lon0/r;->a:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Lon0/r;->b:Ljava/lang/String;

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v4, v1}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", providerName="

    .line 16
    .line 17
    const-string v2, ", termsUrl="

    .line 18
    .line 19
    iget-object v3, p0, Lon0/r;->c:Ljava/lang/String;

    .line 20
    .line 21
    iget-object v4, p0, Lon0/r;->d:Ljava/lang/String;

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object v1, p0, Lon0/r;->e:Ljava/net/URL;

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v1, ", providerInfo="

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget-object v1, p0, Lon0/r;->f:Lon0/s;

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v1, ", isParkingZone="

    .line 42
    .line 43
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    const-string v1, ", selectedParkingSpaceOption="

    .line 47
    .line 48
    const-string v2, ", areaSpecificMessageAccepted="

    .line 49
    .line 50
    iget-object v3, p0, Lon0/r;->h:Ljava/lang/String;

    .line 51
    .line 52
    iget-boolean v4, p0, Lon0/r;->g:Z

    .line 53
    .line 54
    invoke-static {v1, v3, v2, v0, v4}, Lkx/a;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 55
    .line 56
    .line 57
    const-string v1, ")"

    .line 58
    .line 59
    iget-boolean p0, p0, Lon0/r;->i:Z

    .line 60
    .line 61
    invoke-static {v0, p0, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    return-object p0
.end method
