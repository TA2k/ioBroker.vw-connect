.class public final Ljh/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/String;

.field public final c:Z

.field public final d:Z

.field public final e:Z

.field public final f:Z

.field public final g:Z

.field public final h:Z

.field public final i:Ljh/a;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;ZZZZZZLjh/a;)V
    .locals 1

    .line 1
    const-string v0, "currentVersion"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Ljh/h;->a:Ljava/lang/String;

    .line 10
    .line 11
    iput-object p2, p0, Ljh/h;->b:Ljava/lang/String;

    .line 12
    .line 13
    iput-boolean p3, p0, Ljh/h;->c:Z

    .line 14
    .line 15
    iput-boolean p4, p0, Ljh/h;->d:Z

    .line 16
    .line 17
    iput-boolean p5, p0, Ljh/h;->e:Z

    .line 18
    .line 19
    iput-boolean p6, p0, Ljh/h;->f:Z

    .line 20
    .line 21
    iput-boolean p7, p0, Ljh/h;->g:Z

    .line 22
    .line 23
    iput-boolean p8, p0, Ljh/h;->h:Z

    .line 24
    .line 25
    iput-object p9, p0, Ljh/h;->i:Ljh/a;

    .line 26
    .line 27
    return-void
.end method

.method public static a(Ljh/h;ZI)Ljh/h;
    .locals 11

    .line 1
    sget-object v0, Ljh/a;->d:Ljh/a;

    .line 2
    .line 3
    iget-object v2, p0, Ljh/h;->a:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v3, p0, Ljh/h;->b:Ljava/lang/String;

    .line 6
    .line 7
    iget-boolean v4, p0, Ljh/h;->c:Z

    .line 8
    .line 9
    and-int/lit8 v1, p2, 0x8

    .line 10
    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    iget-boolean v1, p0, Ljh/h;->d:Z

    .line 14
    .line 15
    :goto_0
    move v5, v1

    .line 16
    goto :goto_1

    .line 17
    :cond_0
    const/4 v1, 0x1

    .line 18
    goto :goto_0

    .line 19
    :goto_1
    and-int/lit8 v1, p2, 0x10

    .line 20
    .line 21
    const/4 v6, 0x0

    .line 22
    if-eqz v1, :cond_1

    .line 23
    .line 24
    iget-boolean v1, p0, Ljh/h;->e:Z

    .line 25
    .line 26
    goto :goto_2

    .line 27
    :cond_1
    move v1, v6

    .line 28
    :goto_2
    iget-boolean v7, p0, Ljh/h;->f:Z

    .line 29
    .line 30
    and-int/lit8 v8, p2, 0x40

    .line 31
    .line 32
    if-eqz v8, :cond_2

    .line 33
    .line 34
    iget-boolean v6, p0, Ljh/h;->g:Z

    .line 35
    .line 36
    :cond_2
    move v8, v6

    .line 37
    and-int/lit16 v6, p2, 0x80

    .line 38
    .line 39
    if-eqz v6, :cond_3

    .line 40
    .line 41
    iget-boolean p1, p0, Ljh/h;->h:Z

    .line 42
    .line 43
    :cond_3
    move v9, p1

    .line 44
    and-int/lit16 p1, p2, 0x100

    .line 45
    .line 46
    if-eqz p1, :cond_4

    .line 47
    .line 48
    iget-object v0, p0, Ljh/h;->i:Ljh/a;

    .line 49
    .line 50
    :cond_4
    move-object v10, v0

    .line 51
    const-string p0, "currentVersion"

    .line 52
    .line 53
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    move v6, v1

    .line 57
    new-instance v1, Ljh/h;

    .line 58
    .line 59
    invoke-direct/range {v1 .. v10}, Ljh/h;-><init>(Ljava/lang/String;Ljava/lang/String;ZZZZZZLjh/a;)V

    .line 60
    .line 61
    .line 62
    return-object v1
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
    instance-of v1, p1, Ljh/h;

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
    check-cast p1, Ljh/h;

    .line 12
    .line 13
    iget-object v1, p0, Ljh/h;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Ljh/h;->a:Ljava/lang/String;

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
    iget-object v1, p0, Ljh/h;->b:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Ljh/h;->b:Ljava/lang/String;

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
    iget-boolean v1, p0, Ljh/h;->c:Z

    .line 36
    .line 37
    iget-boolean v3, p1, Ljh/h;->c:Z

    .line 38
    .line 39
    if-eq v1, v3, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-boolean v1, p0, Ljh/h;->d:Z

    .line 43
    .line 44
    iget-boolean v3, p1, Ljh/h;->d:Z

    .line 45
    .line 46
    if-eq v1, v3, :cond_5

    .line 47
    .line 48
    return v2

    .line 49
    :cond_5
    iget-boolean v1, p0, Ljh/h;->e:Z

    .line 50
    .line 51
    iget-boolean v3, p1, Ljh/h;->e:Z

    .line 52
    .line 53
    if-eq v1, v3, :cond_6

    .line 54
    .line 55
    return v2

    .line 56
    :cond_6
    iget-boolean v1, p0, Ljh/h;->f:Z

    .line 57
    .line 58
    iget-boolean v3, p1, Ljh/h;->f:Z

    .line 59
    .line 60
    if-eq v1, v3, :cond_7

    .line 61
    .line 62
    return v2

    .line 63
    :cond_7
    iget-boolean v1, p0, Ljh/h;->g:Z

    .line 64
    .line 65
    iget-boolean v3, p1, Ljh/h;->g:Z

    .line 66
    .line 67
    if-eq v1, v3, :cond_8

    .line 68
    .line 69
    return v2

    .line 70
    :cond_8
    iget-boolean v1, p0, Ljh/h;->h:Z

    .line 71
    .line 72
    iget-boolean v3, p1, Ljh/h;->h:Z

    .line 73
    .line 74
    if-eq v1, v3, :cond_9

    .line 75
    .line 76
    return v2

    .line 77
    :cond_9
    iget-object p0, p0, Ljh/h;->i:Ljh/a;

    .line 78
    .line 79
    iget-object p1, p1, Ljh/h;->i:Ljh/a;

    .line 80
    .line 81
    if-eq p0, p1, :cond_a

    .line 82
    .line 83
    return v2

    .line 84
    :cond_a
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Ljh/h;->a:Ljava/lang/String;

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
    iget-object v2, p0, Ljh/h;->b:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Ljh/h;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Ljh/h;->d:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-boolean v2, p0, Ljh/h;->e:Z

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-boolean v2, p0, Ljh/h;->f:Z

    .line 35
    .line 36
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget-boolean v2, p0, Ljh/h;->g:Z

    .line 41
    .line 42
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-boolean v2, p0, Ljh/h;->h:Z

    .line 47
    .line 48
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget-object p0, p0, Ljh/h;->i:Ljh/a;

    .line 53
    .line 54
    if-nez p0, :cond_0

    .line 55
    .line 56
    const/4 p0, 0x0

    .line 57
    goto :goto_0

    .line 58
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 59
    .line 60
    .line 61
    move-result p0

    .line 62
    :goto_0
    add-int/2addr v0, p0

    .line 63
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", newVersion="

    .line 2
    .line 3
    const-string v1, ", hasUpdate="

    .line 4
    .line 5
    const-string v2, "WallboxFirmwareUiState(currentVersion="

    .line 6
    .line 7
    iget-object v3, p0, Ljh/h;->a:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Ljh/h;->b:Ljava/lang/String;

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v4, v1}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", showLoading="

    .line 16
    .line 17
    const-string v2, ", showUpdateBadge="

    .line 18
    .line 19
    iget-boolean v3, p0, Ljh/h;->c:Z

    .line 20
    .line 21
    iget-boolean v4, p0, Ljh/h;->d:Z

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v1, ", showInternetDisclaimer="

    .line 27
    .line 28
    const-string v2, ", isStartUpdateCtaEnabled="

    .line 29
    .line 30
    iget-boolean v3, p0, Ljh/h;->e:Z

    .line 31
    .line 32
    iget-boolean v4, p0, Ljh/h;->f:Z

    .line 33
    .line 34
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 35
    .line 36
    .line 37
    const-string v1, ", automaticUpdatesEnabled="

    .line 38
    .line 39
    const-string v2, ", automaticUpdatesStatus="

    .line 40
    .line 41
    iget-boolean v3, p0, Ljh/h;->g:Z

    .line 42
    .line 43
    iget-boolean v4, p0, Ljh/h;->h:Z

    .line 44
    .line 45
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 46
    .line 47
    .line 48
    iget-object p0, p0, Ljh/h;->i:Ljh/a;

    .line 49
    .line 50
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string p0, ")"

    .line 54
    .line 55
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    return-object p0
.end method
