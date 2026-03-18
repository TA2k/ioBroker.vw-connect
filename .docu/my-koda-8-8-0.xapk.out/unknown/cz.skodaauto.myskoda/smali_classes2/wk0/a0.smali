.class public final Lwk0/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Z

.field public final b:Z

.field public final c:Ljava/lang/String;

.field public final d:Ljava/lang/String;

.field public final e:Ljava/lang/String;

.field public final f:Z

.field public final g:Z


# direct methods
.method public synthetic constructor <init>(IZZ)V
    .locals 10

    and-int/lit8 v0, p1, 0x1

    const/4 v1, 0x1

    if-eqz v0, :cond_0

    move v3, v1

    goto :goto_0

    :cond_0
    move v3, p2

    :goto_0
    and-int/lit8 p2, p1, 0x2

    const/4 v0, 0x0

    if-eqz p2, :cond_1

    move v4, v0

    goto :goto_1

    :cond_1
    move v4, p3

    :goto_1
    and-int/lit8 p2, p1, 0x4

    .line 1
    const-string p3, ""

    if-eqz p2, :cond_2

    move-object v5, p3

    goto :goto_2

    :cond_2
    const-string p2, "McDonald\'s"

    move-object v5, p2

    :goto_2
    and-int/lit8 p2, p1, 0x8

    if-eqz p2, :cond_3

    :goto_3
    move-object v6, p3

    goto :goto_4

    :cond_3
    const-string p3, "Obchodna 6/323, Bratislava"

    goto :goto_3

    :goto_4
    and-int/lit8 p2, p1, 0x10

    if-eqz p2, :cond_4

    const/4 p2, 0x0

    :goto_5
    move-object v7, p2

    goto :goto_6

    :cond_4
    const-string p2, "54 km"

    goto :goto_5

    :goto_6
    and-int/lit8 p1, p1, 0x20

    if-eqz p1, :cond_5

    move v8, v0

    goto :goto_7

    :cond_5
    move v8, v1

    :goto_7
    const/4 v9, 0x0

    move-object v2, p0

    invoke-direct/range {v2 .. v9}, Lwk0/a0;-><init>(ZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)V

    return-void
.end method

.method public constructor <init>(ZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)V
    .locals 1

    const-string v0, "name"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "address"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-boolean p1, p0, Lwk0/a0;->a:Z

    .line 4
    iput-boolean p2, p0, Lwk0/a0;->b:Z

    .line 5
    iput-object p3, p0, Lwk0/a0;->c:Ljava/lang/String;

    .line 6
    iput-object p4, p0, Lwk0/a0;->d:Ljava/lang/String;

    .line 7
    iput-object p5, p0, Lwk0/a0;->e:Ljava/lang/String;

    .line 8
    iput-boolean p6, p0, Lwk0/a0;->f:Z

    .line 9
    iput-boolean p7, p0, Lwk0/a0;->g:Z

    return-void
.end method

.method public static a(Lwk0/a0;ZZZI)Lwk0/a0;
    .locals 8

    .line 1
    and-int/lit8 v0, p4, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-boolean p1, p0, Lwk0/a0;->a:Z

    .line 6
    .line 7
    :cond_0
    move v1, p1

    .line 8
    and-int/lit8 p1, p4, 0x2

    .line 9
    .line 10
    if-eqz p1, :cond_1

    .line 11
    .line 12
    iget-boolean p2, p0, Lwk0/a0;->b:Z

    .line 13
    .line 14
    :cond_1
    move v2, p2

    .line 15
    iget-object v3, p0, Lwk0/a0;->c:Ljava/lang/String;

    .line 16
    .line 17
    iget-object v4, p0, Lwk0/a0;->d:Ljava/lang/String;

    .line 18
    .line 19
    iget-object v5, p0, Lwk0/a0;->e:Ljava/lang/String;

    .line 20
    .line 21
    iget-boolean v6, p0, Lwk0/a0;->f:Z

    .line 22
    .line 23
    and-int/lit8 p1, p4, 0x40

    .line 24
    .line 25
    if-eqz p1, :cond_2

    .line 26
    .line 27
    iget-boolean p3, p0, Lwk0/a0;->g:Z

    .line 28
    .line 29
    :cond_2
    move v7, p3

    .line 30
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 31
    .line 32
    .line 33
    const-string p0, "name"

    .line 34
    .line 35
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    const-string p0, "address"

    .line 39
    .line 40
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    new-instance v0, Lwk0/a0;

    .line 44
    .line 45
    invoke-direct/range {v0 .. v7}, Lwk0/a0;-><init>(ZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)V

    .line 46
    .line 47
    .line 48
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
    instance-of v1, p1, Lwk0/a0;

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
    check-cast p1, Lwk0/a0;

    .line 12
    .line 13
    iget-boolean v1, p0, Lwk0/a0;->a:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Lwk0/a0;->a:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Lwk0/a0;->b:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Lwk0/a0;->b:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-object v1, p0, Lwk0/a0;->c:Ljava/lang/String;

    .line 28
    .line 29
    iget-object v3, p1, Lwk0/a0;->c:Ljava/lang/String;

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
    iget-object v1, p0, Lwk0/a0;->d:Ljava/lang/String;

    .line 39
    .line 40
    iget-object v3, p1, Lwk0/a0;->d:Ljava/lang/String;

    .line 41
    .line 42
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    if-nez v1, :cond_5

    .line 47
    .line 48
    return v2

    .line 49
    :cond_5
    iget-object v1, p0, Lwk0/a0;->e:Ljava/lang/String;

    .line 50
    .line 51
    iget-object v3, p1, Lwk0/a0;->e:Ljava/lang/String;

    .line 52
    .line 53
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    if-nez v1, :cond_6

    .line 58
    .line 59
    return v2

    .line 60
    :cond_6
    iget-boolean v1, p0, Lwk0/a0;->f:Z

    .line 61
    .line 62
    iget-boolean v3, p1, Lwk0/a0;->f:Z

    .line 63
    .line 64
    if-eq v1, v3, :cond_7

    .line 65
    .line 66
    return v2

    .line 67
    :cond_7
    iget-boolean p0, p0, Lwk0/a0;->g:Z

    .line 68
    .line 69
    iget-boolean p1, p1, Lwk0/a0;->g:Z

    .line 70
    .line 71
    if-eq p0, p1, :cond_8

    .line 72
    .line 73
    return v2

    .line 74
    :cond_8
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-boolean v0, p0, Lwk0/a0;->a:Z

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Boolean;->hashCode(Z)I

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
    iget-boolean v2, p0, Lwk0/a0;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lwk0/a0;->c:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v2, p0, Lwk0/a0;->d:Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Lwk0/a0;->e:Ljava/lang/String;

    .line 29
    .line 30
    if-nez v2, :cond_0

    .line 31
    .line 32
    const/4 v2, 0x0

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    :goto_0
    add-int/2addr v0, v2

    .line 39
    mul-int/2addr v0, v1

    .line 40
    iget-boolean v2, p0, Lwk0/a0;->f:Z

    .line 41
    .line 42
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-boolean p0, p0, Lwk0/a0;->g:Z

    .line 47
    .line 48
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    add-int/2addr p0, v0

    .line 53
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", isError="

    .line 2
    .line 3
    const-string v1, ", name="

    .line 4
    .line 5
    const-string v2, "State(isLoading="

    .line 6
    .line 7
    iget-boolean v3, p0, Lwk0/a0;->a:Z

    .line 8
    .line 9
    iget-boolean v4, p0, Lwk0/a0;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v0, v1, v3, v4}, Lvj/b;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", address="

    .line 16
    .line 17
    const-string v2, ", distance="

    .line 18
    .line 19
    iget-object v3, p0, Lwk0/a0;->c:Ljava/lang/String;

    .line 20
    .line 21
    iget-object v4, p0, Lwk0/a0;->d:Ljava/lang/String;

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v1, ", isMyServiceVisible="

    .line 27
    .line 28
    const-string v2, ", isRefreshing="

    .line 29
    .line 30
    iget-object v3, p0, Lwk0/a0;->e:Ljava/lang/String;

    .line 31
    .line 32
    iget-boolean v4, p0, Lwk0/a0;->f:Z

    .line 33
    .line 34
    invoke-static {v3, v1, v2, v0, v4}, La7/g0;->t(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 35
    .line 36
    .line 37
    const-string v1, ")"

    .line 38
    .line 39
    iget-boolean p0, p0, Lwk0/a0;->g:Z

    .line 40
    .line 41
    invoke-static {v0, p0, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0
.end method
