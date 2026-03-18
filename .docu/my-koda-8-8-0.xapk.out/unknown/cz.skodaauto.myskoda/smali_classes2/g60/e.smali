.class public final Lg60/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Z

.field public final b:Z

.field public final c:Z

.field public final d:Lg60/c;

.field public final e:Z

.field public final f:Lg60/d;

.field public final g:Lql0/g;

.field public final h:Z

.field public final i:Z


# direct methods
.method public synthetic constructor <init>(Lg60/c;ZLg60/d;I)V
    .locals 14

    move/from16 v0, p4

    and-int/lit8 v1, v0, 0x1

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-eqz v1, :cond_0

    move v5, v3

    goto :goto_0

    :cond_0
    move v5, v2

    :goto_0
    and-int/lit8 v1, v0, 0x2

    if-eqz v1, :cond_1

    move v6, v2

    goto :goto_1

    :cond_1
    move v6, v3

    :goto_1
    and-int/lit8 v1, v0, 0x4

    if-eqz v1, :cond_2

    move v7, v2

    goto :goto_2

    :cond_2
    move v7, v3

    :goto_2
    and-int/lit8 v1, v0, 0x8

    const/16 v4, 0xf

    if-eqz v1, :cond_3

    .line 11
    new-instance p1, Lg60/c;

    invoke-direct {p1, v4, v2, v2, v2}, Lg60/c;-><init>(IZZZ)V

    :cond_3
    move-object v8, p1

    and-int/lit8 p1, v0, 0x10

    if-eqz p1, :cond_4

    move v9, v2

    goto :goto_3

    :cond_4
    move/from16 v9, p2

    :goto_3
    and-int/lit8 p1, v0, 0x20

    if-eqz p1, :cond_5

    .line 12
    new-instance p1, Lg60/d;

    invoke-direct {p1, v4}, Lg60/d;-><init>(I)V

    move-object v10, p1

    goto :goto_4

    :cond_5
    move-object/from16 v10, p3

    :goto_4
    and-int/lit16 p1, v0, 0x80

    if-eqz p1, :cond_6

    move v12, v2

    goto :goto_5

    :cond_6
    move v12, v3

    :goto_5
    const/4 v13, 0x0

    const/4 v11, 0x0

    move-object v4, p0

    .line 13
    invoke-direct/range {v4 .. v13}, Lg60/e;-><init>(ZZZLg60/c;ZLg60/d;Lql0/g;ZZ)V

    return-void
.end method

.method public constructor <init>(ZZZLg60/c;ZLg60/d;Lql0/g;ZZ)V
    .locals 1

    const-string v0, "honkAndFlash"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "shareVehicleLocation"

    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-boolean p1, p0, Lg60/e;->a:Z

    .line 3
    iput-boolean p2, p0, Lg60/e;->b:Z

    .line 4
    iput-boolean p3, p0, Lg60/e;->c:Z

    .line 5
    iput-object p4, p0, Lg60/e;->d:Lg60/c;

    .line 6
    iput-boolean p5, p0, Lg60/e;->e:Z

    .line 7
    iput-object p6, p0, Lg60/e;->f:Lg60/d;

    .line 8
    iput-object p7, p0, Lg60/e;->g:Lql0/g;

    .line 9
    iput-boolean p8, p0, Lg60/e;->h:Z

    .line 10
    iput-boolean p9, p0, Lg60/e;->i:Z

    return-void
.end method

.method public static a(Lg60/e;ZZLg60/c;ZLg60/d;Lql0/g;ZZI)Lg60/e;
    .locals 2

    .line 1
    and-int/lit8 v0, p9, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-boolean v0, p0, Lg60/e;->a:Z

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    const/4 v0, 0x0

    .line 9
    :goto_0
    and-int/lit8 v1, p9, 0x2

    .line 10
    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    iget-boolean p1, p0, Lg60/e;->b:Z

    .line 14
    .line 15
    :cond_1
    and-int/lit8 v1, p9, 0x4

    .line 16
    .line 17
    if-eqz v1, :cond_2

    .line 18
    .line 19
    iget-boolean p2, p0, Lg60/e;->c:Z

    .line 20
    .line 21
    :cond_2
    and-int/lit8 v1, p9, 0x8

    .line 22
    .line 23
    if-eqz v1, :cond_3

    .line 24
    .line 25
    iget-object p3, p0, Lg60/e;->d:Lg60/c;

    .line 26
    .line 27
    :cond_3
    and-int/lit8 v1, p9, 0x10

    .line 28
    .line 29
    if-eqz v1, :cond_4

    .line 30
    .line 31
    iget-boolean p4, p0, Lg60/e;->e:Z

    .line 32
    .line 33
    :cond_4
    and-int/lit8 v1, p9, 0x20

    .line 34
    .line 35
    if-eqz v1, :cond_5

    .line 36
    .line 37
    iget-object p5, p0, Lg60/e;->f:Lg60/d;

    .line 38
    .line 39
    :cond_5
    and-int/lit8 v1, p9, 0x40

    .line 40
    .line 41
    if-eqz v1, :cond_6

    .line 42
    .line 43
    iget-object p6, p0, Lg60/e;->g:Lql0/g;

    .line 44
    .line 45
    :cond_6
    and-int/lit16 v1, p9, 0x80

    .line 46
    .line 47
    if-eqz v1, :cond_7

    .line 48
    .line 49
    iget-boolean p7, p0, Lg60/e;->h:Z

    .line 50
    .line 51
    :cond_7
    and-int/lit16 p9, p9, 0x100

    .line 52
    .line 53
    if-eqz p9, :cond_8

    .line 54
    .line 55
    iget-boolean p8, p0, Lg60/e;->i:Z

    .line 56
    .line 57
    :cond_8
    move p9, p8

    .line 58
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 59
    .line 60
    .line 61
    const-string p0, "honkAndFlash"

    .line 62
    .line 63
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    const-string p0, "shareVehicleLocation"

    .line 67
    .line 68
    invoke-static {p5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    new-instance p0, Lg60/e;

    .line 72
    .line 73
    move p8, p7

    .line 74
    move-object p7, p6

    .line 75
    move-object p6, p5

    .line 76
    move p5, p4

    .line 77
    move-object p4, p3

    .line 78
    move p3, p2

    .line 79
    move p2, p1

    .line 80
    move p1, v0

    .line 81
    invoke-direct/range {p0 .. p9}, Lg60/e;-><init>(ZZZLg60/c;ZLg60/d;Lql0/g;ZZ)V

    .line 82
    .line 83
    .line 84
    return-object p0
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
    instance-of v1, p1, Lg60/e;

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
    check-cast p1, Lg60/e;

    .line 12
    .line 13
    iget-boolean v1, p0, Lg60/e;->a:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Lg60/e;->a:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Lg60/e;->b:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Lg60/e;->b:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-boolean v1, p0, Lg60/e;->c:Z

    .line 28
    .line 29
    iget-boolean v3, p1, Lg60/e;->c:Z

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-object v1, p0, Lg60/e;->d:Lg60/c;

    .line 35
    .line 36
    iget-object v3, p1, Lg60/e;->d:Lg60/c;

    .line 37
    .line 38
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-nez v1, :cond_5

    .line 43
    .line 44
    return v2

    .line 45
    :cond_5
    iget-boolean v1, p0, Lg60/e;->e:Z

    .line 46
    .line 47
    iget-boolean v3, p1, Lg60/e;->e:Z

    .line 48
    .line 49
    if-eq v1, v3, :cond_6

    .line 50
    .line 51
    return v2

    .line 52
    :cond_6
    iget-object v1, p0, Lg60/e;->f:Lg60/d;

    .line 53
    .line 54
    iget-object v3, p1, Lg60/e;->f:Lg60/d;

    .line 55
    .line 56
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    if-nez v1, :cond_7

    .line 61
    .line 62
    return v2

    .line 63
    :cond_7
    iget-object v1, p0, Lg60/e;->g:Lql0/g;

    .line 64
    .line 65
    iget-object v3, p1, Lg60/e;->g:Lql0/g;

    .line 66
    .line 67
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-nez v1, :cond_8

    .line 72
    .line 73
    return v2

    .line 74
    :cond_8
    iget-boolean v1, p0, Lg60/e;->h:Z

    .line 75
    .line 76
    iget-boolean v3, p1, Lg60/e;->h:Z

    .line 77
    .line 78
    if-eq v1, v3, :cond_9

    .line 79
    .line 80
    return v2

    .line 81
    :cond_9
    iget-boolean p0, p0, Lg60/e;->i:Z

    .line 82
    .line 83
    iget-boolean p1, p1, Lg60/e;->i:Z

    .line 84
    .line 85
    if-eq p0, p1, :cond_a

    .line 86
    .line 87
    return v2

    .line 88
    :cond_a
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-boolean v0, p0, Lg60/e;->a:Z

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
    iget-boolean v2, p0, Lg60/e;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Lg60/e;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v2, p0, Lg60/e;->d:Lg60/c;

    .line 23
    .line 24
    invoke-virtual {v2}, Lg60/c;->hashCode()I

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    add-int/2addr v2, v0

    .line 29
    mul-int/2addr v2, v1

    .line 30
    iget-boolean v0, p0, Lg60/e;->e:Z

    .line 31
    .line 32
    invoke-static {v2, v1, v0}, La7/g0;->e(IIZ)I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    iget-object v2, p0, Lg60/e;->f:Lg60/d;

    .line 37
    .line 38
    invoke-virtual {v2}, Lg60/d;->hashCode()I

    .line 39
    .line 40
    .line 41
    move-result v2

    .line 42
    add-int/2addr v2, v0

    .line 43
    mul-int/2addr v2, v1

    .line 44
    iget-object v0, p0, Lg60/e;->g:Lql0/g;

    .line 45
    .line 46
    if-nez v0, :cond_0

    .line 47
    .line 48
    const/4 v0, 0x0

    .line 49
    goto :goto_0

    .line 50
    :cond_0
    invoke-virtual {v0}, Lql0/g;->hashCode()I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    :goto_0
    add-int/2addr v2, v0

    .line 55
    mul-int/2addr v2, v1

    .line 56
    iget-boolean v0, p0, Lg60/e;->h:Z

    .line 57
    .line 58
    invoke-static {v2, v1, v0}, La7/g0;->e(IIZ)I

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    iget-boolean p0, p0, Lg60/e;->i:Z

    .line 63
    .line 64
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    add-int/2addr p0, v0

    .line 69
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", isWorkshopModeActive="

    .line 2
    .line 3
    const-string v1, ", isMissingLicense="

    .line 4
    .line 5
    const-string v2, "State(isLoading="

    .line 6
    .line 7
    iget-boolean v3, p0, Lg60/e;->a:Z

    .line 8
    .line 9
    iget-boolean v4, p0, Lg60/e;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v0, v1, v3, v4}, Lvj/b;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iget-boolean v1, p0, Lg60/e;->c:Z

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const-string v1, ", honkAndFlash="

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    iget-object v1, p0, Lg60/e;->d:Lg60/c;

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v1, ", isParkingSessionActive="

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    iget-boolean v1, p0, Lg60/e;->e:Z

    .line 36
    .line 37
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    const-string v1, ", shareVehicleLocation="

    .line 41
    .line 42
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    iget-object v1, p0, Lg60/e;->f:Lg60/d;

    .line 46
    .line 47
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string v1, ", error="

    .line 51
    .line 52
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    iget-object v1, p0, Lg60/e;->g:Lql0/g;

    .line 56
    .line 57
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    const-string v1, ", isCatNavAvailable="

    .line 61
    .line 62
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    iget-boolean v1, p0, Lg60/e;->h:Z

    .line 66
    .line 67
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    const-string v1, ", isDialogLoading="

    .line 71
    .line 72
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    const-string v1, ")"

    .line 76
    .line 77
    iget-boolean p0, p0, Lg60/e;->i:Z

    .line 78
    .line 79
    invoke-static {v0, p0, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    return-object p0
.end method
