.class public final Lc80/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Ljava/util/List;

.field public final b:Z

.field public final c:Ljava/lang/String;

.field public final d:Z

.field public final e:Lql0/g;

.field public final f:Z

.field public final g:Z

.field public final h:Ljava/lang/String;

.field public final i:Ljava/lang/String;

.field public final j:Ljava/lang/String;

.field public final k:Z


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;I)V
    .locals 11

    and-int/lit8 v0, p2, 0x8

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    :goto_0
    move v5, v0

    goto :goto_1

    :cond_0
    const/4 v0, 0x0

    goto :goto_0

    :goto_1
    and-int/lit16 p2, p2, 0x200

    .line 1
    const-string v4, ""

    if-eqz p2, :cond_1

    move-object v10, v4

    goto :goto_2

    :cond_1
    move-object v10, p1

    :goto_2
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    const/4 v3, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    move-object v9, v4

    move-object v1, p0

    invoke-direct/range {v1 .. v10}, Lc80/r;-><init>(Ljava/util/List;ZLjava/lang/String;ZLql0/g;ZZLjava/lang/String;Ljava/lang/String;)V

    return-void
.end method

.method public constructor <init>(Ljava/util/List;ZLjava/lang/String;ZLql0/g;ZZLjava/lang/String;Ljava/lang/String;)V
    .locals 1

    const-string v0, "spinLockedTitle"

    invoke-static {p9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lc80/r;->a:Ljava/util/List;

    .line 4
    iput-boolean p2, p0, Lc80/r;->b:Z

    .line 5
    iput-object p3, p0, Lc80/r;->c:Ljava/lang/String;

    .line 6
    iput-boolean p4, p0, Lc80/r;->d:Z

    .line 7
    iput-object p5, p0, Lc80/r;->e:Lql0/g;

    .line 8
    iput-boolean p6, p0, Lc80/r;->f:Z

    .line 9
    iput-boolean p7, p0, Lc80/r;->g:Z

    .line 10
    iput-object p8, p0, Lc80/r;->h:Ljava/lang/String;

    .line 11
    iput-object p9, p0, Lc80/r;->i:Ljava/lang/String;

    if-nez p7, :cond_0

    goto :goto_0

    :cond_0
    move-object p8, p9

    .line 12
    :goto_0
    iput-object p8, p0, Lc80/r;->j:Ljava/lang/String;

    xor-int/lit8 p1, p7, 0x1

    .line 13
    iput-boolean p1, p0, Lc80/r;->k:Z

    return-void
.end method

.method public static a(Lc80/r;Ljava/util/List;ZLjava/lang/String;ZLql0/g;Ljava/lang/String;I)Lc80/r;
    .locals 10

    .line 1
    move/from16 v0, p7

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object p1, p0, Lc80/r;->a:Ljava/util/List;

    .line 8
    .line 9
    :cond_0
    move-object v1, p1

    .line 10
    and-int/lit8 p1, v0, 0x2

    .line 11
    .line 12
    if-eqz p1, :cond_1

    .line 13
    .line 14
    iget-boolean p2, p0, Lc80/r;->b:Z

    .line 15
    .line 16
    :cond_1
    move v2, p2

    .line 17
    and-int/lit8 p1, v0, 0x4

    .line 18
    .line 19
    if-eqz p1, :cond_2

    .line 20
    .line 21
    iget-object p1, p0, Lc80/r;->c:Ljava/lang/String;

    .line 22
    .line 23
    move-object v3, p1

    .line 24
    goto :goto_0

    .line 25
    :cond_2
    move-object v3, p3

    .line 26
    :goto_0
    and-int/lit8 p1, v0, 0x8

    .line 27
    .line 28
    if-eqz p1, :cond_3

    .line 29
    .line 30
    iget-boolean p1, p0, Lc80/r;->d:Z

    .line 31
    .line 32
    move v4, p1

    .line 33
    goto :goto_1

    .line 34
    :cond_3
    move v4, p4

    .line 35
    :goto_1
    and-int/lit8 p1, v0, 0x10

    .line 36
    .line 37
    if-eqz p1, :cond_4

    .line 38
    .line 39
    iget-object p1, p0, Lc80/r;->e:Lql0/g;

    .line 40
    .line 41
    move-object v5, p1

    .line 42
    goto :goto_2

    .line 43
    :cond_4
    move-object v5, p5

    .line 44
    :goto_2
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 45
    .line 46
    .line 47
    and-int/lit8 p1, v0, 0x40

    .line 48
    .line 49
    const/4 p2, 0x1

    .line 50
    if-eqz p1, :cond_5

    .line 51
    .line 52
    iget-boolean p1, p0, Lc80/r;->f:Z

    .line 53
    .line 54
    move v6, p1

    .line 55
    goto :goto_3

    .line 56
    :cond_5
    move v6, p2

    .line 57
    :goto_3
    and-int/lit16 p1, v0, 0x80

    .line 58
    .line 59
    if-eqz p1, :cond_6

    .line 60
    .line 61
    iget-boolean p2, p0, Lc80/r;->g:Z

    .line 62
    .line 63
    :cond_6
    move v7, p2

    .line 64
    and-int/lit16 p1, v0, 0x100

    .line 65
    .line 66
    if-eqz p1, :cond_7

    .line 67
    .line 68
    iget-object p1, p0, Lc80/r;->h:Ljava/lang/String;

    .line 69
    .line 70
    move-object v8, p1

    .line 71
    goto :goto_4

    .line 72
    :cond_7
    move-object/from16 v8, p6

    .line 73
    .line 74
    :goto_4
    iget-object v9, p0, Lc80/r;->i:Ljava/lang/String;

    .line 75
    .line 76
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 77
    .line 78
    .line 79
    const-string p0, "pins"

    .line 80
    .line 81
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    const-string p0, "spinErrorMessage"

    .line 85
    .line 86
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    const-string p0, "operationRequestTitle"

    .line 90
    .line 91
    invoke-static {v8, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    const-string p0, "spinLockedTitle"

    .line 95
    .line 96
    invoke-static {v9, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    new-instance v0, Lc80/r;

    .line 100
    .line 101
    invoke-direct/range {v0 .. v9}, Lc80/r;-><init>(Ljava/util/List;ZLjava/lang/String;ZLql0/g;ZZLjava/lang/String;Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    return-object v0
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_1

    .line 4
    :cond_0
    instance-of v0, p1, Lc80/r;

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_1
    check-cast p1, Lc80/r;

    .line 10
    .line 11
    iget-object v0, p0, Lc80/r;->a:Ljava/util/List;

    .line 12
    .line 13
    iget-object v1, p1, Lc80/r;->a:Ljava/util/List;

    .line 14
    .line 15
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

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
    iget-boolean v0, p0, Lc80/r;->b:Z

    .line 23
    .line 24
    iget-boolean v1, p1, Lc80/r;->b:Z

    .line 25
    .line 26
    if-eq v0, v1, :cond_3

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_3
    iget-object v0, p0, Lc80/r;->c:Ljava/lang/String;

    .line 30
    .line 31
    iget-object v1, p1, Lc80/r;->c:Ljava/lang/String;

    .line 32
    .line 33
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-nez v0, :cond_4

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_4
    iget-boolean v0, p0, Lc80/r;->d:Z

    .line 41
    .line 42
    iget-boolean v1, p1, Lc80/r;->d:Z

    .line 43
    .line 44
    if-eq v0, v1, :cond_5

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_5
    iget-object v0, p0, Lc80/r;->e:Lql0/g;

    .line 48
    .line 49
    iget-object v1, p1, Lc80/r;->e:Lql0/g;

    .line 50
    .line 51
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    if-nez v0, :cond_6

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_6
    iget-boolean v0, p0, Lc80/r;->f:Z

    .line 59
    .line 60
    iget-boolean v1, p1, Lc80/r;->f:Z

    .line 61
    .line 62
    if-eq v0, v1, :cond_7

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_7
    iget-boolean v0, p0, Lc80/r;->g:Z

    .line 66
    .line 67
    iget-boolean v1, p1, Lc80/r;->g:Z

    .line 68
    .line 69
    if-eq v0, v1, :cond_8

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_8
    iget-object v0, p0, Lc80/r;->h:Ljava/lang/String;

    .line 73
    .line 74
    iget-object v1, p1, Lc80/r;->h:Ljava/lang/String;

    .line 75
    .line 76
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    if-nez v0, :cond_9

    .line 81
    .line 82
    goto :goto_0

    .line 83
    :cond_9
    iget-object p0, p0, Lc80/r;->i:Ljava/lang/String;

    .line 84
    .line 85
    iget-object p1, p1, Lc80/r;->i:Ljava/lang/String;

    .line 86
    .line 87
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result p0

    .line 91
    if-nez p0, :cond_a

    .line 92
    .line 93
    :goto_0
    const/4 p0, 0x0

    .line 94
    return p0

    .line 95
    :cond_a
    :goto_1
    const/4 p0, 0x1

    .line 96
    return p0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lc80/r;->a:Ljava/util/List;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

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
    iget-boolean v2, p0, Lc80/r;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lc80/r;->c:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Lc80/r;->d:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    const/4 v2, 0x0

    .line 29
    iget-object v3, p0, Lc80/r;->e:Lql0/g;

    .line 30
    .line 31
    if-nez v3, :cond_0

    .line 32
    .line 33
    move v3, v2

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    invoke-virtual {v3}, Lql0/g;->hashCode()I

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    :goto_0
    add-int/2addr v0, v3

    .line 40
    mul-int/2addr v0, v1

    .line 41
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    iget-boolean v2, p0, Lc80/r;->f:Z

    .line 46
    .line 47
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    iget-boolean v2, p0, Lc80/r;->g:Z

    .line 52
    .line 53
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    iget-object v2, p0, Lc80/r;->h:Ljava/lang/String;

    .line 58
    .line 59
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    iget-object p0, p0, Lc80/r;->i:Ljava/lang/String;

    .line 64
    .line 65
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 66
    .line 67
    .line 68
    move-result p0

    .line 69
    add-int/2addr p0, v0

    .line 70
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "State(pins="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lc80/r;->a:Ljava/util/List;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", isProcessing="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-boolean v1, p0, Lc80/r;->b:Z

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", spinErrorMessage="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", isLoading="

    .line 29
    .line 30
    const-string v2, ", error="

    .line 31
    .line 32
    iget-object v3, p0, Lc80/r;->c:Ljava/lang/String;

    .line 33
    .line 34
    iget-boolean v4, p0, Lc80/r;->d:Z

    .line 35
    .line 36
    invoke-static {v3, v1, v2, v0, v4}, La7/g0;->t(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 37
    .line 38
    .line 39
    iget-object v1, p0, Lc80/r;->e:Lql0/g;

    .line 40
    .line 41
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string v1, ", isBiometricSpin=false, isSpinIncorrect="

    .line 45
    .line 46
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    iget-boolean v1, p0, Lc80/r;->f:Z

    .line 50
    .line 51
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const-string v1, ", isSpinLocked="

    .line 55
    .line 56
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    const-string v1, ", operationRequestTitle="

    .line 60
    .line 61
    const-string v2, ", spinLockedTitle="

    .line 62
    .line 63
    iget-object v3, p0, Lc80/r;->h:Ljava/lang/String;

    .line 64
    .line 65
    iget-boolean v4, p0, Lc80/r;->g:Z

    .line 66
    .line 67
    invoke-static {v1, v3, v2, v0, v4}, Lkx/a;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 68
    .line 69
    .line 70
    const-string v1, ")"

    .line 71
    .line 72
    iget-object p0, p0, Lc80/r;->i:Ljava/lang/String;

    .line 73
    .line 74
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    return-object p0
.end method
