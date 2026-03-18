.class public final Ls10/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# static fields
.field public static final i:I

.field public static final j:I

.field public static final k:Lgy0/e;


# instance fields
.field public final a:Lql0/g;

.field public final b:Ljava/lang/String;

.field public final c:I

.field public final d:Ljava/lang/String;

.field public final e:I

.field public final f:Z

.field public final g:Z

.field public final h:Z


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    sget-object v0, Lr10/a;->f:Lgy0/j;

    .line 2
    .line 3
    iget v1, v0, Lgy0/h;->d:I

    .line 4
    .line 5
    sput v1, Ls10/b;->i:I

    .line 6
    .line 7
    iget v0, v0, Lgy0/h;->e:I

    .line 8
    .line 9
    sput v0, Ls10/b;->j:I

    .line 10
    .line 11
    int-to-float v1, v1

    .line 12
    int-to-float v0, v0

    .line 13
    new-instance v2, Lgy0/e;

    .line 14
    .line 15
    invoke-direct {v2, v1, v0}, Lgy0/e;-><init>(FF)V

    .line 16
    .line 17
    .line 18
    sput-object v2, Ls10/b;->k:Lgy0/e;

    .line 19
    .line 20
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 11

    and-int/lit8 v0, p1, 0x2

    .line 1
    const-string v1, ""

    if-eqz v0, :cond_0

    move-object v4, v1

    goto :goto_0

    :cond_0
    const-string v0, "22"

    move-object v4, v0

    :goto_0
    and-int/lit8 v0, p1, 0x8

    if-eqz v0, :cond_1

    :goto_1
    move-object v6, v1

    goto :goto_2

    :cond_1
    const-string v1, "30%"

    goto :goto_1

    :goto_2
    and-int/lit8 p1, p1, 0x10

    if-eqz p1, :cond_2

    const/4 p1, 0x0

    :goto_3
    move v7, p1

    goto :goto_4

    :cond_2
    const/16 p1, 0x1e

    goto :goto_3

    :goto_4
    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v3, 0x0

    const/4 v5, 0x0

    const/4 v8, 0x0

    move-object v2, p0

    invoke-direct/range {v2 .. v10}, Ls10/b;-><init>(Lql0/g;Ljava/lang/String;ILjava/lang/String;IZZZ)V

    return-void
.end method

.method public constructor <init>(Lql0/g;Ljava/lang/String;ILjava/lang/String;IZZZ)V
    .locals 1

    const-string v0, "targetTemperature"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "minChargeLevelText"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Ls10/b;->a:Lql0/g;

    .line 4
    iput-object p2, p0, Ls10/b;->b:Ljava/lang/String;

    .line 5
    iput p3, p0, Ls10/b;->c:I

    .line 6
    iput-object p4, p0, Ls10/b;->d:Ljava/lang/String;

    .line 7
    iput p5, p0, Ls10/b;->e:I

    .line 8
    iput-boolean p6, p0, Ls10/b;->f:Z

    .line 9
    iput-boolean p7, p0, Ls10/b;->g:Z

    .line 10
    iput-boolean p8, p0, Ls10/b;->h:Z

    return-void
.end method

.method public static a(Ls10/b;Lql0/g;Ljava/lang/String;ILjava/lang/String;IZZI)Ls10/b;
    .locals 9

    .line 1
    move/from16 v0, p8

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object p1, p0, Ls10/b;->a:Lql0/g;

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
    iget-object p2, p0, Ls10/b;->b:Ljava/lang/String;

    .line 15
    .line 16
    :cond_1
    move-object v2, p2

    .line 17
    and-int/lit8 p1, v0, 0x4

    .line 18
    .line 19
    if-eqz p1, :cond_2

    .line 20
    .line 21
    iget p3, p0, Ls10/b;->c:I

    .line 22
    .line 23
    :cond_2
    move v3, p3

    .line 24
    and-int/lit8 p1, v0, 0x8

    .line 25
    .line 26
    if-eqz p1, :cond_3

    .line 27
    .line 28
    iget-object p4, p0, Ls10/b;->d:Ljava/lang/String;

    .line 29
    .line 30
    :cond_3
    move-object v4, p4

    .line 31
    and-int/lit8 p1, v0, 0x10

    .line 32
    .line 33
    if-eqz p1, :cond_4

    .line 34
    .line 35
    iget p5, p0, Ls10/b;->e:I

    .line 36
    .line 37
    :cond_4
    move v5, p5

    .line 38
    and-int/lit8 p1, v0, 0x20

    .line 39
    .line 40
    if-eqz p1, :cond_5

    .line 41
    .line 42
    iget-boolean p6, p0, Ls10/b;->f:Z

    .line 43
    .line 44
    :cond_5
    move v6, p6

    .line 45
    and-int/lit8 p1, v0, 0x40

    .line 46
    .line 47
    if-eqz p1, :cond_6

    .line 48
    .line 49
    iget-boolean p1, p0, Ls10/b;->g:Z

    .line 50
    .line 51
    :goto_0
    move v7, p1

    .line 52
    goto :goto_1

    .line 53
    :cond_6
    const/4 p1, 0x1

    .line 54
    goto :goto_0

    .line 55
    :goto_1
    and-int/lit16 p1, v0, 0x80

    .line 56
    .line 57
    if-eqz p1, :cond_7

    .line 58
    .line 59
    iget-boolean p1, p0, Ls10/b;->h:Z

    .line 60
    .line 61
    move v8, p1

    .line 62
    goto :goto_2

    .line 63
    :cond_7
    move/from16 v8, p7

    .line 64
    .line 65
    :goto_2
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 66
    .line 67
    .line 68
    const-string p0, "targetTemperature"

    .line 69
    .line 70
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    const-string p0, "minChargeLevelText"

    .line 74
    .line 75
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    new-instance v0, Ls10/b;

    .line 79
    .line 80
    invoke-direct/range {v0 .. v8}, Ls10/b;-><init>(Lql0/g;Ljava/lang/String;ILjava/lang/String;IZZZ)V

    .line 81
    .line 82
    .line 83
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
    instance-of v1, p1, Ls10/b;

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
    check-cast p1, Ls10/b;

    .line 12
    .line 13
    iget-object v1, p0, Ls10/b;->a:Lql0/g;

    .line 14
    .line 15
    iget-object v3, p1, Ls10/b;->a:Lql0/g;

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
    iget-object v1, p0, Ls10/b;->b:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Ls10/b;->b:Ljava/lang/String;

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
    iget v1, p0, Ls10/b;->c:I

    .line 36
    .line 37
    iget v3, p1, Ls10/b;->c:I

    .line 38
    .line 39
    if-eq v1, v3, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object v1, p0, Ls10/b;->d:Ljava/lang/String;

    .line 43
    .line 44
    iget-object v3, p1, Ls10/b;->d:Ljava/lang/String;

    .line 45
    .line 46
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-nez v1, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget v1, p0, Ls10/b;->e:I

    .line 54
    .line 55
    iget v3, p1, Ls10/b;->e:I

    .line 56
    .line 57
    if-eq v1, v3, :cond_6

    .line 58
    .line 59
    return v2

    .line 60
    :cond_6
    iget-boolean v1, p0, Ls10/b;->f:Z

    .line 61
    .line 62
    iget-boolean v3, p1, Ls10/b;->f:Z

    .line 63
    .line 64
    if-eq v1, v3, :cond_7

    .line 65
    .line 66
    return v2

    .line 67
    :cond_7
    iget-boolean v1, p0, Ls10/b;->g:Z

    .line 68
    .line 69
    iget-boolean v3, p1, Ls10/b;->g:Z

    .line 70
    .line 71
    if-eq v1, v3, :cond_8

    .line 72
    .line 73
    return v2

    .line 74
    :cond_8
    iget-boolean p0, p0, Ls10/b;->h:Z

    .line 75
    .line 76
    iget-boolean p1, p1, Ls10/b;->h:Z

    .line 77
    .line 78
    if-eq p0, p1, :cond_9

    .line 79
    .line 80
    return v2

    .line 81
    :cond_9
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Ls10/b;->a:Lql0/g;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    invoke-virtual {v0}, Lql0/g;->hashCode()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    :goto_0
    const/16 v1, 0x1f

    .line 12
    .line 13
    mul-int/2addr v0, v1

    .line 14
    iget-object v2, p0, Ls10/b;->b:Ljava/lang/String;

    .line 15
    .line 16
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    iget v2, p0, Ls10/b;->c:I

    .line 21
    .line 22
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    iget-object v2, p0, Ls10/b;->d:Ljava/lang/String;

    .line 27
    .line 28
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    iget v2, p0, Ls10/b;->e:I

    .line 33
    .line 34
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    iget-boolean v2, p0, Ls10/b;->f:Z

    .line 39
    .line 40
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    iget-boolean v2, p0, Ls10/b;->g:Z

    .line 45
    .line 46
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    iget-boolean p0, p0, Ls10/b;->h:Z

    .line 51
    .line 52
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    add-int/2addr p0, v0

    .line 57
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "State(error="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Ls10/b;->a:Lql0/g;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", targetTemperature="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Ls10/b;->b:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", minChargeLevel="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget v1, p0, Ls10/b;->c:I

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", minChargeLevelText="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Ls10/b;->d:Ljava/lang/String;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", minChargeLevelSetting="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget v1, p0, Ls10/b;->e:I

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", isMinChargeLevelSaving="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-boolean v1, p0, Ls10/b;->f:Z

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", isTargetTemperatureSaving="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    const-string v1, ", isMinChargeLevelBottomSheetVisible="

    .line 69
    .line 70
    const-string v2, ")"

    .line 71
    .line 72
    iget-boolean v3, p0, Ls10/b;->g:Z

    .line 73
    .line 74
    iget-boolean p0, p0, Ls10/b;->h:Z

    .line 75
    .line 76
    invoke-static {v0, v3, v1, p0, v2}, Lvj/b;->l(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    return-object p0
.end method
