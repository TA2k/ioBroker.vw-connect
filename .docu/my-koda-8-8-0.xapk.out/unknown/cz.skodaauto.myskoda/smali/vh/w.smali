.class public final Lvh/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:I

.field public final b:Z

.field public final c:Z

.field public final d:Z

.field public final e:Lvh/v;

.field public final f:Lvh/u;


# direct methods
.method public constructor <init>(IZZZLvh/v;Lvh/u;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lvh/w;->a:I

    .line 5
    .line 6
    iput-boolean p2, p0, Lvh/w;->b:Z

    .line 7
    .line 8
    iput-boolean p3, p0, Lvh/w;->c:Z

    .line 9
    .line 10
    iput-boolean p4, p0, Lvh/w;->d:Z

    .line 11
    .line 12
    iput-object p5, p0, Lvh/w;->e:Lvh/v;

    .line 13
    .line 14
    iput-object p6, p0, Lvh/w;->f:Lvh/u;

    .line 15
    .line 16
    return-void
.end method

.method public static a(Lvh/w;IZZZLvh/v;Lvh/u;I)Lvh/w;
    .locals 7

    .line 1
    and-int/lit8 v0, p7, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget p1, p0, Lvh/w;->a:I

    .line 6
    .line 7
    :cond_0
    move v1, p1

    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    and-int/lit8 p1, p7, 0x4

    .line 12
    .line 13
    if-eqz p1, :cond_1

    .line 14
    .line 15
    iget-boolean p2, p0, Lvh/w;->b:Z

    .line 16
    .line 17
    :cond_1
    move v2, p2

    .line 18
    and-int/lit8 p1, p7, 0x8

    .line 19
    .line 20
    if-eqz p1, :cond_2

    .line 21
    .line 22
    iget-boolean p3, p0, Lvh/w;->c:Z

    .line 23
    .line 24
    :cond_2
    move v3, p3

    .line 25
    and-int/lit8 p1, p7, 0x10

    .line 26
    .line 27
    if-eqz p1, :cond_3

    .line 28
    .line 29
    iget-boolean p4, p0, Lvh/w;->d:Z

    .line 30
    .line 31
    :cond_3
    move v4, p4

    .line 32
    and-int/lit8 p1, p7, 0x20

    .line 33
    .line 34
    if-eqz p1, :cond_4

    .line 35
    .line 36
    iget-object p5, p0, Lvh/w;->e:Lvh/v;

    .line 37
    .line 38
    :cond_4
    move-object v5, p5

    .line 39
    and-int/lit8 p1, p7, 0x40

    .line 40
    .line 41
    if-eqz p1, :cond_5

    .line 42
    .line 43
    iget-object p6, p0, Lvh/w;->f:Lvh/u;

    .line 44
    .line 45
    :cond_5
    move-object v6, p6

    .line 46
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    new-instance v0, Lvh/w;

    .line 50
    .line 51
    invoke-direct/range {v0 .. v6}, Lvh/w;-><init>(IZZZLvh/v;Lvh/u;)V

    .line 52
    .line 53
    .line 54
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
    instance-of v0, p1, Lvh/w;

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_1
    check-cast p1, Lvh/w;

    .line 10
    .line 11
    iget v0, p0, Lvh/w;->a:I

    .line 12
    .line 13
    iget v1, p1, Lvh/w;->a:I

    .line 14
    .line 15
    if-eq v0, v1, :cond_2

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_2
    iget-boolean v0, p0, Lvh/w;->b:Z

    .line 19
    .line 20
    iget-boolean v1, p1, Lvh/w;->b:Z

    .line 21
    .line 22
    if-eq v0, v1, :cond_3

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_3
    iget-boolean v0, p0, Lvh/w;->c:Z

    .line 26
    .line 27
    iget-boolean v1, p1, Lvh/w;->c:Z

    .line 28
    .line 29
    if-eq v0, v1, :cond_4

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_4
    iget-boolean v0, p0, Lvh/w;->d:Z

    .line 33
    .line 34
    iget-boolean v1, p1, Lvh/w;->d:Z

    .line 35
    .line 36
    if-eq v0, v1, :cond_5

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_5
    iget-object v0, p0, Lvh/w;->e:Lvh/v;

    .line 40
    .line 41
    iget-object v1, p1, Lvh/w;->e:Lvh/v;

    .line 42
    .line 43
    invoke-virtual {v0, v1}, Lvh/v;->equals(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    if-nez v0, :cond_6

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_6
    iget-object p0, p0, Lvh/w;->f:Lvh/u;

    .line 51
    .line 52
    iget-object p1, p1, Lvh/w;->f:Lvh/u;

    .line 53
    .line 54
    invoke-virtual {p0, p1}, Lvh/u;->equals(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result p0

    .line 58
    if-nez p0, :cond_7

    .line 59
    .line 60
    :goto_0
    const/4 p0, 0x0

    .line 61
    return p0

    .line 62
    :cond_7
    :goto_1
    const/4 p0, 0x1

    .line 63
    return p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Lvh/w;->a:I

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Integer;->hashCode(I)I

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
    const/4 v2, 0x4

    .line 11
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    iget-boolean v2, p0, Lvh/w;->b:Z

    .line 16
    .line 17
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    iget-boolean v2, p0, Lvh/w;->c:Z

    .line 22
    .line 23
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    iget-boolean v2, p0, Lvh/w;->d:Z

    .line 28
    .line 29
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    iget-object v2, p0, Lvh/w;->e:Lvh/v;

    .line 34
    .line 35
    invoke-virtual {v2}, Lvh/v;->hashCode()I

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    add-int/2addr v2, v0

    .line 40
    mul-int/2addr v2, v1

    .line 41
    iget-object p0, p0, Lvh/w;->f:Lvh/u;

    .line 42
    .line 43
    invoke-virtual {p0}, Lvh/u;->hashCode()I

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    add-int/2addr p0, v2

    .line 48
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "SolarSystemOnboardingUiState(currentStep="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lvh/w;->a:I

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", totalSteps=4, stepperVisible="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-boolean v1, p0, Lvh/w;->b:Z

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", closeOnboardingButtonVisible="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", showBottomSheet="

    .line 29
    .line 30
    const-string v2, ", pvInstallation="

    .line 31
    .line 32
    iget-boolean v3, p0, Lvh/w;->c:Z

    .line 33
    .line 34
    iget-boolean v4, p0, Lvh/w;->d:Z

    .line 35
    .line 36
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 37
    .line 38
    .line 39
    iget-object v1, p0, Lvh/w;->e:Lvh/v;

    .line 40
    .line 41
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string v1, ", pvInstallationSubmissionState="

    .line 45
    .line 46
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    iget-object p0, p0, Lvh/w;->f:Lvh/u;

    .line 50
    .line 51
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const-string p0, ")"

    .line 55
    .line 56
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    return-object p0
.end method
