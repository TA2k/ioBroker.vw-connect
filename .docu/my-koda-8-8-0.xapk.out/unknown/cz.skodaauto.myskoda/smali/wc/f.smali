.class public final Lwc/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Z

.field public final b:Z

.field public final c:Z

.field public final d:Ljava/lang/String;

.field public final e:Z

.field public final f:Z


# direct methods
.method public constructor <init>(Ljava/lang/String;ZZZZZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p2, p0, Lwc/f;->a:Z

    .line 5
    .line 6
    iput-boolean p3, p0, Lwc/f;->b:Z

    .line 7
    .line 8
    iput-boolean p4, p0, Lwc/f;->c:Z

    .line 9
    .line 10
    iput-object p1, p0, Lwc/f;->d:Ljava/lang/String;

    .line 11
    .line 12
    iput-boolean p5, p0, Lwc/f;->e:Z

    .line 13
    .line 14
    iput-boolean p6, p0, Lwc/f;->f:Z

    .line 15
    .line 16
    return-void
.end method

.method public static a(Lwc/f;ZZZLjava/lang/String;ZI)Lwc/f;
    .locals 7

    .line 1
    and-int/lit8 v0, p6, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-boolean p1, p0, Lwc/f;->a:Z

    .line 6
    .line 7
    :cond_0
    move v2, p1

    .line 8
    and-int/lit8 p1, p6, 0x2

    .line 9
    .line 10
    if-eqz p1, :cond_1

    .line 11
    .line 12
    iget-boolean p2, p0, Lwc/f;->b:Z

    .line 13
    .line 14
    :cond_1
    move v3, p2

    .line 15
    and-int/lit8 p1, p6, 0x4

    .line 16
    .line 17
    if-eqz p1, :cond_2

    .line 18
    .line 19
    iget-boolean p3, p0, Lwc/f;->c:Z

    .line 20
    .line 21
    :cond_2
    move v4, p3

    .line 22
    and-int/lit8 p1, p6, 0x8

    .line 23
    .line 24
    if-eqz p1, :cond_3

    .line 25
    .line 26
    iget-object p4, p0, Lwc/f;->d:Ljava/lang/String;

    .line 27
    .line 28
    :cond_3
    move-object v1, p4

    .line 29
    and-int/lit8 p1, p6, 0x10

    .line 30
    .line 31
    if-eqz p1, :cond_4

    .line 32
    .line 33
    iget-boolean p5, p0, Lwc/f;->e:Z

    .line 34
    .line 35
    :cond_4
    move v5, p5

    .line 36
    iget-boolean v6, p0, Lwc/f;->f:Z

    .line 37
    .line 38
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    new-instance v0, Lwc/f;

    .line 42
    .line 43
    invoke-direct/range {v0 .. v6}, Lwc/f;-><init>(Ljava/lang/String;ZZZZZ)V

    .line 44
    .line 45
    .line 46
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
    instance-of v1, p1, Lwc/f;

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
    check-cast p1, Lwc/f;

    .line 12
    .line 13
    iget-boolean v1, p0, Lwc/f;->a:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Lwc/f;->a:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Lwc/f;->b:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Lwc/f;->b:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-boolean v1, p0, Lwc/f;->c:Z

    .line 28
    .line 29
    iget-boolean v3, p1, Lwc/f;->c:Z

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-object v1, p0, Lwc/f;->d:Ljava/lang/String;

    .line 35
    .line 36
    iget-object v3, p1, Lwc/f;->d:Ljava/lang/String;

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
    iget-boolean v1, p0, Lwc/f;->e:Z

    .line 46
    .line 47
    iget-boolean v3, p1, Lwc/f;->e:Z

    .line 48
    .line 49
    if-eq v1, v3, :cond_6

    .line 50
    .line 51
    return v2

    .line 52
    :cond_6
    iget-boolean p0, p0, Lwc/f;->f:Z

    .line 53
    .line 54
    iget-boolean p1, p1, Lwc/f;->f:Z

    .line 55
    .line 56
    if-eq p0, p1, :cond_7

    .line 57
    .line 58
    return v2

    .line 59
    :cond_7
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-boolean v0, p0, Lwc/f;->a:Z

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
    iget-boolean v2, p0, Lwc/f;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Lwc/f;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v2, p0, Lwc/f;->d:Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-boolean v2, p0, Lwc/f;->e:Z

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-boolean p0, p0, Lwc/f;->f:Z

    .line 35
    .line 36
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    add-int/2addr p0, v0

    .line 41
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", isCtaEnabled="

    .line 2
    .line 3
    const-string v1, ", isLoading="

    .line 4
    .line 5
    const-string v2, "AddChargingCardUiState(hasInputError="

    .line 6
    .line 7
    iget-boolean v3, p0, Lwc/f;->a:Z

    .line 8
    .line 9
    iget-boolean v4, p0, Lwc/f;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v0, v1, v3, v4}, Lvj/b;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", input="

    .line 16
    .line 17
    const-string v2, ", pairWithSubscription="

    .line 18
    .line 19
    iget-object v3, p0, Lwc/f;->d:Ljava/lang/String;

    .line 20
    .line 21
    iget-boolean v4, p0, Lwc/f;->c:Z

    .line 22
    .line 23
    invoke-static {v1, v3, v2, v0, v4}, Lkx/a;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 24
    .line 25
    .line 26
    const-string v1, ", isToggleVisible="

    .line 27
    .line 28
    const-string v2, ")"

    .line 29
    .line 30
    iget-boolean v3, p0, Lwc/f;->e:Z

    .line 31
    .line 32
    iget-boolean p0, p0, Lwc/f;->f:Z

    .line 33
    .line 34
    invoke-static {v0, v3, v1, p0, v2}, Lvj/b;->l(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0
.end method
