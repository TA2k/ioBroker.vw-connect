.class public final Lsa0/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Z

.field public final b:Z

.field public final c:Z

.field public final d:Z

.field public final e:Ljava/lang/String;

.field public final f:Z


# direct methods
.method public constructor <init>(Ljava/lang/String;ZZZZZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p2, p0, Lsa0/p;->a:Z

    .line 5
    .line 6
    iput-boolean p3, p0, Lsa0/p;->b:Z

    .line 7
    .line 8
    iput-boolean p4, p0, Lsa0/p;->c:Z

    .line 9
    .line 10
    iput-boolean p5, p0, Lsa0/p;->d:Z

    .line 11
    .line 12
    iput-object p1, p0, Lsa0/p;->e:Ljava/lang/String;

    .line 13
    .line 14
    iput-boolean p6, p0, Lsa0/p;->f:Z

    .line 15
    .line 16
    return-void
.end method

.method public static a(Lsa0/p;ZZZZLjava/lang/String;ZI)Lsa0/p;
    .locals 7

    .line 1
    and-int/lit8 v0, p7, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-boolean p1, p0, Lsa0/p;->a:Z

    .line 6
    .line 7
    :cond_0
    move v2, p1

    .line 8
    and-int/lit8 p1, p7, 0x2

    .line 9
    .line 10
    if-eqz p1, :cond_1

    .line 11
    .line 12
    iget-boolean p2, p0, Lsa0/p;->b:Z

    .line 13
    .line 14
    :cond_1
    move v3, p2

    .line 15
    and-int/lit8 p1, p7, 0x4

    .line 16
    .line 17
    if-eqz p1, :cond_2

    .line 18
    .line 19
    iget-boolean p3, p0, Lsa0/p;->c:Z

    .line 20
    .line 21
    :cond_2
    move v4, p3

    .line 22
    and-int/lit8 p1, p7, 0x8

    .line 23
    .line 24
    if-eqz p1, :cond_3

    .line 25
    .line 26
    iget-boolean p4, p0, Lsa0/p;->d:Z

    .line 27
    .line 28
    :cond_3
    move v5, p4

    .line 29
    and-int/lit8 p1, p7, 0x10

    .line 30
    .line 31
    if-eqz p1, :cond_4

    .line 32
    .line 33
    iget-object p5, p0, Lsa0/p;->e:Ljava/lang/String;

    .line 34
    .line 35
    :cond_4
    move-object v1, p5

    .line 36
    and-int/lit8 p1, p7, 0x20

    .line 37
    .line 38
    if-eqz p1, :cond_5

    .line 39
    .line 40
    iget-boolean p6, p0, Lsa0/p;->f:Z

    .line 41
    .line 42
    :cond_5
    move v6, p6

    .line 43
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 44
    .line 45
    .line 46
    new-instance v0, Lsa0/p;

    .line 47
    .line 48
    invoke-direct/range {v0 .. v6}, Lsa0/p;-><init>(Ljava/lang/String;ZZZZZ)V

    .line 49
    .line 50
    .line 51
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
    instance-of v1, p1, Lsa0/p;

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
    check-cast p1, Lsa0/p;

    .line 12
    .line 13
    iget-boolean v1, p0, Lsa0/p;->a:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Lsa0/p;->a:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Lsa0/p;->b:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Lsa0/p;->b:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-boolean v1, p0, Lsa0/p;->c:Z

    .line 28
    .line 29
    iget-boolean v3, p1, Lsa0/p;->c:Z

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-boolean v1, p0, Lsa0/p;->d:Z

    .line 35
    .line 36
    iget-boolean v3, p1, Lsa0/p;->d:Z

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget-object v1, p0, Lsa0/p;->e:Ljava/lang/String;

    .line 42
    .line 43
    iget-object v3, p1, Lsa0/p;->e:Ljava/lang/String;

    .line 44
    .line 45
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    if-nez v1, :cond_6

    .line 50
    .line 51
    return v2

    .line 52
    :cond_6
    iget-boolean p0, p0, Lsa0/p;->f:Z

    .line 53
    .line 54
    iget-boolean p1, p1, Lsa0/p;->f:Z

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
    iget-boolean v0, p0, Lsa0/p;->a:Z

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
    iget-boolean v2, p0, Lsa0/p;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Lsa0/p;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Lsa0/p;->d:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Lsa0/p;->e:Ljava/lang/String;

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-boolean p0, p0, Lsa0/p;->f:Z

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
    const-string v0, ", automaticWakeUpSwitchChecked="

    .line 2
    .line 3
    const-string v1, ", isPredictiveWakeUpVisible="

    .line 4
    .line 5
    const-string v2, "State(automaticWakeUpVisible="

    .line 6
    .line 7
    iget-boolean v3, p0, Lsa0/p;->a:Z

    .line 8
    .line 9
    iget-boolean v4, p0, Lsa0/p;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v0, v1, v3, v4}, Lvj/b;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", isPredictiveWakeUpSwitchChecked="

    .line 16
    .line 17
    const-string v2, ", vehicleName="

    .line 18
    .line 19
    iget-boolean v3, p0, Lsa0/p;->c:Z

    .line 20
    .line 21
    iget-boolean v4, p0, Lsa0/p;->d:Z

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v1, ", sendingPredictiveWakeUp="

    .line 27
    .line 28
    const-string v2, ")"

    .line 29
    .line 30
    iget-object v3, p0, Lsa0/p;->e:Ljava/lang/String;

    .line 31
    .line 32
    iget-boolean p0, p0, Lsa0/p;->f:Z

    .line 33
    .line 34
    invoke-static {v3, v1, v2, v0, p0}, Lc1/j0;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0
.end method
