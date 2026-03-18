.class public final Lh40/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Lh40/m;

.field public final b:Z

.field public final c:Ljava/lang/String;

.field public final d:Z

.field public final e:Z


# direct methods
.method public constructor <init>(Lh40/m;ZLjava/lang/String;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh40/f;->a:Lh40/m;

    .line 5
    .line 6
    iput-boolean p2, p0, Lh40/f;->b:Z

    .line 7
    .line 8
    iput-object p3, p0, Lh40/f;->c:Ljava/lang/String;

    .line 9
    .line 10
    iput-boolean p4, p0, Lh40/f;->d:Z

    .line 11
    .line 12
    const/4 p2, 0x0

    .line 13
    if-eqz p1, :cond_2

    .line 14
    .line 15
    iget-boolean p3, p1, Lh40/m;->z:Z

    .line 16
    .line 17
    if-eqz p3, :cond_0

    .line 18
    .line 19
    iget-boolean p3, p1, Lh40/m;->v:Z

    .line 20
    .line 21
    if-nez p3, :cond_1

    .line 22
    .line 23
    iget-boolean p3, p1, Lh40/m;->y:Z

    .line 24
    .line 25
    if-nez p3, :cond_1

    .line 26
    .line 27
    iget-boolean p3, p1, Lh40/m;->w:Z

    .line 28
    .line 29
    if-nez p3, :cond_1

    .line 30
    .line 31
    :cond_0
    iget-boolean p3, p1, Lh40/m;->A:Z

    .line 32
    .line 33
    if-nez p3, :cond_1

    .line 34
    .line 35
    iget-boolean p3, p1, Lh40/m;->C:Z

    .line 36
    .line 37
    if-nez p3, :cond_1

    .line 38
    .line 39
    iget-boolean p3, p1, Lh40/m;->D:Z

    .line 40
    .line 41
    if-nez p3, :cond_1

    .line 42
    .line 43
    iget-boolean p3, p1, Lh40/m;->E:Z

    .line 44
    .line 45
    if-nez p3, :cond_1

    .line 46
    .line 47
    iget-boolean p1, p1, Lh40/m;->F:Z

    .line 48
    .line 49
    if-eqz p1, :cond_2

    .line 50
    .line 51
    :cond_1
    const/4 p2, 0x1

    .line 52
    :cond_2
    iput-boolean p2, p0, Lh40/f;->e:Z

    .line 53
    .line 54
    return-void
.end method

.method public static a(Lh40/f;Lh40/m;ZLjava/lang/String;ZI)Lh40/f;
    .locals 1

    .line 1
    and-int/lit8 v0, p5, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lh40/f;->a:Lh40/m;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 v0, p5, 0x2

    .line 8
    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    iget-boolean p2, p0, Lh40/f;->b:Z

    .line 12
    .line 13
    :cond_1
    and-int/lit8 v0, p5, 0x4

    .line 14
    .line 15
    if-eqz v0, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lh40/f;->c:Ljava/lang/String;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p5, p5, 0x8

    .line 20
    .line 21
    if-eqz p5, :cond_3

    .line 22
    .line 23
    iget-boolean p4, p0, Lh40/f;->d:Z

    .line 24
    .line 25
    :cond_3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    const-string p0, "inProgressChallengeTitle"

    .line 29
    .line 30
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    new-instance p0, Lh40/f;

    .line 34
    .line 35
    invoke-direct {p0, p1, p2, p3, p4}, Lh40/f;-><init>(Lh40/m;ZLjava/lang/String;Z)V

    .line 36
    .line 37
    .line 38
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
    instance-of v1, p1, Lh40/f;

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
    check-cast p1, Lh40/f;

    .line 12
    .line 13
    iget-object v1, p0, Lh40/f;->a:Lh40/m;

    .line 14
    .line 15
    iget-object v3, p1, Lh40/f;->a:Lh40/m;

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
    iget-boolean v1, p0, Lh40/f;->b:Z

    .line 25
    .line 26
    iget-boolean v3, p1, Lh40/f;->b:Z

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object v1, p0, Lh40/f;->c:Ljava/lang/String;

    .line 32
    .line 33
    iget-object v3, p1, Lh40/f;->c:Ljava/lang/String;

    .line 34
    .line 35
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-nez v1, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-boolean p0, p0, Lh40/f;->d:Z

    .line 43
    .line 44
    iget-boolean p1, p1, Lh40/f;->d:Z

    .line 45
    .line 46
    if-eq p0, p1, :cond_5

    .line 47
    .line 48
    return v2

    .line 49
    :cond_5
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lh40/f;->a:Lh40/m;

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
    invoke-virtual {v0}, Lh40/m;->hashCode()I

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
    iget-boolean v2, p0, Lh40/f;->b:Z

    .line 15
    .line 16
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    iget-object v2, p0, Lh40/f;->c:Ljava/lang/String;

    .line 21
    .line 22
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    iget-boolean p0, p0, Lh40/f;->d:Z

    .line 27
    .line 28
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    add-int/2addr p0, v0

    .line 33
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "State(challenge="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lh40/f;->a:Lh40/m;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", isLoading="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-boolean v1, p0, Lh40/f;->b:Z

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", inProgressChallengeTitle="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", isQuitChallengeDialogVisible="

    .line 29
    .line 30
    const-string v2, ")"

    .line 31
    .line 32
    iget-object v3, p0, Lh40/f;->c:Ljava/lang/String;

    .line 33
    .line 34
    iget-boolean p0, p0, Lh40/f;->d:Z

    .line 35
    .line 36
    invoke-static {v3, v1, v2, v0, p0}, Lc1/j0;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0
.end method
