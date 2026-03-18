.class public final Li31/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lz21/c;

.field public final b:Lz21/e;

.field public final c:Z

.field public final d:Z

.field public final e:Li31/g;

.field public final f:Ljava/lang/Integer;


# direct methods
.method public synthetic constructor <init>(Lz21/c;Lz21/e;ZI)V
    .locals 8

    sget-object v0, Li31/g;->d:Li31/g;

    and-int/lit8 v1, p4, 0x1

    if-eqz v1, :cond_0

    .line 8
    sget-object p1, Lz21/c;->e:Lz21/c;

    :cond_0
    move-object v2, p1

    and-int/lit8 p1, p4, 0x2

    if-eqz p1, :cond_1

    .line 9
    new-instance p2, Lz21/e;

    invoke-direct {p2}, Lz21/e;-><init>()V

    :cond_1
    move-object v3, p2

    and-int/lit8 p1, p4, 0x8

    if-eqz p1, :cond_2

    const/4 p3, 0x0

    :cond_2
    move v5, p3

    and-int/lit8 p1, p4, 0x10

    if-eqz p1, :cond_3

    const/4 v0, 0x0

    :cond_3
    move-object v6, v0

    const/4 v4, 0x0

    const/4 v7, 0x0

    move-object v1, p0

    .line 10
    invoke-direct/range {v1 .. v7}, Li31/j;-><init>(Lz21/c;Lz21/e;ZZLi31/g;Ljava/lang/Integer;)V

    return-void
.end method

.method public constructor <init>(Lz21/c;Lz21/e;ZZLi31/g;Ljava/lang/Integer;)V
    .locals 1

    const-string v0, "moduleVersion"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "preferredModuleVersions"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Li31/j;->a:Lz21/c;

    .line 3
    iput-object p2, p0, Li31/j;->b:Lz21/e;

    .line 4
    iput-boolean p3, p0, Li31/j;->c:Z

    .line 5
    iput-boolean p4, p0, Li31/j;->d:Z

    .line 6
    iput-object p5, p0, Li31/j;->e:Li31/g;

    .line 7
    iput-object p6, p0, Li31/j;->f:Ljava/lang/Integer;

    return-void
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
    instance-of v1, p1, Li31/j;

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
    check-cast p1, Li31/j;

    .line 12
    .line 13
    iget-object v1, p0, Li31/j;->a:Lz21/c;

    .line 14
    .line 15
    iget-object v3, p1, Li31/j;->a:Lz21/c;

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Li31/j;->b:Lz21/e;

    .line 21
    .line 22
    iget-object v3, p1, Li31/j;->b:Lz21/e;

    .line 23
    .line 24
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-nez v1, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-boolean v1, p0, Li31/j;->c:Z

    .line 32
    .line 33
    iget-boolean v3, p1, Li31/j;->c:Z

    .line 34
    .line 35
    if-eq v1, v3, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    iget-boolean v1, p0, Li31/j;->d:Z

    .line 39
    .line 40
    iget-boolean v3, p1, Li31/j;->d:Z

    .line 41
    .line 42
    if-eq v1, v3, :cond_5

    .line 43
    .line 44
    return v2

    .line 45
    :cond_5
    iget-object v1, p0, Li31/j;->e:Li31/g;

    .line 46
    .line 47
    iget-object v3, p1, Li31/j;->e:Li31/g;

    .line 48
    .line 49
    if-eq v1, v3, :cond_6

    .line 50
    .line 51
    return v2

    .line 52
    :cond_6
    iget-object p0, p0, Li31/j;->f:Ljava/lang/Integer;

    .line 53
    .line 54
    iget-object p1, p1, Li31/j;->f:Ljava/lang/Integer;

    .line 55
    .line 56
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result p0

    .line 60
    if-nez p0, :cond_7

    .line 61
    .line 62
    return v2

    .line 63
    :cond_7
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Li31/j;->a:Lz21/c;

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
    iget-object v2, p0, Li31/j;->b:Lz21/e;

    .line 11
    .line 12
    invoke-virtual {v2}, Lz21/e;->hashCode()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    add-int/2addr v2, v0

    .line 17
    mul-int/2addr v2, v1

    .line 18
    iget-boolean v0, p0, Li31/j;->c:Z

    .line 19
    .line 20
    invoke-static {v2, v1, v0}, La7/g0;->e(IIZ)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    iget-boolean v2, p0, Li31/j;->d:Z

    .line 25
    .line 26
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    const/4 v2, 0x0

    .line 31
    iget-object v3, p0, Li31/j;->e:Li31/g;

    .line 32
    .line 33
    if-nez v3, :cond_0

    .line 34
    .line 35
    move v3, v2

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    :goto_0
    add-int/2addr v0, v3

    .line 42
    mul-int/2addr v0, v1

    .line 43
    iget-object p0, p0, Li31/j;->f:Ljava/lang/Integer;

    .line 44
    .line 45
    if-nez p0, :cond_1

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_1
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    :goto_1
    add-int/2addr v0, v2

    .line 53
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "Config(moduleVersion="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Li31/j;->a:Lz21/c;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", preferredModuleVersions="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Li31/j;->b:Lz21/e;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", shouldMockData="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", electricVehicle="

    .line 29
    .line 30
    const-string v2, ", brand="

    .line 31
    .line 32
    iget-boolean v3, p0, Li31/j;->c:Z

    .line 33
    .line 34
    iget-boolean v4, p0, Li31/j;->d:Z

    .line 35
    .line 36
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 37
    .line 38
    .line 39
    iget-object v1, p0, Li31/j;->e:Li31/g;

    .line 40
    .line 41
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string v1, ", odometer="

    .line 45
    .line 46
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    iget-object p0, p0, Li31/j;->f:Ljava/lang/Integer;

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
