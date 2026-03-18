.class public final Ltz/k4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Z

.field public final b:Z

.field public final c:Z

.field public final d:Z

.field public final e:Ltz/h4;

.field public final f:Ljava/util/List;

.field public final g:Ljava/util/List;

.field public final h:Z


# direct methods
.method public synthetic constructor <init>(Ljava/util/List;Ljava/util/List;I)V
    .locals 11

    and-int/lit8 v0, p3, 0x1

    const/4 v1, 0x0

    const/4 v2, 0x1

    if-eqz v0, :cond_0

    move v4, v2

    goto :goto_0

    :cond_0
    move v4, v1

    :goto_0
    and-int/lit8 v0, p3, 0x2

    if-eqz v0, :cond_1

    move v5, v2

    goto :goto_1

    :cond_1
    move v5, v1

    :goto_1
    and-int/lit8 v0, p3, 0x4

    if-eqz v0, :cond_2

    move v6, v2

    goto :goto_2

    :cond_2
    move v6, v1

    .line 10
    :goto_2
    sget-object v8, Ltz/h4;->d:Ltz/h4;

    and-int/lit8 v0, p3, 0x20

    .line 11
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    if-eqz v0, :cond_3

    move-object v9, v1

    goto :goto_3

    :cond_3
    move-object v9, p1

    :goto_3
    and-int/lit8 p1, p3, 0x40

    if-eqz p1, :cond_4

    move-object v10, v1

    goto :goto_4

    :cond_4
    move-object v10, p2

    :goto_4
    const/4 v7, 0x0

    move-object v3, p0

    invoke-direct/range {v3 .. v10}, Ltz/k4;-><init>(ZZZZLtz/h4;Ljava/util/List;Ljava/util/List;)V

    return-void
.end method

.method public constructor <init>(ZZZZLtz/h4;Ljava/util/List;Ljava/util/List;)V
    .locals 1

    const-string v0, "cardItems"

    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "rowItems"

    invoke-static {p7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-boolean p1, p0, Ltz/k4;->a:Z

    .line 3
    iput-boolean p2, p0, Ltz/k4;->b:Z

    .line 4
    iput-boolean p3, p0, Ltz/k4;->c:Z

    .line 5
    iput-boolean p4, p0, Ltz/k4;->d:Z

    .line 6
    iput-object p5, p0, Ltz/k4;->e:Ltz/h4;

    .line 7
    iput-object p6, p0, Ltz/k4;->f:Ljava/util/List;

    .line 8
    iput-object p7, p0, Ltz/k4;->g:Ljava/util/List;

    if-nez p1, :cond_0

    if-nez p2, :cond_0

    if-eqz p3, :cond_1

    :cond_0
    if-nez p4, :cond_1

    const/4 p1, 0x1

    goto :goto_0

    :cond_1
    const/4 p1, 0x0

    .line 9
    :goto_0
    iput-boolean p1, p0, Ltz/k4;->h:Z

    return-void
.end method

.method public static a(Ltz/k4;ZZZZLtz/h4;Ljava/util/List;Ljava/util/List;I)Ltz/k4;
    .locals 8

    .line 1
    and-int/lit8 v0, p8, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-boolean p1, p0, Ltz/k4;->a:Z

    .line 6
    .line 7
    :cond_0
    move v1, p1

    .line 8
    and-int/lit8 p1, p8, 0x2

    .line 9
    .line 10
    if-eqz p1, :cond_1

    .line 11
    .line 12
    iget-boolean p2, p0, Ltz/k4;->b:Z

    .line 13
    .line 14
    :cond_1
    move v2, p2

    .line 15
    and-int/lit8 p1, p8, 0x4

    .line 16
    .line 17
    if-eqz p1, :cond_2

    .line 18
    .line 19
    iget-boolean p3, p0, Ltz/k4;->c:Z

    .line 20
    .line 21
    :cond_2
    move v3, p3

    .line 22
    and-int/lit8 p1, p8, 0x8

    .line 23
    .line 24
    if-eqz p1, :cond_3

    .line 25
    .line 26
    iget-boolean p4, p0, Ltz/k4;->d:Z

    .line 27
    .line 28
    :cond_3
    move v4, p4

    .line 29
    and-int/lit8 p1, p8, 0x10

    .line 30
    .line 31
    if-eqz p1, :cond_4

    .line 32
    .line 33
    iget-object p5, p0, Ltz/k4;->e:Ltz/h4;

    .line 34
    .line 35
    :cond_4
    move-object v5, p5

    .line 36
    and-int/lit8 p1, p8, 0x20

    .line 37
    .line 38
    if-eqz p1, :cond_5

    .line 39
    .line 40
    iget-object p6, p0, Ltz/k4;->f:Ljava/util/List;

    .line 41
    .line 42
    :cond_5
    move-object v6, p6

    .line 43
    and-int/lit8 p1, p8, 0x40

    .line 44
    .line 45
    if-eqz p1, :cond_6

    .line 46
    .line 47
    iget-object p7, p0, Ltz/k4;->g:Ljava/util/List;

    .line 48
    .line 49
    :cond_6
    move-object v7, p7

    .line 50
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 51
    .line 52
    .line 53
    const-string p0, "chargingPlanFlow"

    .line 54
    .line 55
    invoke-static {v5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    const-string p0, "cardItems"

    .line 59
    .line 60
    invoke-static {v6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    const-string p0, "rowItems"

    .line 64
    .line 65
    invoke-static {v7, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    new-instance v0, Ltz/k4;

    .line 69
    .line 70
    invoke-direct/range {v0 .. v7}, Ltz/k4;-><init>(ZZZZLtz/h4;Ljava/util/List;Ljava/util/List;)V

    .line 71
    .line 72
    .line 73
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
    instance-of v1, p1, Ltz/k4;

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
    check-cast p1, Ltz/k4;

    .line 12
    .line 13
    iget-boolean v1, p0, Ltz/k4;->a:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Ltz/k4;->a:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Ltz/k4;->b:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Ltz/k4;->b:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-boolean v1, p0, Ltz/k4;->c:Z

    .line 28
    .line 29
    iget-boolean v3, p1, Ltz/k4;->c:Z

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-boolean v1, p0, Ltz/k4;->d:Z

    .line 35
    .line 36
    iget-boolean v3, p1, Ltz/k4;->d:Z

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget-object v1, p0, Ltz/k4;->e:Ltz/h4;

    .line 42
    .line 43
    iget-object v3, p1, Ltz/k4;->e:Ltz/h4;

    .line 44
    .line 45
    if-eq v1, v3, :cond_6

    .line 46
    .line 47
    return v2

    .line 48
    :cond_6
    iget-object v1, p0, Ltz/k4;->f:Ljava/util/List;

    .line 49
    .line 50
    iget-object v3, p1, Ltz/k4;->f:Ljava/util/List;

    .line 51
    .line 52
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-nez v1, :cond_7

    .line 57
    .line 58
    return v2

    .line 59
    :cond_7
    iget-object p0, p0, Ltz/k4;->g:Ljava/util/List;

    .line 60
    .line 61
    iget-object p1, p1, Ltz/k4;->g:Ljava/util/List;

    .line 62
    .line 63
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result p0

    .line 67
    if-nez p0, :cond_8

    .line 68
    .line 69
    return v2

    .line 70
    :cond_8
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-boolean v0, p0, Ltz/k4;->a:Z

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
    iget-boolean v2, p0, Ltz/k4;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Ltz/k4;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Ltz/k4;->d:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Ltz/k4;->e:Ltz/h4;

    .line 29
    .line 30
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    add-int/2addr v2, v0

    .line 35
    mul-int/2addr v2, v1

    .line 36
    iget-object v0, p0, Ltz/k4;->f:Ljava/util/List;

    .line 37
    .line 38
    invoke-static {v2, v1, v0}, Lia/b;->a(IILjava/util/List;)I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    iget-object p0, p0, Ltz/k4;->g:Ljava/util/List;

    .line 43
    .line 44
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    add-int/2addr p0, v0

    .line 49
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", isSubscriptionStatusLoading="

    .line 2
    .line 3
    const-string v1, ", isMarketConfigurationLoading="

    .line 4
    .line 5
    const-string v2, "State(isConsentLoading="

    .line 6
    .line 7
    iget-boolean v3, p0, Ltz/k4;->a:Z

    .line 8
    .line 9
    iget-boolean v4, p0, Ltz/k4;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v0, v1, v3, v4}, Lvj/b;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", isMockEnvironment="

    .line 16
    .line 17
    const-string v2, ", chargingPlanFlow="

    .line 18
    .line 19
    iget-boolean v3, p0, Ltz/k4;->c:Z

    .line 20
    .line 21
    iget-boolean v4, p0, Ltz/k4;->d:Z

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object v1, p0, Ltz/k4;->e:Ltz/h4;

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v1, ", cardItems="

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget-object v1, p0, Ltz/k4;->f:Ljava/util/List;

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v1, ", rowItems="

    .line 42
    .line 43
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    const-string v1, ")"

    .line 47
    .line 48
    iget-object p0, p0, Ltz/k4;->g:Ljava/util/List;

    .line 49
    .line 50
    invoke-static {v0, p0, v1}, Lu/w;->i(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    return-object p0
.end method
