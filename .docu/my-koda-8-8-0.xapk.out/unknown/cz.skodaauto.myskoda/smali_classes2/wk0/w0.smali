.class public final Lwk0/w0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Z

.field public final b:Z

.field public final c:Ljava/lang/String;

.field public final d:Ljava/util/List;

.field public final e:Ljava/lang/String;

.field public final f:Ljava/lang/String;

.field public final g:Lwk0/q0;


# direct methods
.method public constructor <init>(ZZLjava/lang/String;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;Lwk0/q0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lwk0/w0;->a:Z

    .line 5
    .line 6
    iput-boolean p2, p0, Lwk0/w0;->b:Z

    .line 7
    .line 8
    iput-object p3, p0, Lwk0/w0;->c:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Lwk0/w0;->d:Ljava/util/List;

    .line 11
    .line 12
    iput-object p5, p0, Lwk0/w0;->e:Ljava/lang/String;

    .line 13
    .line 14
    iput-object p6, p0, Lwk0/w0;->f:Ljava/lang/String;

    .line 15
    .line 16
    iput-object p7, p0, Lwk0/w0;->g:Lwk0/q0;

    .line 17
    .line 18
    return-void
.end method

.method public static a(Lwk0/w0;Lwk0/q0;)Lwk0/w0;
    .locals 8

    .line 1
    iget-boolean v1, p0, Lwk0/w0;->a:Z

    .line 2
    .line 3
    iget-boolean v2, p0, Lwk0/w0;->b:Z

    .line 4
    .line 5
    iget-object v3, p0, Lwk0/w0;->c:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v4, p0, Lwk0/w0;->d:Ljava/util/List;

    .line 8
    .line 9
    iget-object v5, p0, Lwk0/w0;->e:Ljava/lang/String;

    .line 10
    .line 11
    iget-object v6, p0, Lwk0/w0;->f:Ljava/lang/String;

    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    new-instance v0, Lwk0/w0;

    .line 17
    .line 18
    move-object v7, p1

    .line 19
    invoke-direct/range {v0 .. v7}, Lwk0/w0;-><init>(ZZLjava/lang/String;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;Lwk0/q0;)V

    .line 20
    .line 21
    .line 22
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
    instance-of v1, p1, Lwk0/w0;

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
    check-cast p1, Lwk0/w0;

    .line 12
    .line 13
    iget-boolean v1, p0, Lwk0/w0;->a:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Lwk0/w0;->a:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Lwk0/w0;->b:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Lwk0/w0;->b:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-object v1, p0, Lwk0/w0;->c:Ljava/lang/String;

    .line 28
    .line 29
    iget-object v3, p1, Lwk0/w0;->c:Ljava/lang/String;

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
    iget-object v1, p0, Lwk0/w0;->d:Ljava/util/List;

    .line 39
    .line 40
    iget-object v3, p1, Lwk0/w0;->d:Ljava/util/List;

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
    iget-object v1, p0, Lwk0/w0;->e:Ljava/lang/String;

    .line 50
    .line 51
    iget-object v3, p1, Lwk0/w0;->e:Ljava/lang/String;

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
    iget-object v1, p0, Lwk0/w0;->f:Ljava/lang/String;

    .line 61
    .line 62
    iget-object v3, p1, Lwk0/w0;->f:Ljava/lang/String;

    .line 63
    .line 64
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    if-nez v1, :cond_7

    .line 69
    .line 70
    return v2

    .line 71
    :cond_7
    iget-object p0, p0, Lwk0/w0;->g:Lwk0/q0;

    .line 72
    .line 73
    iget-object p1, p1, Lwk0/w0;->g:Lwk0/q0;

    .line 74
    .line 75
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result p0

    .line 79
    if-nez p0, :cond_8

    .line 80
    .line 81
    return v2

    .line 82
    :cond_8
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-boolean v0, p0, Lwk0/w0;->a:Z

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
    iget-boolean v2, p0, Lwk0/w0;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    const/4 v2, 0x0

    .line 17
    iget-object v3, p0, Lwk0/w0;->c:Ljava/lang/String;

    .line 18
    .line 19
    if-nez v3, :cond_0

    .line 20
    .line 21
    move v3, v2

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    :goto_0
    add-int/2addr v0, v3

    .line 28
    mul-int/2addr v0, v1

    .line 29
    iget-object v3, p0, Lwk0/w0;->d:Ljava/util/List;

    .line 30
    .line 31
    if-nez v3, :cond_1

    .line 32
    .line 33
    move v3, v2

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    :goto_1
    add-int/2addr v0, v3

    .line 40
    mul-int/2addr v0, v1

    .line 41
    iget-object v3, p0, Lwk0/w0;->e:Ljava/lang/String;

    .line 42
    .line 43
    if-nez v3, :cond_2

    .line 44
    .line 45
    move v3, v2

    .line 46
    goto :goto_2

    .line 47
    :cond_2
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 48
    .line 49
    .line 50
    move-result v3

    .line 51
    :goto_2
    add-int/2addr v0, v3

    .line 52
    mul-int/2addr v0, v1

    .line 53
    iget-object v3, p0, Lwk0/w0;->f:Ljava/lang/String;

    .line 54
    .line 55
    if-nez v3, :cond_3

    .line 56
    .line 57
    move v3, v2

    .line 58
    goto :goto_3

    .line 59
    :cond_3
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 60
    .line 61
    .line 62
    move-result v3

    .line 63
    :goto_3
    add-int/2addr v0, v3

    .line 64
    mul-int/2addr v0, v1

    .line 65
    iget-object p0, p0, Lwk0/w0;->g:Lwk0/q0;

    .line 66
    .line 67
    if-nez p0, :cond_4

    .line 68
    .line 69
    goto :goto_4

    .line 70
    :cond_4
    invoke-virtual {p0}, Lwk0/q0;->hashCode()I

    .line 71
    .line 72
    .line 73
    move-result v2

    .line 74
    :goto_4
    add-int/2addr v0, v2

    .line 75
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", freeOutsideParkingHours="

    .line 2
    .line 3
    const-string v1, ", price="

    .line 4
    .line 5
    const-string v2, "DetailState(isParkedHere="

    .line 6
    .line 7
    iget-boolean v3, p0, Lwk0/w0;->a:Z

    .line 8
    .line 9
    iget-boolean v4, p0, Lwk0/w0;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v0, v1, v3, v4}, Lvj/b;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", prices="

    .line 16
    .line 17
    const-string v2, ", capacity="

    .line 18
    .line 19
    iget-object v3, p0, Lwk0/w0;->c:Ljava/lang/String;

    .line 20
    .line 21
    iget-object v4, p0, Lwk0/w0;->d:Ljava/util/List;

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lu/w;->m(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v1, ", additionalInfo="

    .line 27
    .line 28
    const-string v2, ", expandedPrices="

    .line 29
    .line 30
    iget-object v3, p0, Lwk0/w0;->e:Ljava/lang/String;

    .line 31
    .line 32
    iget-object v4, p0, Lwk0/w0;->f:Ljava/lang/String;

    .line 33
    .line 34
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    iget-object p0, p0, Lwk0/w0;->g:Lwk0/q0;

    .line 38
    .line 39
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string p0, ")"

    .line 43
    .line 44
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    return-object p0
.end method
