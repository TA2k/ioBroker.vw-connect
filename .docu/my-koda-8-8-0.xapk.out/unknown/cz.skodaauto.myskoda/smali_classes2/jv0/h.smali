.class public final Ljv0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/util/List;

.field public final c:Liv0/f;

.field public final d:Z

.field public final e:Z

.field public final f:Z

.field public final g:Z

.field public final h:Z

.field public final i:Z


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/util/List;Liv0/f;ZZZZZ)V
    .locals 1

    .line 1
    const-string v0, "selectedMapFeature"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Ljv0/h;->a:Ljava/lang/String;

    .line 10
    .line 11
    iput-object p2, p0, Ljv0/h;->b:Ljava/util/List;

    .line 12
    .line 13
    iput-object p3, p0, Ljv0/h;->c:Liv0/f;

    .line 14
    .line 15
    iput-boolean p4, p0, Ljv0/h;->d:Z

    .line 16
    .line 17
    iput-boolean p5, p0, Ljv0/h;->e:Z

    .line 18
    .line 19
    iput-boolean p6, p0, Ljv0/h;->f:Z

    .line 20
    .line 21
    iput-boolean p7, p0, Ljv0/h;->g:Z

    .line 22
    .line 23
    iput-boolean p8, p0, Ljv0/h;->h:Z

    .line 24
    .line 25
    const/4 p1, 0x7

    .line 26
    new-array p1, p1, [Liv0/f;

    .line 27
    .line 28
    sget-object p2, Liv0/a;->a:Liv0/a;

    .line 29
    .line 30
    const/4 p4, 0x0

    .line 31
    aput-object p2, p1, p4

    .line 32
    .line 33
    const/4 p2, 0x1

    .line 34
    sget-object p4, Liv0/c;->a:Liv0/c;

    .line 35
    .line 36
    aput-object p4, p1, p2

    .line 37
    .line 38
    sget-object p4, Liv0/i;->a:Liv0/i;

    .line 39
    .line 40
    const/4 p5, 0x2

    .line 41
    aput-object p4, p1, p5

    .line 42
    .line 43
    sget-object p4, Liv0/h;->a:Liv0/h;

    .line 44
    .line 45
    const/4 p5, 0x3

    .line 46
    aput-object p4, p1, p5

    .line 47
    .line 48
    sget-object p4, Liv0/m;->a:Liv0/m;

    .line 49
    .line 50
    const/4 p5, 0x4

    .line 51
    aput-object p4, p1, p5

    .line 52
    .line 53
    sget-object p4, Liv0/d;->a:Liv0/d;

    .line 54
    .line 55
    const/4 p5, 0x5

    .line 56
    aput-object p4, p1, p5

    .line 57
    .line 58
    sget-object p4, Liv0/u;->a:Liv0/u;

    .line 59
    .line 60
    const/4 p5, 0x6

    .line 61
    aput-object p4, p1, p5

    .line 62
    .line 63
    invoke-static {p1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    invoke-interface {p1, p3}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result p1

    .line 71
    xor-int/2addr p1, p2

    .line 72
    iput-boolean p1, p0, Ljv0/h;->i:Z

    .line 73
    .line 74
    return-void
.end method

.method public static a(Ljv0/h;Ljava/lang/String;Ljava/util/List;Liv0/f;ZZZZZI)Ljv0/h;
    .locals 9

    .line 1
    move/from16 v0, p9

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object p1, p0, Ljv0/h;->a:Ljava/lang/String;

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
    iget-object p2, p0, Ljv0/h;->b:Ljava/util/List;

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
    iget-object p3, p0, Ljv0/h;->c:Liv0/f;

    .line 22
    .line 23
    :cond_2
    move-object v3, p3

    .line 24
    and-int/lit8 p1, v0, 0x8

    .line 25
    .line 26
    if-eqz p1, :cond_3

    .line 27
    .line 28
    iget-boolean p4, p0, Ljv0/h;->d:Z

    .line 29
    .line 30
    :cond_3
    move v4, p4

    .line 31
    and-int/lit8 p1, v0, 0x10

    .line 32
    .line 33
    if-eqz p1, :cond_4

    .line 34
    .line 35
    iget-boolean p5, p0, Ljv0/h;->e:Z

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
    iget-boolean p6, p0, Ljv0/h;->f:Z

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
    iget-boolean p1, p0, Ljv0/h;->g:Z

    .line 50
    .line 51
    move v7, p1

    .line 52
    goto :goto_0

    .line 53
    :cond_6
    move/from16 v7, p7

    .line 54
    .line 55
    :goto_0
    and-int/lit16 p1, v0, 0x80

    .line 56
    .line 57
    if-eqz p1, :cond_7

    .line 58
    .line 59
    iget-boolean p1, p0, Ljv0/h;->h:Z

    .line 60
    .line 61
    move v8, p1

    .line 62
    goto :goto_1

    .line 63
    :cond_7
    move/from16 v8, p8

    .line 64
    .line 65
    :goto_1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 66
    .line 67
    .line 68
    const-string p0, "selectedMapFeature"

    .line 69
    .line 70
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    new-instance v0, Ljv0/h;

    .line 74
    .line 75
    invoke-direct/range {v0 .. v8}, Ljv0/h;-><init>(Ljava/lang/String;Ljava/util/List;Liv0/f;ZZZZZ)V

    .line 76
    .line 77
    .line 78
    return-object v0
.end method


# virtual methods
.method public final b()Z
    .locals 4

    .line 1
    iget-object v0, p0, Ljv0/h;->c:Liv0/f;

    .line 2
    .line 3
    sget-object v1, Liv0/g;->a:Liv0/g;

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    iget-boolean v3, p0, Ljv0/h;->f:Z

    .line 10
    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    if-nez v3, :cond_3

    .line 14
    .line 15
    :cond_0
    sget-object v2, Liv0/n;->a:Liv0/n;

    .line 16
    .line 17
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    if-eqz v2, :cond_1

    .line 22
    .line 23
    if-nez v3, :cond_3

    .line 24
    .line 25
    :cond_1
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-nez v0, :cond_2

    .line 30
    .line 31
    iget-boolean v0, p0, Ljv0/h;->d:Z

    .line 32
    .line 33
    if-nez v0, :cond_3

    .line 34
    .line 35
    :cond_2
    if-eqz v3, :cond_4

    .line 36
    .line 37
    iget-boolean p0, p0, Ljv0/h;->e:Z

    .line 38
    .line 39
    if-eqz p0, :cond_4

    .line 40
    .line 41
    :cond_3
    const/4 p0, 0x1

    .line 42
    return p0

    .line 43
    :cond_4
    const/4 p0, 0x0

    .line 44
    return p0
.end method

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
    instance-of v1, p1, Ljv0/h;

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
    check-cast p1, Ljv0/h;

    .line 12
    .line 13
    iget-object v1, p0, Ljv0/h;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Ljv0/h;->a:Ljava/lang/String;

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
    iget-object v1, p0, Ljv0/h;->b:Ljava/util/List;

    .line 25
    .line 26
    iget-object v3, p1, Ljv0/h;->b:Ljava/util/List;

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
    iget-object v1, p0, Ljv0/h;->c:Liv0/f;

    .line 36
    .line 37
    iget-object v3, p1, Ljv0/h;->c:Liv0/f;

    .line 38
    .line 39
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-nez v1, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    iget-boolean v1, p0, Ljv0/h;->d:Z

    .line 47
    .line 48
    iget-boolean v3, p1, Ljv0/h;->d:Z

    .line 49
    .line 50
    if-eq v1, v3, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget-boolean v1, p0, Ljv0/h;->e:Z

    .line 54
    .line 55
    iget-boolean v3, p1, Ljv0/h;->e:Z

    .line 56
    .line 57
    if-eq v1, v3, :cond_6

    .line 58
    .line 59
    return v2

    .line 60
    :cond_6
    iget-boolean v1, p0, Ljv0/h;->f:Z

    .line 61
    .line 62
    iget-boolean v3, p1, Ljv0/h;->f:Z

    .line 63
    .line 64
    if-eq v1, v3, :cond_7

    .line 65
    .line 66
    return v2

    .line 67
    :cond_7
    iget-boolean v1, p0, Ljv0/h;->g:Z

    .line 68
    .line 69
    iget-boolean v3, p1, Ljv0/h;->g:Z

    .line 70
    .line 71
    if-eq v1, v3, :cond_8

    .line 72
    .line 73
    return v2

    .line 74
    :cond_8
    iget-boolean p0, p0, Ljv0/h;->h:Z

    .line 75
    .line 76
    iget-boolean p1, p1, Ljv0/h;->h:Z

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
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Ljv0/h;->a:Ljava/lang/String;

    .line 3
    .line 4
    if-nez v1, :cond_0

    .line 5
    .line 6
    move v1, v0

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    :goto_0
    const/16 v2, 0x1f

    .line 13
    .line 14
    mul-int/2addr v1, v2

    .line 15
    iget-object v3, p0, Ljv0/h;->b:Ljava/util/List;

    .line 16
    .line 17
    if-nez v3, :cond_1

    .line 18
    .line 19
    goto :goto_1

    .line 20
    :cond_1
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    :goto_1
    add-int/2addr v1, v0

    .line 25
    mul-int/2addr v1, v2

    .line 26
    iget-object v0, p0, Ljv0/h;->c:Liv0/f;

    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    add-int/2addr v0, v1

    .line 33
    mul-int/2addr v0, v2

    .line 34
    iget-boolean v1, p0, Ljv0/h;->d:Z

    .line 35
    .line 36
    invoke-static {v0, v2, v1}, La7/g0;->e(IIZ)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget-boolean v1, p0, Ljv0/h;->e:Z

    .line 41
    .line 42
    invoke-static {v0, v2, v1}, La7/g0;->e(IIZ)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-boolean v1, p0, Ljv0/h;->f:Z

    .line 47
    .line 48
    invoke-static {v0, v2, v1}, La7/g0;->e(IIZ)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget-boolean v1, p0, Ljv0/h;->g:Z

    .line 53
    .line 54
    invoke-static {v0, v2, v1}, La7/g0;->e(IIZ)I

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    iget-boolean p0, p0, Ljv0/h;->h:Z

    .line 59
    .line 60
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    add-int/2addr p0, v0

    .line 65
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", chips="

    .line 2
    .line 3
    const-string v1, ", selectedMapFeature="

    .line 4
    .line 5
    const-string v2, "State(title="

    .line 6
    .line 7
    iget-object v3, p0, Ljv0/h;->a:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Ljv0/h;->b:Ljava/util/List;

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v1, v4}, Lvj/b;->n(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iget-object v1, p0, Ljv0/h;->c:Liv0/f;

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const-string v1, ", isPoiSelected="

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    iget-boolean v1, p0, Ljv0/h;->d:Z

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v1, ", isOfferSelected="

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v1, ", showFeatureDrawer="

    .line 36
    .line 37
    const-string v2, ", isPoisLoading="

    .line 38
    .line 39
    iget-boolean v3, p0, Ljv0/h;->e:Z

    .line 40
    .line 41
    iget-boolean v4, p0, Ljv0/h;->f:Z

    .line 42
    .line 43
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 44
    .line 45
    .line 46
    const-string v1, ", isSearchBarAnimRunning="

    .line 47
    .line 48
    const-string v2, ")"

    .line 49
    .line 50
    iget-boolean v3, p0, Ljv0/h;->g:Z

    .line 51
    .line 52
    iget-boolean p0, p0, Ljv0/h;->h:Z

    .line 53
    .line 54
    invoke-static {v0, v3, v1, p0, v2}, Lvj/b;->l(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    return-object p0
.end method
