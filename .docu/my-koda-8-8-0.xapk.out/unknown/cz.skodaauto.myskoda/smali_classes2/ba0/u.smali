.class public final Lba0/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Llf0/i;

.field public final b:Ler0/g;

.field public final c:Laa0/c;

.field public final d:Z

.field public final e:Lql0/g;

.field public final f:Ljava/util/List;

.field public final g:Z

.field public final h:Z

.field public final i:Z

.field public final j:Z

.field public final k:Z

.field public final l:Z

.field public final m:Z


# direct methods
.method public constructor <init>(Llf0/i;Ler0/g;Laa0/c;ZLql0/g;Ljava/util/List;Z)V
    .locals 1

    .line 1
    const-string v0, "viewMode"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "subscriptionLicenseState"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "backups"

    .line 12
    .line 13
    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lba0/u;->a:Llf0/i;

    .line 20
    .line 21
    iput-object p2, p0, Lba0/u;->b:Ler0/g;

    .line 22
    .line 23
    iput-object p3, p0, Lba0/u;->c:Laa0/c;

    .line 24
    .line 25
    iput-boolean p4, p0, Lba0/u;->d:Z

    .line 26
    .line 27
    iput-object p5, p0, Lba0/u;->e:Lql0/g;

    .line 28
    .line 29
    iput-object p6, p0, Lba0/u;->f:Ljava/util/List;

    .line 30
    .line 31
    iput-boolean p7, p0, Lba0/u;->g:Z

    .line 32
    .line 33
    move-object p2, p6

    .line 34
    check-cast p2, Ljava/util/Collection;

    .line 35
    .line 36
    invoke-interface {p2}, Ljava/util/Collection;->isEmpty()Z

    .line 37
    .line 38
    .line 39
    move-result p2

    .line 40
    const/4 p5, 0x1

    .line 41
    xor-int/2addr p2, p5

    .line 42
    iput-boolean p2, p0, Lba0/u;->h:Z

    .line 43
    .line 44
    const/16 p2, 0xa

    .line 45
    .line 46
    const/4 p7, 0x0

    .line 47
    if-nez p4, :cond_0

    .line 48
    .line 49
    if-nez p3, :cond_0

    .line 50
    .line 51
    invoke-interface {p6}, Ljava/util/List;->size()I

    .line 52
    .line 53
    .line 54
    move-result p3

    .line 55
    if-ge p3, p2, :cond_0

    .line 56
    .line 57
    move p3, p5

    .line 58
    goto :goto_0

    .line 59
    :cond_0
    move p3, p7

    .line 60
    :goto_0
    iput-boolean p3, p0, Lba0/u;->i:Z

    .line 61
    .line 62
    invoke-interface {p6}, Ljava/util/List;->size()I

    .line 63
    .line 64
    .line 65
    move-result p3

    .line 66
    if-lt p3, p2, :cond_1

    .line 67
    .line 68
    move p2, p5

    .line 69
    goto :goto_1

    .line 70
    :cond_1
    move p2, p7

    .line 71
    :goto_1
    iput-boolean p2, p0, Lba0/u;->j:Z

    .line 72
    .line 73
    sget-object p2, Llf0/i;->h:Llf0/i;

    .line 74
    .line 75
    if-ne p1, p2, :cond_2

    .line 76
    .line 77
    move p2, p5

    .line 78
    goto :goto_2

    .line 79
    :cond_2
    move p2, p7

    .line 80
    :goto_2
    iput-boolean p2, p0, Lba0/u;->k:Z

    .line 81
    .line 82
    invoke-static {p1}, Llp/tf;->d(Llf0/i;)Z

    .line 83
    .line 84
    .line 85
    move-result p1

    .line 86
    iput-boolean p1, p0, Lba0/u;->l:Z

    .line 87
    .line 88
    if-nez p2, :cond_4

    .line 89
    .line 90
    if-eqz p1, :cond_3

    .line 91
    .line 92
    goto :goto_3

    .line 93
    :cond_3
    move p5, p7

    .line 94
    :cond_4
    :goto_3
    iput-boolean p5, p0, Lba0/u;->m:Z

    .line 95
    .line 96
    return-void
.end method

.method public static a(Lba0/u;Llf0/i;Ler0/g;Laa0/c;ZLql0/g;Ljava/util/List;ZI)Lba0/u;
    .locals 8

    .line 1
    and-int/lit8 v0, p8, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lba0/u;->a:Llf0/i;

    .line 6
    .line 7
    :cond_0
    move-object v1, p1

    .line 8
    and-int/lit8 p1, p8, 0x2

    .line 9
    .line 10
    if-eqz p1, :cond_1

    .line 11
    .line 12
    iget-object p2, p0, Lba0/u;->b:Ler0/g;

    .line 13
    .line 14
    :cond_1
    move-object v2, p2

    .line 15
    and-int/lit8 p1, p8, 0x4

    .line 16
    .line 17
    if-eqz p1, :cond_2

    .line 18
    .line 19
    iget-object p3, p0, Lba0/u;->c:Laa0/c;

    .line 20
    .line 21
    :cond_2
    move-object v3, p3

    .line 22
    and-int/lit8 p1, p8, 0x8

    .line 23
    .line 24
    if-eqz p1, :cond_3

    .line 25
    .line 26
    iget-boolean p4, p0, Lba0/u;->d:Z

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
    iget-object p5, p0, Lba0/u;->e:Lql0/g;

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
    iget-object p6, p0, Lba0/u;->f:Ljava/util/List;

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
    iget-boolean p7, p0, Lba0/u;->g:Z

    .line 48
    .line 49
    :cond_6
    move v7, p7

    .line 50
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 51
    .line 52
    .line 53
    const-string p0, "viewMode"

    .line 54
    .line 55
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    const-string p0, "subscriptionLicenseState"

    .line 59
    .line 60
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    const-string p0, "backups"

    .line 64
    .line 65
    invoke-static {v6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    new-instance v0, Lba0/u;

    .line 69
    .line 70
    invoke-direct/range {v0 .. v7}, Lba0/u;-><init>(Llf0/i;Ler0/g;Laa0/c;ZLql0/g;Ljava/util/List;Z)V

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
    instance-of v1, p1, Lba0/u;

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
    check-cast p1, Lba0/u;

    .line 12
    .line 13
    iget-object v1, p0, Lba0/u;->a:Llf0/i;

    .line 14
    .line 15
    iget-object v3, p1, Lba0/u;->a:Llf0/i;

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Lba0/u;->b:Ler0/g;

    .line 21
    .line 22
    iget-object v3, p1, Lba0/u;->b:Ler0/g;

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-object v1, p0, Lba0/u;->c:Laa0/c;

    .line 28
    .line 29
    iget-object v3, p1, Lba0/u;->c:Laa0/c;

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
    iget-boolean v1, p0, Lba0/u;->d:Z

    .line 39
    .line 40
    iget-boolean v3, p1, Lba0/u;->d:Z

    .line 41
    .line 42
    if-eq v1, v3, :cond_5

    .line 43
    .line 44
    return v2

    .line 45
    :cond_5
    iget-object v1, p0, Lba0/u;->e:Lql0/g;

    .line 46
    .line 47
    iget-object v3, p1, Lba0/u;->e:Lql0/g;

    .line 48
    .line 49
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    if-nez v1, :cond_6

    .line 54
    .line 55
    return v2

    .line 56
    :cond_6
    iget-object v1, p0, Lba0/u;->f:Ljava/util/List;

    .line 57
    .line 58
    iget-object v3, p1, Lba0/u;->f:Ljava/util/List;

    .line 59
    .line 60
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-nez v1, :cond_7

    .line 65
    .line 66
    return v2

    .line 67
    :cond_7
    iget-boolean p0, p0, Lba0/u;->g:Z

    .line 68
    .line 69
    iget-boolean p1, p1, Lba0/u;->g:Z

    .line 70
    .line 71
    if-eq p0, p1, :cond_8

    .line 72
    .line 73
    return v2

    .line 74
    :cond_8
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lba0/u;->a:Llf0/i;

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
    iget-object v2, p0, Lba0/u;->b:Ler0/g;

    .line 11
    .line 12
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    add-int/2addr v2, v0

    .line 17
    mul-int/2addr v2, v1

    .line 18
    const/4 v0, 0x0

    .line 19
    iget-object v3, p0, Lba0/u;->c:Laa0/c;

    .line 20
    .line 21
    if-nez v3, :cond_0

    .line 22
    .line 23
    move v3, v0

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    invoke-virtual {v3}, Laa0/c;->hashCode()I

    .line 26
    .line 27
    .line 28
    move-result v3

    .line 29
    :goto_0
    add-int/2addr v2, v3

    .line 30
    mul-int/2addr v2, v1

    .line 31
    iget-boolean v3, p0, Lba0/u;->d:Z

    .line 32
    .line 33
    invoke-static {v2, v1, v3}, La7/g0;->e(IIZ)I

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    iget-object v3, p0, Lba0/u;->e:Lql0/g;

    .line 38
    .line 39
    if-nez v3, :cond_1

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    invoke-virtual {v3}, Lql0/g;->hashCode()I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    :goto_1
    add-int/2addr v2, v0

    .line 47
    mul-int/2addr v2, v1

    .line 48
    iget-object v0, p0, Lba0/u;->f:Ljava/util/List;

    .line 49
    .line 50
    invoke-static {v2, v1, v0}, Lia/b;->a(IILjava/util/List;)I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    iget-boolean p0, p0, Lba0/u;->g:Z

    .line 55
    .line 56
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 57
    .line 58
    .line 59
    move-result p0

    .line 60
    add-int/2addr p0, v0

    .line 61
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "State(viewMode="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lba0/u;->a:Llf0/i;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", subscriptionLicenseState="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lba0/u;->b:Ler0/g;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", appliedBackup="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lba0/u;->c:Laa0/c;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", isLoading="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-boolean v1, p0, Lba0/u;->d:Z

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", error="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Lba0/u;->e:Lql0/g;

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", backups="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object v1, p0, Lba0/u;->f:Ljava/util/List;

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", dataUnavailable="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    const-string v1, ")"

    .line 69
    .line 70
    iget-boolean p0, p0, Lba0/u;->g:Z

    .line 71
    .line 72
    invoke-static {v0, p0, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    return-object p0
.end method
