.class public final Lvy/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Ler0/g;

.field public final b:Llf0/i;

.field public final c:Z

.field public final d:Z

.field public final e:Z

.field public final f:Lvy/o;

.field public final g:Lbo0/l;

.field public final h:Lvy/n;

.field public final i:Z

.field public final j:Z

.field public final k:Z

.field public final l:Z


# direct methods
.method public synthetic constructor <init>(Ler0/g;Llf0/i;Lvy/o;Lbo0/l;Lvy/n;I)V
    .locals 18

    move/from16 v0, p6

    and-int/lit8 v1, v0, 0x1

    if-eqz v1, :cond_0

    .line 14
    sget-object v1, Ler0/g;->d:Ler0/g;

    move-object v3, v1

    goto :goto_0

    :cond_0
    move-object/from16 v3, p1

    :goto_0
    and-int/lit8 v1, v0, 0x2

    if-eqz v1, :cond_1

    .line 15
    sget-object v1, Llf0/i;->j:Llf0/i;

    move-object v4, v1

    goto :goto_1

    :cond_1
    move-object/from16 v4, p2

    :goto_1
    and-int/lit8 v1, v0, 0x4

    if-eqz v1, :cond_2

    const/4 v1, 0x1

    :goto_2
    move v5, v1

    goto :goto_3

    :cond_2
    const/4 v1, 0x0

    goto :goto_2

    :goto_3
    and-int/lit8 v1, v0, 0x20

    if-eqz v1, :cond_3

    .line 16
    sget-object v1, Lvy/o;->d:Lvy/o;

    move-object v8, v1

    goto :goto_4

    :cond_3
    move-object/from16 v8, p3

    :goto_4
    and-int/lit8 v1, v0, 0x40

    if-eqz v1, :cond_4

    .line 17
    new-instance v1, Lbo0/l;

    invoke-direct {v1}, Lbo0/l;-><init>()V

    move-object v9, v1

    goto :goto_5

    :cond_4
    move-object/from16 v9, p4

    :goto_5
    and-int/lit16 v0, v0, 0x80

    if-eqz v0, :cond_5

    .line 18
    new-instance v10, Lvy/n;

    const/16 v16, 0x0

    const/16 v17, 0x7f

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    invoke-direct/range {v10 .. v17}, Lvy/n;-><init>(Ljava/lang/String;Ljava/lang/String;FZZLvf0/g;I)V

    goto :goto_6

    :cond_5
    move-object/from16 v10, p5

    :goto_6
    const/4 v11, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    move-object/from16 v2, p0

    .line 19
    invoke-direct/range {v2 .. v11}, Lvy/p;-><init>(Ler0/g;Llf0/i;ZZZLvy/o;Lbo0/l;Lvy/n;Z)V

    return-void
.end method

.method public constructor <init>(Ler0/g;Llf0/i;ZZZLvy/o;Lbo0/l;Lvy/n;Z)V
    .locals 1

    const-string v0, "subscriptionLicenseState"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "viewMode"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "status"

    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "plan"

    invoke-static {p7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "gauge"

    invoke-static {p8, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lvy/p;->a:Ler0/g;

    .line 3
    iput-object p2, p0, Lvy/p;->b:Llf0/i;

    .line 4
    iput-boolean p3, p0, Lvy/p;->c:Z

    .line 5
    iput-boolean p4, p0, Lvy/p;->d:Z

    .line 6
    iput-boolean p5, p0, Lvy/p;->e:Z

    .line 7
    iput-object p6, p0, Lvy/p;->f:Lvy/o;

    .line 8
    iput-object p7, p0, Lvy/p;->g:Lbo0/l;

    .line 9
    iput-object p8, p0, Lvy/p;->h:Lvy/n;

    .line 10
    iput-boolean p9, p0, Lvy/p;->i:Z

    .line 11
    sget-object p1, Llf0/i;->h:Llf0/i;

    const/4 p3, 0x0

    const/4 p4, 0x1

    if-ne p2, p1, :cond_0

    move p1, p4

    goto :goto_0

    :cond_0
    move p1, p3

    :goto_0
    iput-boolean p1, p0, Lvy/p;->j:Z

    .line 12
    invoke-static {p2}, Llp/tf;->d(Llf0/i;)Z

    move-result p2

    iput-boolean p2, p0, Lvy/p;->k:Z

    if-nez p1, :cond_1

    if-eqz p2, :cond_2

    :cond_1
    move p3, p4

    .line 13
    :cond_2
    iput-boolean p3, p0, Lvy/p;->l:Z

    return-void
.end method

.method public static a(Lvy/p;ZZLvy/o;Lbo0/l;Lvy/n;ZI)Lvy/p;
    .locals 10

    .line 1
    move/from16 v0, p7

    .line 2
    .line 3
    iget-object v1, p0, Lvy/p;->a:Ler0/g;

    .line 4
    .line 5
    iget-object v2, p0, Lvy/p;->b:Llf0/i;

    .line 6
    .line 7
    and-int/lit8 v3, v0, 0x4

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    iget-boolean p1, p0, Lvy/p;->c:Z

    .line 12
    .line 13
    :cond_0
    move v3, p1

    .line 14
    and-int/lit8 p1, v0, 0x8

    .line 15
    .line 16
    if-eqz p1, :cond_1

    .line 17
    .line 18
    iget-boolean p2, p0, Lvy/p;->d:Z

    .line 19
    .line 20
    :cond_1
    move v4, p2

    .line 21
    and-int/lit8 p1, v0, 0x10

    .line 22
    .line 23
    if-eqz p1, :cond_2

    .line 24
    .line 25
    iget-boolean p1, p0, Lvy/p;->e:Z

    .line 26
    .line 27
    :goto_0
    move v5, p1

    .line 28
    goto :goto_1

    .line 29
    :cond_2
    const/4 p1, 0x1

    .line 30
    goto :goto_0

    .line 31
    :goto_1
    and-int/lit8 p1, v0, 0x20

    .line 32
    .line 33
    if-eqz p1, :cond_3

    .line 34
    .line 35
    iget-object p3, p0, Lvy/p;->f:Lvy/o;

    .line 36
    .line 37
    :cond_3
    move-object v6, p3

    .line 38
    and-int/lit8 p1, v0, 0x40

    .line 39
    .line 40
    if-eqz p1, :cond_4

    .line 41
    .line 42
    iget-object p4, p0, Lvy/p;->g:Lbo0/l;

    .line 43
    .line 44
    :cond_4
    move-object v7, p4

    .line 45
    and-int/lit16 p1, v0, 0x80

    .line 46
    .line 47
    if-eqz p1, :cond_5

    .line 48
    .line 49
    iget-object p1, p0, Lvy/p;->h:Lvy/n;

    .line 50
    .line 51
    move-object v8, p1

    .line 52
    goto :goto_2

    .line 53
    :cond_5
    move-object v8, p5

    .line 54
    :goto_2
    and-int/lit16 p1, v0, 0x100

    .line 55
    .line 56
    if-eqz p1, :cond_6

    .line 57
    .line 58
    iget-boolean p1, p0, Lvy/p;->i:Z

    .line 59
    .line 60
    move v9, p1

    .line 61
    goto :goto_3

    .line 62
    :cond_6
    move/from16 v9, p6

    .line 63
    .line 64
    :goto_3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 65
    .line 66
    .line 67
    const-string p0, "subscriptionLicenseState"

    .line 68
    .line 69
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    const-string p0, "viewMode"

    .line 73
    .line 74
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    const-string p0, "status"

    .line 78
    .line 79
    invoke-static {v6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    const-string p0, "plan"

    .line 83
    .line 84
    invoke-static {v7, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    const-string p0, "gauge"

    .line 88
    .line 89
    invoke-static {v8, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    new-instance v0, Lvy/p;

    .line 93
    .line 94
    invoke-direct/range {v0 .. v9}, Lvy/p;-><init>(Ler0/g;Llf0/i;ZZZLvy/o;Lbo0/l;Lvy/n;Z)V

    .line 95
    .line 96
    .line 97
    return-object v0
.end method


# virtual methods
.method public final b()Z
    .locals 4

    .line 1
    sget-object v0, Lvy/o;->h:Lvy/o;

    .line 2
    .line 3
    sget-object v1, Lvy/o;->d:Lvy/o;

    .line 4
    .line 5
    sget-object v2, Lvy/o;->e:Lvy/o;

    .line 6
    .line 7
    sget-object v3, Lvy/o;->f:Lvy/o;

    .line 8
    .line 9
    filled-new-array {v0, v1, v2, v3}, [Lvy/o;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    iget-object v1, p0, Lvy/p;->f:Lvy/o;

    .line 18
    .line 19
    invoke-interface {v0, v1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    iget-boolean v0, p0, Lvy/p;->c:Z

    .line 26
    .line 27
    if-nez v0, :cond_0

    .line 28
    .line 29
    iget-boolean p0, p0, Lvy/p;->l:Z

    .line 30
    .line 31
    if-nez p0, :cond_0

    .line 32
    .line 33
    const/4 p0, 0x1

    .line 34
    return p0

    .line 35
    :cond_0
    const/4 p0, 0x0

    .line 36
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
    instance-of v1, p1, Lvy/p;

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
    check-cast p1, Lvy/p;

    .line 12
    .line 13
    iget-object v1, p0, Lvy/p;->a:Ler0/g;

    .line 14
    .line 15
    iget-object v3, p1, Lvy/p;->a:Ler0/g;

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Lvy/p;->b:Llf0/i;

    .line 21
    .line 22
    iget-object v3, p1, Lvy/p;->b:Llf0/i;

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-boolean v1, p0, Lvy/p;->c:Z

    .line 28
    .line 29
    iget-boolean v3, p1, Lvy/p;->c:Z

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-boolean v1, p0, Lvy/p;->d:Z

    .line 35
    .line 36
    iget-boolean v3, p1, Lvy/p;->d:Z

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget-boolean v1, p0, Lvy/p;->e:Z

    .line 42
    .line 43
    iget-boolean v3, p1, Lvy/p;->e:Z

    .line 44
    .line 45
    if-eq v1, v3, :cond_6

    .line 46
    .line 47
    return v2

    .line 48
    :cond_6
    iget-object v1, p0, Lvy/p;->f:Lvy/o;

    .line 49
    .line 50
    iget-object v3, p1, Lvy/p;->f:Lvy/o;

    .line 51
    .line 52
    if-eq v1, v3, :cond_7

    .line 53
    .line 54
    return v2

    .line 55
    :cond_7
    iget-object v1, p0, Lvy/p;->g:Lbo0/l;

    .line 56
    .line 57
    iget-object v3, p1, Lvy/p;->g:Lbo0/l;

    .line 58
    .line 59
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    if-nez v1, :cond_8

    .line 64
    .line 65
    return v2

    .line 66
    :cond_8
    iget-object v1, p0, Lvy/p;->h:Lvy/n;

    .line 67
    .line 68
    iget-object v3, p1, Lvy/p;->h:Lvy/n;

    .line 69
    .line 70
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result v1

    .line 74
    if-nez v1, :cond_9

    .line 75
    .line 76
    return v2

    .line 77
    :cond_9
    iget-boolean p0, p0, Lvy/p;->i:Z

    .line 78
    .line 79
    iget-boolean p1, p1, Lvy/p;->i:Z

    .line 80
    .line 81
    if-eq p0, p1, :cond_a

    .line 82
    .line 83
    return v2

    .line 84
    :cond_a
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lvy/p;->a:Ler0/g;

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
    iget-object v2, p0, Lvy/p;->b:Llf0/i;

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
    iget-boolean v0, p0, Lvy/p;->c:Z

    .line 19
    .line 20
    invoke-static {v2, v1, v0}, La7/g0;->e(IIZ)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    iget-boolean v2, p0, Lvy/p;->d:Z

    .line 25
    .line 26
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    iget-boolean v2, p0, Lvy/p;->e:Z

    .line 31
    .line 32
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    iget-object v2, p0, Lvy/p;->f:Lvy/o;

    .line 37
    .line 38
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 39
    .line 40
    .line 41
    move-result v2

    .line 42
    add-int/2addr v2, v0

    .line 43
    mul-int/2addr v2, v1

    .line 44
    iget-object v0, p0, Lvy/p;->g:Lbo0/l;

    .line 45
    .line 46
    invoke-virtual {v0}, Lbo0/l;->hashCode()I

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    add-int/2addr v0, v2

    .line 51
    mul-int/2addr v0, v1

    .line 52
    iget-object v2, p0, Lvy/p;->h:Lvy/n;

    .line 53
    .line 54
    invoke-virtual {v2}, Lvy/n;->hashCode()I

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    add-int/2addr v2, v0

    .line 59
    mul-int/2addr v2, v1

    .line 60
    iget-boolean p0, p0, Lvy/p;->i:Z

    .line 61
    .line 62
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 63
    .line 64
    .line 65
    move-result p0

    .line 66
    add-int/2addr p0, v2

    .line 67
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "State(subscriptionLicenseState="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lvy/p;->a:Ler0/g;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", viewMode="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lvy/p;->b:Llf0/i;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", isLoading="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", isRefreshing="

    .line 29
    .line 30
    const-string v2, ", isRefreshEnabled="

    .line 31
    .line 32
    iget-boolean v3, p0, Lvy/p;->c:Z

    .line 33
    .line 34
    iget-boolean v4, p0, Lvy/p;->d:Z

    .line 35
    .line 36
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 37
    .line 38
    .line 39
    iget-boolean v1, p0, Lvy/p;->e:Z

    .line 40
    .line 41
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string v1, ", status="

    .line 45
    .line 46
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    iget-object v1, p0, Lvy/p;->f:Lvy/o;

    .line 50
    .line 51
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const-string v1, ", plan="

    .line 55
    .line 56
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    iget-object v1, p0, Lvy/p;->g:Lbo0/l;

    .line 60
    .line 61
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    const-string v1, ", gauge="

    .line 65
    .line 66
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    iget-object v1, p0, Lvy/p;->h:Lvy/n;

    .line 70
    .line 71
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    const-string v1, ", hasOutsideTemperatureCapability="

    .line 75
    .line 76
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    const-string v1, ")"

    .line 80
    .line 81
    iget-boolean p0, p0, Lvy/p;->i:Z

    .line 82
    .line 83
    invoke-static {v0, p0, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    return-object p0
.end method
