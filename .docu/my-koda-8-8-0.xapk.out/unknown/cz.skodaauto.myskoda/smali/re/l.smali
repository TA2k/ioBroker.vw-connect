.class public final Lre/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/util/List;

.field public final b:Lje/r;

.field public final c:Z

.field public final d:Llc/l;

.field public final e:Z

.field public final f:Z


# direct methods
.method public constructor <init>(Ljava/util/List;Lje/r;ZLlc/l;ZZ)V
    .locals 1

    .line 1
    const-string v0, "currencies"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lre/l;->a:Ljava/util/List;

    .line 10
    .line 11
    iput-object p2, p0, Lre/l;->b:Lje/r;

    .line 12
    .line 13
    iput-boolean p3, p0, Lre/l;->c:Z

    .line 14
    .line 15
    iput-object p4, p0, Lre/l;->d:Llc/l;

    .line 16
    .line 17
    iput-boolean p5, p0, Lre/l;->e:Z

    .line 18
    .line 19
    iput-boolean p6, p0, Lre/l;->f:Z

    .line 20
    .line 21
    return-void
.end method

.method public static a(Lre/l;Ljava/util/List;ZLlc/l;ZZI)Lre/l;
    .locals 7

    .line 1
    and-int/lit8 v0, p6, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lre/l;->a:Ljava/util/List;

    .line 6
    .line 7
    :cond_0
    move-object v1, p1

    .line 8
    and-int/lit8 p1, p6, 0x2

    .line 9
    .line 10
    if-eqz p1, :cond_1

    .line 11
    .line 12
    iget-object p1, p0, Lre/l;->b:Lje/r;

    .line 13
    .line 14
    :goto_0
    move-object v2, p1

    .line 15
    goto :goto_1

    .line 16
    :cond_1
    const/4 p1, 0x0

    .line 17
    goto :goto_0

    .line 18
    :goto_1
    and-int/lit8 p1, p6, 0x4

    .line 19
    .line 20
    if-eqz p1, :cond_2

    .line 21
    .line 22
    iget-boolean p2, p0, Lre/l;->c:Z

    .line 23
    .line 24
    :cond_2
    move v3, p2

    .line 25
    and-int/lit8 p1, p6, 0x8

    .line 26
    .line 27
    if-eqz p1, :cond_3

    .line 28
    .line 29
    iget-object p3, p0, Lre/l;->d:Llc/l;

    .line 30
    .line 31
    :cond_3
    move-object v4, p3

    .line 32
    and-int/lit8 p1, p6, 0x10

    .line 33
    .line 34
    if-eqz p1, :cond_4

    .line 35
    .line 36
    iget-boolean p4, p0, Lre/l;->e:Z

    .line 37
    .line 38
    :cond_4
    move v5, p4

    .line 39
    and-int/lit8 p1, p6, 0x20

    .line 40
    .line 41
    if-eqz p1, :cond_5

    .line 42
    .line 43
    iget-boolean p5, p0, Lre/l;->f:Z

    .line 44
    .line 45
    :cond_5
    move v6, p5

    .line 46
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    const-string p0, "currencies"

    .line 50
    .line 51
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    new-instance v0, Lre/l;

    .line 55
    .line 56
    invoke-direct/range {v0 .. v6}, Lre/l;-><init>(Ljava/util/List;Lje/r;ZLlc/l;ZZ)V

    .line 57
    .line 58
    .line 59
    return-object v0
.end method


# virtual methods
.method public final b()Lre/i;
    .locals 5

    .line 1
    iget-boolean v0, p0, Lre/l;->f:Z

    .line 2
    .line 3
    iget-boolean v1, p0, Lre/l;->e:Z

    .line 4
    .line 5
    iget-object v2, p0, Lre/l;->d:Llc/l;

    .line 6
    .line 7
    iget-boolean v3, p0, Lre/l;->c:Z

    .line 8
    .line 9
    if-nez v3, :cond_1

    .line 10
    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    new-instance v2, Lre/g;

    .line 15
    .line 16
    new-instance v3, Lre/a;

    .line 17
    .line 18
    iget-object v4, p0, Lre/l;->a:Ljava/util/List;

    .line 19
    .line 20
    iget-object p0, p0, Lre/l;->b:Lje/r;

    .line 21
    .line 22
    invoke-direct {v3, v4, p0}, Lre/a;-><init>(Ljava/util/List;Lje/r;)V

    .line 23
    .line 24
    .line 25
    invoke-direct {v2, v3, v1, v0}, Lre/g;-><init>(Lre/a;ZZ)V

    .line 26
    .line 27
    .line 28
    return-object v2

    .line 29
    :cond_1
    :goto_0
    new-instance p0, Lre/h;

    .line 30
    .line 31
    invoke-direct {p0, v3, v2, v1, v0}, Lre/h;-><init>(ZLlc/l;ZZ)V

    .line 32
    .line 33
    .line 34
    return-object p0
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
    instance-of v1, p1, Lre/l;

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
    check-cast p1, Lre/l;

    .line 12
    .line 13
    iget-object v1, p0, Lre/l;->a:Ljava/util/List;

    .line 14
    .line 15
    iget-object v3, p1, Lre/l;->a:Ljava/util/List;

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
    iget-object v1, p0, Lre/l;->b:Lje/r;

    .line 25
    .line 26
    iget-object v3, p1, Lre/l;->b:Lje/r;

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
    iget-boolean v1, p0, Lre/l;->c:Z

    .line 36
    .line 37
    iget-boolean v3, p1, Lre/l;->c:Z

    .line 38
    .line 39
    if-eq v1, v3, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object v1, p0, Lre/l;->d:Llc/l;

    .line 43
    .line 44
    iget-object v3, p1, Lre/l;->d:Llc/l;

    .line 45
    .line 46
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-nez v1, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget-boolean v1, p0, Lre/l;->e:Z

    .line 54
    .line 55
    iget-boolean v3, p1, Lre/l;->e:Z

    .line 56
    .line 57
    if-eq v1, v3, :cond_6

    .line 58
    .line 59
    return v2

    .line 60
    :cond_6
    iget-boolean p0, p0, Lre/l;->f:Z

    .line 61
    .line 62
    iget-boolean p1, p1, Lre/l;->f:Z

    .line 63
    .line 64
    if-eq p0, p1, :cond_7

    .line 65
    .line 66
    return v2

    .line 67
    :cond_7
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lre/l;->a:Ljava/util/List;

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
    const/4 v2, 0x0

    .line 11
    iget-object v3, p0, Lre/l;->b:Lje/r;

    .line 12
    .line 13
    if-nez v3, :cond_0

    .line 14
    .line 15
    move v3, v2

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    invoke-virtual {v3}, Lje/r;->hashCode()I

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    :goto_0
    add-int/2addr v0, v3

    .line 22
    mul-int/2addr v0, v1

    .line 23
    iget-boolean v3, p0, Lre/l;->c:Z

    .line 24
    .line 25
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    iget-object v3, p0, Lre/l;->d:Llc/l;

    .line 30
    .line 31
    if-nez v3, :cond_1

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_1
    invoke-virtual {v3}, Llc/l;->hashCode()I

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    :goto_1
    add-int/2addr v0, v2

    .line 39
    mul-int/2addr v0, v1

    .line 40
    iget-boolean v2, p0, Lre/l;->e:Z

    .line 41
    .line 42
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-boolean p0, p0, Lre/l;->f:Z

    .line 47
    .line 48
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    add-int/2addr p0, v0

    .line 53
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "KolaWizardSetupCurrencyViewModelState(currencies="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lre/l;->a:Ljava/util/List;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", selectedCurrency="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lre/l;->b:Lje/r;

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
    iget-boolean v1, p0, Lre/l;->c:Z

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", error="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lre/l;->d:Llc/l;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", isBackSelected="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    const-string v1, ", isNextSelected="

    .line 49
    .line 50
    const-string v2, ")"

    .line 51
    .line 52
    iget-boolean v3, p0, Lre/l;->e:Z

    .line 53
    .line 54
    iget-boolean p0, p0, Lre/l;->f:Z

    .line 55
    .line 56
    invoke-static {v0, v3, v1, p0, v2}, Lvj/b;->l(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    return-object p0
.end method
