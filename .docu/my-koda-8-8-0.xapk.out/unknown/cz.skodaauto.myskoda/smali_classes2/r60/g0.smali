.class public final Lr60/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Lql0/g;

.field public final b:Z

.field public final c:Z

.field public final d:Ljava/util/List;

.field public final e:Ljava/util/List;

.field public final f:Z


# direct methods
.method public constructor <init>(Ljava/util/List;Ljava/util/List;Lql0/g;ZZZ)V
    .locals 1

    .line 1
    const-string v0, "payToParkSupportedCountries"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "payToFuelSupportedCountries"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p3, p0, Lr60/g0;->a:Lql0/g;

    .line 15
    .line 16
    iput-boolean p4, p0, Lr60/g0;->b:Z

    .line 17
    .line 18
    iput-boolean p5, p0, Lr60/g0;->c:Z

    .line 19
    .line 20
    iput-object p1, p0, Lr60/g0;->d:Ljava/util/List;

    .line 21
    .line 22
    iput-object p2, p0, Lr60/g0;->e:Ljava/util/List;

    .line 23
    .line 24
    iput-boolean p6, p0, Lr60/g0;->f:Z

    .line 25
    .line 26
    return-void
.end method

.method public static a(Lr60/g0;Lql0/g;ZLjava/util/List;Ljava/util/List;ZI)Lr60/g0;
    .locals 7

    .line 1
    and-int/lit8 v0, p6, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lr60/g0;->a:Lql0/g;

    .line 6
    .line 7
    :cond_0
    move-object v3, p1

    .line 8
    and-int/lit8 p1, p6, 0x2

    .line 9
    .line 10
    if-eqz p1, :cond_1

    .line 11
    .line 12
    iget-boolean p2, p0, Lr60/g0;->b:Z

    .line 13
    .line 14
    :cond_1
    move v4, p2

    .line 15
    and-int/lit8 p1, p6, 0x4

    .line 16
    .line 17
    if-eqz p1, :cond_2

    .line 18
    .line 19
    iget-boolean p1, p0, Lr60/g0;->c:Z

    .line 20
    .line 21
    :goto_0
    move v5, p1

    .line 22
    goto :goto_1

    .line 23
    :cond_2
    const/4 p1, 0x1

    .line 24
    goto :goto_0

    .line 25
    :goto_1
    and-int/lit8 p1, p6, 0x8

    .line 26
    .line 27
    if-eqz p1, :cond_3

    .line 28
    .line 29
    iget-object p3, p0, Lr60/g0;->d:Ljava/util/List;

    .line 30
    .line 31
    :cond_3
    move-object v1, p3

    .line 32
    and-int/lit8 p1, p6, 0x10

    .line 33
    .line 34
    if-eqz p1, :cond_4

    .line 35
    .line 36
    iget-object p4, p0, Lr60/g0;->e:Ljava/util/List;

    .line 37
    .line 38
    :cond_4
    move-object v2, p4

    .line 39
    and-int/lit8 p1, p6, 0x20

    .line 40
    .line 41
    if-eqz p1, :cond_5

    .line 42
    .line 43
    iget-boolean p5, p0, Lr60/g0;->f:Z

    .line 44
    .line 45
    :cond_5
    move v6, p5

    .line 46
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    const-string p0, "payToParkSupportedCountries"

    .line 50
    .line 51
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    const-string p0, "payToFuelSupportedCountries"

    .line 55
    .line 56
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    new-instance v0, Lr60/g0;

    .line 60
    .line 61
    invoke-direct/range {v0 .. v6}, Lr60/g0;-><init>(Ljava/util/List;Ljava/util/List;Lql0/g;ZZZ)V

    .line 62
    .line 63
    .line 64
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
    instance-of v1, p1, Lr60/g0;

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
    check-cast p1, Lr60/g0;

    .line 12
    .line 13
    iget-object v1, p0, Lr60/g0;->a:Lql0/g;

    .line 14
    .line 15
    iget-object v3, p1, Lr60/g0;->a:Lql0/g;

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
    iget-boolean v1, p0, Lr60/g0;->b:Z

    .line 25
    .line 26
    iget-boolean v3, p1, Lr60/g0;->b:Z

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-boolean v1, p0, Lr60/g0;->c:Z

    .line 32
    .line 33
    iget-boolean v3, p1, Lr60/g0;->c:Z

    .line 34
    .line 35
    if-eq v1, v3, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    iget-object v1, p0, Lr60/g0;->d:Ljava/util/List;

    .line 39
    .line 40
    iget-object v3, p1, Lr60/g0;->d:Ljava/util/List;

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
    iget-object v1, p0, Lr60/g0;->e:Ljava/util/List;

    .line 50
    .line 51
    iget-object v3, p1, Lr60/g0;->e:Ljava/util/List;

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
    iget-boolean p0, p0, Lr60/g0;->f:Z

    .line 61
    .line 62
    iget-boolean p1, p1, Lr60/g0;->f:Z

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
    .locals 3

    .line 1
    iget-object v0, p0, Lr60/g0;->a:Lql0/g;

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
    invoke-virtual {v0}, Lql0/g;->hashCode()I

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
    iget-boolean v2, p0, Lr60/g0;->b:Z

    .line 15
    .line 16
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    iget-boolean v2, p0, Lr60/g0;->c:Z

    .line 21
    .line 22
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    iget-object v2, p0, Lr60/g0;->d:Ljava/util/List;

    .line 27
    .line 28
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    iget-object v2, p0, Lr60/g0;->e:Ljava/util/List;

    .line 33
    .line 34
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    iget-boolean p0, p0, Lr60/g0;->f:Z

    .line 39
    .line 40
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    add-int/2addr p0, v0

    .line 45
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", isLoading="

    .line 2
    .line 3
    const-string v1, ", isEmptyState="

    .line 4
    .line 5
    const-string v2, "State(error="

    .line 6
    .line 7
    iget-object v3, p0, Lr60/g0;->a:Lql0/g;

    .line 8
    .line 9
    iget-boolean v4, p0, Lr60/g0;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v4, v1}, Lp3/m;->s(Ljava/lang/String;Lql0/g;Ljava/lang/String;ZLjava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iget-boolean v1, p0, Lr60/g0;->c:Z

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const-string v1, ", payToParkSupportedCountries="

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    iget-object v1, p0, Lr60/g0;->d:Ljava/util/List;

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v1, ", payToFuelSupportedCountries="

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    iget-object v1, p0, Lr60/g0;->e:Ljava/util/List;

    .line 36
    .line 37
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    const-string v1, ", isParkFuelEnabled="

    .line 41
    .line 42
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    iget-boolean p0, p0, Lr60/g0;->f:Z

    .line 46
    .line 47
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string p0, ")"

    .line 51
    .line 52
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0
.end method
