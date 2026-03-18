.class public final Lvk0/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvk0/j0;


# instance fields
.field public final a:Lvk0/d;

.field public final b:Ljava/util/List;

.field public final c:Ljava/util/Set;

.field public final d:Ljava/lang/Object;

.field public final e:Ljava/lang/Object;

.field public final f:Ljava/lang/Object;

.field public final g:Ljava/util/List;

.field public final h:Lvk0/n;


# direct methods
.method public constructor <init>(Lvk0/d;Ljava/util/List;Ljava/util/Set;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/ArrayList;Lvk0/n;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lvk0/j;->a:Lvk0/d;

    .line 5
    .line 6
    iput-object p2, p0, Lvk0/j;->b:Ljava/util/List;

    .line 7
    .line 8
    iput-object p3, p0, Lvk0/j;->c:Ljava/util/Set;

    .line 9
    .line 10
    iput-object p4, p0, Lvk0/j;->d:Ljava/lang/Object;

    .line 11
    .line 12
    iput-object p5, p0, Lvk0/j;->e:Ljava/lang/Object;

    .line 13
    .line 14
    iput-object p6, p0, Lvk0/j;->f:Ljava/lang/Object;

    .line 15
    .line 16
    iput-object p7, p0, Lvk0/j;->g:Ljava/util/List;

    .line 17
    .line 18
    iput-object p8, p0, Lvk0/j;->h:Lvk0/n;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final a()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/j;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->m:Ljava/lang/String;

    .line 4
    .line 5
    return-object p0
.end method

.method public final b()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/j;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->e:Ljava/lang/String;

    .line 4
    .line 5
    return-object p0
.end method

.method public final c()Lvk0/l;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/j;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->h:Lvk0/l;

    .line 4
    .line 5
    return-object p0
.end method

.method public final d()Lvk0/i0;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/j;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->k:Lvk0/i0;

    .line 4
    .line 5
    return-object p0
.end method

.method public final e()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/j;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->j:Ljava/util/List;

    .line 4
    .line 5
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_1

    .line 4
    :cond_0
    instance-of v0, p1, Lvk0/j;

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_1
    check-cast p1, Lvk0/j;

    .line 10
    .line 11
    iget-object v0, p0, Lvk0/j;->a:Lvk0/d;

    .line 12
    .line 13
    iget-object v1, p1, Lvk0/j;->a:Lvk0/d;

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Lvk0/d;->equals(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-nez v0, :cond_2

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_2
    iget-object v0, p0, Lvk0/j;->b:Ljava/util/List;

    .line 23
    .line 24
    iget-object v1, p1, Lvk0/j;->b:Ljava/util/List;

    .line 25
    .line 26
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-nez v0, :cond_3

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_3
    iget-object v0, p0, Lvk0/j;->c:Ljava/util/Set;

    .line 34
    .line 35
    iget-object v1, p1, Lvk0/j;->c:Ljava/util/Set;

    .line 36
    .line 37
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-nez v0, :cond_4

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_4
    iget-object v0, p0, Lvk0/j;->d:Ljava/lang/Object;

    .line 45
    .line 46
    iget-object v1, p1, Lvk0/j;->d:Ljava/lang/Object;

    .line 47
    .line 48
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    if-nez v0, :cond_5

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_5
    iget-object v0, p0, Lvk0/j;->e:Ljava/lang/Object;

    .line 56
    .line 57
    iget-object v1, p1, Lvk0/j;->e:Ljava/lang/Object;

    .line 58
    .line 59
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    if-nez v0, :cond_6

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_6
    iget-object v0, p0, Lvk0/j;->f:Ljava/lang/Object;

    .line 67
    .line 68
    iget-object v1, p1, Lvk0/j;->f:Ljava/lang/Object;

    .line 69
    .line 70
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    if-nez v0, :cond_7

    .line 75
    .line 76
    goto :goto_0

    .line 77
    :cond_7
    iget-object v0, p0, Lvk0/j;->g:Ljava/util/List;

    .line 78
    .line 79
    iget-object v1, p1, Lvk0/j;->g:Ljava/util/List;

    .line 80
    .line 81
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result v0

    .line 85
    if-nez v0, :cond_8

    .line 86
    .line 87
    goto :goto_0

    .line 88
    :cond_8
    iget-object p0, p0, Lvk0/j;->h:Lvk0/n;

    .line 89
    .line 90
    iget-object p1, p1, Lvk0/j;->h:Lvk0/n;

    .line 91
    .line 92
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result p0

    .line 96
    if-nez p0, :cond_9

    .line 97
    .line 98
    :goto_0
    const/4 p0, 0x0

    .line 99
    return p0

    .line 100
    :cond_9
    :goto_1
    const/4 p0, 0x1

    .line 101
    return p0
.end method

.method public final f()Lvk0/y;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/j;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->n:Lvk0/y;

    .line 4
    .line 5
    return-object p0
.end method

.method public final g()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/j;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->g:Ljava/util/List;

    .line 4
    .line 5
    return-object p0
.end method

.method public final getAddress()Lbl0/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/j;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->d:Lbl0/a;

    .line 4
    .line 5
    return-object p0
.end method

.method public final getDescription()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/j;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->c:Ljava/lang/String;

    .line 4
    .line 5
    return-object p0
.end method

.method public final getId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/j;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->a:Ljava/lang/String;

    .line 4
    .line 5
    return-object p0
.end method

.method public final getLocation()Lxj0/f;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/j;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->f:Lxj0/f;

    .line 4
    .line 5
    return-object p0
.end method

.method public final getName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/j;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->b:Ljava/lang/String;

    .line 4
    .line 5
    return-object p0
.end method

.method public final h()Loo0/b;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/j;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->l:Loo0/b;

    .line 4
    .line 5
    return-object p0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lvk0/j;->a:Lvk0/d;

    .line 2
    .line 3
    invoke-virtual {v0}, Lvk0/d;->hashCode()I

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
    iget-object v2, p0, Lvk0/j;->b:Ljava/util/List;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lvk0/j;->c:Ljava/util/Set;

    .line 17
    .line 18
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v0

    .line 23
    mul-int/2addr v2, v1

    .line 24
    iget-object v0, p0, Lvk0/j;->d:Ljava/lang/Object;

    .line 25
    .line 26
    invoke-static {v2, v0, v1}, Lp3/m;->b(ILjava/lang/Object;I)I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    iget-object v2, p0, Lvk0/j;->e:Ljava/lang/Object;

    .line 31
    .line 32
    invoke-static {v0, v2, v1}, Lp3/m;->b(ILjava/lang/Object;I)I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    iget-object v2, p0, Lvk0/j;->f:Ljava/lang/Object;

    .line 37
    .line 38
    invoke-static {v0, v2, v1}, Lp3/m;->b(ILjava/lang/Object;I)I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    const/4 v2, 0x0

    .line 43
    iget-object v3, p0, Lvk0/j;->g:Ljava/util/List;

    .line 44
    .line 45
    if-nez v3, :cond_0

    .line 46
    .line 47
    move v3, v2

    .line 48
    goto :goto_0

    .line 49
    :cond_0
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    :goto_0
    add-int/2addr v0, v3

    .line 54
    mul-int/2addr v0, v1

    .line 55
    iget-object p0, p0, Lvk0/j;->h:Lvk0/n;

    .line 56
    .line 57
    if-nez p0, :cond_1

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_1
    invoke-virtual {p0}, Lvk0/n;->hashCode()I

    .line 61
    .line 62
    .line 63
    move-result v2

    .line 64
    :goto_1
    add-int/2addr v0, v2

    .line 65
    return v0
.end method

.method public final i()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/j;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->i:Ljava/lang/Boolean;

    .line 4
    .line 5
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "ChargingStation(detail="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lvk0/j;->a:Lvk0/d;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", chargingOperators="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lvk0/j;->b:Ljava/util/List;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", groupPartners="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lvk0/j;->c:Ljava/util/Set;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", authorizations="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lvk0/j;->d:Ljava/lang/Object;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", connectors="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Lvk0/j;->e:Ljava/lang/Object;

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", paymentMethods="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object v1, p0, Lvk0/j;->f:Ljava/lang/Object;

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", amenities="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget-object v1, p0, Lvk0/j;->g:Ljava/util/List;

    .line 69
    .line 70
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v1, ", dailyPopularity="

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    iget-object p0, p0, Lvk0/j;->h:Lvk0/n;

    .line 79
    .line 80
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string p0, ")"

    .line 84
    .line 85
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    return-object p0
.end method
