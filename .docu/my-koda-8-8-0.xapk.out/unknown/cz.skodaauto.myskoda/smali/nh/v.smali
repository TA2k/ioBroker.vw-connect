.class public final Lnh/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Z

.field public final c:Z

.field public final d:Z

.field public final e:Llc/l;

.field public final f:Ljava/util/List;

.field public final g:Lnh/h;

.field public final h:Z

.field public final i:Z

.field public final j:Z


# direct methods
.method public constructor <init>(Ljava/lang/String;ZZZLlc/l;Ljava/util/List;Lnh/h;ZZZ)V
    .locals 1

    .line 1
    const-string v0, "homeChargingCards"

    .line 2
    .line 3
    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "screenState"

    .line 7
    .line 8
    invoke-static {p7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lnh/v;->a:Ljava/lang/String;

    .line 15
    .line 16
    iput-boolean p2, p0, Lnh/v;->b:Z

    .line 17
    .line 18
    iput-boolean p3, p0, Lnh/v;->c:Z

    .line 19
    .line 20
    iput-boolean p4, p0, Lnh/v;->d:Z

    .line 21
    .line 22
    iput-object p5, p0, Lnh/v;->e:Llc/l;

    .line 23
    .line 24
    iput-object p6, p0, Lnh/v;->f:Ljava/util/List;

    .line 25
    .line 26
    iput-object p7, p0, Lnh/v;->g:Lnh/h;

    .line 27
    .line 28
    iput-boolean p8, p0, Lnh/v;->h:Z

    .line 29
    .line 30
    iput-boolean p9, p0, Lnh/v;->i:Z

    .line 31
    .line 32
    iput-boolean p10, p0, Lnh/v;->j:Z

    .line 33
    .line 34
    return-void
.end method

.method public static a(Lnh/v;Ljava/lang/String;ZZZLlc/l;Ljava/util/ArrayList;Lnh/h;I)Lnh/v;
    .locals 11

    .line 1
    move/from16 v0, p8

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object p1, p0, Lnh/v;->a:Ljava/lang/String;

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
    iget-boolean p1, p0, Lnh/v;->b:Z

    .line 15
    .line 16
    move v2, p1

    .line 17
    goto :goto_0

    .line 18
    :cond_1
    move v2, p2

    .line 19
    :goto_0
    and-int/lit8 p1, v0, 0x4

    .line 20
    .line 21
    if-eqz p1, :cond_2

    .line 22
    .line 23
    iget-boolean p1, p0, Lnh/v;->c:Z

    .line 24
    .line 25
    move v3, p1

    .line 26
    goto :goto_1

    .line 27
    :cond_2
    move v3, p3

    .line 28
    :goto_1
    and-int/lit8 p1, v0, 0x8

    .line 29
    .line 30
    if-eqz p1, :cond_3

    .line 31
    .line 32
    iget-boolean p1, p0, Lnh/v;->d:Z

    .line 33
    .line 34
    move v4, p1

    .line 35
    goto :goto_2

    .line 36
    :cond_3
    move v4, p4

    .line 37
    :goto_2
    and-int/lit8 p1, v0, 0x10

    .line 38
    .line 39
    if-eqz p1, :cond_4

    .line 40
    .line 41
    iget-object p1, p0, Lnh/v;->e:Llc/l;

    .line 42
    .line 43
    move-object v5, p1

    .line 44
    goto :goto_3

    .line 45
    :cond_4
    move-object/from16 v5, p5

    .line 46
    .line 47
    :goto_3
    and-int/lit8 p1, v0, 0x20

    .line 48
    .line 49
    if-eqz p1, :cond_5

    .line 50
    .line 51
    iget-object p1, p0, Lnh/v;->f:Ljava/util/List;

    .line 52
    .line 53
    move-object v6, p1

    .line 54
    goto :goto_4

    .line 55
    :cond_5
    move-object/from16 v6, p6

    .line 56
    .line 57
    :goto_4
    and-int/lit8 p1, v0, 0x40

    .line 58
    .line 59
    if-eqz p1, :cond_6

    .line 60
    .line 61
    iget-object p1, p0, Lnh/v;->g:Lnh/h;

    .line 62
    .line 63
    move-object v7, p1

    .line 64
    goto :goto_5

    .line 65
    :cond_6
    move-object/from16 v7, p7

    .line 66
    .line 67
    :goto_5
    and-int/lit16 p1, v0, 0x80

    .line 68
    .line 69
    const/4 v8, 0x1

    .line 70
    if-eqz p1, :cond_7

    .line 71
    .line 72
    iget-boolean p1, p0, Lnh/v;->h:Z

    .line 73
    .line 74
    goto :goto_6

    .line 75
    :cond_7
    move p1, v8

    .line 76
    :goto_6
    and-int/lit16 v9, v0, 0x100

    .line 77
    .line 78
    if-eqz v9, :cond_8

    .line 79
    .line 80
    iget-boolean v9, p0, Lnh/v;->i:Z

    .line 81
    .line 82
    goto :goto_7

    .line 83
    :cond_8
    move v9, v8

    .line 84
    :goto_7
    and-int/lit16 v0, v0, 0x200

    .line 85
    .line 86
    if-eqz v0, :cond_9

    .line 87
    .line 88
    iget-boolean v8, p0, Lnh/v;->j:Z

    .line 89
    .line 90
    :cond_9
    move v10, v8

    .line 91
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 92
    .line 93
    .line 94
    const-string p0, "cardCode"

    .line 95
    .line 96
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    const-string p0, "homeChargingCards"

    .line 100
    .line 101
    invoke-static {v6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    const-string p0, "screenState"

    .line 105
    .line 106
    invoke-static {v7, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    new-instance v0, Lnh/v;

    .line 110
    .line 111
    move v8, p1

    .line 112
    invoke-direct/range {v0 .. v10}, Lnh/v;-><init>(Ljava/lang/String;ZZZLlc/l;Ljava/util/List;Lnh/h;ZZZ)V

    .line 113
    .line 114
    .line 115
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
    instance-of v1, p1, Lnh/v;

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
    check-cast p1, Lnh/v;

    .line 12
    .line 13
    iget-object v1, p0, Lnh/v;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lnh/v;->a:Ljava/lang/String;

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
    iget-boolean v1, p0, Lnh/v;->b:Z

    .line 25
    .line 26
    iget-boolean v3, p1, Lnh/v;->b:Z

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-boolean v1, p0, Lnh/v;->c:Z

    .line 32
    .line 33
    iget-boolean v3, p1, Lnh/v;->c:Z

    .line 34
    .line 35
    if-eq v1, v3, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    iget-boolean v1, p0, Lnh/v;->d:Z

    .line 39
    .line 40
    iget-boolean v3, p1, Lnh/v;->d:Z

    .line 41
    .line 42
    if-eq v1, v3, :cond_5

    .line 43
    .line 44
    return v2

    .line 45
    :cond_5
    iget-object v1, p0, Lnh/v;->e:Llc/l;

    .line 46
    .line 47
    iget-object v3, p1, Lnh/v;->e:Llc/l;

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
    iget-object v1, p0, Lnh/v;->f:Ljava/util/List;

    .line 57
    .line 58
    iget-object v3, p1, Lnh/v;->f:Ljava/util/List;

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
    iget-object v1, p0, Lnh/v;->g:Lnh/h;

    .line 68
    .line 69
    iget-object v3, p1, Lnh/v;->g:Lnh/h;

    .line 70
    .line 71
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v1

    .line 75
    if-nez v1, :cond_8

    .line 76
    .line 77
    return v2

    .line 78
    :cond_8
    iget-boolean v1, p0, Lnh/v;->h:Z

    .line 79
    .line 80
    iget-boolean v3, p1, Lnh/v;->h:Z

    .line 81
    .line 82
    if-eq v1, v3, :cond_9

    .line 83
    .line 84
    return v2

    .line 85
    :cond_9
    iget-boolean v1, p0, Lnh/v;->i:Z

    .line 86
    .line 87
    iget-boolean v3, p1, Lnh/v;->i:Z

    .line 88
    .line 89
    if-eq v1, v3, :cond_a

    .line 90
    .line 91
    return v2

    .line 92
    :cond_a
    iget-boolean p0, p0, Lnh/v;->j:Z

    .line 93
    .line 94
    iget-boolean p1, p1, Lnh/v;->j:Z

    .line 95
    .line 96
    if-eq p0, p1, :cond_b

    .line 97
    .line 98
    return v2

    .line 99
    :cond_b
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lnh/v;->a:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

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
    iget-boolean v2, p0, Lnh/v;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Lnh/v;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Lnh/v;->d:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Lnh/v;->e:Llc/l;

    .line 29
    .line 30
    if-nez v2, :cond_0

    .line 31
    .line 32
    const/4 v2, 0x0

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    invoke-virtual {v2}, Llc/l;->hashCode()I

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    :goto_0
    add-int/2addr v0, v2

    .line 39
    mul-int/2addr v0, v1

    .line 40
    iget-object v2, p0, Lnh/v;->f:Ljava/util/List;

    .line 41
    .line 42
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-object v2, p0, Lnh/v;->g:Lnh/h;

    .line 47
    .line 48
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    add-int/2addr v2, v0

    .line 53
    mul-int/2addr v2, v1

    .line 54
    iget-boolean v0, p0, Lnh/v;->h:Z

    .line 55
    .line 56
    invoke-static {v2, v1, v0}, La7/g0;->e(IIZ)I

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    iget-boolean v2, p0, Lnh/v;->i:Z

    .line 61
    .line 62
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    iget-boolean p0, p0, Lnh/v;->j:Z

    .line 67
    .line 68
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    add-int/2addr p0, v0

    .line 73
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", isConnectingChargingCard="

    .line 2
    .line 3
    const-string v1, ", isFetchingChargingCards="

    .line 4
    .line 5
    const-string v2, "WallboxAddChargingCardViewModelState(cardCode="

    .line 6
    .line 7
    iget-object v3, p0, Lnh/v;->a:Ljava/lang/String;

    .line 8
    .line 9
    iget-boolean v4, p0, Lnh/v;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v1, v4}, Lia/b;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", isCardConnectRequestFailed="

    .line 16
    .line 17
    const-string v2, ", error="

    .line 18
    .line 19
    iget-boolean v3, p0, Lnh/v;->c:Z

    .line 20
    .line 21
    iget-boolean v4, p0, Lnh/v;->d:Z

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object v1, p0, Lnh/v;->e:Llc/l;

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v1, ", homeChargingCards="

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget-object v1, p0, Lnh/v;->f:Ljava/util/List;

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v1, ", screenState="

    .line 42
    .line 43
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    iget-object v1, p0, Lnh/v;->g:Lnh/h;

    .line 47
    .line 48
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    const-string v1, ", userFinishAddChargingCard="

    .line 52
    .line 53
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    iget-boolean v1, p0, Lnh/v;->h:Z

    .line 57
    .line 58
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    const-string v1, ", isCancelingAddChargingCard="

    .line 62
    .line 63
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    const-string v1, ", isChargingCardSuccessfullyConnected="

    .line 67
    .line 68
    const-string v2, ")"

    .line 69
    .line 70
    iget-boolean v3, p0, Lnh/v;->i:Z

    .line 71
    .line 72
    iget-boolean p0, p0, Lnh/v;->j:Z

    .line 73
    .line 74
    invoke-static {v0, v3, v1, p0, v2}, Lvj/b;->l(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    return-object p0
.end method
