.class public final Lze/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/util/List;

.field public final c:Ljava/util/List;

.field public final d:Z

.field public final e:Z

.field public final f:Lqe/a;

.field public final g:Ljava/util/List;

.field public final h:Z

.field public final i:Llc/l;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/util/List;Ljava/util/List;ZZLqe/a;Ljava/util/List;ZLlc/l;)V
    .locals 1

    .line 1
    const-string v0, "currencySymbol"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "season"

    .line 7
    .line 8
    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "selectedDays"

    .line 12
    .line 13
    invoke-static {p7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lze/d;->a:Ljava/lang/String;

    .line 20
    .line 21
    iput-object p2, p0, Lze/d;->b:Ljava/util/List;

    .line 22
    .line 23
    iput-object p3, p0, Lze/d;->c:Ljava/util/List;

    .line 24
    .line 25
    iput-boolean p4, p0, Lze/d;->d:Z

    .line 26
    .line 27
    iput-boolean p5, p0, Lze/d;->e:Z

    .line 28
    .line 29
    iput-object p6, p0, Lze/d;->f:Lqe/a;

    .line 30
    .line 31
    iput-object p7, p0, Lze/d;->g:Ljava/util/List;

    .line 32
    .line 33
    iput-boolean p8, p0, Lze/d;->h:Z

    .line 34
    .line 35
    iput-object p9, p0, Lze/d;->i:Llc/l;

    .line 36
    .line 37
    return-void
.end method

.method public static a(Lze/d;Ljava/util/ArrayList;ZZLlc/l;I)Lze/d;
    .locals 10

    .line 1
    iget-object v1, p0, Lze/d;->a:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v2, p0, Lze/d;->b:Ljava/util/List;

    .line 4
    .line 5
    and-int/lit8 v0, p5, 0x4

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget-object p1, p0, Lze/d;->c:Ljava/util/List;

    .line 10
    .line 11
    :cond_0
    move-object v3, p1

    .line 12
    and-int/lit8 p1, p5, 0x8

    .line 13
    .line 14
    if-eqz p1, :cond_1

    .line 15
    .line 16
    iget-boolean p2, p0, Lze/d;->d:Z

    .line 17
    .line 18
    :cond_1
    move v4, p2

    .line 19
    and-int/lit8 p1, p5, 0x10

    .line 20
    .line 21
    if-eqz p1, :cond_2

    .line 22
    .line 23
    iget-boolean p3, p0, Lze/d;->e:Z

    .line 24
    .line 25
    :cond_2
    move v5, p3

    .line 26
    iget-object v6, p0, Lze/d;->f:Lqe/a;

    .line 27
    .line 28
    iget-object v7, p0, Lze/d;->g:Ljava/util/List;

    .line 29
    .line 30
    iget-boolean v8, p0, Lze/d;->h:Z

    .line 31
    .line 32
    and-int/lit16 p1, p5, 0x100

    .line 33
    .line 34
    if-eqz p1, :cond_3

    .line 35
    .line 36
    iget-object p4, p0, Lze/d;->i:Llc/l;

    .line 37
    .line 38
    :cond_3
    move-object v9, p4

    .line 39
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 40
    .line 41
    .line 42
    const-string p0, "currencySymbol"

    .line 43
    .line 44
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    const-string p0, "season"

    .line 48
    .line 49
    invoke-static {v6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    const-string p0, "selectedDays"

    .line 53
    .line 54
    invoke-static {v7, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    new-instance v0, Lze/d;

    .line 58
    .line 59
    invoke-direct/range {v0 .. v9}, Lze/d;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/util/List;ZZLqe/a;Ljava/util/List;ZLlc/l;)V

    .line 60
    .line 61
    .line 62
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
    instance-of v1, p1, Lze/d;

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
    check-cast p1, Lze/d;

    .line 12
    .line 13
    iget-object v1, p0, Lze/d;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lze/d;->a:Ljava/lang/String;

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
    iget-object v1, p0, Lze/d;->b:Ljava/util/List;

    .line 25
    .line 26
    iget-object v3, p1, Lze/d;->b:Ljava/util/List;

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
    iget-object v1, p0, Lze/d;->c:Ljava/util/List;

    .line 36
    .line 37
    iget-object v3, p1, Lze/d;->c:Ljava/util/List;

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
    iget-boolean v1, p0, Lze/d;->d:Z

    .line 47
    .line 48
    iget-boolean v3, p1, Lze/d;->d:Z

    .line 49
    .line 50
    if-eq v1, v3, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget-boolean v1, p0, Lze/d;->e:Z

    .line 54
    .line 55
    iget-boolean v3, p1, Lze/d;->e:Z

    .line 56
    .line 57
    if-eq v1, v3, :cond_6

    .line 58
    .line 59
    return v2

    .line 60
    :cond_6
    iget-object v1, p0, Lze/d;->f:Lqe/a;

    .line 61
    .line 62
    iget-object v3, p1, Lze/d;->f:Lqe/a;

    .line 63
    .line 64
    if-eq v1, v3, :cond_7

    .line 65
    .line 66
    return v2

    .line 67
    :cond_7
    iget-object v1, p0, Lze/d;->g:Ljava/util/List;

    .line 68
    .line 69
    iget-object v3, p1, Lze/d;->g:Ljava/util/List;

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
    iget-boolean v1, p0, Lze/d;->h:Z

    .line 79
    .line 80
    iget-boolean v3, p1, Lze/d;->h:Z

    .line 81
    .line 82
    if-eq v1, v3, :cond_9

    .line 83
    .line 84
    return v2

    .line 85
    :cond_9
    iget-object p0, p0, Lze/d;->i:Llc/l;

    .line 86
    .line 87
    iget-object p1, p1, Lze/d;->i:Llc/l;

    .line 88
    .line 89
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result p0

    .line 93
    if-nez p0, :cond_a

    .line 94
    .line 95
    return v2

    .line 96
    :cond_a
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lze/d;->a:Ljava/lang/String;

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
    iget-object v2, p0, Lze/d;->b:Ljava/util/List;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lze/d;->c:Ljava/util/List;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Lze/d;->d:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-boolean v2, p0, Lze/d;->e:Z

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-object v2, p0, Lze/d;->f:Lqe/a;

    .line 35
    .line 36
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    add-int/2addr v2, v0

    .line 41
    mul-int/2addr v2, v1

    .line 42
    iget-object v0, p0, Lze/d;->g:Ljava/util/List;

    .line 43
    .line 44
    invoke-static {v2, v1, v0}, Lia/b;->a(IILjava/util/List;)I

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    iget-boolean v2, p0, Lze/d;->h:Z

    .line 49
    .line 50
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    iget-object p0, p0, Lze/d;->i:Llc/l;

    .line 55
    .line 56
    if-nez p0, :cond_0

    .line 57
    .line 58
    const/4 p0, 0x0

    .line 59
    goto :goto_0

    .line 60
    :cond_0
    invoke-virtual {p0}, Llc/l;->hashCode()I

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    :goto_0
    add-int/2addr v0, p0

    .line 65
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", timeLabels="

    .line 2
    .line 3
    const-string v1, ", daySlots="

    .line 4
    .line 5
    const-string v2, "EnterSlotsUiState(currencySymbol="

    .line 6
    .line 7
    iget-object v3, p0, Lze/d;->a:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Lze/d;->b:Ljava/util/List;

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v1, v4}, Lvj/b;->n(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", isNextButtonEnabled="

    .line 16
    .line 17
    const-string v2, ", isSettingMultipleFixedRates="

    .line 18
    .line 19
    iget-object v3, p0, Lze/d;->c:Ljava/util/List;

    .line 20
    .line 21
    iget-boolean v4, p0, Lze/d;->d:Z

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->w(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;ZLjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-boolean v1, p0, Lze/d;->e:Z

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v1, ", season="

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget-object v1, p0, Lze/d;->f:Lqe/a;

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v1, ", selectedDays="

    .line 42
    .line 43
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    const-string v1, ", areAllDaysSelected="

    .line 47
    .line 48
    const-string v2, ", error="

    .line 49
    .line 50
    iget-object v3, p0, Lze/d;->g:Ljava/util/List;

    .line 51
    .line 52
    iget-boolean v4, p0, Lze/d;->h:Z

    .line 53
    .line 54
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->w(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;ZLjava/lang/String;)V

    .line 55
    .line 56
    .line 57
    iget-object p0, p0, Lze/d;->i:Llc/l;

    .line 58
    .line 59
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    const-string p0, ")"

    .line 63
    .line 64
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    return-object p0
.end method
