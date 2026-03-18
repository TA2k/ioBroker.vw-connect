.class public final Lbo0/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Z

.field public final c:Ljava/util/Set;

.field public final d:Lbo0/p;

.field public final e:Z

.field public final f:Z

.field public final g:Z

.field public final h:Z

.field public final i:Z

.field public final j:Z

.field public final k:Ljava/time/LocalTime;

.field public final l:Lsx0/b;

.field public final m:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;ZLjava/util/Set;Lbo0/p;ZZZZZZLjava/time/LocalTime;)V
    .locals 1

    .line 1
    const-string v0, "selectedDays"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "selectedFrequency"

    .line 7
    .line 8
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lbo0/q;->a:Ljava/lang/String;

    .line 15
    .line 16
    iput-boolean p2, p0, Lbo0/q;->b:Z

    .line 17
    .line 18
    iput-object p3, p0, Lbo0/q;->c:Ljava/util/Set;

    .line 19
    .line 20
    iput-object p4, p0, Lbo0/q;->d:Lbo0/p;

    .line 21
    .line 22
    iput-boolean p5, p0, Lbo0/q;->e:Z

    .line 23
    .line 24
    iput-boolean p6, p0, Lbo0/q;->f:Z

    .line 25
    .line 26
    iput-boolean p7, p0, Lbo0/q;->g:Z

    .line 27
    .line 28
    iput-boolean p8, p0, Lbo0/q;->h:Z

    .line 29
    .line 30
    iput-boolean p9, p0, Lbo0/q;->i:Z

    .line 31
    .line 32
    iput-boolean p10, p0, Lbo0/q;->j:Z

    .line 33
    .line 34
    iput-object p11, p0, Lbo0/q;->k:Ljava/time/LocalTime;

    .line 35
    .line 36
    sget-object p1, Lbo0/o;->a:Lsx0/b;

    .line 37
    .line 38
    iput-object p1, p0, Lbo0/q;->l:Lsx0/b;

    .line 39
    .line 40
    invoke-static {p11}, Lua0/g;->b(Ljava/time/LocalTime;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    iput-object p1, p0, Lbo0/q;->m:Ljava/lang/String;

    .line 45
    .line 46
    return-void
.end method

.method public static a(Lbo0/q;Ljava/lang/String;ZLjava/util/Set;Lbo0/p;ZZZZZZLjava/time/LocalTime;I)Lbo0/q;
    .locals 12

    .line 1
    move/from16 v0, p12

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object p1, p0, Lbo0/q;->a:Ljava/lang/String;

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
    iget-boolean p2, p0, Lbo0/q;->b:Z

    .line 15
    .line 16
    :cond_1
    move v2, p2

    .line 17
    and-int/lit8 p1, v0, 0x4

    .line 18
    .line 19
    if-eqz p1, :cond_2

    .line 20
    .line 21
    iget-object p3, p0, Lbo0/q;->c:Ljava/util/Set;

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
    iget-object p1, p0, Lbo0/q;->d:Lbo0/p;

    .line 29
    .line 30
    move-object v4, p1

    .line 31
    goto :goto_0

    .line 32
    :cond_3
    move-object/from16 v4, p4

    .line 33
    .line 34
    :goto_0
    and-int/lit8 p1, v0, 0x10

    .line 35
    .line 36
    if-eqz p1, :cond_4

    .line 37
    .line 38
    iget-boolean p1, p0, Lbo0/q;->e:Z

    .line 39
    .line 40
    move v5, p1

    .line 41
    goto :goto_1

    .line 42
    :cond_4
    move/from16 v5, p5

    .line 43
    .line 44
    :goto_1
    and-int/lit8 p1, v0, 0x20

    .line 45
    .line 46
    if-eqz p1, :cond_5

    .line 47
    .line 48
    iget-boolean p1, p0, Lbo0/q;->f:Z

    .line 49
    .line 50
    move v6, p1

    .line 51
    goto :goto_2

    .line 52
    :cond_5
    move/from16 v6, p6

    .line 53
    .line 54
    :goto_2
    and-int/lit8 p1, v0, 0x40

    .line 55
    .line 56
    if-eqz p1, :cond_6

    .line 57
    .line 58
    iget-boolean p1, p0, Lbo0/q;->g:Z

    .line 59
    .line 60
    move v7, p1

    .line 61
    goto :goto_3

    .line 62
    :cond_6
    move/from16 v7, p7

    .line 63
    .line 64
    :goto_3
    and-int/lit16 p1, v0, 0x80

    .line 65
    .line 66
    if-eqz p1, :cond_7

    .line 67
    .line 68
    iget-boolean p1, p0, Lbo0/q;->h:Z

    .line 69
    .line 70
    move v8, p1

    .line 71
    goto :goto_4

    .line 72
    :cond_7
    move/from16 v8, p8

    .line 73
    .line 74
    :goto_4
    and-int/lit16 p1, v0, 0x100

    .line 75
    .line 76
    if-eqz p1, :cond_8

    .line 77
    .line 78
    iget-boolean p1, p0, Lbo0/q;->i:Z

    .line 79
    .line 80
    move v9, p1

    .line 81
    goto :goto_5

    .line 82
    :cond_8
    move/from16 v9, p9

    .line 83
    .line 84
    :goto_5
    and-int/lit16 p1, v0, 0x200

    .line 85
    .line 86
    if-eqz p1, :cond_9

    .line 87
    .line 88
    iget-boolean p1, p0, Lbo0/q;->j:Z

    .line 89
    .line 90
    move v10, p1

    .line 91
    goto :goto_6

    .line 92
    :cond_9
    move/from16 v10, p10

    .line 93
    .line 94
    :goto_6
    and-int/lit16 p1, v0, 0x400

    .line 95
    .line 96
    if-eqz p1, :cond_a

    .line 97
    .line 98
    iget-object p1, p0, Lbo0/q;->k:Ljava/time/LocalTime;

    .line 99
    .line 100
    move-object v11, p1

    .line 101
    goto :goto_7

    .line 102
    :cond_a
    move-object/from16 v11, p11

    .line 103
    .line 104
    :goto_7
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 105
    .line 106
    .line 107
    const-string p0, "title"

    .line 108
    .line 109
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    const-string p0, "selectedDays"

    .line 113
    .line 114
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    const-string p0, "selectedFrequency"

    .line 118
    .line 119
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    const-string p0, "readyAt"

    .line 123
    .line 124
    invoke-static {v11, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    new-instance v0, Lbo0/q;

    .line 128
    .line 129
    invoke-direct/range {v0 .. v11}, Lbo0/q;-><init>(Ljava/lang/String;ZLjava/util/Set;Lbo0/p;ZZZZZZLjava/time/LocalTime;)V

    .line 130
    .line 131
    .line 132
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
    instance-of v1, p1, Lbo0/q;

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
    check-cast p1, Lbo0/q;

    .line 12
    .line 13
    iget-object v1, p0, Lbo0/q;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lbo0/q;->a:Ljava/lang/String;

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
    iget-boolean v1, p0, Lbo0/q;->b:Z

    .line 25
    .line 26
    iget-boolean v3, p1, Lbo0/q;->b:Z

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object v1, p0, Lbo0/q;->c:Ljava/util/Set;

    .line 32
    .line 33
    iget-object v3, p1, Lbo0/q;->c:Ljava/util/Set;

    .line 34
    .line 35
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-nez v1, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object v1, p0, Lbo0/q;->d:Lbo0/p;

    .line 43
    .line 44
    iget-object v3, p1, Lbo0/q;->d:Lbo0/p;

    .line 45
    .line 46
    if-eq v1, v3, :cond_5

    .line 47
    .line 48
    return v2

    .line 49
    :cond_5
    iget-boolean v1, p0, Lbo0/q;->e:Z

    .line 50
    .line 51
    iget-boolean v3, p1, Lbo0/q;->e:Z

    .line 52
    .line 53
    if-eq v1, v3, :cond_6

    .line 54
    .line 55
    return v2

    .line 56
    :cond_6
    iget-boolean v1, p0, Lbo0/q;->f:Z

    .line 57
    .line 58
    iget-boolean v3, p1, Lbo0/q;->f:Z

    .line 59
    .line 60
    if-eq v1, v3, :cond_7

    .line 61
    .line 62
    return v2

    .line 63
    :cond_7
    iget-boolean v1, p0, Lbo0/q;->g:Z

    .line 64
    .line 65
    iget-boolean v3, p1, Lbo0/q;->g:Z

    .line 66
    .line 67
    if-eq v1, v3, :cond_8

    .line 68
    .line 69
    return v2

    .line 70
    :cond_8
    iget-boolean v1, p0, Lbo0/q;->h:Z

    .line 71
    .line 72
    iget-boolean v3, p1, Lbo0/q;->h:Z

    .line 73
    .line 74
    if-eq v1, v3, :cond_9

    .line 75
    .line 76
    return v2

    .line 77
    :cond_9
    iget-boolean v1, p0, Lbo0/q;->i:Z

    .line 78
    .line 79
    iget-boolean v3, p1, Lbo0/q;->i:Z

    .line 80
    .line 81
    if-eq v1, v3, :cond_a

    .line 82
    .line 83
    return v2

    .line 84
    :cond_a
    iget-boolean v1, p0, Lbo0/q;->j:Z

    .line 85
    .line 86
    iget-boolean v3, p1, Lbo0/q;->j:Z

    .line 87
    .line 88
    if-eq v1, v3, :cond_b

    .line 89
    .line 90
    return v2

    .line 91
    :cond_b
    iget-object p0, p0, Lbo0/q;->k:Ljava/time/LocalTime;

    .line 92
    .line 93
    iget-object p1, p1, Lbo0/q;->k:Ljava/time/LocalTime;

    .line 94
    .line 95
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result p0

    .line 99
    if-nez p0, :cond_c

    .line 100
    .line 101
    return v2

    .line 102
    :cond_c
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lbo0/q;->a:Ljava/lang/String;

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
    iget-boolean v2, p0, Lbo0/q;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lbo0/q;->c:Ljava/util/Set;

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
    iget-object v0, p0, Lbo0/q;->d:Lbo0/p;

    .line 25
    .line 26
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    add-int/2addr v0, v2

    .line 31
    mul-int/2addr v0, v1

    .line 32
    iget-boolean v2, p0, Lbo0/q;->e:Z

    .line 33
    .line 34
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    iget-boolean v2, p0, Lbo0/q;->f:Z

    .line 39
    .line 40
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    iget-boolean v2, p0, Lbo0/q;->g:Z

    .line 45
    .line 46
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    iget-boolean v2, p0, Lbo0/q;->h:Z

    .line 51
    .line 52
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    iget-boolean v2, p0, Lbo0/q;->i:Z

    .line 57
    .line 58
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    iget-boolean v2, p0, Lbo0/q;->j:Z

    .line 63
    .line 64
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    iget-object p0, p0, Lbo0/q;->k:Ljava/time/LocalTime;

    .line 69
    .line 70
    invoke-virtual {p0}, Ljava/time/LocalTime;->hashCode()I

    .line 71
    .line 72
    .line 73
    move-result p0

    .line 74
    add-int/2addr p0, v0

    .line 75
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", isTimePickerDialogVisible="

    .line 2
    .line 3
    const-string v1, ", selectedDays="

    .line 4
    .line 5
    const-string v2, "State(title="

    .line 6
    .line 7
    iget-object v3, p0, Lbo0/q;->a:Ljava/lang/String;

    .line 8
    .line 9
    iget-boolean v4, p0, Lbo0/q;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v1, v4}, Lia/b;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iget-object v1, p0, Lbo0/q;->c:Ljava/util/Set;

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const-string v1, ", selectedFrequency="

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    iget-object v1, p0, Lbo0/q;->d:Lbo0/p;

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v1, ", startAirCondition="

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v1, ", isFrequencySectionVisible="

    .line 36
    .line 37
    const-string v2, ", isClimateControlVisible="

    .line 38
    .line 39
    iget-boolean v3, p0, Lbo0/q;->e:Z

    .line 40
    .line 41
    iget-boolean v4, p0, Lbo0/q;->f:Z

    .line 42
    .line 43
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 44
    .line 45
    .line 46
    const-string v1, ", isSaveEnabled="

    .line 47
    .line 48
    const-string v2, ", isSaveVisible="

    .line 49
    .line 50
    iget-boolean v3, p0, Lbo0/q;->g:Z

    .line 51
    .line 52
    iget-boolean v4, p0, Lbo0/q;->h:Z

    .line 53
    .line 54
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 55
    .line 56
    .line 57
    const-string v1, ", isDemoMode="

    .line 58
    .line 59
    const-string v2, ", readyAt="

    .line 60
    .line 61
    iget-boolean v3, p0, Lbo0/q;->i:Z

    .line 62
    .line 63
    iget-boolean v4, p0, Lbo0/q;->j:Z

    .line 64
    .line 65
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 66
    .line 67
    .line 68
    iget-object p0, p0, Lbo0/q;->k:Ljava/time/LocalTime;

    .line 69
    .line 70
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string p0, ")"

    .line 74
    .line 75
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    return-object p0
.end method
