.class public final Lc00/x1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Lc00/v1;

.field public final b:Lc00/v1;

.field public final c:Lc00/v1;

.field public final d:Lc00/v1;

.field public final e:Lc00/w1;

.field public final f:Z

.field public final g:Z

.field public final h:J

.field public final i:Z

.field public final j:I

.field public final k:I

.field public final l:I

.field public final m:I


# direct methods
.method public constructor <init>(Lc00/v1;Lc00/v1;Lc00/v1;Lc00/v1;Lc00/w1;ZZJZ)V
    .locals 1

    .line 1
    const-string v0, "leftSeat"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "rightSeat"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "steeringWheel"

    .line 12
    .line 13
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lc00/x1;->a:Lc00/v1;

    .line 20
    .line 21
    iput-object p2, p0, Lc00/x1;->b:Lc00/v1;

    .line 22
    .line 23
    iput-object p3, p0, Lc00/x1;->c:Lc00/v1;

    .line 24
    .line 25
    iput-object p4, p0, Lc00/x1;->d:Lc00/v1;

    .line 26
    .line 27
    iput-object p5, p0, Lc00/x1;->e:Lc00/w1;

    .line 28
    .line 29
    iput-boolean p6, p0, Lc00/x1;->f:Z

    .line 30
    .line 31
    iput-boolean p7, p0, Lc00/x1;->g:Z

    .line 32
    .line 33
    iput-wide p8, p0, Lc00/x1;->h:J

    .line 34
    .line 35
    iput-boolean p10, p0, Lc00/x1;->i:Z

    .line 36
    .line 37
    sget-object p5, Lc00/w1;->d:Lc00/w1;

    .line 38
    .line 39
    invoke-static {p0, p1, p5}, Lc00/z1;->a(Lc00/x1;Lc00/v1;Lc00/w1;)I

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    iput p1, p0, Lc00/x1;->j:I

    .line 44
    .line 45
    sget-object p1, Lc00/w1;->e:Lc00/w1;

    .line 46
    .line 47
    invoke-static {p0, p2, p1}, Lc00/z1;->a(Lc00/x1;Lc00/v1;Lc00/w1;)I

    .line 48
    .line 49
    .line 50
    move-result p1

    .line 51
    iput p1, p0, Lc00/x1;->k:I

    .line 52
    .line 53
    if-nez p3, :cond_0

    .line 54
    .line 55
    sget-object p3, Lc00/v1;->f:Lc00/v1;

    .line 56
    .line 57
    :cond_0
    const/4 p1, 0x0

    .line 58
    invoke-static {p0, p3, p1}, Lc00/z1;->b(Lc00/x1;Lc00/v1;Z)I

    .line 59
    .line 60
    .line 61
    move-result p1

    .line 62
    iput p1, p0, Lc00/x1;->l:I

    .line 63
    .line 64
    if-nez p4, :cond_1

    .line 65
    .line 66
    sget-object p4, Lc00/v1;->f:Lc00/v1;

    .line 67
    .line 68
    :cond_1
    const/4 p1, 0x1

    .line 69
    invoke-static {p0, p4, p1}, Lc00/z1;->b(Lc00/x1;Lc00/v1;Z)I

    .line 70
    .line 71
    .line 72
    move-result p1

    .line 73
    iput p1, p0, Lc00/x1;->m:I

    .line 74
    .line 75
    return-void
.end method

.method public static a(Lc00/x1;Lc00/v1;Lc00/v1;Lc00/v1;Lc00/v1;Lc00/w1;ZZJZI)Lc00/x1;
    .locals 11

    .line 1
    move/from16 v0, p11

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object p1, p0, Lc00/x1;->a:Lc00/v1;

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
    iget-object p2, p0, Lc00/x1;->b:Lc00/v1;

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
    iget-object p3, p0, Lc00/x1;->c:Lc00/v1;

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
    iget-object p4, p0, Lc00/x1;->d:Lc00/v1;

    .line 29
    .line 30
    :cond_3
    move-object v4, p4

    .line 31
    and-int/lit8 p1, v0, 0x10

    .line 32
    .line 33
    if-eqz p1, :cond_4

    .line 34
    .line 35
    iget-object p1, p0, Lc00/x1;->e:Lc00/w1;

    .line 36
    .line 37
    move-object v5, p1

    .line 38
    goto :goto_0

    .line 39
    :cond_4
    move-object/from16 v5, p5

    .line 40
    .line 41
    :goto_0
    and-int/lit8 p1, v0, 0x20

    .line 42
    .line 43
    if-eqz p1, :cond_5

    .line 44
    .line 45
    iget-boolean p1, p0, Lc00/x1;->f:Z

    .line 46
    .line 47
    move v6, p1

    .line 48
    goto :goto_1

    .line 49
    :cond_5
    move/from16 v6, p6

    .line 50
    .line 51
    :goto_1
    and-int/lit8 p1, v0, 0x40

    .line 52
    .line 53
    if-eqz p1, :cond_6

    .line 54
    .line 55
    iget-boolean p1, p0, Lc00/x1;->g:Z

    .line 56
    .line 57
    move v7, p1

    .line 58
    goto :goto_2

    .line 59
    :cond_6
    move/from16 v7, p7

    .line 60
    .line 61
    :goto_2
    and-int/lit16 p1, v0, 0x80

    .line 62
    .line 63
    if-eqz p1, :cond_7

    .line 64
    .line 65
    iget-wide p1, p0, Lc00/x1;->h:J

    .line 66
    .line 67
    move-wide v8, p1

    .line 68
    goto :goto_3

    .line 69
    :cond_7
    move-wide/from16 v8, p8

    .line 70
    .line 71
    :goto_3
    and-int/lit16 p1, v0, 0x100

    .line 72
    .line 73
    if-eqz p1, :cond_8

    .line 74
    .line 75
    iget-boolean p1, p0, Lc00/x1;->i:Z

    .line 76
    .line 77
    move v10, p1

    .line 78
    goto :goto_4

    .line 79
    :cond_8
    move/from16 v10, p10

    .line 80
    .line 81
    :goto_4
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 82
    .line 83
    .line 84
    const-string p0, "leftSeat"

    .line 85
    .line 86
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    const-string p0, "rightSeat"

    .line 90
    .line 91
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    const-string p0, "steeringWheel"

    .line 95
    .line 96
    invoke-static {v5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    new-instance v0, Lc00/x1;

    .line 100
    .line 101
    invoke-direct/range {v0 .. v10}, Lc00/x1;-><init>(Lc00/v1;Lc00/v1;Lc00/v1;Lc00/v1;Lc00/w1;ZZJZ)V

    .line 102
    .line 103
    .line 104
    return-object v0
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lc00/x1;

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
    check-cast p1, Lc00/x1;

    .line 12
    .line 13
    iget-object v1, p0, Lc00/x1;->a:Lc00/v1;

    .line 14
    .line 15
    iget-object v3, p1, Lc00/x1;->a:Lc00/v1;

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Lc00/x1;->b:Lc00/v1;

    .line 21
    .line 22
    iget-object v3, p1, Lc00/x1;->b:Lc00/v1;

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-object v1, p0, Lc00/x1;->c:Lc00/v1;

    .line 28
    .line 29
    iget-object v3, p1, Lc00/x1;->c:Lc00/v1;

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-object v1, p0, Lc00/x1;->d:Lc00/v1;

    .line 35
    .line 36
    iget-object v3, p1, Lc00/x1;->d:Lc00/v1;

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget-object v1, p0, Lc00/x1;->e:Lc00/w1;

    .line 42
    .line 43
    iget-object v3, p1, Lc00/x1;->e:Lc00/w1;

    .line 44
    .line 45
    if-eq v1, v3, :cond_6

    .line 46
    .line 47
    return v2

    .line 48
    :cond_6
    iget-boolean v1, p0, Lc00/x1;->f:Z

    .line 49
    .line 50
    iget-boolean v3, p1, Lc00/x1;->f:Z

    .line 51
    .line 52
    if-eq v1, v3, :cond_7

    .line 53
    .line 54
    return v2

    .line 55
    :cond_7
    iget-boolean v1, p0, Lc00/x1;->g:Z

    .line 56
    .line 57
    iget-boolean v3, p1, Lc00/x1;->g:Z

    .line 58
    .line 59
    if-eq v1, v3, :cond_8

    .line 60
    .line 61
    return v2

    .line 62
    :cond_8
    iget-wide v3, p0, Lc00/x1;->h:J

    .line 63
    .line 64
    iget-wide v5, p1, Lc00/x1;->h:J

    .line 65
    .line 66
    invoke-static {v3, v4, v5, v6}, Lmy0/c;->d(JJ)Z

    .line 67
    .line 68
    .line 69
    move-result v1

    .line 70
    if-nez v1, :cond_9

    .line 71
    .line 72
    return v2

    .line 73
    :cond_9
    iget-boolean p0, p0, Lc00/x1;->i:Z

    .line 74
    .line 75
    iget-boolean p1, p1, Lc00/x1;->i:Z

    .line 76
    .line 77
    if-eq p0, p1, :cond_a

    .line 78
    .line 79
    return v2

    .line 80
    :cond_a
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lc00/x1;->a:Lc00/v1;

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
    iget-object v2, p0, Lc00/x1;->b:Lc00/v1;

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
    iget-object v3, p0, Lc00/x1;->c:Lc00/v1;

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
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

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
    iget-object v3, p0, Lc00/x1;->d:Lc00/v1;

    .line 32
    .line 33
    if-nez v3, :cond_1

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    :goto_1
    add-int/2addr v2, v0

    .line 41
    mul-int/2addr v2, v1

    .line 42
    iget-object v0, p0, Lc00/x1;->e:Lc00/w1;

    .line 43
    .line 44
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    add-int/2addr v0, v2

    .line 49
    mul-int/2addr v0, v1

    .line 50
    iget-boolean v2, p0, Lc00/x1;->f:Z

    .line 51
    .line 52
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    iget-boolean v2, p0, Lc00/x1;->g:Z

    .line 57
    .line 58
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    sget v2, Lmy0/c;->g:I

    .line 63
    .line 64
    iget-wide v2, p0, Lc00/x1;->h:J

    .line 65
    .line 66
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    iget-boolean p0, p0, Lc00/x1;->i:Z

    .line 71
    .line 72
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 73
    .line 74
    .line 75
    move-result p0

    .line 76
    add-int/2addr p0, v0

    .line 77
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-wide v0, p0, Lc00/x1;->h:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lmy0/c;->o(J)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v2, "State(leftSeat="

    .line 10
    .line 11
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    iget-object v2, p0, Lc00/x1;->a:Lc00/v1;

    .line 15
    .line 16
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string v2, ", rightSeat="

    .line 20
    .line 21
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    iget-object v2, p0, Lc00/x1;->b:Lc00/v1;

    .line 25
    .line 26
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string v2, ", leftRearSeat="

    .line 30
    .line 31
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    iget-object v2, p0, Lc00/x1;->c:Lc00/v1;

    .line 35
    .line 36
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    const-string v2, ", rightRearSeat="

    .line 40
    .line 41
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    iget-object v2, p0, Lc00/x1;->d:Lc00/v1;

    .line 45
    .line 46
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    const-string v2, ", steeringWheel="

    .line 50
    .line 51
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    iget-object v2, p0, Lc00/x1;->e:Lc00/w1;

    .line 55
    .line 56
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    const-string v2, ", isSaveAvailable="

    .line 60
    .line 61
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    iget-boolean v2, p0, Lc00/x1;->f:Z

    .line 65
    .line 66
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    const-string v2, ", isDemoMode="

    .line 70
    .line 71
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    const-string v2, ", seatAnimationDuration="

    .line 75
    .line 76
    const-string v3, ", areBackSeatsAvailable="

    .line 77
    .line 78
    iget-boolean v4, p0, Lc00/x1;->g:Z

    .line 79
    .line 80
    invoke-static {v2, v0, v3, v1, v4}, Lkx/a;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 81
    .line 82
    .line 83
    const-string v0, ")"

    .line 84
    .line 85
    iget-boolean p0, p0, Lc00/x1;->i:Z

    .line 86
    .line 87
    invoke-static {v1, p0, v0}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    return-object p0
.end method
