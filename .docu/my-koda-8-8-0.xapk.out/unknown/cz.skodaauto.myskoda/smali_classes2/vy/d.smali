.class public final Lvy/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Llf0/i;

.field public final b:Ljava/lang/String;

.field public final c:Ljava/lang/String;

.field public final d:Z

.field public final e:Z

.field public final f:Z

.field public final g:Z

.field public final h:Z

.field public final i:Z

.field public final j:Z


# direct methods
.method public synthetic constructor <init>(Llf0/i;Ljava/lang/String;Ljava/lang/String;I)V
    .locals 11

    and-int/lit8 v0, p4, 0x1

    if-eqz v0, :cond_0

    .line 12
    sget-object p1, Llf0/i;->j:Llf0/i;

    :cond_0
    move-object v1, p1

    and-int/lit8 p1, p4, 0x2

    .line 13
    const-string v0, ""

    if-eqz p1, :cond_1

    move-object v2, v0

    goto :goto_0

    :cond_1
    move-object v2, p2

    :goto_0
    and-int/lit8 p1, p4, 0x4

    if-eqz p1, :cond_2

    move-object v3, v0

    goto :goto_1

    :cond_2
    move-object v3, p3

    :goto_1
    and-int/lit8 p1, p4, 0x8

    if-eqz p1, :cond_3

    const/4 p1, 0x1

    :goto_2
    move v4, p1

    goto :goto_3

    :cond_3
    const/4 p1, 0x0

    goto :goto_2

    :goto_3
    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    move-object v0, p0

    invoke-direct/range {v0 .. v10}, Lvy/d;-><init>(Llf0/i;Ljava/lang/String;Ljava/lang/String;ZZZZZZZ)V

    return-void
.end method

.method public constructor <init>(Llf0/i;Ljava/lang/String;Ljava/lang/String;ZZZZZZZ)V
    .locals 1

    const-string v0, "viewMode"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "subtitle"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "description"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lvy/d;->a:Llf0/i;

    .line 3
    iput-object p2, p0, Lvy/d;->b:Ljava/lang/String;

    .line 4
    iput-object p3, p0, Lvy/d;->c:Ljava/lang/String;

    .line 5
    iput-boolean p4, p0, Lvy/d;->d:Z

    .line 6
    iput-boolean p5, p0, Lvy/d;->e:Z

    .line 7
    iput-boolean p6, p0, Lvy/d;->f:Z

    .line 8
    iput-boolean p7, p0, Lvy/d;->g:Z

    .line 9
    iput-boolean p8, p0, Lvy/d;->h:Z

    .line 10
    iput-boolean p9, p0, Lvy/d;->i:Z

    .line 11
    iput-boolean p10, p0, Lvy/d;->j:Z

    return-void
.end method

.method public static a(Lvy/d;Llf0/i;Ljava/lang/String;Ljava/lang/String;ZZZZZI)Lvy/d;
    .locals 11

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
    iget-object p1, p0, Lvy/d;->a:Llf0/i;

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
    iget-object p1, p0, Lvy/d;->b:Ljava/lang/String;

    .line 15
    .line 16
    move-object v2, p1

    .line 17
    goto :goto_0

    .line 18
    :cond_1
    move-object v2, p2

    .line 19
    :goto_0
    and-int/lit8 p1, v0, 0x4

    .line 20
    .line 21
    if-eqz p1, :cond_2

    .line 22
    .line 23
    iget-object p1, p0, Lvy/d;->c:Ljava/lang/String;

    .line 24
    .line 25
    move-object v3, p1

    .line 26
    goto :goto_1

    .line 27
    :cond_2
    move-object v3, p3

    .line 28
    :goto_1
    and-int/lit8 p1, v0, 0x8

    .line 29
    .line 30
    if-eqz p1, :cond_3

    .line 31
    .line 32
    iget-boolean p1, p0, Lvy/d;->d:Z

    .line 33
    .line 34
    :goto_2
    move v4, p1

    .line 35
    goto :goto_3

    .line 36
    :cond_3
    const/4 p1, 0x0

    .line 37
    goto :goto_2

    .line 38
    :goto_3
    and-int/lit8 p1, v0, 0x10

    .line 39
    .line 40
    if-eqz p1, :cond_4

    .line 41
    .line 42
    iget-boolean p1, p0, Lvy/d;->e:Z

    .line 43
    .line 44
    move v5, p1

    .line 45
    goto :goto_4

    .line 46
    :cond_4
    move v5, p4

    .line 47
    :goto_4
    and-int/lit8 p1, v0, 0x20

    .line 48
    .line 49
    if-eqz p1, :cond_5

    .line 50
    .line 51
    iget-boolean p1, p0, Lvy/d;->f:Z

    .line 52
    .line 53
    move v6, p1

    .line 54
    goto :goto_5

    .line 55
    :cond_5
    move/from16 v6, p5

    .line 56
    .line 57
    :goto_5
    and-int/lit8 p1, v0, 0x40

    .line 58
    .line 59
    if-eqz p1, :cond_6

    .line 60
    .line 61
    iget-boolean p1, p0, Lvy/d;->g:Z

    .line 62
    .line 63
    :goto_6
    move v7, p1

    .line 64
    goto :goto_7

    .line 65
    :cond_6
    const/4 p1, 0x1

    .line 66
    goto :goto_6

    .line 67
    :goto_7
    and-int/lit16 p1, v0, 0x80

    .line 68
    .line 69
    if-eqz p1, :cond_7

    .line 70
    .line 71
    iget-boolean p1, p0, Lvy/d;->h:Z

    .line 72
    .line 73
    move v8, p1

    .line 74
    goto :goto_8

    .line 75
    :cond_7
    move/from16 v8, p6

    .line 76
    .line 77
    :goto_8
    and-int/lit16 p1, v0, 0x100

    .line 78
    .line 79
    if-eqz p1, :cond_8

    .line 80
    .line 81
    iget-boolean p1, p0, Lvy/d;->i:Z

    .line 82
    .line 83
    move v9, p1

    .line 84
    goto :goto_9

    .line 85
    :cond_8
    move/from16 v9, p7

    .line 86
    .line 87
    :goto_9
    and-int/lit16 p1, v0, 0x200

    .line 88
    .line 89
    if-eqz p1, :cond_9

    .line 90
    .line 91
    iget-boolean p1, p0, Lvy/d;->j:Z

    .line 92
    .line 93
    move v10, p1

    .line 94
    goto :goto_a

    .line 95
    :cond_9
    move/from16 v10, p8

    .line 96
    .line 97
    :goto_a
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 98
    .line 99
    .line 100
    const-string p0, "viewMode"

    .line 101
    .line 102
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    const-string p0, "subtitle"

    .line 106
    .line 107
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    const-string p0, "description"

    .line 111
    .line 112
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    new-instance v0, Lvy/d;

    .line 116
    .line 117
    invoke-direct/range {v0 .. v10}, Lvy/d;-><init>(Llf0/i;Ljava/lang/String;Ljava/lang/String;ZZZZZZZ)V

    .line 118
    .line 119
    .line 120
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
    instance-of v1, p1, Lvy/d;

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
    check-cast p1, Lvy/d;

    .line 12
    .line 13
    iget-object v1, p0, Lvy/d;->a:Llf0/i;

    .line 14
    .line 15
    iget-object v3, p1, Lvy/d;->a:Llf0/i;

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Lvy/d;->b:Ljava/lang/String;

    .line 21
    .line 22
    iget-object v3, p1, Lvy/d;->b:Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-nez v1, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object v1, p0, Lvy/d;->c:Ljava/lang/String;

    .line 32
    .line 33
    iget-object v3, p1, Lvy/d;->c:Ljava/lang/String;

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
    iget-boolean v1, p0, Lvy/d;->d:Z

    .line 43
    .line 44
    iget-boolean v3, p1, Lvy/d;->d:Z

    .line 45
    .line 46
    if-eq v1, v3, :cond_5

    .line 47
    .line 48
    return v2

    .line 49
    :cond_5
    iget-boolean v1, p0, Lvy/d;->e:Z

    .line 50
    .line 51
    iget-boolean v3, p1, Lvy/d;->e:Z

    .line 52
    .line 53
    if-eq v1, v3, :cond_6

    .line 54
    .line 55
    return v2

    .line 56
    :cond_6
    iget-boolean v1, p0, Lvy/d;->f:Z

    .line 57
    .line 58
    iget-boolean v3, p1, Lvy/d;->f:Z

    .line 59
    .line 60
    if-eq v1, v3, :cond_7

    .line 61
    .line 62
    return v2

    .line 63
    :cond_7
    iget-boolean v1, p0, Lvy/d;->g:Z

    .line 64
    .line 65
    iget-boolean v3, p1, Lvy/d;->g:Z

    .line 66
    .line 67
    if-eq v1, v3, :cond_8

    .line 68
    .line 69
    return v2

    .line 70
    :cond_8
    iget-boolean v1, p0, Lvy/d;->h:Z

    .line 71
    .line 72
    iget-boolean v3, p1, Lvy/d;->h:Z

    .line 73
    .line 74
    if-eq v1, v3, :cond_9

    .line 75
    .line 76
    return v2

    .line 77
    :cond_9
    iget-boolean v1, p0, Lvy/d;->i:Z

    .line 78
    .line 79
    iget-boolean v3, p1, Lvy/d;->i:Z

    .line 80
    .line 81
    if-eq v1, v3, :cond_a

    .line 82
    .line 83
    return v2

    .line 84
    :cond_a
    iget-boolean p0, p0, Lvy/d;->j:Z

    .line 85
    .line 86
    iget-boolean p1, p1, Lvy/d;->j:Z

    .line 87
    .line 88
    if-eq p0, p1, :cond_b

    .line 89
    .line 90
    return v2

    .line 91
    :cond_b
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lvy/d;->a:Llf0/i;

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
    iget-object v2, p0, Lvy/d;->b:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lvy/d;->c:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Lvy/d;->d:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-boolean v2, p0, Lvy/d;->e:Z

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-boolean v2, p0, Lvy/d;->f:Z

    .line 35
    .line 36
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget-boolean v2, p0, Lvy/d;->g:Z

    .line 41
    .line 42
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-boolean v2, p0, Lvy/d;->h:Z

    .line 47
    .line 48
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget-boolean v2, p0, Lvy/d;->i:Z

    .line 53
    .line 54
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    iget-boolean p0, p0, Lvy/d;->j:Z

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
    iget-object v1, p0, Lvy/d;->a:Llf0/i;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", subtitle="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lvy/d;->b:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", description="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", isLoading="

    .line 29
    .line 30
    const-string v2, ", isSwitchEnabled="

    .line 31
    .line 32
    iget-object v3, p0, Lvy/d;->c:Ljava/lang/String;

    .line 33
    .line 34
    iget-boolean v4, p0, Lvy/d;->d:Z

    .line 35
    .line 36
    invoke-static {v3, v1, v2, v0, v4}, La7/g0;->t(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 37
    .line 38
    .line 39
    const-string v1, ", isSwitchChecked="

    .line 40
    .line 41
    const-string v2, ", isSendingRequest="

    .line 42
    .line 43
    iget-boolean v3, p0, Lvy/d;->e:Z

    .line 44
    .line 45
    iget-boolean v4, p0, Lvy/d;->f:Z

    .line 46
    .line 47
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 48
    .line 49
    .line 50
    const-string v1, ", isNotifySilentLoading="

    .line 51
    .line 52
    const-string v2, ", isSilentLoading="

    .line 53
    .line 54
    iget-boolean v3, p0, Lvy/d;->g:Z

    .line 55
    .line 56
    iget-boolean v4, p0, Lvy/d;->h:Z

    .line 57
    .line 58
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 59
    .line 60
    .line 61
    const-string v1, ", hasOutsideTemperatureCapability="

    .line 62
    .line 63
    const-string v2, ")"

    .line 64
    .line 65
    iget-boolean v3, p0, Lvy/d;->i:Z

    .line 66
    .line 67
    iget-boolean p0, p0, Lvy/d;->j:Z

    .line 68
    .line 69
    invoke-static {v0, v3, v1, p0, v2}, Lvj/b;->l(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0
.end method
