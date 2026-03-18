.class public final Lcom/google/android/gms/location/LocationRequest;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/gms/common/internal/ReflectedParcelable;


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/google/android/gms/location/LocationRequest;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public d:I

.field public final e:J

.field public final f:J

.field public final g:J

.field public final h:J

.field public i:I

.field public final j:F

.field public final k:Z

.field public final l:J

.field public final m:I

.field public final n:I

.field public final o:Z

.field public final p:Landroid/os/WorkSource;

.field public final q:Lgp/g;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lkg/l0;

    .line 2
    .line 3
    const/16 v1, 0x1b

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lkg/l0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lcom/google/android/gms/location/LocationRequest;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(IJJJJJIFZJIIZLandroid/os/WorkSource;Lgp/g;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lcom/google/android/gms/location/LocationRequest;->d:I

    .line 5
    .line 6
    const/16 v0, 0x69

    .line 7
    .line 8
    const-wide v1, 0x7fffffffffffffffL

    .line 9
    .line 10
    .line 11
    .line 12
    .line 13
    if-ne p1, v0, :cond_0

    .line 14
    .line 15
    iput-wide v1, p0, Lcom/google/android/gms/location/LocationRequest;->e:J

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    iput-wide p2, p0, Lcom/google/android/gms/location/LocationRequest;->e:J

    .line 19
    .line 20
    :goto_0
    iput-wide p4, p0, Lcom/google/android/gms/location/LocationRequest;->f:J

    .line 21
    .line 22
    iput-wide p6, p0, Lcom/google/android/gms/location/LocationRequest;->g:J

    .line 23
    .line 24
    cmp-long p1, p8, v1

    .line 25
    .line 26
    if-nez p1, :cond_1

    .line 27
    .line 28
    move-wide p4, p10

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 31
    .line 32
    .line 33
    move-result-wide p4

    .line 34
    sub-long/2addr p8, p4

    .line 35
    const-wide/16 p4, 0x1

    .line 36
    .line 37
    invoke-static {p4, p5, p8, p9}, Ljava/lang/Math;->max(JJ)J

    .line 38
    .line 39
    .line 40
    move-result-wide p4

    .line 41
    invoke-static {p4, p5, p10, p11}, Ljava/lang/Math;->min(JJ)J

    .line 42
    .line 43
    .line 44
    move-result-wide p4

    .line 45
    :goto_1
    iput-wide p4, p0, Lcom/google/android/gms/location/LocationRequest;->h:J

    .line 46
    .line 47
    iput p12, p0, Lcom/google/android/gms/location/LocationRequest;->i:I

    .line 48
    .line 49
    move/from16 p1, p13

    .line 50
    .line 51
    iput p1, p0, Lcom/google/android/gms/location/LocationRequest;->j:F

    .line 52
    .line 53
    move/from16 p1, p14

    .line 54
    .line 55
    iput-boolean p1, p0, Lcom/google/android/gms/location/LocationRequest;->k:Z

    .line 56
    .line 57
    const-wide/16 p4, -0x1

    .line 58
    .line 59
    cmp-long p1, p15, p4

    .line 60
    .line 61
    if-eqz p1, :cond_2

    .line 62
    .line 63
    move-wide/from16 p2, p15

    .line 64
    .line 65
    :cond_2
    iput-wide p2, p0, Lcom/google/android/gms/location/LocationRequest;->l:J

    .line 66
    .line 67
    move/from16 p1, p17

    .line 68
    .line 69
    iput p1, p0, Lcom/google/android/gms/location/LocationRequest;->m:I

    .line 70
    .line 71
    move/from16 p1, p18

    .line 72
    .line 73
    iput p1, p0, Lcom/google/android/gms/location/LocationRequest;->n:I

    .line 74
    .line 75
    move/from16 p1, p19

    .line 76
    .line 77
    iput-boolean p1, p0, Lcom/google/android/gms/location/LocationRequest;->o:Z

    .line 78
    .line 79
    move-object/from16 p1, p20

    .line 80
    .line 81
    iput-object p1, p0, Lcom/google/android/gms/location/LocationRequest;->p:Landroid/os/WorkSource;

    .line 82
    .line 83
    move-object/from16 p1, p21

    .line 84
    .line 85
    iput-object p1, p0, Lcom/google/android/gms/location/LocationRequest;->q:Lgp/g;

    .line 86
    .line 87
    return-void
.end method

.method public static y0(J)Ljava/lang/String;
    .locals 2

    .line 1
    const-wide v0, 0x7fffffffffffffffL

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    cmp-long v0, p0, v0

    .line 7
    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    const-string p0, "\u221e"

    .line 11
    .line 12
    return-object p0

    .line 13
    :cond_0
    sget-object v0, Lgp/m;->b:Ljava/lang/StringBuilder;

    .line 14
    .line 15
    monitor-enter v0

    .line 16
    const/4 v1, 0x0

    .line 17
    :try_start_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->setLength(I)V

    .line 18
    .line 19
    .line 20
    invoke-static {p0, p1, v0}, Lgp/m;->a(JLjava/lang/StringBuilder;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    monitor-exit v0

    .line 28
    return-object p0

    .line 29
    :catchall_0
    move-exception p0

    .line 30
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 31
    throw p0
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    instance-of v0, p1, Lcom/google/android/gms/location/LocationRequest;

    .line 2
    .line 3
    if-eqz v0, :cond_2

    .line 4
    .line 5
    check-cast p1, Lcom/google/android/gms/location/LocationRequest;

    .line 6
    .line 7
    iget v0, p0, Lcom/google/android/gms/location/LocationRequest;->d:I

    .line 8
    .line 9
    iget v1, p1, Lcom/google/android/gms/location/LocationRequest;->d:I

    .line 10
    .line 11
    if-ne v0, v1, :cond_2

    .line 12
    .line 13
    const/16 v1, 0x69

    .line 14
    .line 15
    if-ne v0, v1, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    iget-wide v0, p0, Lcom/google/android/gms/location/LocationRequest;->e:J

    .line 19
    .line 20
    iget-wide v2, p1, Lcom/google/android/gms/location/LocationRequest;->e:J

    .line 21
    .line 22
    cmp-long v0, v0, v2

    .line 23
    .line 24
    if-nez v0, :cond_2

    .line 25
    .line 26
    :goto_0
    iget-wide v0, p0, Lcom/google/android/gms/location/LocationRequest;->f:J

    .line 27
    .line 28
    iget-wide v2, p1, Lcom/google/android/gms/location/LocationRequest;->f:J

    .line 29
    .line 30
    cmp-long v0, v0, v2

    .line 31
    .line 32
    if-nez v0, :cond_2

    .line 33
    .line 34
    invoke-virtual {p0}, Lcom/google/android/gms/location/LocationRequest;->x0()Z

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    invoke-virtual {p1}, Lcom/google/android/gms/location/LocationRequest;->x0()Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-ne v0, v1, :cond_2

    .line 43
    .line 44
    invoke-virtual {p0}, Lcom/google/android/gms/location/LocationRequest;->x0()Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-eqz v0, :cond_1

    .line 49
    .line 50
    iget-wide v0, p0, Lcom/google/android/gms/location/LocationRequest;->g:J

    .line 51
    .line 52
    iget-wide v2, p1, Lcom/google/android/gms/location/LocationRequest;->g:J

    .line 53
    .line 54
    cmp-long v0, v0, v2

    .line 55
    .line 56
    if-nez v0, :cond_2

    .line 57
    .line 58
    :cond_1
    iget-wide v0, p0, Lcom/google/android/gms/location/LocationRequest;->h:J

    .line 59
    .line 60
    iget-wide v2, p1, Lcom/google/android/gms/location/LocationRequest;->h:J

    .line 61
    .line 62
    cmp-long v0, v0, v2

    .line 63
    .line 64
    if-nez v0, :cond_2

    .line 65
    .line 66
    iget v0, p0, Lcom/google/android/gms/location/LocationRequest;->i:I

    .line 67
    .line 68
    iget v1, p1, Lcom/google/android/gms/location/LocationRequest;->i:I

    .line 69
    .line 70
    if-ne v0, v1, :cond_2

    .line 71
    .line 72
    iget v0, p0, Lcom/google/android/gms/location/LocationRequest;->j:F

    .line 73
    .line 74
    iget v1, p1, Lcom/google/android/gms/location/LocationRequest;->j:F

    .line 75
    .line 76
    cmpl-float v0, v0, v1

    .line 77
    .line 78
    if-nez v0, :cond_2

    .line 79
    .line 80
    iget-boolean v0, p0, Lcom/google/android/gms/location/LocationRequest;->k:Z

    .line 81
    .line 82
    iget-boolean v1, p1, Lcom/google/android/gms/location/LocationRequest;->k:Z

    .line 83
    .line 84
    if-ne v0, v1, :cond_2

    .line 85
    .line 86
    iget v0, p0, Lcom/google/android/gms/location/LocationRequest;->m:I

    .line 87
    .line 88
    iget v1, p1, Lcom/google/android/gms/location/LocationRequest;->m:I

    .line 89
    .line 90
    if-ne v0, v1, :cond_2

    .line 91
    .line 92
    iget v0, p0, Lcom/google/android/gms/location/LocationRequest;->n:I

    .line 93
    .line 94
    iget v1, p1, Lcom/google/android/gms/location/LocationRequest;->n:I

    .line 95
    .line 96
    if-ne v0, v1, :cond_2

    .line 97
    .line 98
    iget-boolean v0, p0, Lcom/google/android/gms/location/LocationRequest;->o:Z

    .line 99
    .line 100
    iget-boolean v1, p1, Lcom/google/android/gms/location/LocationRequest;->o:Z

    .line 101
    .line 102
    if-ne v0, v1, :cond_2

    .line 103
    .line 104
    iget-object v0, p0, Lcom/google/android/gms/location/LocationRequest;->p:Landroid/os/WorkSource;

    .line 105
    .line 106
    iget-object v1, p1, Lcom/google/android/gms/location/LocationRequest;->p:Landroid/os/WorkSource;

    .line 107
    .line 108
    invoke-virtual {v0, v1}, Landroid/os/WorkSource;->equals(Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result v0

    .line 112
    if-eqz v0, :cond_2

    .line 113
    .line 114
    iget-object p0, p0, Lcom/google/android/gms/location/LocationRequest;->q:Lgp/g;

    .line 115
    .line 116
    iget-object p1, p1, Lcom/google/android/gms/location/LocationRequest;->q:Lgp/g;

    .line 117
    .line 118
    invoke-static {p0, p1}, Lno/c0;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    move-result p0

    .line 122
    if-eqz p0, :cond_2

    .line 123
    .line 124
    const/4 p0, 0x1

    .line 125
    return p0

    .line 126
    :cond_2
    const/4 p0, 0x0

    .line 127
    return p0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget v0, p0, Lcom/google/android/gms/location/LocationRequest;->d:I

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-wide v1, p0, Lcom/google/android/gms/location/LocationRequest;->e:J

    .line 8
    .line 9
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    iget-wide v2, p0, Lcom/google/android/gms/location/LocationRequest;->f:J

    .line 14
    .line 15
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    iget-object p0, p0, Lcom/google/android/gms/location/LocationRequest;->p:Landroid/os/WorkSource;

    .line 20
    .line 21
    filled-new-array {v0, v1, v2, p0}, [Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-static {p0}, Ljava/util/Arrays;->hashCode([Ljava/lang/Object;)I

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 10

    .line 1
    const-string v0, "Request["

    .line 2
    .line 3
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget v1, p0, Lcom/google/android/gms/location/LocationRequest;->d:I

    .line 8
    .line 9
    const-string v2, "/"

    .line 10
    .line 11
    iget-wide v3, p0, Lcom/google/android/gms/location/LocationRequest;->g:J

    .line 12
    .line 13
    iget-wide v5, p0, Lcom/google/android/gms/location/LocationRequest;->e:J

    .line 14
    .line 15
    const/16 v7, 0x69

    .line 16
    .line 17
    if-ne v1, v7, :cond_0

    .line 18
    .line 19
    invoke-static {v1}, Lpp/k;->b(I)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    const-wide/16 v8, 0x0

    .line 27
    .line 28
    cmp-long v1, v3, v8

    .line 29
    .line 30
    if-lez v1, :cond_2

    .line 31
    .line 32
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-static {v3, v4, v0}, Lgp/m;->a(JLjava/lang/StringBuilder;)V

    .line 36
    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_0
    const-string v1, "@"

    .line 40
    .line 41
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    invoke-virtual {p0}, Lcom/google/android/gms/location/LocationRequest;->x0()Z

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    if-eqz v1, :cond_1

    .line 49
    .line 50
    invoke-static {v5, v6, v0}, Lgp/m;->a(JLjava/lang/StringBuilder;)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    invoke-static {v3, v4, v0}, Lgp/m;->a(JLjava/lang/StringBuilder;)V

    .line 57
    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_1
    invoke-static {v5, v6, v0}, Lgp/m;->a(JLjava/lang/StringBuilder;)V

    .line 61
    .line 62
    .line 63
    :goto_0
    const-string v1, " "

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget v1, p0, Lcom/google/android/gms/location/LocationRequest;->d:I

    .line 69
    .line 70
    invoke-static {v1}, Lpp/k;->b(I)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    :cond_2
    :goto_1
    iget v1, p0, Lcom/google/android/gms/location/LocationRequest;->d:I

    .line 78
    .line 79
    iget-wide v2, p0, Lcom/google/android/gms/location/LocationRequest;->f:J

    .line 80
    .line 81
    if-ne v1, v7, :cond_3

    .line 82
    .line 83
    goto :goto_2

    .line 84
    :cond_3
    cmp-long v1, v2, v5

    .line 85
    .line 86
    if-eqz v1, :cond_4

    .line 87
    .line 88
    :goto_2
    const-string v1, ", minUpdateInterval="

    .line 89
    .line 90
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    invoke-static {v2, v3}, Lcom/google/android/gms/location/LocationRequest;->y0(J)Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    :cond_4
    iget v1, p0, Lcom/google/android/gms/location/LocationRequest;->j:F

    .line 101
    .line 102
    float-to-double v2, v1

    .line 103
    const-wide/16 v8, 0x0

    .line 104
    .line 105
    cmpl-double v2, v2, v8

    .line 106
    .line 107
    if-lez v2, :cond_5

    .line 108
    .line 109
    const-string v2, ", minUpdateDistance="

    .line 110
    .line 111
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    :cond_5
    iget v1, p0, Lcom/google/android/gms/location/LocationRequest;->d:I

    .line 118
    .line 119
    const-wide v2, 0x7fffffffffffffffL

    .line 120
    .line 121
    .line 122
    .line 123
    .line 124
    iget-wide v8, p0, Lcom/google/android/gms/location/LocationRequest;->l:J

    .line 125
    .line 126
    if-ne v1, v7, :cond_6

    .line 127
    .line 128
    cmp-long v1, v8, v2

    .line 129
    .line 130
    if-eqz v1, :cond_7

    .line 131
    .line 132
    goto :goto_3

    .line 133
    :cond_6
    cmp-long v1, v8, v5

    .line 134
    .line 135
    if-eqz v1, :cond_7

    .line 136
    .line 137
    :goto_3
    const-string v1, ", maxUpdateAge="

    .line 138
    .line 139
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 140
    .line 141
    .line 142
    invoke-static {v8, v9}, Lcom/google/android/gms/location/LocationRequest;->y0(J)Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object v1

    .line 146
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 147
    .line 148
    .line 149
    :cond_7
    iget-wide v4, p0, Lcom/google/android/gms/location/LocationRequest;->h:J

    .line 150
    .line 151
    cmp-long v1, v4, v2

    .line 152
    .line 153
    if-eqz v1, :cond_8

    .line 154
    .line 155
    const-string v1, ", duration="

    .line 156
    .line 157
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 158
    .line 159
    .line 160
    invoke-static {v4, v5, v0}, Lgp/m;->a(JLjava/lang/StringBuilder;)V

    .line 161
    .line 162
    .line 163
    :cond_8
    iget v1, p0, Lcom/google/android/gms/location/LocationRequest;->i:I

    .line 164
    .line 165
    const v2, 0x7fffffff

    .line 166
    .line 167
    .line 168
    if-eq v1, v2, :cond_9

    .line 169
    .line 170
    const-string v1, ", maxUpdates="

    .line 171
    .line 172
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 173
    .line 174
    .line 175
    iget v1, p0, Lcom/google/android/gms/location/LocationRequest;->i:I

    .line 176
    .line 177
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 178
    .line 179
    .line 180
    :cond_9
    const/4 v1, 0x2

    .line 181
    iget v2, p0, Lcom/google/android/gms/location/LocationRequest;->n:I

    .line 182
    .line 183
    const/4 v3, 0x1

    .line 184
    const-string v4, ", "

    .line 185
    .line 186
    if-eqz v2, :cond_d

    .line 187
    .line 188
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 189
    .line 190
    .line 191
    if-eqz v2, :cond_c

    .line 192
    .line 193
    if-eq v2, v3, :cond_b

    .line 194
    .line 195
    if-ne v2, v1, :cond_a

    .line 196
    .line 197
    const-string v2, "THROTTLE_NEVER"

    .line 198
    .line 199
    goto :goto_4

    .line 200
    :cond_a
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 201
    .line 202
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 203
    .line 204
    .line 205
    throw p0

    .line 206
    :cond_b
    const-string v2, "THROTTLE_ALWAYS"

    .line 207
    .line 208
    goto :goto_4

    .line 209
    :cond_c
    const-string v2, "THROTTLE_BACKGROUND"

    .line 210
    .line 211
    :goto_4
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 212
    .line 213
    .line 214
    :cond_d
    iget v2, p0, Lcom/google/android/gms/location/LocationRequest;->m:I

    .line 215
    .line 216
    if-eqz v2, :cond_11

    .line 217
    .line 218
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 219
    .line 220
    .line 221
    if-eqz v2, :cond_10

    .line 222
    .line 223
    if-eq v2, v3, :cond_f

    .line 224
    .line 225
    if-ne v2, v1, :cond_e

    .line 226
    .line 227
    const-string v1, "GRANULARITY_FINE"

    .line 228
    .line 229
    goto :goto_5

    .line 230
    :cond_e
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 231
    .line 232
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 233
    .line 234
    .line 235
    throw p0

    .line 236
    :cond_f
    const-string v1, "GRANULARITY_COARSE"

    .line 237
    .line 238
    goto :goto_5

    .line 239
    :cond_10
    const-string v1, "GRANULARITY_PERMISSION_LEVEL"

    .line 240
    .line 241
    :goto_5
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 242
    .line 243
    .line 244
    :cond_11
    iget-boolean v1, p0, Lcom/google/android/gms/location/LocationRequest;->k:Z

    .line 245
    .line 246
    if-eqz v1, :cond_12

    .line 247
    .line 248
    const-string v1, ", waitForAccurateLocation"

    .line 249
    .line 250
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 251
    .line 252
    .line 253
    :cond_12
    iget-boolean v1, p0, Lcom/google/android/gms/location/LocationRequest;->o:Z

    .line 254
    .line 255
    if-eqz v1, :cond_13

    .line 256
    .line 257
    const-string v1, ", bypass"

    .line 258
    .line 259
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 260
    .line 261
    .line 262
    :cond_13
    sget-object v1, Lto/d;->d:Ljava/lang/reflect/Method;

    .line 263
    .line 264
    iget-object v2, p0, Lcom/google/android/gms/location/LocationRequest;->p:Landroid/os/WorkSource;

    .line 265
    .line 266
    const-string v5, "WorkSourceUtil"

    .line 267
    .line 268
    const/4 v6, 0x0

    .line 269
    if-eqz v1, :cond_14

    .line 270
    .line 271
    :try_start_0
    invoke-virtual {v1, v2, v6}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    move-result-object v1

    .line 275
    invoke-static {v1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 276
    .line 277
    .line 278
    check-cast v1, Ljava/lang/Boolean;

    .line 279
    .line 280
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 281
    .line 282
    .line 283
    move-result v3
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 284
    goto :goto_7

    .line 285
    :catch_0
    move-exception v1

    .line 286
    const-string v7, "Unable to check WorkSource emptiness"

    .line 287
    .line 288
    invoke-static {v5, v7, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 289
    .line 290
    .line 291
    :cond_14
    sget-object v1, Lto/d;->c:Ljava/lang/reflect/Method;

    .line 292
    .line 293
    const/4 v7, 0x0

    .line 294
    if-eqz v1, :cond_15

    .line 295
    .line 296
    :try_start_1
    invoke-virtual {v1, v2, v6}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    move-result-object v1

    .line 300
    invoke-static {v1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 301
    .line 302
    .line 303
    check-cast v1, Ljava/lang/Integer;

    .line 304
    .line 305
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 306
    .line 307
    .line 308
    move-result v1
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 309
    goto :goto_6

    .line 310
    :catch_1
    move-exception v1

    .line 311
    const-string v6, "Unable to assign blame through WorkSource"

    .line 312
    .line 313
    invoke-static {v5, v6, v1}, Landroid/util/Log;->wtf(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 314
    .line 315
    .line 316
    :cond_15
    move v1, v7

    .line 317
    :goto_6
    if-nez v1, :cond_16

    .line 318
    .line 319
    goto :goto_7

    .line 320
    :cond_16
    move v3, v7

    .line 321
    :goto_7
    if-nez v3, :cond_17

    .line 322
    .line 323
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 324
    .line 325
    .line 326
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 327
    .line 328
    .line 329
    :cond_17
    iget-object p0, p0, Lcom/google/android/gms/location/LocationRequest;->q:Lgp/g;

    .line 330
    .line 331
    if-eqz p0, :cond_18

    .line 332
    .line 333
    const-string v1, ", impersonation="

    .line 334
    .line 335
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 336
    .line 337
    .line 338
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 339
    .line 340
    .line 341
    :cond_18
    const/16 p0, 0x5d

    .line 342
    .line 343
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 344
    .line 345
    .line 346
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 347
    .line 348
    .line 349
    move-result-object p0

    .line 350
    return-object p0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 6

    .line 1
    const/16 v0, 0x4f45

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget v1, p0, Lcom/google/android/gms/location/LocationRequest;->d:I

    .line 8
    .line 9
    const/4 v2, 0x1

    .line 10
    const/4 v3, 0x4

    .line 11
    invoke-static {p1, v2, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 15
    .line 16
    .line 17
    const/4 v1, 0x2

    .line 18
    const/16 v2, 0x8

    .line 19
    .line 20
    invoke-static {p1, v1, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 21
    .line 22
    .line 23
    iget-wide v4, p0, Lcom/google/android/gms/location/LocationRequest;->e:J

    .line 24
    .line 25
    invoke-virtual {p1, v4, v5}, Landroid/os/Parcel;->writeLong(J)V

    .line 26
    .line 27
    .line 28
    const/4 v1, 0x3

    .line 29
    invoke-static {p1, v1, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 30
    .line 31
    .line 32
    iget-wide v4, p0, Lcom/google/android/gms/location/LocationRequest;->f:J

    .line 33
    .line 34
    invoke-virtual {p1, v4, v5}, Landroid/os/Parcel;->writeLong(J)V

    .line 35
    .line 36
    .line 37
    iget v1, p0, Lcom/google/android/gms/location/LocationRequest;->i:I

    .line 38
    .line 39
    const/4 v4, 0x6

    .line 40
    invoke-static {p1, v4, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 44
    .line 45
    .line 46
    const/4 v1, 0x7

    .line 47
    invoke-static {p1, v1, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 48
    .line 49
    .line 50
    iget v1, p0, Lcom/google/android/gms/location/LocationRequest;->j:F

    .line 51
    .line 52
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeFloat(F)V

    .line 53
    .line 54
    .line 55
    invoke-static {p1, v2, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 56
    .line 57
    .line 58
    iget-wide v4, p0, Lcom/google/android/gms/location/LocationRequest;->g:J

    .line 59
    .line 60
    invoke-virtual {p1, v4, v5}, Landroid/os/Parcel;->writeLong(J)V

    .line 61
    .line 62
    .line 63
    const/16 v1, 0x9

    .line 64
    .line 65
    invoke-static {p1, v1, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 66
    .line 67
    .line 68
    iget-boolean v1, p0, Lcom/google/android/gms/location/LocationRequest;->k:Z

    .line 69
    .line 70
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 71
    .line 72
    .line 73
    const/16 v1, 0xa

    .line 74
    .line 75
    invoke-static {p1, v1, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 76
    .line 77
    .line 78
    iget-wide v4, p0, Lcom/google/android/gms/location/LocationRequest;->h:J

    .line 79
    .line 80
    invoke-virtual {p1, v4, v5}, Landroid/os/Parcel;->writeLong(J)V

    .line 81
    .line 82
    .line 83
    const/16 v1, 0xb

    .line 84
    .line 85
    invoke-static {p1, v1, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 86
    .line 87
    .line 88
    iget-wide v1, p0, Lcom/google/android/gms/location/LocationRequest;->l:J

    .line 89
    .line 90
    invoke-virtual {p1, v1, v2}, Landroid/os/Parcel;->writeLong(J)V

    .line 91
    .line 92
    .line 93
    const/16 v1, 0xc

    .line 94
    .line 95
    invoke-static {p1, v1, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 96
    .line 97
    .line 98
    iget v1, p0, Lcom/google/android/gms/location/LocationRequest;->m:I

    .line 99
    .line 100
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 101
    .line 102
    .line 103
    const/16 v1, 0xd

    .line 104
    .line 105
    invoke-static {p1, v1, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 106
    .line 107
    .line 108
    iget v1, p0, Lcom/google/android/gms/location/LocationRequest;->n:I

    .line 109
    .line 110
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 111
    .line 112
    .line 113
    const/16 v1, 0xf

    .line 114
    .line 115
    invoke-static {p1, v1, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 116
    .line 117
    .line 118
    iget-boolean v1, p0, Lcom/google/android/gms/location/LocationRequest;->o:Z

    .line 119
    .line 120
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 121
    .line 122
    .line 123
    const/16 v1, 0x10

    .line 124
    .line 125
    iget-object v2, p0, Lcom/google/android/gms/location/LocationRequest;->p:Landroid/os/WorkSource;

    .line 126
    .line 127
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 128
    .line 129
    .line 130
    const/16 v1, 0x11

    .line 131
    .line 132
    iget-object p0, p0, Lcom/google/android/gms/location/LocationRequest;->q:Lgp/g;

    .line 133
    .line 134
    invoke-static {p1, v1, p0, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 135
    .line 136
    .line 137
    invoke-static {p1, v0}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 138
    .line 139
    .line 140
    return-void
.end method

.method public final x0()Z
    .locals 5

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iget-wide v2, p0, Lcom/google/android/gms/location/LocationRequest;->g:J

    .line 4
    .line 5
    cmp-long v0, v2, v0

    .line 6
    .line 7
    if-lez v0, :cond_0

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    shr-long v1, v2, v0

    .line 11
    .line 12
    iget-wide v3, p0, Lcom/google/android/gms/location/LocationRequest;->e:J

    .line 13
    .line 14
    cmp-long p0, v1, v3

    .line 15
    .line 16
    if-ltz p0, :cond_0

    .line 17
    .line 18
    return v0

    .line 19
    :cond_0
    const/4 p0, 0x0

    .line 20
    return p0
.end method
