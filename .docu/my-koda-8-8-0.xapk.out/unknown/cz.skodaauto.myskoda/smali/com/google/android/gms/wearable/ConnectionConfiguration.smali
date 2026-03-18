.class public Lcom/google/android/gms/wearable/ConnectionConfiguration;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/gms/common/internal/ReflectedParcelable;


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/google/android/gms/wearable/ConnectionConfiguration;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:Ljava/lang/String;

.field public final f:I

.field public final g:I

.field public final h:Z

.field public final i:Z

.field public volatile j:Ljava/lang/String;

.field public final k:Z

.field public final l:Ljava/lang/String;

.field public final m:Ljava/lang/String;

.field public final n:I

.field public final o:Ljava/util/List;

.field public final p:Z

.field public final q:Z

.field public final r:Lbq/i;

.field public final s:Z

.field public final t:Lbq/h;

.field public final u:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lsp/w;

    .line 2
    .line 3
    const/16 v1, 0x9

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lsp/w;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;IIZZLjava/lang/String;ZLjava/lang/String;Ljava/lang/String;ILjava/util/ArrayList;ZZLbq/i;ZLbq/h;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->d:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->e:Ljava/lang/String;

    .line 7
    .line 8
    iput p3, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->f:I

    .line 9
    .line 10
    iput p4, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->g:I

    .line 11
    .line 12
    iput-boolean p5, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->h:Z

    .line 13
    .line 14
    iput-boolean p6, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->i:Z

    .line 15
    .line 16
    iput-object p7, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->j:Ljava/lang/String;

    .line 17
    .line 18
    iput-boolean p8, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->k:Z

    .line 19
    .line 20
    iput-object p9, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->l:Ljava/lang/String;

    .line 21
    .line 22
    iput-object p10, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->m:Ljava/lang/String;

    .line 23
    .line 24
    iput p11, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->n:I

    .line 25
    .line 26
    iput-object p12, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->o:Ljava/util/List;

    .line 27
    .line 28
    iput-boolean p13, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->p:Z

    .line 29
    .line 30
    iput-boolean p14, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->q:Z

    .line 31
    .line 32
    iput-object p15, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->r:Lbq/i;

    .line 33
    .line 34
    move/from16 p1, p16

    .line 35
    .line 36
    iput-boolean p1, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->s:Z

    .line 37
    .line 38
    move-object/from16 p1, p17

    .line 39
    .line 40
    iput-object p1, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->t:Lbq/h;

    .line 41
    .line 42
    move/from16 p1, p18

    .line 43
    .line 44
    iput p1, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->u:I

    .line 45
    .line 46
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    instance-of v0, p1, Lcom/google/android/gms/wearable/ConnectionConfiguration;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    return v1

    .line 7
    :cond_0
    check-cast p1, Lcom/google/android/gms/wearable/ConnectionConfiguration;

    .line 8
    .line 9
    iget-object v0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->d:Ljava/lang/String;

    .line 10
    .line 11
    iget-object v2, p1, Lcom/google/android/gms/wearable/ConnectionConfiguration;->d:Ljava/lang/String;

    .line 12
    .line 13
    invoke-static {v0, v2}, Lno/c0;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_1

    .line 18
    .line 19
    iget-object v0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->e:Ljava/lang/String;

    .line 20
    .line 21
    iget-object v2, p1, Lcom/google/android/gms/wearable/ConnectionConfiguration;->e:Ljava/lang/String;

    .line 22
    .line 23
    invoke-static {v0, v2}, Lno/c0;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_1

    .line 28
    .line 29
    iget v0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->f:I

    .line 30
    .line 31
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    iget v2, p1, Lcom/google/android/gms/wearable/ConnectionConfiguration;->f:I

    .line 36
    .line 37
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 38
    .line 39
    .line 40
    move-result-object v2

    .line 41
    invoke-static {v0, v2}, Lno/c0;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    if-eqz v0, :cond_1

    .line 46
    .line 47
    iget v0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->g:I

    .line 48
    .line 49
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    iget v2, p1, Lcom/google/android/gms/wearable/ConnectionConfiguration;->g:I

    .line 54
    .line 55
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    invoke-static {v0, v2}, Lno/c0;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    if-eqz v0, :cond_1

    .line 64
    .line 65
    iget-boolean v0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->h:Z

    .line 66
    .line 67
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    iget-boolean v2, p1, Lcom/google/android/gms/wearable/ConnectionConfiguration;->h:Z

    .line 72
    .line 73
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    invoke-static {v0, v2}, Lno/c0;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    if-eqz v0, :cond_1

    .line 82
    .line 83
    iget-boolean v0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->k:Z

    .line 84
    .line 85
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    iget-boolean v2, p1, Lcom/google/android/gms/wearable/ConnectionConfiguration;->k:Z

    .line 90
    .line 91
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 92
    .line 93
    .line 94
    move-result-object v2

    .line 95
    invoke-static {v0, v2}, Lno/c0;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    if-eqz v0, :cond_1

    .line 100
    .line 101
    iget-boolean v0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->p:Z

    .line 102
    .line 103
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    iget-boolean v2, p1, Lcom/google/android/gms/wearable/ConnectionConfiguration;->p:Z

    .line 108
    .line 109
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 110
    .line 111
    .line 112
    move-result-object v2

    .line 113
    invoke-static {v0, v2}, Lno/c0;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result v0

    .line 117
    if-eqz v0, :cond_1

    .line 118
    .line 119
    iget-boolean p0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->q:Z

    .line 120
    .line 121
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    iget-boolean p1, p1, Lcom/google/android/gms/wearable/ConnectionConfiguration;->q:Z

    .line 126
    .line 127
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 128
    .line 129
    .line 130
    move-result-object p1

    .line 131
    invoke-static {p0, p1}, Lno/c0;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result p0

    .line 135
    if-eqz p0, :cond_1

    .line 136
    .line 137
    const/4 p0, 0x1

    .line 138
    return p0

    .line 139
    :cond_1
    return v1
.end method

.method public final hashCode()I
    .locals 9

    .line 1
    iget v0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->f:I

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 4
    .line 5
    .line 6
    move-result-object v3

    .line 7
    iget v0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->g:I

    .line 8
    .line 9
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 10
    .line 11
    .line 12
    move-result-object v4

    .line 13
    iget-boolean v0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->h:Z

    .line 14
    .line 15
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 16
    .line 17
    .line 18
    move-result-object v5

    .line 19
    iget-boolean v0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->k:Z

    .line 20
    .line 21
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 22
    .line 23
    .line 24
    move-result-object v6

    .line 25
    iget-boolean v0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->p:Z

    .line 26
    .line 27
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 28
    .line 29
    .line 30
    move-result-object v7

    .line 31
    iget-boolean v0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->q:Z

    .line 32
    .line 33
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 34
    .line 35
    .line 36
    move-result-object v8

    .line 37
    iget-object v1, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->d:Ljava/lang/String;

    .line 38
    .line 39
    iget-object v2, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->e:Ljava/lang/String;

    .line 40
    .line 41
    filled-new-array/range {v1 .. v8}, [Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-static {p0}, Ljava/util/Arrays;->hashCode([Ljava/lang/Object;)I

    .line 46
    .line 47
    .line 48
    move-result p0

    .line 49
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "ConnectionConfiguration[ Name="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->d:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", Address="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->e:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", Type="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget v1, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->f:I

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", Role="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget v1, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->g:I

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", Enabled="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-boolean v1, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->h:Z

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", IsConnected="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-boolean v1, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->i:Z

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", PeerNodeId="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget-object v1, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->j:Ljava/lang/String;

    .line 69
    .line 70
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v1, ", BtlePriority="

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    iget-boolean v1, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->k:Z

    .line 79
    .line 80
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v1, ", NodeId="

    .line 84
    .line 85
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    iget-object v1, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->l:Ljava/lang/String;

    .line 89
    .line 90
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string v1, ", PackageName="

    .line 94
    .line 95
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    iget-object v1, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->m:Ljava/lang/String;

    .line 99
    .line 100
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    const-string v1, ", ConnectionRetryStrategy="

    .line 104
    .line 105
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    iget v1, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->n:I

    .line 109
    .line 110
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    const-string v1, ", allowedConfigPackages="

    .line 114
    .line 115
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    iget-object v1, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->o:Ljava/util/List;

    .line 119
    .line 120
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    const-string v1, ", Migrating="

    .line 124
    .line 125
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    iget-boolean v1, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->p:Z

    .line 129
    .line 130
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    const-string v1, ", DataItemSyncEnabled="

    .line 134
    .line 135
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    iget-boolean v1, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->q:Z

    .line 139
    .line 140
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 141
    .line 142
    .line 143
    const-string v1, ", ConnectionRestrictions="

    .line 144
    .line 145
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 146
    .line 147
    .line 148
    iget-object v1, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->r:Lbq/i;

    .line 149
    .line 150
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 151
    .line 152
    .line 153
    const-string v1, ", removeConnectionWhenBondRemovedByUser="

    .line 154
    .line 155
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 156
    .line 157
    .line 158
    iget-boolean v1, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->s:Z

    .line 159
    .line 160
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 161
    .line 162
    .line 163
    const-string v1, ", maxSupportedRemoteAndroidSdkVersion="

    .line 164
    .line 165
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 166
    .line 167
    .line 168
    iget p0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->u:I

    .line 169
    .line 170
    const-string v1, "]"

    .line 171
    .line 172
    invoke-static {p0, v1, v0}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    return-object p0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->d:Ljava/lang/String;

    .line 2
    .line 3
    const/16 v1, 0x4f45

    .line 4
    .line 5
    invoke-static {p1, v1}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const/4 v2, 0x2

    .line 10
    invoke-static {p1, v0, v2}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 11
    .line 12
    .line 13
    const/4 v0, 0x3

    .line 14
    iget-object v2, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->e:Ljava/lang/String;

    .line 15
    .line 16
    invoke-static {p1, v2, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    iget v0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->f:I

    .line 20
    .line 21
    const/4 v2, 0x4

    .line 22
    invoke-static {p1, v2, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 26
    .line 27
    .line 28
    iget v0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->g:I

    .line 29
    .line 30
    const/4 v3, 0x5

    .line 31
    invoke-static {p1, v3, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 35
    .line 36
    .line 37
    iget-boolean v0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->h:Z

    .line 38
    .line 39
    const/4 v3, 0x6

    .line 40
    invoke-static {p1, v3, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 44
    .line 45
    .line 46
    iget-boolean v0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->i:Z

    .line 47
    .line 48
    const/4 v3, 0x7

    .line 49
    invoke-static {p1, v3, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 53
    .line 54
    .line 55
    const/16 v0, 0x8

    .line 56
    .line 57
    iget-object v3, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->j:Ljava/lang/String;

    .line 58
    .line 59
    invoke-static {p1, v3, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 60
    .line 61
    .line 62
    iget-boolean v0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->k:Z

    .line 63
    .line 64
    const/16 v3, 0x9

    .line 65
    .line 66
    invoke-static {p1, v3, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 70
    .line 71
    .line 72
    const/16 v0, 0xa

    .line 73
    .line 74
    iget-object v3, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->l:Ljava/lang/String;

    .line 75
    .line 76
    invoke-static {p1, v3, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 77
    .line 78
    .line 79
    const/16 v0, 0xb

    .line 80
    .line 81
    iget-object v3, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->m:Ljava/lang/String;

    .line 82
    .line 83
    invoke-static {p1, v3, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 84
    .line 85
    .line 86
    iget v0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->n:I

    .line 87
    .line 88
    const/16 v3, 0xc

    .line 89
    .line 90
    invoke-static {p1, v3, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 94
    .line 95
    .line 96
    const/16 v0, 0xd

    .line 97
    .line 98
    iget-object v3, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->o:Ljava/util/List;

    .line 99
    .line 100
    invoke-static {p1, v0, v3}, Ljp/dc;->p(Landroid/os/Parcel;ILjava/util/List;)V

    .line 101
    .line 102
    .line 103
    iget-boolean v0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->p:Z

    .line 104
    .line 105
    const/16 v3, 0xe

    .line 106
    .line 107
    invoke-static {p1, v3, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 111
    .line 112
    .line 113
    iget-boolean v0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->q:Z

    .line 114
    .line 115
    const/16 v3, 0xf

    .line 116
    .line 117
    invoke-static {p1, v3, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 121
    .line 122
    .line 123
    const/16 v0, 0x10

    .line 124
    .line 125
    iget-object v3, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->r:Lbq/i;

    .line 126
    .line 127
    invoke-static {p1, v0, v3, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 128
    .line 129
    .line 130
    iget-boolean v0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->s:Z

    .line 131
    .line 132
    const/16 v3, 0x11

    .line 133
    .line 134
    invoke-static {p1, v3, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 135
    .line 136
    .line 137
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 138
    .line 139
    .line 140
    const/16 v0, 0x12

    .line 141
    .line 142
    iget-object v3, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->t:Lbq/h;

    .line 143
    .line 144
    invoke-static {p1, v0, v3, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 145
    .line 146
    .line 147
    iget p0, p0, Lcom/google/android/gms/wearable/ConnectionConfiguration;->u:I

    .line 148
    .line 149
    const/16 p2, 0x13

    .line 150
    .line 151
    invoke-static {p1, p2, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 152
    .line 153
    .line 154
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeInt(I)V

    .line 155
    .line 156
    .line 157
    invoke-static {p1, v1}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 158
    .line 159
    .line 160
    return-void
.end method
