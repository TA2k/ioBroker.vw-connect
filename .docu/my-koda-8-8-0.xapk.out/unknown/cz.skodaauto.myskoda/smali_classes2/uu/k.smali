.class public final synthetic Luu/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:Luu/x;

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Lcom/google/android/gms/maps/model/LatLng;

.field public final synthetic g:J

.field public final synthetic h:D

.field public final synthetic i:J

.field public final synthetic j:F

.field public final synthetic k:F


# direct methods
.method public synthetic constructor <init>(Luu/x;Lay0/k;Lcom/google/android/gms/maps/model/LatLng;JDJFF)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luu/k;->d:Luu/x;

    .line 5
    .line 6
    iput-object p2, p0, Luu/k;->e:Lay0/k;

    .line 7
    .line 8
    iput-object p3, p0, Luu/k;->f:Lcom/google/android/gms/maps/model/LatLng;

    .line 9
    .line 10
    iput-wide p4, p0, Luu/k;->g:J

    .line 11
    .line 12
    iput-wide p6, p0, Luu/k;->h:D

    .line 13
    .line 14
    iput-wide p8, p0, Luu/k;->i:J

    .line 15
    .line 16
    iput p10, p0, Luu/k;->j:F

    .line 17
    .line 18
    iput p11, p0, Luu/k;->k:F

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 7

    .line 1
    iget-object v0, p0, Luu/k;->d:Luu/x;

    .line 2
    .line 3
    if-eqz v0, :cond_2

    .line 4
    .line 5
    iget-object v0, v0, Luu/x;->h:Lqp/g;

    .line 6
    .line 7
    if-eqz v0, :cond_2

    .line 8
    .line 9
    new-instance v1, Lsp/f;

    .line 10
    .line 11
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    const-wide/16 v2, 0x0

    .line 15
    .line 16
    iput-wide v2, v1, Lsp/f;->e:D

    .line 17
    .line 18
    const/high16 v2, 0x41200000    # 10.0f

    .line 19
    .line 20
    iput v2, v1, Lsp/f;->f:F

    .line 21
    .line 22
    const/high16 v2, -0x1000000

    .line 23
    .line 24
    iput v2, v1, Lsp/f;->g:I

    .line 25
    .line 26
    const/4 v2, 0x0

    .line 27
    iput v2, v1, Lsp/f;->h:I

    .line 28
    .line 29
    const/4 v3, 0x0

    .line 30
    iput v3, v1, Lsp/f;->i:F

    .line 31
    .line 32
    const/4 v3, 0x1

    .line 33
    iput-boolean v3, v1, Lsp/f;->j:Z

    .line 34
    .line 35
    const/4 v4, 0x0

    .line 36
    iput-object v4, v1, Lsp/f;->l:Ljava/util/ArrayList;

    .line 37
    .line 38
    iget-object v5, p0, Luu/k;->f:Lcom/google/android/gms/maps/model/LatLng;

    .line 39
    .line 40
    iput-object v5, v1, Lsp/f;->d:Lcom/google/android/gms/maps/model/LatLng;

    .line 41
    .line 42
    iput-boolean v2, v1, Lsp/f;->k:Z

    .line 43
    .line 44
    iget-wide v5, p0, Luu/k;->g:J

    .line 45
    .line 46
    invoke-static {v5, v6}, Le3/j0;->z(J)I

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    iput v2, v1, Lsp/f;->h:I

    .line 51
    .line 52
    iget-wide v5, p0, Luu/k;->h:D

    .line 53
    .line 54
    iput-wide v5, v1, Lsp/f;->e:D

    .line 55
    .line 56
    iget-wide v5, p0, Luu/k;->i:J

    .line 57
    .line 58
    invoke-static {v5, v6}, Le3/j0;->z(J)I

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    iput v2, v1, Lsp/f;->g:I

    .line 63
    .line 64
    iput-object v4, v1, Lsp/f;->l:Ljava/util/ArrayList;

    .line 65
    .line 66
    iget v2, p0, Luu/k;->j:F

    .line 67
    .line 68
    iput v2, v1, Lsp/f;->f:F

    .line 69
    .line 70
    iput-boolean v3, v1, Lsp/f;->j:Z

    .line 71
    .line 72
    iget v2, p0, Luu/k;->k:F

    .line 73
    .line 74
    iput v2, v1, Lsp/f;->i:F

    .line 75
    .line 76
    :try_start_0
    new-instance v2, Lsp/e;

    .line 77
    .line 78
    iget-object v0, v0, Lqp/g;->a:Lrp/f;

    .line 79
    .line 80
    invoke-virtual {v0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 81
    .line 82
    .line 83
    move-result-object v3

    .line 84
    invoke-static {v3, v1}, Lhp/j;->c(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 85
    .line 86
    .line 87
    const/16 v1, 0x23

    .line 88
    .line 89
    invoke-virtual {v0, v3, v1}, Lbp/a;->c(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    invoke-virtual {v0}, Landroid/os/Parcel;->readStrongBinder()Landroid/os/IBinder;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    sget v3, Lhp/o;->d:I

    .line 98
    .line 99
    const-string v3, "com.google.android.gms.maps.model.internal.ICircleDelegate"

    .line 100
    .line 101
    if-nez v1, :cond_0

    .line 102
    .line 103
    move-object v5, v4

    .line 104
    goto :goto_0

    .line 105
    :cond_0
    invoke-interface {v1, v3}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 106
    .line 107
    .line 108
    move-result-object v5

    .line 109
    instance-of v6, v5, Lhp/p;

    .line 110
    .line 111
    if-eqz v6, :cond_1

    .line 112
    .line 113
    check-cast v5, Lhp/p;

    .line 114
    .line 115
    goto :goto_0

    .line 116
    :cond_1
    new-instance v5, Lhp/n;

    .line 117
    .line 118
    const/4 v6, 0x5

    .line 119
    invoke-direct {v5, v1, v3, v6}, Lbp/a;-><init>(Landroid/os/IBinder;Ljava/lang/String;I)V

    .line 120
    .line 121
    .line 122
    :goto_0
    invoke-virtual {v0}, Landroid/os/Parcel;->recycle()V

    .line 123
    .line 124
    .line 125
    invoke-direct {v2, v5}, Lsp/e;-><init>(Lhp/p;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 126
    .line 127
    .line 128
    invoke-virtual {v2, v4}, Lsp/e;->a(Ljava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    new-instance v0, Luu/m;

    .line 132
    .line 133
    iget-object p0, p0, Luu/k;->e:Lay0/k;

    .line 134
    .line 135
    invoke-direct {v0, v2, p0}, Luu/m;-><init>(Lsp/e;Lay0/k;)V

    .line 136
    .line 137
    .line 138
    return-object v0

    .line 139
    :catch_0
    move-exception p0

    .line 140
    new-instance v0, La8/r0;

    .line 141
    .line 142
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 143
    .line 144
    .line 145
    throw v0

    .line 146
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 147
    .line 148
    const-string v0, "Error adding circle"

    .line 149
    .line 150
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    throw p0
.end method
