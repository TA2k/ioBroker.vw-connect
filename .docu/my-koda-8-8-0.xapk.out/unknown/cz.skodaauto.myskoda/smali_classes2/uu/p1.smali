.class public final synthetic Luu/p1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:Luu/x;

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Ljava/util/ArrayList;

.field public final synthetic g:Z

.field public final synthetic h:J

.field public final synthetic i:J

.field public final synthetic j:F

.field public final synthetic k:F


# direct methods
.method public synthetic constructor <init>(Luu/x;Lay0/k;Ljava/util/ArrayList;ZJJFF)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luu/p1;->d:Luu/x;

    .line 5
    .line 6
    iput-object p2, p0, Luu/p1;->e:Lay0/k;

    .line 7
    .line 8
    iput-object p3, p0, Luu/p1;->f:Ljava/util/ArrayList;

    .line 9
    .line 10
    iput-boolean p4, p0, Luu/p1;->g:Z

    .line 11
    .line 12
    iput-wide p5, p0, Luu/p1;->h:J

    .line 13
    .line 14
    iput-wide p7, p0, Luu/p1;->i:J

    .line 15
    .line 16
    iput p9, p0, Luu/p1;->j:F

    .line 17
    .line 18
    iput p10, p0, Luu/p1;->k:F

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 7

    .line 1
    iget-object v0, p0, Luu/p1;->d:Luu/x;

    .line 2
    .line 3
    iget-object v0, v0, Luu/x;->h:Lqp/g;

    .line 4
    .line 5
    if-eqz v0, :cond_3

    .line 6
    .line 7
    new-instance v1, Lsp/p;

    .line 8
    .line 9
    invoke-direct {v1}, Lsp/p;-><init>()V

    .line 10
    .line 11
    .line 12
    iget-object v2, p0, Luu/p1;->f:Ljava/util/ArrayList;

    .line 13
    .line 14
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    if-eqz v3, :cond_0

    .line 23
    .line 24
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    check-cast v3, Lcom/google/android/gms/maps/model/LatLng;

    .line 29
    .line 30
    iget-object v4, v1, Lsp/p;->d:Ljava/util/List;

    .line 31
    .line 32
    invoke-interface {v4, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    iget-boolean v2, p0, Luu/p1;->g:Z

    .line 37
    .line 38
    iput-boolean v2, v1, Lsp/p;->l:Z

    .line 39
    .line 40
    iget-wide v2, p0, Luu/p1;->h:J

    .line 41
    .line 42
    invoke-static {v2, v3}, Le3/j0;->z(J)I

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    iput v2, v1, Lsp/p;->h:I

    .line 47
    .line 48
    const/4 v2, 0x0

    .line 49
    iput-boolean v2, v1, Lsp/p;->k:Z

    .line 50
    .line 51
    iget-wide v3, p0, Luu/p1;->i:J

    .line 52
    .line 53
    invoke-static {v3, v4}, Le3/j0;->z(J)I

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    iput v3, v1, Lsp/p;->g:I

    .line 58
    .line 59
    iput v2, v1, Lsp/p;->m:I

    .line 60
    .line 61
    const/4 v2, 0x0

    .line 62
    iput-object v2, v1, Lsp/p;->n:Ljava/util/List;

    .line 63
    .line 64
    iget v3, p0, Luu/p1;->j:F

    .line 65
    .line 66
    iput v3, v1, Lsp/p;->f:F

    .line 67
    .line 68
    const/4 v3, 0x1

    .line 69
    iput-boolean v3, v1, Lsp/p;->j:Z

    .line 70
    .line 71
    iget v3, p0, Luu/p1;->k:F

    .line 72
    .line 73
    iput v3, v1, Lsp/p;->i:F

    .line 74
    .line 75
    :try_start_0
    new-instance v3, Lsp/o;

    .line 76
    .line 77
    iget-object v0, v0, Lqp/g;->a:Lrp/f;

    .line 78
    .line 79
    invoke-virtual {v0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 80
    .line 81
    .line 82
    move-result-object v4

    .line 83
    invoke-static {v4, v1}, Lhp/j;->c(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 84
    .line 85
    .line 86
    const/16 v1, 0xa

    .line 87
    .line 88
    invoke-virtual {v0, v4, v1}, Lbp/a;->c(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    invoke-virtual {v0}, Landroid/os/Parcel;->readStrongBinder()Landroid/os/IBinder;

    .line 93
    .line 94
    .line 95
    move-result-object v1

    .line 96
    sget v4, Lhp/e;->d:I

    .line 97
    .line 98
    const-string v4, "com.google.android.gms.maps.model.internal.IPolygonDelegate"

    .line 99
    .line 100
    if-nez v1, :cond_1

    .line 101
    .line 102
    move-object v5, v2

    .line 103
    goto :goto_1

    .line 104
    :cond_1
    invoke-interface {v1, v4}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 105
    .line 106
    .line 107
    move-result-object v5

    .line 108
    instance-of v6, v5, Lhp/f;

    .line 109
    .line 110
    if-eqz v6, :cond_2

    .line 111
    .line 112
    check-cast v5, Lhp/f;

    .line 113
    .line 114
    goto :goto_1

    .line 115
    :cond_2
    new-instance v5, Lhp/d;

    .line 116
    .line 117
    const/4 v6, 0x5

    .line 118
    invoke-direct {v5, v1, v4, v6}, Lbp/a;-><init>(Landroid/os/IBinder;Ljava/lang/String;I)V

    .line 119
    .line 120
    .line 121
    :goto_1
    invoke-virtual {v0}, Landroid/os/Parcel;->recycle()V

    .line 122
    .line 123
    .line 124
    invoke-direct {v3, v5}, Lsp/o;-><init>(Lhp/f;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 125
    .line 126
    .line 127
    invoke-virtual {v3, v2}, Lsp/o;->a(Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    new-instance v0, Luu/q1;

    .line 131
    .line 132
    iget-object p0, p0, Luu/p1;->e:Lay0/k;

    .line 133
    .line 134
    invoke-direct {v0, v3, p0}, Luu/q1;-><init>(Lsp/o;Lay0/k;)V

    .line 135
    .line 136
    .line 137
    return-object v0

    .line 138
    :catch_0
    move-exception p0

    .line 139
    new-instance v0, La8/r0;

    .line 140
    .line 141
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 142
    .line 143
    .line 144
    throw v0

    .line 145
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 146
    .line 147
    const-string v0, "Error adding polygon"

    .line 148
    .line 149
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    throw p0
.end method
