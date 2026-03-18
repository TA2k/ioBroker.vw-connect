.class public final synthetic Luu/u1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:Luu/x;

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Ljava/util/ArrayList;

.field public final synthetic g:Ljava/util/List;

.field public final synthetic h:J

.field public final synthetic i:Lsp/d;

.field public final synthetic j:Ljava/util/List;

.field public final synthetic k:Lsp/d;

.field public final synthetic l:Z

.field public final synthetic m:F


# direct methods
.method public synthetic constructor <init>(Luu/x;Lay0/k;Ljava/util/ArrayList;Ljava/util/List;JLsp/d;Ljava/util/List;Lsp/d;ZF)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luu/u1;->d:Luu/x;

    .line 5
    .line 6
    iput-object p2, p0, Luu/u1;->e:Lay0/k;

    .line 7
    .line 8
    iput-object p3, p0, Luu/u1;->f:Ljava/util/ArrayList;

    .line 9
    .line 10
    iput-object p4, p0, Luu/u1;->g:Ljava/util/List;

    .line 11
    .line 12
    iput-wide p5, p0, Luu/u1;->h:J

    .line 13
    .line 14
    iput-object p7, p0, Luu/u1;->i:Lsp/d;

    .line 15
    .line 16
    iput-object p8, p0, Luu/u1;->j:Ljava/util/List;

    .line 17
    .line 18
    iput-object p9, p0, Luu/u1;->k:Lsp/d;

    .line 19
    .line 20
    iput-boolean p10, p0, Luu/u1;->l:Z

    .line 21
    .line 22
    iput p11, p0, Luu/u1;->m:F

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 7

    .line 1
    iget-object v0, p0, Luu/u1;->d:Luu/x;

    .line 2
    .line 3
    iget-object v0, v0, Luu/x;->h:Lqp/g;

    .line 4
    .line 5
    if-eqz v0, :cond_4

    .line 6
    .line 7
    new-instance v1, Lsp/r;

    .line 8
    .line 9
    invoke-direct {v1}, Lsp/r;-><init>()V

    .line 10
    .line 11
    .line 12
    iget-object v2, p0, Luu/u1;->f:Ljava/util/ArrayList;

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
    iget-object v4, v1, Lsp/r;->d:Ljava/util/List;

    .line 31
    .line 32
    invoke-interface {v4, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    iget-object v2, p0, Luu/u1;->g:Ljava/util/List;

    .line 37
    .line 38
    check-cast v2, Ljava/lang/Iterable;

    .line 39
    .line 40
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 41
    .line 42
    .line 43
    move-result-object v2

    .line 44
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 45
    .line 46
    .line 47
    move-result v3

    .line 48
    if-eqz v3, :cond_1

    .line 49
    .line 50
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v3

    .line 54
    check-cast v3, Lsp/u;

    .line 55
    .line 56
    iget-object v4, v1, Lsp/r;->o:Ljava/util/List;

    .line 57
    .line 58
    invoke-interface {v4, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_1
    const/4 v2, 0x0

    .line 63
    iput-boolean v2, v1, Lsp/r;->j:Z

    .line 64
    .line 65
    iget-wide v3, p0, Luu/u1;->h:J

    .line 66
    .line 67
    invoke-static {v3, v4}, Le3/j0;->z(J)I

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    iput v3, v1, Lsp/r;->f:I

    .line 72
    .line 73
    const-string v3, "endCap must not be null"

    .line 74
    .line 75
    iget-object v4, p0, Luu/u1;->i:Lsp/d;

    .line 76
    .line 77
    invoke-static {v4, v3}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    iput-object v4, v1, Lsp/r;->l:Lsp/d;

    .line 81
    .line 82
    iput-boolean v2, v1, Lsp/r;->i:Z

    .line 83
    .line 84
    iput v2, v1, Lsp/r;->m:I

    .line 85
    .line 86
    iget-object v2, p0, Luu/u1;->j:Ljava/util/List;

    .line 87
    .line 88
    iput-object v2, v1, Lsp/r;->n:Ljava/util/List;

    .line 89
    .line 90
    const-string v2, "startCap must not be null"

    .line 91
    .line 92
    iget-object v3, p0, Luu/u1;->k:Lsp/d;

    .line 93
    .line 94
    invoke-static {v3, v2}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    iput-object v3, v1, Lsp/r;->k:Lsp/d;

    .line 98
    .line 99
    iget-boolean v2, p0, Luu/u1;->l:Z

    .line 100
    .line 101
    iput-boolean v2, v1, Lsp/r;->h:Z

    .line 102
    .line 103
    iget v2, p0, Luu/u1;->m:F

    .line 104
    .line 105
    iput v2, v1, Lsp/r;->e:F

    .line 106
    .line 107
    const/4 v2, 0x0

    .line 108
    iput v2, v1, Lsp/r;->g:F

    .line 109
    .line 110
    :try_start_0
    new-instance v2, Lsp/q;

    .line 111
    .line 112
    iget-object v0, v0, Lqp/g;->a:Lrp/f;

    .line 113
    .line 114
    invoke-virtual {v0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 115
    .line 116
    .line 117
    move-result-object v3

    .line 118
    invoke-static {v3, v1}, Lhp/j;->c(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 119
    .line 120
    .line 121
    const/16 v1, 0x9

    .line 122
    .line 123
    invoke-virtual {v0, v3, v1}, Lbp/a;->c(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 124
    .line 125
    .line 126
    move-result-object v0

    .line 127
    invoke-virtual {v0}, Landroid/os/Parcel;->readStrongBinder()Landroid/os/IBinder;

    .line 128
    .line 129
    .line 130
    move-result-object v1

    .line 131
    sget v3, Lhp/h;->d:I

    .line 132
    .line 133
    const-string v3, "com.google.android.gms.maps.model.internal.IPolylineDelegate"

    .line 134
    .line 135
    const/4 v4, 0x0

    .line 136
    if-nez v1, :cond_2

    .line 137
    .line 138
    move-object v5, v4

    .line 139
    goto :goto_2

    .line 140
    :cond_2
    invoke-interface {v1, v3}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 141
    .line 142
    .line 143
    move-result-object v5

    .line 144
    instance-of v6, v5, Lhp/i;

    .line 145
    .line 146
    if-eqz v6, :cond_3

    .line 147
    .line 148
    check-cast v5, Lhp/i;

    .line 149
    .line 150
    goto :goto_2

    .line 151
    :cond_3
    new-instance v5, Lhp/g;

    .line 152
    .line 153
    const/4 v6, 0x5

    .line 154
    invoke-direct {v5, v1, v3, v6}, Lbp/a;-><init>(Landroid/os/IBinder;Ljava/lang/String;I)V

    .line 155
    .line 156
    .line 157
    :goto_2
    invoke-virtual {v0}, Landroid/os/Parcel;->recycle()V

    .line 158
    .line 159
    .line 160
    invoke-direct {v2, v5}, Lsp/q;-><init>(Lhp/i;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 161
    .line 162
    .line 163
    invoke-virtual {v2, v4}, Lsp/q;->a(Ljava/lang/Object;)V

    .line 164
    .line 165
    .line 166
    new-instance v0, Luu/v1;

    .line 167
    .line 168
    iget-object p0, p0, Luu/u1;->e:Lay0/k;

    .line 169
    .line 170
    invoke-direct {v0, v2, p0}, Luu/v1;-><init>(Lsp/q;Lay0/k;)V

    .line 171
    .line 172
    .line 173
    return-object v0

    .line 174
    :catch_0
    move-exception p0

    .line 175
    new-instance v0, La8/r0;

    .line 176
    .line 177
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 178
    .line 179
    .line 180
    throw v0

    .line 181
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 182
    .line 183
    const-string v0, "Error adding Polyline"

    .line 184
    .line 185
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 186
    .line 187
    .line 188
    throw p0
.end method
