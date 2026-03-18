.class public final Lno/f0;
.super Lbp/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Lno/e;

.field public final e:I


# direct methods
.method public constructor <init>(Lno/e;I)V
    .locals 2

    .line 1
    const-string v0, "com.google.android.gms.common.internal.IGmsCallbacks"

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-direct {p0, v0, v1}, Lbp/j;-><init>(Ljava/lang/String;I)V

    .line 5
    .line 6
    .line 7
    iput-object p1, p0, Lno/f0;->d:Lno/e;

    .line 8
    .line 9
    iput p2, p0, Lno/f0;->e:I

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final R(ILandroid/os/Parcel;Landroid/os/Parcel;)Z
    .locals 7

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x1

    .line 3
    if-eq p1, v1, :cond_7

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    if-eq p1, v2, :cond_6

    .line 7
    .line 8
    const/4 v2, 0x3

    .line 9
    if-eq p1, v2, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    return p0

    .line 13
    :cond_0
    invoke-virtual {p2}, Landroid/os/Parcel;->readInt()I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    invoke-virtual {p2}, Landroid/os/Parcel;->readStrongBinder()Landroid/os/IBinder;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    sget-object v3, Lno/j0;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 22
    .line 23
    invoke-static {p2, v3}, Lep/a;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    check-cast v3, Lno/j0;

    .line 28
    .line 29
    invoke-static {p2}, Lep/a;->b(Landroid/os/Parcel;)V

    .line 30
    .line 31
    .line 32
    iget-object p2, p0, Lno/f0;->d:Lno/e;

    .line 33
    .line 34
    const-string v4, "onPostInitCompleteWithConnectionInfo can be called only once per call togetRemoteService"

    .line 35
    .line 36
    invoke-static {p2, v4}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    invoke-static {v3}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    iput-object v3, p2, Lno/e;->v:Lno/j0;

    .line 43
    .line 44
    invoke-virtual {p2}, Lno/e;->z()Z

    .line 45
    .line 46
    .line 47
    move-result p2

    .line 48
    if-eqz p2, :cond_5

    .line 49
    .line 50
    iget-object p2, v3, Lno/j0;->g:Lno/g;

    .line 51
    .line 52
    invoke-static {}, Lno/n;->e()Lno/n;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    if-nez p2, :cond_1

    .line 57
    .line 58
    move-object p2, v0

    .line 59
    goto :goto_0

    .line 60
    :cond_1
    iget-object p2, p2, Lno/g;->d:Lno/o;

    .line 61
    .line 62
    :goto_0
    monitor-enter v4

    .line 63
    if-nez p2, :cond_4

    .line 64
    .line 65
    :try_start_0
    sget-object p2, Lno/n;->c:Lno/o;

    .line 66
    .line 67
    :cond_2
    :goto_1
    iput-object p2, v4, Lno/n;->a:Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 68
    .line 69
    :cond_3
    monitor-exit v4

    .line 70
    goto :goto_3

    .line 71
    :catchall_0
    move-exception p0

    .line 72
    goto :goto_2

    .line 73
    :cond_4
    :try_start_1
    iget-object v5, v4, Lno/n;->a:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast v5, Lno/o;

    .line 76
    .line 77
    if-eqz v5, :cond_2

    .line 78
    .line 79
    iget v5, v5, Lno/o;->d:I

    .line 80
    .line 81
    iget v6, p2, Lno/o;->d:I

    .line 82
    .line 83
    if-ge v5, v6, :cond_3

    .line 84
    .line 85
    goto :goto_1

    .line 86
    :goto_2
    monitor-exit v4
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 87
    throw p0

    .line 88
    :cond_5
    :goto_3
    iget-object p2, v3, Lno/j0;->d:Landroid/os/Bundle;

    .line 89
    .line 90
    iget-object v3, p0, Lno/f0;->d:Lno/e;

    .line 91
    .line 92
    const-string v4, "onPostInitComplete can be called only once per call to getRemoteService"

    .line 93
    .line 94
    invoke-static {v3, v4}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    iget-object v3, p0, Lno/f0;->d:Lno/e;

    .line 98
    .line 99
    iget v4, p0, Lno/f0;->e:I

    .line 100
    .line 101
    invoke-virtual {v3, p1, v2, p2, v4}, Lno/e;->x(ILandroid/os/IBinder;Landroid/os/Bundle;I)V

    .line 102
    .line 103
    .line 104
    iput-object v0, p0, Lno/f0;->d:Lno/e;

    .line 105
    .line 106
    goto :goto_4

    .line 107
    :cond_6
    invoke-virtual {p2}, Landroid/os/Parcel;->readInt()I

    .line 108
    .line 109
    .line 110
    sget-object p0, Landroid/os/Bundle;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 111
    .line 112
    invoke-static {p2, p0}, Lep/a;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    check-cast p0, Landroid/os/Bundle;

    .line 117
    .line 118
    invoke-static {p2}, Lep/a;->b(Landroid/os/Parcel;)V

    .line 119
    .line 120
    .line 121
    new-instance p0, Ljava/lang/Exception;

    .line 122
    .line 123
    invoke-direct {p0}, Ljava/lang/Exception;-><init>()V

    .line 124
    .line 125
    .line 126
    const-string p1, "GmsClient"

    .line 127
    .line 128
    const-string p2, "received deprecated onAccountValidationComplete callback, ignoring"

    .line 129
    .line 130
    invoke-static {p1, p2, p0}, Landroid/util/Log;->wtf(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 131
    .line 132
    .line 133
    goto :goto_4

    .line 134
    :cond_7
    invoke-virtual {p2}, Landroid/os/Parcel;->readInt()I

    .line 135
    .line 136
    .line 137
    move-result p1

    .line 138
    invoke-virtual {p2}, Landroid/os/Parcel;->readStrongBinder()Landroid/os/IBinder;

    .line 139
    .line 140
    .line 141
    move-result-object v2

    .line 142
    sget-object v3, Landroid/os/Bundle;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 143
    .line 144
    invoke-static {p2, v3}, Lep/a;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 145
    .line 146
    .line 147
    move-result-object v3

    .line 148
    check-cast v3, Landroid/os/Bundle;

    .line 149
    .line 150
    invoke-static {p2}, Lep/a;->b(Landroid/os/Parcel;)V

    .line 151
    .line 152
    .line 153
    iget-object p2, p0, Lno/f0;->d:Lno/e;

    .line 154
    .line 155
    const-string v4, "onPostInitComplete can be called only once per call to getRemoteService"

    .line 156
    .line 157
    invoke-static {p2, v4}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    iget-object p2, p0, Lno/f0;->d:Lno/e;

    .line 161
    .line 162
    iget v4, p0, Lno/f0;->e:I

    .line 163
    .line 164
    invoke-virtual {p2, p1, v2, v3, v4}, Lno/e;->x(ILandroid/os/IBinder;Landroid/os/Bundle;I)V

    .line 165
    .line 166
    .line 167
    iput-object v0, p0, Lno/f0;->d:Lno/e;

    .line 168
    .line 169
    :goto_4
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 170
    .line 171
    .line 172
    return v1
.end method
