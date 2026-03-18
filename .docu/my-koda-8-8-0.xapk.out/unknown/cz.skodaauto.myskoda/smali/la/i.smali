.class public final Lla/i;
.super Landroid/os/Binder;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lla/f;


# instance fields
.field public final synthetic c:Landroidx/room/MultiInstanceInvalidationService;


# direct methods
.method public constructor <init>(Landroidx/room/MultiInstanceInvalidationService;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lla/i;->c:Landroidx/room/MultiInstanceInvalidationService;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/os/Binder;-><init>()V

    .line 4
    .line 5
    .line 6
    sget-object p1, Lla/f;->b:Ljava/lang/String;

    .line 7
    .line 8
    invoke-virtual {p0, p0, p1}, Landroid/os/Binder;->attachInterface(Landroid/os/IInterface;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final L([Ljava/lang/String;I)V
    .locals 7

    .line 1
    const-string v0, "tables"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lla/i;->c:Landroidx/room/MultiInstanceInvalidationService;

    .line 7
    .line 8
    iget-object v0, p0, Landroidx/room/MultiInstanceInvalidationService;->f:Lla/j;

    .line 9
    .line 10
    monitor-enter v0

    .line 11
    :try_start_0
    iget-object v1, p0, Landroidx/room/MultiInstanceInvalidationService;->e:Ljava/util/LinkedHashMap;

    .line 12
    .line 13
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    invoke-virtual {v1, v2}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    check-cast v1, Ljava/lang/String;

    .line 22
    .line 23
    if-nez v1, :cond_0

    .line 24
    .line 25
    const-string p0, "ROOM"

    .line 26
    .line 27
    const-string p1, "Remote invalidation client ID not registered"

    .line 28
    .line 29
    invoke-static {p0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 30
    .line 31
    .line 32
    monitor-exit v0

    .line 33
    return-void

    .line 34
    :catchall_0
    move-exception p0

    .line 35
    goto :goto_3

    .line 36
    :cond_0
    :try_start_1
    iget-object v2, p0, Landroidx/room/MultiInstanceInvalidationService;->f:Lla/j;

    .line 37
    .line 38
    invoke-virtual {v2}, Landroid/os/RemoteCallbackList;->beginBroadcast()I

    .line 39
    .line 40
    .line 41
    move-result v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 42
    const/4 v3, 0x0

    .line 43
    :goto_0
    if-ge v3, v2, :cond_3

    .line 44
    .line 45
    :try_start_2
    iget-object v4, p0, Landroidx/room/MultiInstanceInvalidationService;->f:Lla/j;

    .line 46
    .line 47
    invoke-virtual {v4, v3}, Landroid/os/RemoteCallbackList;->getBroadcastCookie(I)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v4

    .line 51
    const-string v5, "null cannot be cast to non-null type kotlin.Int"

    .line 52
    .line 53
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    check-cast v4, Ljava/lang/Integer;

    .line 57
    .line 58
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 59
    .line 60
    .line 61
    move-result v5

    .line 62
    iget-object v6, p0, Landroidx/room/MultiInstanceInvalidationService;->e:Ljava/util/LinkedHashMap;

    .line 63
    .line 64
    invoke-virtual {v6, v4}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v4

    .line 68
    check-cast v4, Ljava/lang/String;

    .line 69
    .line 70
    if-eq p2, v5, :cond_2

    .line 71
    .line 72
    invoke-virtual {v1, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v4
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 76
    if-nez v4, :cond_1

    .line 77
    .line 78
    goto :goto_1

    .line 79
    :cond_1
    :try_start_3
    iget-object v4, p0, Landroidx/room/MultiInstanceInvalidationService;->f:Lla/j;

    .line 80
    .line 81
    invoke-virtual {v4, v3}, Landroid/os/RemoteCallbackList;->getBroadcastItem(I)Landroid/os/IInterface;

    .line 82
    .line 83
    .line 84
    move-result-object v4

    .line 85
    check-cast v4, Lla/e;

    .line 86
    .line 87
    invoke-interface {v4, p1}, Lla/e;->e([Ljava/lang/String;)V
    :try_end_3
    .catch Landroid/os/RemoteException; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 88
    .line 89
    .line 90
    goto :goto_1

    .line 91
    :catchall_1
    move-exception p1

    .line 92
    goto :goto_2

    .line 93
    :catch_0
    move-exception v4

    .line 94
    :try_start_4
    const-string v5, "ROOM"

    .line 95
    .line 96
    const-string v6, "Error invoking a remote callback"

    .line 97
    .line 98
    invoke-static {v5, v6, v4}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 99
    .line 100
    .line 101
    :cond_2
    :goto_1
    add-int/lit8 v3, v3, 0x1

    .line 102
    .line 103
    goto :goto_0

    .line 104
    :goto_2
    :try_start_5
    iget-object p0, p0, Landroidx/room/MultiInstanceInvalidationService;->f:Lla/j;

    .line 105
    .line 106
    invoke-virtual {p0}, Landroid/os/RemoteCallbackList;->finishBroadcast()V

    .line 107
    .line 108
    .line 109
    throw p1

    .line 110
    :cond_3
    iget-object p0, p0, Landroidx/room/MultiInstanceInvalidationService;->f:Lla/j;

    .line 111
    .line 112
    invoke-virtual {p0}, Landroid/os/RemoteCallbackList;->finishBroadcast()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 113
    .line 114
    .line 115
    monitor-exit v0

    .line 116
    return-void

    .line 117
    :goto_3
    monitor-exit v0

    .line 118
    throw p0
.end method

.method public final asBinder()Landroid/os/IBinder;
    .locals 0

    .line 1
    return-object p0
.end method

.method public final onTransact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z
    .locals 5

    .line 1
    sget-object v0, Lla/f;->b:Ljava/lang/String;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-lt p1, v1, :cond_0

    .line 5
    .line 6
    const v2, 0xffffff

    .line 7
    .line 8
    .line 9
    if-gt p1, v2, :cond_0

    .line 10
    .line 11
    invoke-virtual {p2, v0}, Landroid/os/Parcel;->enforceInterface(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    const v2, 0x5f4e5446

    .line 15
    .line 16
    .line 17
    if-ne p1, v2, :cond_1

    .line 18
    .line 19
    invoke-virtual {p3, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    return v1

    .line 23
    :cond_1
    const/4 v0, 0x0

    .line 24
    if-eq p1, v1, :cond_6

    .line 25
    .line 26
    const/4 v2, 0x2

    .line 27
    if-eq p1, v2, :cond_3

    .line 28
    .line 29
    const/4 v0, 0x3

    .line 30
    if-eq p1, v0, :cond_2

    .line 31
    .line 32
    invoke-super {p0, p1, p2, p3, p4}, Landroid/os/Binder;->onTransact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    return p0

    .line 37
    :cond_2
    invoke-virtual {p2}, Landroid/os/Parcel;->readInt()I

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    invoke-virtual {p2}, Landroid/os/Parcel;->createStringArray()[Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p2

    .line 45
    invoke-virtual {p0, p2, p1}, Lla/i;->L([Ljava/lang/String;I)V

    .line 46
    .line 47
    .line 48
    return v1

    .line 49
    :cond_3
    invoke-virtual {p2}, Landroid/os/Parcel;->readStrongBinder()Landroid/os/IBinder;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    if-nez p1, :cond_4

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_4
    sget-object p4, Lla/e;->a:Ljava/lang/String;

    .line 57
    .line 58
    invoke-interface {p1, p4}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 59
    .line 60
    .line 61
    move-result-object p4

    .line 62
    if-eqz p4, :cond_5

    .line 63
    .line 64
    instance-of v0, p4, Lla/e;

    .line 65
    .line 66
    if-eqz v0, :cond_5

    .line 67
    .line 68
    move-object v0, p4

    .line 69
    check-cast v0, Lla/e;

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_5
    new-instance v0, Lla/d;

    .line 73
    .line 74
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 75
    .line 76
    .line 77
    iput-object p1, v0, Lla/d;->c:Landroid/os/IBinder;

    .line 78
    .line 79
    :goto_0
    invoke-virtual {p2}, Landroid/os/Parcel;->readInt()I

    .line 80
    .line 81
    .line 82
    move-result p1

    .line 83
    const-string p2, "callback"

    .line 84
    .line 85
    invoke-static {v0, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    iget-object p0, p0, Lla/i;->c:Landroidx/room/MultiInstanceInvalidationService;

    .line 89
    .line 90
    iget-object p2, p0, Landroidx/room/MultiInstanceInvalidationService;->f:Lla/j;

    .line 91
    .line 92
    monitor-enter p2

    .line 93
    :try_start_0
    iget-object p4, p0, Landroidx/room/MultiInstanceInvalidationService;->f:Lla/j;

    .line 94
    .line 95
    invoke-virtual {p4, v0}, Landroid/os/RemoteCallbackList;->unregister(Landroid/os/IInterface;)Z

    .line 96
    .line 97
    .line 98
    iget-object p0, p0, Landroidx/room/MultiInstanceInvalidationService;->e:Ljava/util/LinkedHashMap;

    .line 99
    .line 100
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    invoke-interface {p0, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    check-cast p0, Ljava/lang/String;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 109
    .line 110
    monitor-exit p2

    .line 111
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 112
    .line 113
    .line 114
    return v1

    .line 115
    :catchall_0
    move-exception p0

    .line 116
    monitor-exit p2

    .line 117
    throw p0

    .line 118
    :cond_6
    invoke-virtual {p2}, Landroid/os/Parcel;->readStrongBinder()Landroid/os/IBinder;

    .line 119
    .line 120
    .line 121
    move-result-object p1

    .line 122
    if-nez p1, :cond_7

    .line 123
    .line 124
    goto :goto_1

    .line 125
    :cond_7
    sget-object p4, Lla/e;->a:Ljava/lang/String;

    .line 126
    .line 127
    invoke-interface {p1, p4}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 128
    .line 129
    .line 130
    move-result-object p4

    .line 131
    if-eqz p4, :cond_8

    .line 132
    .line 133
    instance-of v0, p4, Lla/e;

    .line 134
    .line 135
    if-eqz v0, :cond_8

    .line 136
    .line 137
    move-object v0, p4

    .line 138
    check-cast v0, Lla/e;

    .line 139
    .line 140
    goto :goto_1

    .line 141
    :cond_8
    new-instance v0, Lla/d;

    .line 142
    .line 143
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 144
    .line 145
    .line 146
    iput-object p1, v0, Lla/d;->c:Landroid/os/IBinder;

    .line 147
    .line 148
    :goto_1
    invoke-virtual {p2}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object p1

    .line 152
    const-string p2, "callback"

    .line 153
    .line 154
    invoke-static {v0, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 155
    .line 156
    .line 157
    const/4 p2, 0x0

    .line 158
    if-nez p1, :cond_9

    .line 159
    .line 160
    goto :goto_3

    .line 161
    :cond_9
    iget-object p0, p0, Lla/i;->c:Landroidx/room/MultiInstanceInvalidationService;

    .line 162
    .line 163
    iget-object p4, p0, Landroidx/room/MultiInstanceInvalidationService;->f:Lla/j;

    .line 164
    .line 165
    monitor-enter p4

    .line 166
    :try_start_1
    iget v2, p0, Landroidx/room/MultiInstanceInvalidationService;->d:I

    .line 167
    .line 168
    add-int/lit8 v2, v2, 0x1

    .line 169
    .line 170
    iput v2, p0, Landroidx/room/MultiInstanceInvalidationService;->d:I

    .line 171
    .line 172
    iget-object v3, p0, Landroidx/room/MultiInstanceInvalidationService;->f:Lla/j;

    .line 173
    .line 174
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 175
    .line 176
    .line 177
    move-result-object v4

    .line 178
    invoke-virtual {v3, v0, v4}, Landroid/os/RemoteCallbackList;->register(Landroid/os/IInterface;Ljava/lang/Object;)Z

    .line 179
    .line 180
    .line 181
    move-result v0

    .line 182
    if-eqz v0, :cond_a

    .line 183
    .line 184
    iget-object p0, p0, Landroidx/room/MultiInstanceInvalidationService;->e:Ljava/util/LinkedHashMap;

    .line 185
    .line 186
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 187
    .line 188
    .line 189
    move-result-object p2

    .line 190
    invoke-interface {p0, p2, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move p2, v2

    .line 194
    goto :goto_2

    .line 195
    :catchall_1
    move-exception p0

    .line 196
    goto :goto_4

    .line 197
    :cond_a
    iget p1, p0, Landroidx/room/MultiInstanceInvalidationService;->d:I

    .line 198
    .line 199
    add-int/lit8 p1, p1, -0x1

    .line 200
    .line 201
    iput p1, p0, Landroidx/room/MultiInstanceInvalidationService;->d:I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 202
    .line 203
    :goto_2
    monitor-exit p4

    .line 204
    :goto_3
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 205
    .line 206
    .line 207
    invoke-virtual {p3, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 208
    .line 209
    .line 210
    return v1

    .line 211
    :goto_4
    monitor-exit p4

    .line 212
    throw p0
.end method
