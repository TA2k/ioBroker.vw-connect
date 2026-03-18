.class public final Luu/x;
.super Leb/j0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lqp/g;

.field public final i:Lqp/h;

.field public final j:Luu/z;

.field public final k:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(Lqp/g;Lqp/h;Luu/z;)V
    .locals 1

    .line 1
    const-string v0, "map"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "mapView"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sget-object v0, Luu/t0;->a:Luu/t0;

    .line 12
    .line 13
    invoke-direct {p0, v0}, Leb/j0;-><init>(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Luu/x;->h:Lqp/g;

    .line 17
    .line 18
    iput-object p2, p0, Luu/x;->i:Lqp/h;

    .line 19
    .line 20
    iput-object p3, p0, Luu/x;->j:Luu/z;

    .line 21
    .line 22
    new-instance p1, Ljava/util/ArrayList;

    .line 23
    .line 24
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 25
    .line 26
    .line 27
    iput-object p1, p0, Luu/x;->k:Ljava/util/ArrayList;

    .line 28
    .line 29
    invoke-virtual {p0}, Luu/x;->J()V

    .line 30
    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public final J()V
    .locals 5

    .line 1
    new-instance v0, Luu/w;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Luu/w;-><init>(Luu/x;)V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Luu/x;->h:Lqp/g;

    .line 7
    .line 8
    iget-object v2, v1, Lqp/g;->a:Lrp/f;

    .line 9
    .line 10
    iget-object v3, v1, Lqp/g;->a:Lrp/f;

    .line 11
    .line 12
    :try_start_0
    new-instance v4, Lqp/j;

    .line 13
    .line 14
    invoke-direct {v4, v0}, Lqp/j;-><init>(Luu/w;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v2}, Lbp/a;->S()Landroid/os/Parcel;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-static {v0, v4}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 22
    .line 23
    .line 24
    const/16 v4, 0x59

    .line 25
    .line 26
    invoke-virtual {v2, v0, v4}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_4

    .line 27
    .line 28
    .line 29
    new-instance v0, Luu/w;

    .line 30
    .line 31
    invoke-direct {v0, p0}, Luu/w;-><init>(Luu/x;)V

    .line 32
    .line 33
    .line 34
    :try_start_1
    new-instance v2, Lqp/j;

    .line 35
    .line 36
    const/4 v4, 0x0

    .line 37
    invoke-direct {v2, v0, v4}, Lqp/j;-><init>(Luu/w;C)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {v3}, Lbp/a;->S()Landroid/os/Parcel;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    invoke-static {v0, v2}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 45
    .line 46
    .line 47
    const/16 v2, 0x53

    .line 48
    .line 49
    invoke-virtual {v3, v0, v2}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_1
    .catch Landroid/os/RemoteException; {:try_start_1 .. :try_end_1} :catch_3

    .line 50
    .line 51
    .line 52
    new-instance v0, Luu/w;

    .line 53
    .line 54
    invoke-direct {v0, p0}, Luu/w;-><init>(Luu/x;)V

    .line 55
    .line 56
    .line 57
    :try_start_2
    new-instance v2, Lqp/j;

    .line 58
    .line 59
    const/4 v4, 0x0

    .line 60
    invoke-direct {v2, v0, v4}, Lqp/j;-><init>(Luu/w;I)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v3}, Lbp/a;->S()Landroid/os/Parcel;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    invoke-static {v0, v2}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 68
    .line 69
    .line 70
    const/16 v2, 0x55

    .line 71
    .line 72
    invoke-virtual {v3, v0, v2}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_2
    .catch Landroid/os/RemoteException; {:try_start_2 .. :try_end_2} :catch_2

    .line 73
    .line 74
    .line 75
    new-instance v0, Luu/w;

    .line 76
    .line 77
    invoke-direct {v0, p0}, Luu/w;-><init>(Luu/x;)V

    .line 78
    .line 79
    .line 80
    :try_start_3
    new-instance v2, Lqp/j;

    .line 81
    .line 82
    const/4 v4, 0x0

    .line 83
    invoke-direct {v2, v0, v4}, Lqp/j;-><init>(Luu/w;S)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v3}, Lbp/a;->S()Landroid/os/Parcel;

    .line 87
    .line 88
    .line 89
    move-result-object v0

    .line 90
    invoke-static {v0, v2}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 91
    .line 92
    .line 93
    const/16 v2, 0x57

    .line 94
    .line 95
    invoke-virtual {v3, v0, v2}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_3
    .catch Landroid/os/RemoteException; {:try_start_3 .. :try_end_3} :catch_1

    .line 96
    .line 97
    .line 98
    new-instance v0, Luu/w;

    .line 99
    .line 100
    invoke-direct {v0, p0}, Luu/w;-><init>(Luu/x;)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {v1, v0}, Lqp/g;->j(Lqp/e;)V

    .line 104
    .line 105
    .line 106
    new-instance v0, Luu/w;

    .line 107
    .line 108
    invoke-direct {v0, p0}, Luu/w;-><init>(Luu/x;)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {v1, v0}, Lqp/g;->h(Lqp/c;)V

    .line 112
    .line 113
    .line 114
    new-instance v0, Luu/w;

    .line 115
    .line 116
    invoke-direct {v0, p0}, Luu/w;-><init>(Luu/x;)V

    .line 117
    .line 118
    .line 119
    :try_start_4
    new-instance v2, Lqp/j;

    .line 120
    .line 121
    const/4 v4, 0x0

    .line 122
    invoke-direct {v2, v0, v4}, Lqp/j;-><init>(Luu/w;B)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v3}, Lbp/a;->S()Landroid/os/Parcel;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    invoke-static {v0, v2}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 130
    .line 131
    .line 132
    const/16 v2, 0x56

    .line 133
    .line 134
    invoke-virtual {v3, v0, v2}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_4
    .catch Landroid/os/RemoteException; {:try_start_4 .. :try_end_4} :catch_0

    .line 135
    .line 136
    .line 137
    new-instance v0, Luu/w;

    .line 138
    .line 139
    invoke-direct {v0, p0}, Luu/w;-><init>(Luu/x;)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {v1, v0}, Lqp/g;->i(Lqp/d;)V

    .line 143
    .line 144
    .line 145
    new-instance v0, Lt1/j0;

    .line 146
    .line 147
    const/4 v2, 0x7

    .line 148
    invoke-direct {v0, p0, v2}, Lt1/j0;-><init>(Ljava/lang/Object;I)V

    .line 149
    .line 150
    .line 151
    invoke-virtual {v1, v0}, Lqp/g;->k(Lqp/f;)V

    .line 152
    .line 153
    .line 154
    new-instance v0, Lb81/c;

    .line 155
    .line 156
    new-instance v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;

    .line 157
    .line 158
    const/16 v3, 0x9

    .line 159
    .line 160
    invoke-direct {v2, p0, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;-><init>(Ljava/lang/Object;I)V

    .line 161
    .line 162
    .line 163
    iget-object p0, p0, Luu/x;->i:Lqp/h;

    .line 164
    .line 165
    invoke-direct {v0, p0, v2}, Lb81/c;-><init>(Lqp/h;Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;)V

    .line 166
    .line 167
    .line 168
    invoke-virtual {v1, v0}, Lqp/g;->g(Lqp/a;)V

    .line 169
    .line 170
    .line 171
    return-void

    .line 172
    :catch_0
    move-exception p0

    .line 173
    new-instance v0, La8/r0;

    .line 174
    .line 175
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 176
    .line 177
    .line 178
    throw v0

    .line 179
    :catch_1
    move-exception p0

    .line 180
    new-instance v0, La8/r0;

    .line 181
    .line 182
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 183
    .line 184
    .line 185
    throw v0

    .line 186
    :catch_2
    move-exception p0

    .line 187
    new-instance v0, La8/r0;

    .line 188
    .line 189
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 190
    .line 191
    .line 192
    throw v0

    .line 193
    :catch_3
    move-exception p0

    .line 194
    new-instance v0, La8/r0;

    .line 195
    .line 196
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 197
    .line 198
    .line 199
    throw v0

    .line 200
    :catch_4
    move-exception p0

    .line 201
    new-instance v0, La8/r0;

    .line 202
    .line 203
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 204
    .line 205
    .line 206
    throw v0
.end method

.method public final b(III)V
    .locals 0

    .line 1
    iget-object p0, p0, Luu/x;->k:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-static {p0, p1, p2, p3}, Leb/j0;->y(Ljava/util/ArrayList;III)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final c(II)V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    iget-object v1, p0, Luu/x;->k:Ljava/util/ArrayList;

    .line 3
    .line 4
    if-ge v0, p2, :cond_0

    .line 5
    .line 6
    add-int v2, p1, v0

    .line 7
    .line 8
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    check-cast v1, Luu/s0;

    .line 13
    .line 14
    invoke-interface {v1}, Luu/s0;->d()V

    .line 15
    .line 16
    .line 17
    add-int/lit8 v0, v0, 0x1

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const/4 p0, 0x1

    .line 21
    if-ne p2, p0, :cond_1

    .line 22
    .line 23
    invoke-virtual {v1, p1}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :cond_1
    add-int/2addr p2, p1

    .line 28
    invoke-virtual {v1, p1, p2}, Ljava/util/ArrayList;->subList(II)Ljava/util/List;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    invoke-interface {p0}, Ljava/util/List;->clear()V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method public final e(ILjava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p2, Luu/s0;

    .line 2
    .line 3
    const-string p0, "instance"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final k(ILjava/lang/Object;)V
    .locals 1

    .line 1
    check-cast p2, Luu/s0;

    .line 2
    .line 3
    const-string v0, "instance"

    .line 4
    .line 5
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Luu/x;->k:Ljava/util/ArrayList;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    invoke-interface {p2}, Luu/s0;->a()V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public final z()V
    .locals 3

    .line 1
    iget-object v0, p0, Luu/x;->h:Lqp/g;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    :try_start_0
    iget-object v0, v0, Lqp/g;->a:Lrp/f;

    .line 7
    .line 8
    invoke-virtual {v0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    const/16 v2, 0xe

    .line 13
    .line 14
    invoke-virtual {v0, v1, v2}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 15
    .line 16
    .line 17
    iget-object p0, p0, Luu/x;->k:Ljava/util/ArrayList;

    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-eqz v1, :cond_0

    .line 28
    .line 29
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    check-cast v1, Luu/s0;

    .line 34
    .line 35
    invoke-interface {v1}, Luu/s0;->b()V

    .line 36
    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    invoke-virtual {p0}, Ljava/util/ArrayList;->clear()V

    .line 40
    .line 41
    .line 42
    return-void

    .line 43
    :catch_0
    move-exception p0

    .line 44
    new-instance v0, La8/r0;

    .line 45
    .line 46
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 47
    .line 48
    .line 49
    throw v0
.end method
