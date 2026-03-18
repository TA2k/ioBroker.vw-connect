.class public final Landroidx/lifecycle/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/v;


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Landroidx/lifecycle/f;Landroidx/lifecycle/v;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Landroidx/lifecycle/h;->d:I

    const-string v0, "defaultLifecycleObserver"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Landroidx/lifecycle/h;->e:Ljava/lang/Object;

    .line 3
    iput-object p2, p0, Landroidx/lifecycle/h;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroidx/lifecycle/r;Lra/d;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Landroidx/lifecycle/h;->d:I

    .line 10
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 11
    iput-object p1, p0, Landroidx/lifecycle/h;->e:Ljava/lang/Object;

    iput-object p2, p0, Landroidx/lifecycle/h;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroidx/lifecycle/w;)V
    .locals 2

    const/4 v0, 0x2

    iput v0, p0, Landroidx/lifecycle/h;->d:I

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    iput-object p1, p0, Landroidx/lifecycle/h;->e:Ljava/lang/Object;

    .line 6
    sget-object v0, Landroidx/lifecycle/d;->c:Landroidx/lifecycle/d;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    .line 7
    iget-object v1, v0, Landroidx/lifecycle/d;->a:Ljava/util/HashMap;

    invoke-virtual {v1, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroidx/lifecycle/b;

    if-eqz v1, :cond_0

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    .line 8
    invoke-virtual {v0, p1, v1}, Landroidx/lifecycle/d;->a(Ljava/lang/Class;[Ljava/lang/reflect/Method;)Landroidx/lifecycle/b;

    move-result-object v1

    .line 9
    :goto_0
    iput-object v1, p0, Landroidx/lifecycle/h;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lqp/h;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Landroidx/lifecycle/h;->d:I

    const-string v0, "mapView"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/lifecycle/h;->e:Ljava/lang/Object;

    .line 13
    sget-object p1, Landroidx/lifecycle/q;->e:Landroidx/lifecycle/q;

    iput-object p1, p0, Landroidx/lifecycle/h;->f:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public a(Landroidx/lifecycle/p;)V
    .locals 5

    .line 1
    iget-object v0, p0, Landroidx/lifecycle/h;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lqp/h;

    .line 4
    .line 5
    sget-object v1, Luu/r0;->a:[I

    .line 6
    .line 7
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    aget v1, v1, v2

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    const/4 v3, 0x5

    .line 15
    const/4 v4, 0x4

    .line 16
    packed-switch v1, :pswitch_data_0

    .line 17
    .line 18
    .line 19
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 20
    .line 21
    new-instance v0, Ljava/lang/StringBuilder;

    .line 22
    .line 23
    const-string v1, "Unsupported lifecycle event: "

    .line 24
    .line 25
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw p0

    .line 43
    :pswitch_0
    iget-object v0, v0, Lqp/h;->d:Lqn/s;

    .line 44
    .line 45
    iget-object v1, v0, Lqn/s;->a:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast v1, Lil/g;

    .line 48
    .line 49
    if-eqz v1, :cond_0

    .line 50
    .line 51
    :try_start_0
    iget-object v0, v1, Lil/g;->f:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast v0, Lrp/g;

    .line 54
    .line 55
    invoke-virtual {v0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    const/16 v2, 0xd

    .line 60
    .line 61
    invoke-virtual {v0, v1, v2}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 62
    .line 63
    .line 64
    goto/16 :goto_2

    .line 65
    .line 66
    :catch_0
    move-exception p0

    .line 67
    new-instance p1, La8/r0;

    .line 68
    .line 69
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 70
    .line 71
    .line 72
    throw p1

    .line 73
    :cond_0
    invoke-virtual {v0, v4}, Lqn/s;->f(I)V

    .line 74
    .line 75
    .line 76
    goto/16 :goto_2

    .line 77
    .line 78
    :pswitch_1
    iget-object v0, v0, Lqp/h;->d:Lqn/s;

    .line 79
    .line 80
    iget-object v1, v0, Lqn/s;->a:Ljava/lang/Object;

    .line 81
    .line 82
    check-cast v1, Lil/g;

    .line 83
    .line 84
    if-eqz v1, :cond_1

    .line 85
    .line 86
    :try_start_1
    iget-object v0, v1, Lil/g;->f:Ljava/lang/Object;

    .line 87
    .line 88
    check-cast v0, Lrp/g;

    .line 89
    .line 90
    invoke-virtual {v0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    invoke-virtual {v0, v1, v4}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_1
    .catch Landroid/os/RemoteException; {:try_start_1 .. :try_end_1} :catch_1

    .line 95
    .line 96
    .line 97
    goto/16 :goto_2

    .line 98
    .line 99
    :catch_1
    move-exception p0

    .line 100
    new-instance p1, La8/r0;

    .line 101
    .line 102
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 103
    .line 104
    .line 105
    throw p1

    .line 106
    :cond_1
    invoke-virtual {v0, v3}, Lqn/s;->f(I)V

    .line 107
    .line 108
    .line 109
    goto/16 :goto_2

    .line 110
    .line 111
    :pswitch_2
    iget-object v0, v0, Lqp/h;->d:Lqn/s;

    .line 112
    .line 113
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 114
    .line 115
    .line 116
    new-instance v1, Lyo/e;

    .line 117
    .line 118
    const/4 v3, 0x1

    .line 119
    invoke-direct {v1, v0, v3}, Lyo/e;-><init>(Lqn/s;I)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {v0, v2, v1}, Lqn/s;->g(Landroid/os/Bundle;Lyo/f;)V

    .line 123
    .line 124
    .line 125
    goto :goto_2

    .line 126
    :pswitch_3
    iget-object v0, v0, Lqp/h;->d:Lqn/s;

    .line 127
    .line 128
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 129
    .line 130
    .line 131
    new-instance v1, Lyo/e;

    .line 132
    .line 133
    const/4 v3, 0x0

    .line 134
    invoke-direct {v1, v0, v3}, Lyo/e;-><init>(Lqn/s;I)V

    .line 135
    .line 136
    .line 137
    invoke-virtual {v0, v2, v1}, Lqn/s;->g(Landroid/os/Bundle;Lyo/f;)V

    .line 138
    .line 139
    .line 140
    goto :goto_2

    .line 141
    :pswitch_4
    new-instance v1, Landroid/os/Bundle;

    .line 142
    .line 143
    invoke-direct {v1}, Landroid/os/Bundle;-><init>()V

    .line 144
    .line 145
    .line 146
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 147
    .line 148
    .line 149
    invoke-static {}, Landroid/os/StrictMode;->getThreadPolicy()Landroid/os/StrictMode$ThreadPolicy;

    .line 150
    .line 151
    .line 152
    move-result-object v2

    .line 153
    new-instance v3, Landroid/os/StrictMode$ThreadPolicy$Builder;

    .line 154
    .line 155
    invoke-direct {v3, v2}, Landroid/os/StrictMode$ThreadPolicy$Builder;-><init>(Landroid/os/StrictMode$ThreadPolicy;)V

    .line 156
    .line 157
    .line 158
    invoke-virtual {v3}, Landroid/os/StrictMode$ThreadPolicy$Builder;->permitAll()Landroid/os/StrictMode$ThreadPolicy$Builder;

    .line 159
    .line 160
    .line 161
    move-result-object v3

    .line 162
    invoke-virtual {v3}, Landroid/os/StrictMode$ThreadPolicy$Builder;->build()Landroid/os/StrictMode$ThreadPolicy;

    .line 163
    .line 164
    .line 165
    move-result-object v3

    .line 166
    invoke-static {v3}, Landroid/os/StrictMode;->setThreadPolicy(Landroid/os/StrictMode$ThreadPolicy;)V

    .line 167
    .line 168
    .line 169
    :try_start_2
    iget-object v3, v0, Lqp/h;->d:Lqn/s;

    .line 170
    .line 171
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 172
    .line 173
    .line 174
    new-instance v4, Lyo/c;

    .line 175
    .line 176
    invoke-direct {v4, v3, v1}, Lyo/c;-><init>(Lqn/s;Landroid/os/Bundle;)V

    .line 177
    .line 178
    .line 179
    invoke-virtual {v3, v1, v4}, Lqn/s;->g(Landroid/os/Bundle;Lyo/f;)V

    .line 180
    .line 181
    .line 182
    iget-object v1, v3, Lqn/s;->a:Ljava/lang/Object;

    .line 183
    .line 184
    check-cast v1, Lil/g;

    .line 185
    .line 186
    if-nez v1, :cond_2

    .line 187
    .line 188
    invoke-static {v0}, Lqn/s;->e(Landroid/widget/FrameLayout;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 189
    .line 190
    .line 191
    goto :goto_0

    .line 192
    :catchall_0
    move-exception p0

    .line 193
    goto :goto_1

    .line 194
    :cond_2
    :goto_0
    invoke-static {v2}, Landroid/os/StrictMode;->setThreadPolicy(Landroid/os/StrictMode$ThreadPolicy;)V

    .line 195
    .line 196
    .line 197
    goto :goto_2

    .line 198
    :goto_1
    invoke-static {v2}, Landroid/os/StrictMode;->setThreadPolicy(Landroid/os/StrictMode$ThreadPolicy;)V

    .line 199
    .line 200
    .line 201
    throw p0

    .line 202
    :pswitch_5
    iget-object v0, v0, Lqp/h;->d:Lqn/s;

    .line 203
    .line 204
    iget-object v1, v0, Lqn/s;->a:Ljava/lang/Object;

    .line 205
    .line 206
    check-cast v1, Lil/g;

    .line 207
    .line 208
    if-eqz v1, :cond_3

    .line 209
    .line 210
    :try_start_3
    iget-object v0, v1, Lil/g;->f:Ljava/lang/Object;

    .line 211
    .line 212
    check-cast v0, Lrp/g;

    .line 213
    .line 214
    invoke-virtual {v0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 215
    .line 216
    .line 217
    move-result-object v1

    .line 218
    invoke-virtual {v0, v1, v3}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_3
    .catch Landroid/os/RemoteException; {:try_start_3 .. :try_end_3} :catch_2

    .line 219
    .line 220
    .line 221
    goto :goto_2

    .line 222
    :catch_2
    move-exception p0

    .line 223
    new-instance p1, La8/r0;

    .line 224
    .line 225
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 226
    .line 227
    .line 228
    throw p1

    .line 229
    :cond_3
    const/4 v1, 0x1

    .line 230
    invoke-virtual {v0, v1}, Lqn/s;->f(I)V

    .line 231
    .line 232
    .line 233
    :goto_2
    invoke-virtual {p1}, Landroidx/lifecycle/p;->a()Landroidx/lifecycle/q;

    .line 234
    .line 235
    .line 236
    move-result-object p1

    .line 237
    iput-object p1, p0, Landroidx/lifecycle/h;->f:Ljava/lang/Object;

    .line 238
    .line 239
    return-void

    .line 240
    nop

    .line 241
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public b(Landroidx/lifecycle/q;)V
    .locals 2

    .line 1
    :cond_0
    :goto_0
    iget-object v0, p0, Landroidx/lifecycle/h;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/lifecycle/q;

    .line 4
    .line 5
    if-eq v0, p1, :cond_4

    .line 6
    .line 7
    invoke-virtual {v0, p1}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-gez v0, :cond_2

    .line 12
    .line 13
    sget-object v0, Landroidx/lifecycle/p;->Companion:Landroidx/lifecycle/n;

    .line 14
    .line 15
    iget-object v1, p0, Landroidx/lifecycle/h;->f:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v1, Landroidx/lifecycle/q;

    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 20
    .line 21
    .line 22
    invoke-static {v1}, Landroidx/lifecycle/n;->b(Landroidx/lifecycle/q;)Landroidx/lifecycle/p;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    invoke-virtual {p0, v0}, Landroidx/lifecycle/h;->a(Landroidx/lifecycle/p;)V

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 33
    .line 34
    new-instance v0, Ljava/lang/StringBuilder;

    .line 35
    .line 36
    const-string v1, "no event up from "

    .line 37
    .line 38
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    iget-object p0, p0, Landroidx/lifecycle/h;->f:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast p0, Landroidx/lifecycle/q;

    .line 44
    .line 45
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p1

    .line 60
    :cond_2
    iget-object v0, p0, Landroidx/lifecycle/h;->f:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v0, Landroidx/lifecycle/q;

    .line 63
    .line 64
    invoke-virtual {v0, p1}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    if-lez v0, :cond_0

    .line 69
    .line 70
    sget-object v0, Landroidx/lifecycle/p;->Companion:Landroidx/lifecycle/n;

    .line 71
    .line 72
    iget-object v1, p0, Landroidx/lifecycle/h;->f:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast v1, Landroidx/lifecycle/q;

    .line 75
    .line 76
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 77
    .line 78
    .line 79
    invoke-static {v1}, Landroidx/lifecycle/n;->a(Landroidx/lifecycle/q;)Landroidx/lifecycle/p;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    if-eqz v0, :cond_3

    .line 84
    .line 85
    invoke-virtual {p0, v0}, Landroidx/lifecycle/h;->a(Landroidx/lifecycle/p;)V

    .line 86
    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_3
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 90
    .line 91
    new-instance v0, Ljava/lang/StringBuilder;

    .line 92
    .line 93
    const-string v1, "no event down from "

    .line 94
    .line 95
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    iget-object p0, p0, Landroidx/lifecycle/h;->f:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast p0, Landroidx/lifecycle/q;

    .line 101
    .line 102
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    throw p1

    .line 117
    :cond_4
    return-void
.end method

.method public final f(Landroidx/lifecycle/x;Landroidx/lifecycle/p;)V
    .locals 3

    .line 1
    iget v0, p0, Landroidx/lifecycle/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object p1, Luu/r0;->a:[I

    .line 7
    .line 8
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    aget p1, p1, v0

    .line 13
    .line 14
    const/4 v0, 0x1

    .line 15
    if-ne p1, v0, :cond_0

    .line 16
    .line 17
    iget-object p1, p0, Landroidx/lifecycle/h;->f:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p1, Landroidx/lifecycle/q;

    .line 20
    .line 21
    sget-object p2, Landroidx/lifecycle/q;->f:Landroidx/lifecycle/q;

    .line 22
    .line 23
    invoke-virtual {p1, p2}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    if-lez p1, :cond_1

    .line 28
    .line 29
    invoke-virtual {p0, p2}, Landroidx/lifecycle/h;->b(Landroidx/lifecycle/q;)V

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    invoke-virtual {p2}, Landroidx/lifecycle/p;->a()Landroidx/lifecycle/q;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    invoke-virtual {p0, p1}, Landroidx/lifecycle/h;->b(Landroidx/lifecycle/q;)V

    .line 38
    .line 39
    .line 40
    :cond_1
    :goto_0
    return-void

    .line 41
    :pswitch_0
    iget-object v0, p0, Landroidx/lifecycle/h;->f:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v0, Landroidx/lifecycle/b;

    .line 44
    .line 45
    iget-object v0, v0, Landroidx/lifecycle/b;->a:Ljava/util/HashMap;

    .line 46
    .line 47
    invoke-virtual {v0, p2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    check-cast v1, Ljava/util/List;

    .line 52
    .line 53
    iget-object p0, p0, Landroidx/lifecycle/h;->e:Ljava/lang/Object;

    .line 54
    .line 55
    invoke-static {v1, p1, p2, p0}, Landroidx/lifecycle/b;->a(Ljava/util/List;Landroidx/lifecycle/x;Landroidx/lifecycle/p;Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    sget-object v1, Landroidx/lifecycle/p;->ON_ANY:Landroidx/lifecycle/p;

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    check-cast v0, Ljava/util/List;

    .line 65
    .line 66
    invoke-static {v0, p1, p2, p0}, Landroidx/lifecycle/b;->a(Ljava/util/List;Landroidx/lifecycle/x;Landroidx/lifecycle/p;Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    return-void

    .line 70
    :pswitch_1
    sget-object p1, Landroidx/lifecycle/p;->ON_START:Landroidx/lifecycle/p;

    .line 71
    .line 72
    if-ne p2, p1, :cond_2

    .line 73
    .line 74
    iget-object p1, p0, Landroidx/lifecycle/h;->e:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast p1, Landroidx/lifecycle/r;

    .line 77
    .line 78
    invoke-virtual {p1, p0}, Landroidx/lifecycle/r;->d(Landroidx/lifecycle/w;)V

    .line 79
    .line 80
    .line 81
    iget-object p0, p0, Landroidx/lifecycle/h;->f:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast p0, Lra/d;

    .line 84
    .line 85
    invoke-virtual {p0}, Lra/d;->d()V

    .line 86
    .line 87
    .line 88
    :cond_2
    return-void

    .line 89
    :pswitch_2
    iget-object v0, p0, Landroidx/lifecycle/h;->e:Ljava/lang/Object;

    .line 90
    .line 91
    check-cast v0, Landroidx/lifecycle/f;

    .line 92
    .line 93
    sget-object v1, Landroidx/lifecycle/g;->a:[I

    .line 94
    .line 95
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 96
    .line 97
    .line 98
    move-result v2

    .line 99
    aget v1, v1, v2

    .line 100
    .line 101
    packed-switch v1, :pswitch_data_1

    .line 102
    .line 103
    .line 104
    new-instance p0, La8/r0;

    .line 105
    .line 106
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 107
    .line 108
    .line 109
    throw p0

    .line 110
    :pswitch_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 111
    .line 112
    const-string p1, "ON_ANY must not been send by anybody"

    .line 113
    .line 114
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    throw p0

    .line 118
    :pswitch_4
    invoke-interface {v0, p1}, Landroidx/lifecycle/f;->onDestroy(Landroidx/lifecycle/x;)V

    .line 119
    .line 120
    .line 121
    goto :goto_1

    .line 122
    :pswitch_5
    invoke-interface {v0, p1}, Landroidx/lifecycle/f;->onStop(Landroidx/lifecycle/x;)V

    .line 123
    .line 124
    .line 125
    goto :goto_1

    .line 126
    :pswitch_6
    invoke-interface {v0, p1}, Landroidx/lifecycle/f;->onPause(Landroidx/lifecycle/x;)V

    .line 127
    .line 128
    .line 129
    goto :goto_1

    .line 130
    :pswitch_7
    invoke-interface {v0, p1}, Landroidx/lifecycle/f;->onResume(Landroidx/lifecycle/x;)V

    .line 131
    .line 132
    .line 133
    goto :goto_1

    .line 134
    :pswitch_8
    invoke-interface {v0, p1}, Landroidx/lifecycle/f;->onStart(Landroidx/lifecycle/x;)V

    .line 135
    .line 136
    .line 137
    goto :goto_1

    .line 138
    :pswitch_9
    invoke-interface {v0, p1}, Landroidx/lifecycle/f;->onCreate(Landroidx/lifecycle/x;)V

    .line 139
    .line 140
    .line 141
    :goto_1
    iget-object p0, p0, Landroidx/lifecycle/h;->f:Ljava/lang/Object;

    .line 142
    .line 143
    check-cast p0, Landroidx/lifecycle/v;

    .line 144
    .line 145
    if-eqz p0, :cond_3

    .line 146
    .line 147
    invoke-interface {p0, p1, p2}, Landroidx/lifecycle/v;->f(Landroidx/lifecycle/x;Landroidx/lifecycle/p;)V

    .line 148
    .line 149
    .line 150
    :cond_3
    return-void

    .line 151
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 152
    .line 153
    .line 154
    .line 155
    .line 156
    .line 157
    .line 158
    .line 159
    .line 160
    .line 161
    :pswitch_data_1
    .packed-switch 0x1
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
    .end packed-switch
.end method
