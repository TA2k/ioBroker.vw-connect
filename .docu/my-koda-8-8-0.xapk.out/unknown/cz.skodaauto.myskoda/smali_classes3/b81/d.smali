.class public final Lb81/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Llo/n;
.implements Lh1/l;
.implements Lju/b;
.implements Lretrofit2/Callback;
.implements Lkw/b;
.implements Lk0/c;
.implements Ld6/s;
.implements Ldy0/c;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;


# direct methods
.method public constructor <init>(I)V
    .locals 1

    iput p1, p0, Lb81/d;->d:I

    sparse-switch p1, :sswitch_data_0

    .line 27
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 28
    new-instance p1, Landroidx/collection/a1;

    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, v0}, Landroidx/collection/a1;-><init>(I)V

    .line 30
    iput-object p1, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 31
    new-instance p1, Landroidx/collection/u;

    const/4 v0, 0x0

    .line 32
    invoke-direct {p1, v0}, Landroidx/collection/u;-><init>(Ljava/lang/Object;)V

    .line 33
    iput-object p1, p0, Lb81/d;->f:Ljava/lang/Object;

    return-void

    .line 34
    :sswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 35
    new-instance p1, Ljava/util/HashMap;

    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    iput-object p1, p0, Lb81/d;->e:Ljava/lang/Object;

    return-void

    .line 36
    :sswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 37
    new-instance p1, Ljava/util/concurrent/atomic/AtomicInteger;

    invoke-direct {p1}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>()V

    iput-object p1, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 38
    new-instance p1, Ljava/util/concurrent/atomic/AtomicInteger;

    invoke-direct {p1}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>()V

    iput-object p1, p0, Lb81/d;->f:Ljava/lang/Object;

    return-void

    :sswitch_data_0
    .sparse-switch
        0x10 -> :sswitch_1
        0x1c -> :sswitch_0
    .end sparse-switch
.end method

.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lb81/d;->d:I

    iput-object p2, p0, Lb81/d;->e:Ljava/lang/Object;

    iput-object p3, p0, Lb81/d;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(IZ)V
    .locals 0

    .line 2
    iput p1, p0, Lb81/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;I)V
    .locals 8

    iput p2, p0, Lb81/d;->d:I

    sparse-switch p2, :sswitch_data_0

    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    iput-object p1, p0, Lb81/d;->e:Ljava/lang/Object;

    const/4 p1, 0x0

    .line 17
    iput-object p1, p0, Lb81/d;->f:Ljava/lang/Object;

    return-void

    .line 18
    :sswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 19
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object p1

    iput-object p1, p0, Lb81/d;->e:Ljava/lang/Object;

    const p2, 0x7f120155

    .line 20
    invoke-virtual {p1, p2}, Landroid/content/res/Resources;->getResourcePackageName(I)Ljava/lang/String;

    move-result-object p1

    iput-object p1, p0, Lb81/d;->f:Ljava/lang/Object;

    return-void

    .line 21
    :sswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p2, Ljava/util/concurrent/atomic/AtomicLong;

    const-wide/16 v0, -0x1

    invoke-direct {p2, v0, v1}, Ljava/util/concurrent/atomic/AtomicLong;-><init>(J)V

    iput-object p2, p0, Lb81/d;->f:Ljava/lang/Object;

    .line 22
    new-instance v6, Lno/q;

    const-string p2, "mlkit:vision"

    invoke-direct {v6, p2}, Lno/q;-><init>(Ljava/lang/String;)V

    .line 23
    new-instance v2, Lpo/b;

    .line 24
    sget-object v7, Lko/h;->c:Lko/h;

    const/4 v4, 0x0

    .line 25
    sget-object v5, Lpo/b;->n:Lc2/k;

    move-object v3, p1

    invoke-direct/range {v2 .. v7}, Lko/i;-><init>(Landroid/content/Context;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Lc2/k;Lko/b;Lko/h;)V

    .line 26
    iput-object v2, p0, Lb81/d;->e:Ljava/lang/Object;

    return-void

    nop

    :sswitch_data_0
    .sparse-switch
        0xe -> :sswitch_1
        0x11 -> :sswitch_0
    .end sparse-switch
.end method

.method public constructor <init>(Landroid/view/WindowInsetsAnimation$Bounds;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Lb81/d;->d:I

    .line 39
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 40
    invoke-static {p1}, La8/m;->x(Landroid/view/WindowInsetsAnimation$Bounds;)Landroid/graphics/Insets;

    move-result-object v0

    invoke-static {v0}, Ls5/b;->c(Landroid/graphics/Insets;)Ls5/b;

    move-result-object v0

    .line 41
    iput-object v0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 42
    invoke-static {p1}, La8/m;->f(Landroid/view/WindowInsetsAnimation$Bounds;)Landroid/graphics/Insets;

    move-result-object p1

    invoke-static {p1}, Ls5/b;->c(Landroid/graphics/Insets;)Ls5/b;

    move-result-object p1

    .line 43
    iput-object p1, p0, Lb81/d;->f:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V
    .locals 0

    .line 3
    iput p4, p0, Lb81/d;->d:I

    iput-object p1, p0, Lb81/d;->f:Ljava/lang/Object;

    iput-object p2, p0, Lb81/d;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 1

    const/16 v0, 0xf

    iput v0, p0, Lb81/d;->d:I

    .line 10
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 11
    const-string v0, ".lck"

    invoke-virtual {p1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    iput-object p1, p0, Lb81/d;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Lww/d;Ljava/util/Locale;)V
    .locals 0

    const/16 p1, 0x17

    iput p1, p0, Lb81/d;->d:I

    const-string p1, "locale"

    invoke-static {p3, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    iput-object p2, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 6
    iput-object p3, p0, Lb81/d;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lkw0/c;ILaw0/h;Ljava/lang/Throwable;)V
    .locals 0

    const/4 p2, 0x4

    iput p2, p0, Lb81/d;->d:I

    const-string p2, "request"

    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 44
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 45
    iput-object p1, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 46
    iput-object p3, p0, Lb81/d;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ll71/w;Ll71/z;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lb81/d;->d:I

    const-string v0, "dependencies"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "trajectoryConfig"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 13
    iput-object p1, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 14
    iput-object p2, p0, Lb81/d;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lv3/h0;Lt3/q0;)V
    .locals 1

    const/16 v0, 0x18

    iput v0, p0, Lb81/d;->d:I

    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 9
    invoke-static {p2}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    move-result-object p1

    iput-object p1, p0, Lb81/d;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lvp/k3;)V
    .locals 1

    const/16 v0, 0x19

    iput v0, p0, Lb81/d;->d:I

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lb81/d;->f:Ljava/lang/Object;

    return-void
.end method

.method public static h()Lf8/d;
    .locals 2

    .line 1
    new-instance v0, Lf8/d;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x1

    .line 7
    iput-boolean v1, v0, Lf8/d;->e:Z

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public a(Lretrofit2/Call;Ljava/lang/Throwable;)V
    .locals 1

    .line 1
    const-string p1, "t"

    .line 2
    .line 3
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lb81/d;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p1, Lji/d;

    .line 9
    .line 10
    instance-of v0, p2, Ljava/io/IOException;

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    new-instance v0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$NetworkError;

    .line 15
    .line 16
    check-cast p2, Ljava/io/IOException;

    .line 17
    .line 18
    invoke-direct {v0, p2}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$NetworkError;-><init>(Ljava/io/IOException;)V

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$UnknownError;

    .line 23
    .line 24
    invoke-direct {v0, p2}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$UnknownError;-><init>(Ljava/lang/Throwable;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast p0, Lretrofit2/Callback;

    .line 30
    .line 31
    invoke-static {v0}, Lretrofit2/Response;->a(Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;)Lretrofit2/Response;

    .line 32
    .line 33
    .line 34
    move-result-object p2

    .line 35
    invoke-interface {p0, p1, p2}, Lretrofit2/Callback;->b(Lretrofit2/Call;Lretrofit2/Response;)V

    .line 36
    .line 37
    .line 38
    return-void
.end method

.method public accept(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lb81/d;->d:I

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x1

    .line 7
    packed-switch v1, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    move-object/from16 v1, p2

    .line 11
    .line 12
    check-cast v1, Laq/k;

    .line 13
    .line 14
    move-object/from16 v4, p1

    .line 15
    .line 16
    check-cast v4, Lxo/i;

    .line 17
    .line 18
    invoke-virtual {v4}, Lno/e;->r()Landroid/os/IInterface;

    .line 19
    .line 20
    .line 21
    move-result-object v4

    .line 22
    check-cast v4, Lxo/k;

    .line 23
    .line 24
    new-instance v5, Lxo/e;

    .line 25
    .line 26
    sget-object v6, Lfv/b;->n:Lfv/b;

    .line 27
    .line 28
    invoke-direct {v5, v1, v6}, Lxo/e;-><init>(Laq/k;Lxo/a;)V

    .line 29
    .line 30
    .line 31
    invoke-static {}, Lkp/b8;->b()Lko/f;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    iget-object v6, v0, Lb81/d;->e:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v6, Ljava/util/List;

    .line 38
    .line 39
    iget-object v0, v0, Lb81/d;->f:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v0, Lxo/c;

    .line 42
    .line 43
    invoke-virtual {v4}, Lxo/k;->a()Landroid/os/Parcel;

    .line 44
    .line 45
    .line 46
    move-result-object v7

    .line 47
    invoke-virtual {v7, v6}, Landroid/os/Parcel;->writeStringList(Ljava/util/List;)V

    .line 48
    .line 49
    .line 50
    sget v6, Lfp/a;->a:I

    .line 51
    .line 52
    invoke-virtual {v7, v3}, Landroid/os/Parcel;->writeInt(I)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v7, v0}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {v7, v5}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v7, v3}, Landroid/os/Parcel;->writeInt(I)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v1, v7, v2}, Lko/f;->writeToParcel(Landroid/os/Parcel;I)V

    .line 65
    .line 66
    .line 67
    const/16 v0, 0x32

    .line 68
    .line 69
    invoke-virtual {v4, v7, v0}, Lxo/k;->b(Landroid/os/Parcel;I)V

    .line 70
    .line 71
    .line 72
    return-void

    .line 73
    :pswitch_0
    move-object/from16 v1, p2

    .line 74
    .line 75
    check-cast v1, Laq/k;

    .line 76
    .line 77
    move-object/from16 v4, p1

    .line 78
    .line 79
    check-cast v4, Lgp/f;

    .line 80
    .line 81
    iget-object v5, v0, Lb81/d;->e:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast v5, Lcom/google/android/gms/internal/measurement/i4;

    .line 84
    .line 85
    iget-object v0, v0, Lb81/d;->f:Ljava/lang/Object;

    .line 86
    .line 87
    move-object v7, v0

    .line 88
    check-cast v7, Lcom/google/android/gms/location/LocationRequest;

    .line 89
    .line 90
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 91
    .line 92
    .line 93
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/i4;->z()Lis/b;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    iget-object v6, v0, Lis/b;->c:Ljava/lang/Object;

    .line 98
    .line 99
    move-object v15, v6

    .line 100
    check-cast v15, Llo/k;

    .line 101
    .line 102
    invoke-static {v15}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    invoke-virtual {v4}, Lno/e;->k()[Ljo/d;

    .line 106
    .line 107
    .line 108
    move-result-object v6

    .line 109
    const/4 v8, 0x0

    .line 110
    if-eqz v6, :cond_3

    .line 111
    .line 112
    move v9, v2

    .line 113
    :goto_0
    array-length v10, v6

    .line 114
    if-ge v9, v10, :cond_1

    .line 115
    .line 116
    aget-object v10, v6, v9

    .line 117
    .line 118
    const-string v11, "location_updates_with_callback"

    .line 119
    .line 120
    iget-object v12, v10, Ljo/d;->d:Ljava/lang/String;

    .line 121
    .line 122
    invoke-virtual {v11, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    move-result v11

    .line 126
    if-eqz v11, :cond_0

    .line 127
    .line 128
    goto :goto_1

    .line 129
    :cond_0
    add-int/lit8 v9, v9, 0x1

    .line 130
    .line 131
    goto :goto_0

    .line 132
    :cond_1
    move-object v10, v8

    .line 133
    :goto_1
    if-nez v10, :cond_2

    .line 134
    .line 135
    goto :goto_2

    .line 136
    :cond_2
    invoke-virtual {v10}, Ljo/d;->x0()J

    .line 137
    .line 138
    .line 139
    move-result-wide v9

    .line 140
    const-wide/16 v11, 0x1

    .line 141
    .line 142
    cmp-long v6, v9, v11

    .line 143
    .line 144
    if-ltz v6, :cond_3

    .line 145
    .line 146
    move v2, v3

    .line 147
    :cond_3
    :goto_2
    iget-object v6, v4, Lgp/f;->A:Landroidx/collection/a1;

    .line 148
    .line 149
    monitor-enter v6

    .line 150
    :try_start_0
    iget-object v9, v4, Lgp/f;->A:Landroidx/collection/a1;

    .line 151
    .line 152
    invoke-virtual {v9, v15}, Landroidx/collection/a1;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v9

    .line 156
    check-cast v9, Lgp/e;

    .line 157
    .line 158
    if-eqz v9, :cond_6

    .line 159
    .line 160
    if-eqz v2, :cond_4

    .line 161
    .line 162
    goto :goto_6

    .line 163
    :cond_4
    iget-object v5, v9, Lgp/e;->d:Lcom/google/android/gms/internal/measurement/i4;

    .line 164
    .line 165
    monitor-enter v5
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 166
    :try_start_1
    iget-object v10, v5, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 167
    .line 168
    check-cast v10, Lis/b;

    .line 169
    .line 170
    if-eq v10, v0, :cond_5

    .line 171
    .line 172
    iput-object v8, v10, Lis/b;->b:Ljava/lang/Object;

    .line 173
    .line 174
    iput-object v8, v10, Lis/b;->c:Ljava/lang/Object;

    .line 175
    .line 176
    iput-object v0, v5, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 177
    .line 178
    :cond_5
    :try_start_2
    monitor-exit v5
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 179
    goto :goto_3

    .line 180
    :catchall_0
    move-exception v0

    .line 181
    goto :goto_4

    .line 182
    :goto_3
    move-object/from16 v19, v9

    .line 183
    .line 184
    move-object v9, v8

    .line 185
    goto :goto_7

    .line 186
    :goto_4
    :try_start_3
    monitor-exit v5
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 187
    :try_start_4
    throw v0

    .line 188
    :goto_5
    move-object v3, v6

    .line 189
    goto/16 :goto_a

    .line 190
    .line 191
    :cond_6
    :goto_6
    new-instance v0, Lgp/e;

    .line 192
    .line 193
    invoke-direct {v0, v5}, Lgp/e;-><init>(Lcom/google/android/gms/internal/measurement/i4;)V

    .line 194
    .line 195
    .line 196
    iget-object v5, v4, Lgp/f;->A:Landroidx/collection/a1;

    .line 197
    .line 198
    invoke-virtual {v5, v15, v0}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-object/from16 v19, v0

    .line 202
    .line 203
    :goto_7
    if-eqz v2, :cond_8

    .line 204
    .line 205
    invoke-virtual {v4}, Lno/e;->r()Landroid/os/IInterface;

    .line 206
    .line 207
    .line 208
    move-result-object v0

    .line 209
    check-cast v0, Lgp/v;

    .line 210
    .line 211
    iget-object v2, v15, Llo/k;->a:Ljava/lang/Object;

    .line 212
    .line 213
    invoke-static {v2}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    .line 214
    .line 215
    .line 216
    move-result v2

    .line 217
    new-instance v4, Ljava/lang/StringBuilder;

    .line 218
    .line 219
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    .line 220
    .line 221
    .line 222
    iget-object v5, v15, Llo/k;->b:Ljava/lang/String;

    .line 223
    .line 224
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 225
    .line 226
    .line 227
    const-string v5, "@"

    .line 228
    .line 229
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 230
    .line 231
    .line 232
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 233
    .line 234
    .line 235
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 236
    .line 237
    .line 238
    move-result-object v21

    .line 239
    new-instance v16, Lgp/h;

    .line 240
    .line 241
    if-nez v9, :cond_7

    .line 242
    .line 243
    move-object/from16 v18, v8

    .line 244
    .line 245
    goto :goto_8

    .line 246
    :cond_7
    move-object/from16 v18, v9

    .line 247
    .line 248
    :goto_8
    const/16 v17, 0x2

    .line 249
    .line 250
    const/16 v20, 0x0

    .line 251
    .line 252
    invoke-direct/range {v16 .. v21}, Lgp/h;-><init>(ILandroid/os/IBinder;Landroid/os/IBinder;Landroid/app/PendingIntent;Ljava/lang/String;)V

    .line 253
    .line 254
    .line 255
    move-object/from16 v2, v16

    .line 256
    .line 257
    new-instance v4, Lbp/r;

    .line 258
    .line 259
    invoke-direct {v4, v8, v1, v3}, Lbp/r;-><init>(Ljava/lang/Object;Laq/k;I)V

    .line 260
    .line 261
    .line 262
    invoke-virtual {v0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 263
    .line 264
    .line 265
    move-result-object v1

    .line 266
    invoke-static {v1, v2}, Lgp/b;->b(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 267
    .line 268
    .line 269
    invoke-static {v1, v7}, Lgp/b;->b(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 270
    .line 271
    .line 272
    invoke-virtual {v1, v4}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 273
    .line 274
    .line 275
    const/16 v2, 0x58

    .line 276
    .line 277
    invoke-virtual {v0, v1, v2}, Lbp/a;->U(Landroid/os/Parcel;I)V

    .line 278
    .line 279
    .line 280
    move-object v3, v6

    .line 281
    goto :goto_9

    .line 282
    :catchall_1
    move-exception v0

    .line 283
    goto :goto_5

    .line 284
    :cond_8
    move-object/from16 v0, v19

    .line 285
    .line 286
    invoke-virtual {v4}, Lno/e;->r()Landroid/os/IInterface;

    .line 287
    .line 288
    .line 289
    move-result-object v2

    .line 290
    check-cast v2, Lgp/v;

    .line 291
    .line 292
    new-instance v18, Lgp/i;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 293
    .line 294
    const/4 v12, 0x0

    .line 295
    const-wide v13, 0x7fffffffffffffffL

    .line 296
    .line 297
    .line 298
    .line 299
    .line 300
    const/4 v8, 0x0

    .line 301
    const/4 v9, 0x0

    .line 302
    const/4 v10, 0x0

    .line 303
    const/4 v11, 0x0

    .line 304
    move-object v3, v6

    .line 305
    move-object/from16 v6, v18

    .line 306
    .line 307
    :try_start_5
    invoke-direct/range {v6 .. v14}, Lgp/i;-><init>(Lcom/google/android/gms/location/LocationRequest;Ljava/util/ArrayList;ZZZZJ)V

    .line 308
    .line 309
    .line 310
    new-instance v4, Lgp/c;

    .line 311
    .line 312
    invoke-direct {v4, v1, v0}, Lgp/c;-><init>(Laq/k;Lgp/e;)V

    .line 313
    .line 314
    .line 315
    iget-object v1, v15, Llo/k;->a:Ljava/lang/Object;

    .line 316
    .line 317
    invoke-static {v1}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    .line 318
    .line 319
    .line 320
    move-result v1

    .line 321
    new-instance v5, Ljava/lang/StringBuilder;

    .line 322
    .line 323
    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    .line 324
    .line 325
    .line 326
    iget-object v6, v15, Llo/k;->b:Ljava/lang/String;

    .line 327
    .line 328
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 329
    .line 330
    .line 331
    const-string v6, "@"

    .line 332
    .line 333
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 334
    .line 335
    .line 336
    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 337
    .line 338
    .line 339
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 340
    .line 341
    .line 342
    move-result-object v23

    .line 343
    new-instance v16, Lgp/j;

    .line 344
    .line 345
    const/16 v19, 0x0

    .line 346
    .line 347
    const/16 v21, 0x0

    .line 348
    .line 349
    const/16 v17, 0x1

    .line 350
    .line 351
    move-object/from16 v20, v0

    .line 352
    .line 353
    move-object/from16 v22, v4

    .line 354
    .line 355
    invoke-direct/range {v16 .. v23}, Lgp/j;-><init>(ILgp/i;Landroid/os/IBinder;Landroid/os/IBinder;Landroid/app/PendingIntent;Landroid/os/IBinder;Ljava/lang/String;)V

    .line 356
    .line 357
    .line 358
    move-object/from16 v0, v16

    .line 359
    .line 360
    invoke-virtual {v2}, Lbp/a;->S()Landroid/os/Parcel;

    .line 361
    .line 362
    .line 363
    move-result-object v1

    .line 364
    invoke-static {v1, v0}, Lgp/b;->b(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 365
    .line 366
    .line 367
    const/16 v0, 0x3b

    .line 368
    .line 369
    invoke-virtual {v2, v1, v0}, Lbp/a;->U(Landroid/os/Parcel;I)V

    .line 370
    .line 371
    .line 372
    :goto_9
    monitor-exit v3

    .line 373
    return-void

    .line 374
    :catchall_2
    move-exception v0

    .line 375
    :goto_a
    monitor-exit v3
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 376
    throw v0

    .line 377
    :pswitch_data_0
    .packed-switch 0x5
        :pswitch_0
    .end packed-switch
.end method

.method public b(Lretrofit2/Call;Lretrofit2/Response;)V
    .locals 11

    .line 1
    iget-object p1, p0, Lb81/d;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p1, Lji/d;

    .line 4
    .line 5
    iget-object v0, p1, Lji/d;->e:Lcariad/charging/multicharge/retrofit/coroutineAdapter/a;

    .line 6
    .line 7
    iget-object v1, v0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/a;->a:Ljava/lang/Class;

    .line 8
    .line 9
    iget-object v2, p2, Lretrofit2/Response;->b:Ljava/lang/Object;

    .line 10
    .line 11
    iget-object v3, p2, Lretrofit2/Response;->a:Ld01/t0;

    .line 12
    .line 13
    iget-object v4, v3, Ld01/t0;->i:Ld01/y;

    .line 14
    .line 15
    iget-boolean v5, v3, Ld01/t0;->t:Z

    .line 16
    .line 17
    const-string v6, "Content-Disposition"

    .line 18
    .line 19
    invoke-virtual {v4, v6}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v4

    .line 23
    const/4 v6, 0x0

    .line 24
    const/4 v7, 0x0

    .line 25
    if-eqz v4, :cond_0

    .line 26
    .line 27
    const-string v8, "="

    .line 28
    .line 29
    filled-new-array {v8}, [Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v8

    .line 33
    const/4 v9, 0x6

    .line 34
    invoke-static {v4, v8, v9}, Lly0/p;->Y(Ljava/lang/CharSequence;[Ljava/lang/String;I)Ljava/util/List;

    .line 35
    .line 36
    .line 37
    move-result-object v4

    .line 38
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 39
    .line 40
    .line 41
    move-result v8

    .line 42
    const/4 v9, 0x2

    .line 43
    if-ne v8, v9, :cond_0

    .line 44
    .line 45
    invoke-static {v4}, Lmx0/q;->U(Ljava/util/List;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v4

    .line 49
    check-cast v4, Ljava/lang/String;

    .line 50
    .line 51
    if-eqz v4, :cond_0

    .line 52
    .line 53
    const-string v8, "\""

    .line 54
    .line 55
    const-string v9, ""

    .line 56
    .line 57
    invoke-static {v6, v4, v8, v9}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v4

    .line 61
    goto :goto_0

    .line 62
    :cond_0
    move-object v4, v7

    .line 63
    :goto_0
    const/4 v8, 0x1

    .line 64
    if-eqz v5, :cond_1

    .line 65
    .line 66
    const-class v9, Ljava/io/File;

    .line 67
    .line 68
    invoke-virtual {v1, v9}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v9

    .line 72
    if-eqz v9, :cond_1

    .line 73
    .line 74
    instance-of v9, v2, Ljava/io/File;

    .line 75
    .line 76
    if-eqz v9, :cond_1

    .line 77
    .line 78
    if-eqz v4, :cond_1

    .line 79
    .line 80
    move v9, v8

    .line 81
    goto :goto_1

    .line 82
    :cond_1
    move v9, v6

    .line 83
    :goto_1
    if-nez v9, :cond_2

    .line 84
    .line 85
    if-eqz v5, :cond_2

    .line 86
    .line 87
    if-eqz v2, :cond_2

    .line 88
    .line 89
    move v10, v8

    .line 90
    goto :goto_2

    .line 91
    :cond_2
    move v10, v6

    .line 92
    :goto_2
    if-eqz v5, :cond_3

    .line 93
    .line 94
    const-class v5, Llx0/b0;

    .line 95
    .line 96
    invoke-virtual {v1, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v1

    .line 100
    if-eqz v1, :cond_3

    .line 101
    .line 102
    move v1, v8

    .line 103
    goto :goto_3

    .line 104
    :cond_3
    move v1, v6

    .line 105
    :goto_3
    if-eqz v9, :cond_8

    .line 106
    .line 107
    const-string p2, "null cannot be cast to non-null type java.io.File"

    .line 108
    .line 109
    invoke-static {v2, p2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    check-cast v2, Ljava/io/File;

    .line 113
    .line 114
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    new-instance p2, Ljava/io/File;

    .line 118
    .line 119
    invoke-direct {p2, v4}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {v2}, Ljava/io/File;->getPath()Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object v0

    .line 126
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    invoke-static {v0}, Llp/wd;->c(Ljava/lang/String;)I

    .line 130
    .line 131
    .line 132
    move-result v1

    .line 133
    invoke-virtual {v0, v6, v1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 134
    .line 135
    .line 136
    move-result-object v3

    .line 137
    const-string v4, "substring(...)"

    .line 138
    .line 139
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {v0, v1}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 150
    .line 151
    .line 152
    move-result v1

    .line 153
    if-nez v1, :cond_4

    .line 154
    .line 155
    sget-object v0, Lmx0/s;->d:Lmx0/s;

    .line 156
    .line 157
    goto :goto_5

    .line 158
    :cond_4
    new-array v1, v8, [C

    .line 159
    .line 160
    sget-char v4, Ljava/io/File;->separatorChar:C

    .line 161
    .line 162
    aput-char v4, v1, v6

    .line 163
    .line 164
    invoke-static {v0, v1}, Lly0/p;->X(Ljava/lang/CharSequence;[C)Ljava/util/List;

    .line 165
    .line 166
    .line 167
    move-result-object v0

    .line 168
    check-cast v0, Ljava/lang/Iterable;

    .line 169
    .line 170
    new-instance v1, Ljava/util/ArrayList;

    .line 171
    .line 172
    const/16 v4, 0xa

    .line 173
    .line 174
    invoke-static {v0, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 175
    .line 176
    .line 177
    move-result v4

    .line 178
    invoke-direct {v1, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 179
    .line 180
    .line 181
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 182
    .line 183
    .line 184
    move-result-object v0

    .line 185
    :goto_4
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 186
    .line 187
    .line 188
    move-result v4

    .line 189
    if-eqz v4, :cond_5

    .line 190
    .line 191
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object v4

    .line 195
    check-cast v4, Ljava/lang/String;

    .line 196
    .line 197
    new-instance v5, Ljava/io/File;

    .line 198
    .line 199
    invoke-direct {v5, v4}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 200
    .line 201
    .line 202
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 203
    .line 204
    .line 205
    goto :goto_4

    .line 206
    :cond_5
    move-object v0, v1

    .line 207
    :goto_5
    new-instance v1, Ljava/io/File;

    .line 208
    .line 209
    invoke-direct {v1, v3}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 210
    .line 211
    .line 212
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 213
    .line 214
    .line 215
    move-result v3

    .line 216
    if-nez v3, :cond_6

    .line 217
    .line 218
    new-instance v0, Ljava/io/File;

    .line 219
    .line 220
    const-string v3, ".."

    .line 221
    .line 222
    invoke-direct {v0, v3}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 223
    .line 224
    .line 225
    goto :goto_6

    .line 226
    :cond_6
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 227
    .line 228
    .line 229
    move-result v3

    .line 230
    sub-int/2addr v3, v8

    .line 231
    if-ltz v3, :cond_7

    .line 232
    .line 233
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 234
    .line 235
    .line 236
    move-result v4

    .line 237
    if-gt v3, v4, :cond_7

    .line 238
    .line 239
    new-instance v4, Ljava/io/File;

    .line 240
    .line 241
    invoke-interface {v0, v6, v3}, Ljava/util/List;->subList(II)Ljava/util/List;

    .line 242
    .line 243
    .line 244
    move-result-object v0

    .line 245
    move-object v5, v0

    .line 246
    check-cast v5, Ljava/lang/Iterable;

    .line 247
    .line 248
    sget-object v6, Ljava/io/File;->separator:Ljava/lang/String;

    .line 249
    .line 250
    const-string v0, "separator"

    .line 251
    .line 252
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 253
    .line 254
    .line 255
    const/4 v9, 0x0

    .line 256
    const/16 v10, 0x3e

    .line 257
    .line 258
    const/4 v7, 0x0

    .line 259
    const/4 v8, 0x0

    .line 260
    invoke-static/range {v5 .. v10}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 261
    .line 262
    .line 263
    move-result-object v0

    .line 264
    invoke-direct {v4, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 265
    .line 266
    .line 267
    move-object v0, v4

    .line 268
    :goto_6
    invoke-static {v1, v0}, Lwx0/i;->e(Ljava/io/File;Ljava/io/File;)Ljava/io/File;

    .line 269
    .line 270
    .line 271
    move-result-object v0

    .line 272
    invoke-static {v0, p2}, Lwx0/i;->e(Ljava/io/File;Ljava/io/File;)Ljava/io/File;

    .line 273
    .line 274
    .line 275
    move-result-object p2

    .line 276
    invoke-virtual {v2, p2}, Ljava/io/File;->renameTo(Ljava/io/File;)Z

    .line 277
    .line 278
    .line 279
    new-instance v0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;

    .line 280
    .line 281
    invoke-direct {v0, p2}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;-><init>(Ljava/lang/Object;)V

    .line 282
    .line 283
    .line 284
    goto :goto_7

    .line 285
    :cond_7
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 286
    .line 287
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 288
    .line 289
    .line 290
    throw p0

    .line 291
    :cond_8
    if-eqz v10, :cond_9

    .line 292
    .line 293
    new-instance v0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;

    .line 294
    .line 295
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 296
    .line 297
    .line 298
    invoke-direct {v0, v2}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;-><init>(Ljava/lang/Object;)V

    .line 299
    .line 300
    .line 301
    goto :goto_7

    .line 302
    :cond_9
    if-eqz v1, :cond_a

    .line 303
    .line 304
    new-instance v0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;

    .line 305
    .line 306
    sget-object p2, Llx0/b0;->a:Llx0/b0;

    .line 307
    .line 308
    invoke-direct {v0, p2}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;-><init>(Ljava/lang/Object;)V

    .line 309
    .line 310
    .line 311
    goto :goto_7

    .line 312
    :cond_a
    :try_start_0
    iget-object p2, p2, Lretrofit2/Response;->c:Ld01/v0;

    .line 313
    .line 314
    if-eqz p2, :cond_b

    .line 315
    .line 316
    iget-object v0, v0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/a;->b:Lretrofit2/Converter;

    .line 317
    .line 318
    invoke-interface {v0, p2}, Lretrofit2/Converter;->j(Ljava/lang/Object;)Ljava/lang/Object;

    .line 319
    .line 320
    .line 321
    move-result-object v7
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 322
    :catch_0
    :cond_b
    new-instance v0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;

    .line 323
    .line 324
    iget-object p2, v3, Ld01/t0;->f:Ljava/lang/String;

    .line 325
    .line 326
    iget v1, v3, Ld01/t0;->g:I

    .line 327
    .line 328
    iget-object v2, v3, Ld01/t0;->d:Ld01/k0;

    .line 329
    .line 330
    const-string v3, "traceparent"

    .line 331
    .line 332
    iget-object v2, v2, Ld01/k0;->c:Ld01/y;

    .line 333
    .line 334
    invoke-virtual {v2, v3}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 335
    .line 336
    .line 337
    move-result-object v2

    .line 338
    invoke-direct {v0, v7, p2, v1, v2}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;-><init>(Ljava/lang/Object;Ljava/lang/String;ILjava/lang/String;)V

    .line 339
    .line 340
    .line 341
    :goto_7
    iget-object p0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 342
    .line 343
    check-cast p0, Lretrofit2/Callback;

    .line 344
    .line 345
    invoke-static {v0}, Lretrofit2/Response;->a(Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;)Lretrofit2/Response;

    .line 346
    .line 347
    .line 348
    move-result-object p2

    .line 349
    invoke-interface {p0, p1, p2}, Lretrofit2/Callback;->b(Lretrofit2/Call;Lretrofit2/Response;)V

    .line 350
    .line 351
    .line 352
    return-void
.end method

.method public c(Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget v0, p0, Lb81/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Void;

    .line 7
    .line 8
    iget-object p1, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p1, Landroid/view/Surface;

    .line 11
    .line 12
    invoke-virtual {p1}, Landroid/view/Surface;->release()V

    .line 13
    .line 14
    .line 15
    iget-object p0, p0, Lb81/d;->f:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Landroid/graphics/SurfaceTexture;

    .line 18
    .line 19
    invoke-virtual {p0}, Landroid/graphics/SurfaceTexture;->release()V

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :pswitch_0
    check-cast p1, Lp0/l;

    .line 24
    .line 25
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    iget-object p0, p0, Lb81/d;->f:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast p0, Landroidx/lifecycle/c1;

    .line 31
    .line 32
    iget-object p0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p0, Lp0/m;

    .line 35
    .line 36
    invoke-interface {p0, p1}, Lp0/m;->c(Lp0/l;)V

    .line 37
    .line 38
    .line 39
    return-void

    .line 40
    :pswitch_1
    check-cast p1, Lp0/l;

    .line 41
    .line 42
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 43
    .line 44
    .line 45
    iget-object p0, p0, Lb81/d;->f:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast p0, Lil/g;

    .line 48
    .line 49
    iget-object p0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast p0, Lp0/c;

    .line 52
    .line 53
    invoke-virtual {p0, p1}, Lp0/c;->c(Lp0/l;)V

    .line 54
    .line 55
    .line 56
    return-void

    .line 57
    :pswitch_data_0
    .packed-switch 0x12
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public d(Lhy0/z;Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "property"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lb81/d;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p1, Lww/e;

    .line 9
    .line 10
    iget-object p1, p1, Lww/e;->a:Landroid/content/SharedPreferences;

    .line 11
    .line 12
    invoke-interface {p1}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    iget-object p0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Ljava/lang/String;

    .line 19
    .line 20
    invoke-interface {p1, p0, p2}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-interface {p0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method public e(Lka/v0;Lb8/i;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroidx/collection/a1;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Landroidx/collection/a1;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Lka/f1;

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    invoke-static {}, Lka/f1;->a()Lka/f1;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-virtual {p0, p1, v0}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    :cond_0
    iput-object p2, v0, Lka/f1;->c:Lb8/i;

    .line 21
    .line 22
    iget p0, v0, Lka/f1;->a:I

    .line 23
    .line 24
    or-int/lit8 p0, p0, 0x8

    .line 25
    .line 26
    iput p0, v0, Lka/f1;->a:I

    .line 27
    .line 28
    return-void
.end method

.method public f()Ld5/c;
    .locals 2

    .line 1
    iget-object v0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/String;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-static {v0}, Ld5/h;->o(Ljava/lang/String;)Ld5/h;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    const-string v1, "DimensionDescription: Null value & symbol for "

    .line 15
    .line 16
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    iget-object p0, p0, Lb81/d;->f:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast p0, Ljava/lang/String;

    .line 22
    .line 23
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    const-string p0, ". Using WrapContent."

    .line 27
    .line 28
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    const-string v0, "CCL"

    .line 36
    .line 37
    invoke-static {v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 38
    .line 39
    .line 40
    const-string p0, "wrap"

    .line 41
    .line 42
    invoke-static {p0}, Ld5/h;->o(Ljava/lang/String;)Ld5/h;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0
.end method

.method public g(F)F
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lb81/d;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Lm1/t;

    .line 6
    .line 7
    invoke-virtual {v1}, Lm1/t;->h()Lm1/l;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    iget-object v2, v2, Lm1/l;->k:Ljava/lang/Object;

    .line 12
    .line 13
    iget-object v0, v0, Lb81/d;->f:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v0, Lh1/n;

    .line 16
    .line 17
    move-object v3, v2

    .line 18
    check-cast v3, Ljava/util/Collection;

    .line 19
    .line 20
    invoke-interface {v3}, Ljava/util/Collection;->size()I

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    const/high16 v5, 0x7f800000    # Float.POSITIVE_INFINITY

    .line 25
    .line 26
    const/4 v6, 0x0

    .line 27
    move v9, v5

    .line 28
    move v7, v6

    .line 29
    const/high16 v8, -0x800000    # Float.NEGATIVE_INFINITY

    .line 30
    .line 31
    :goto_0
    const/4 v10, 0x0

    .line 32
    const/4 v11, 0x1

    .line 33
    if-ge v7, v3, :cond_4

    .line 34
    .line 35
    invoke-interface {v2, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v12

    .line 39
    check-cast v12, Lm1/m;

    .line 40
    .line 41
    instance-of v13, v12, Lo1/e0;

    .line 42
    .line 43
    if-eqz v13, :cond_0

    .line 44
    .line 45
    move-object v13, v12

    .line 46
    check-cast v13, Lo1/e0;

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_0
    const/4 v13, 0x0

    .line 50
    :goto_1
    if-eqz v13, :cond_1

    .line 51
    .line 52
    invoke-interface {v13}, Lo1/e0;->c()Z

    .line 53
    .line 54
    .line 55
    move-result v13

    .line 56
    if-ne v13, v11, :cond_1

    .line 57
    .line 58
    const/high16 p0, -0x800000    # Float.NEGATIVE_INFINITY

    .line 59
    .line 60
    goto :goto_2

    .line 61
    :cond_1
    invoke-virtual {v1}, Lm1/t;->h()Lm1/l;

    .line 62
    .line 63
    .line 64
    move-result-object v11

    .line 65
    invoke-static {v11}, Lkp/da;->c(Lm1/l;)I

    .line 66
    .line 67
    .line 68
    move-result v11

    .line 69
    invoke-virtual {v1}, Lm1/t;->h()Lm1/l;

    .line 70
    .line 71
    .line 72
    move-result-object v13

    .line 73
    iget v13, v13, Lm1/l;->l:I

    .line 74
    .line 75
    neg-int v13, v13

    .line 76
    invoke-virtual {v1}, Lm1/t;->h()Lm1/l;

    .line 77
    .line 78
    .line 79
    move-result-object v14

    .line 80
    iget v14, v14, Lm1/l;->p:I

    .line 81
    .line 82
    iget v15, v12, Lm1/m;->p:I

    .line 83
    .line 84
    iget v12, v12, Lm1/m;->o:I

    .line 85
    .line 86
    const/high16 p0, -0x800000    # Float.NEGATIVE_INFINITY

    .line 87
    .line 88
    invoke-virtual {v1}, Lm1/t;->h()Lm1/l;

    .line 89
    .line 90
    .line 91
    move-result-object v4

    .line 92
    iget v4, v4, Lm1/l;->n:I

    .line 93
    .line 94
    invoke-interface {v0, v11, v15, v13, v14}, Lh1/n;->a(IIII)I

    .line 95
    .line 96
    .line 97
    move-result v4

    .line 98
    int-to-float v4, v4

    .line 99
    int-to-float v11, v12

    .line 100
    sub-float/2addr v11, v4

    .line 101
    cmpg-float v4, v11, v10

    .line 102
    .line 103
    if-gtz v4, :cond_2

    .line 104
    .line 105
    cmpl-float v4, v11, v8

    .line 106
    .line 107
    if-lez v4, :cond_2

    .line 108
    .line 109
    move v8, v11

    .line 110
    :cond_2
    cmpl-float v4, v11, v10

    .line 111
    .line 112
    if-ltz v4, :cond_3

    .line 113
    .line 114
    cmpg-float v4, v11, v9

    .line 115
    .line 116
    if-gez v4, :cond_3

    .line 117
    .line 118
    move v9, v11

    .line 119
    :cond_3
    :goto_2
    add-int/lit8 v7, v7, 0x1

    .line 120
    .line 121
    goto :goto_0

    .line 122
    :cond_4
    const/high16 p0, -0x800000    # Float.NEGATIVE_INFINITY

    .line 123
    .line 124
    iget-object v0, v1, Lm1/t;->f:Ll2/j1;

    .line 125
    .line 126
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object v0

    .line 130
    check-cast v0, Lm1/l;

    .line 131
    .line 132
    iget-object v0, v0, Lm1/l;->i:Lt4/c;

    .line 133
    .line 134
    invoke-static/range {p1 .. p1}, Ljava/lang/Math;->abs(F)F

    .line 135
    .line 136
    .line 137
    move-result v1

    .line 138
    sget v2, Lh1/k;->a:F

    .line 139
    .line 140
    invoke-interface {v0, v2}, Lt4/c;->w0(F)F

    .line 141
    .line 142
    .line 143
    move-result v0

    .line 144
    cmpg-float v0, v1, v0

    .line 145
    .line 146
    const/4 v1, 0x2

    .line 147
    if-gez v0, :cond_5

    .line 148
    .line 149
    goto :goto_3

    .line 150
    :cond_5
    cmpl-float v0, p1, v10

    .line 151
    .line 152
    if-lez v0, :cond_6

    .line 153
    .line 154
    move v6, v11

    .line 155
    goto :goto_3

    .line 156
    :cond_6
    move v6, v1

    .line 157
    :goto_3
    if-nez v6, :cond_7

    .line 158
    .line 159
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    .line 160
    .line 161
    .line 162
    move-result v0

    .line 163
    invoke-static {v8}, Ljava/lang/Math;->abs(F)F

    .line 164
    .line 165
    .line 166
    move-result v1

    .line 167
    cmpg-float v0, v0, v1

    .line 168
    .line 169
    if-gtz v0, :cond_a

    .line 170
    .line 171
    goto :goto_4

    .line 172
    :cond_7
    if-ne v6, v11, :cond_8

    .line 173
    .line 174
    :goto_4
    move v8, v9

    .line 175
    goto :goto_5

    .line 176
    :cond_8
    if-ne v6, v1, :cond_9

    .line 177
    .line 178
    goto :goto_5

    .line 179
    :cond_9
    move v8, v10

    .line 180
    :cond_a
    :goto_5
    cmpg-float v0, v8, v5

    .line 181
    .line 182
    if-nez v0, :cond_b

    .line 183
    .line 184
    goto :goto_6

    .line 185
    :cond_b
    cmpg-float v0, v8, p0

    .line 186
    .line 187
    if-nez v0, :cond_c

    .line 188
    .line 189
    :goto_6
    return v10

    .line 190
    :cond_c
    return v8
.end method

.method public get()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lj1/a;

    .line 4
    .line 5
    iget-object v0, v0, Lj1/a;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Landroid/content/Context;

    .line 8
    .line 9
    iget-object p0, p0, Lb81/d;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Lkx0/a;

    .line 12
    .line 13
    invoke-interface {p0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Lhu/b1;

    .line 18
    .line 19
    new-instance v1, Lhu/a0;

    .line 20
    .line 21
    invoke-direct {v1, v0, p0}, Lhu/a0;-><init>(Landroid/content/Context;Lhu/b1;)V

    .line 22
    .line 23
    .line 24
    return-object v1
.end method

.method public getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;
    .locals 0

    .line 1
    const-string p1, "property"

    .line 2
    .line 3
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lb81/d;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p1, Lww/e;

    .line 9
    .line 10
    iget-object p1, p1, Lww/e;->a:Landroid/content/SharedPreferences;

    .line 11
    .line 12
    iget-object p0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Ljava/lang/String;

    .line 15
    .line 16
    const/4 p2, 0x0

    .line 17
    invoke-interface {p1, p0, p2}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method

.method public i()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 3
    .line 4
    iput-object v0, p0, Lb81/d;->f:Ljava/lang/Object;

    .line 5
    .line 6
    return-void
.end method

.method public j(FF)F
    .locals 3

    .line 1
    invoke-static {p2}, Ljava/lang/Math;->abs(F)F

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    iget-object p0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lm1/t;

    .line 8
    .line 9
    invoke-virtual {p0}, Lm1/t;->h()Lm1/l;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    iget-object v0, p0, Lm1/l;->k:Ljava/lang/Object;

    .line 14
    .line 15
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    const/4 v1, 0x0

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    goto :goto_1

    .line 23
    :cond_0
    iget-object p0, p0, Lm1/l;->k:Ljava/lang/Object;

    .line 24
    .line 25
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    check-cast p0, Ljava/lang/Iterable;

    .line 30
    .line 31
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    if-eqz v2, :cond_1

    .line 40
    .line 41
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    check-cast v2, Lm1/m;

    .line 46
    .line 47
    iget v2, v2, Lm1/m;->p:I

    .line 48
    .line 49
    add-int/2addr v1, v2

    .line 50
    goto :goto_0

    .line 51
    :cond_1
    div-int/2addr v1, v0

    .line 52
    :goto_1
    int-to-float p0, v1

    .line 53
    sub-float/2addr p1, p0

    .line 54
    const/4 p0, 0x0

    .line 55
    cmpg-float v0, p1, p0

    .line 56
    .line 57
    if-gez v0, :cond_2

    .line 58
    .line 59
    move p1, p0

    .line 60
    :cond_2
    invoke-static {p2}, Ljava/lang/Math;->signum(F)F

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    mul-float/2addr p0, p1

    .line 65
    return p0
.end method

.method public k(La8/g;)V
    .locals 3

    .line 1
    monitor-enter p1

    .line 2
    monitor-exit p1

    .line 3
    iget-object v0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Landroid/os/Handler;

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    new-instance v1, La8/z;

    .line 10
    .line 11
    const/16 v2, 0xe

    .line 12
    .line 13
    invoke-direct {v1, v2, p0, p1}, La8/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, v1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 17
    .line 18
    .line 19
    :cond_0
    return-void
.end method

.method public l()Lt3/q0;
    .locals 0

    .line 1
    iget-object p0, p0, Lb81/d;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ll2/j1;

    .line 4
    .line 5
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lt3/q0;

    .line 10
    .line 11
    return-object p0
.end method

.method public declared-synchronized m()Ljava/util/Map;
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lb81/d;->f:Ljava/lang/Object;

    .line 3
    .line 4
    check-cast v0, Ljava/util/Map;

    .line 5
    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    new-instance v0, Ljava/util/HashMap;

    .line 9
    .line 10
    iget-object v1, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Ljava/util/HashMap;

    .line 13
    .line 14
    invoke-direct {v0, v1}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    .line 15
    .line 16
    .line 17
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    iput-object v0, p0, Lb81/d;->f:Ljava/lang/Object;

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :catchall_0
    move-exception v0

    .line 25
    goto :goto_1

    .line 26
    :cond_0
    :goto_0
    iget-object v0, p0, Lb81/d;->f:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v0, Ljava/util/Map;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 29
    .line 30
    monitor-exit p0

    .line 31
    return-object v0

    .line 32
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 33
    throw v0
.end method

.method public n(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object v0, p0, Lb81/d;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/String;

    .line 4
    .line 5
    iget-object p0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Landroid/content/res/Resources;

    .line 8
    .line 9
    const-string v1, "string"

    .line 10
    .line 11
    invoke-virtual {p0, p1, v1, v0}, Landroid/content/res/Resources;->getIdentifier(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    if-nez p1, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x0

    .line 18
    return-object p0

    .line 19
    :cond_0
    invoke-virtual {p0, p1}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method public o()V
    .locals 4

    .line 1
    iget-object v0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/String;

    .line 4
    .line 5
    iget-object v1, p0, Lb81/d;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Ljava/nio/channels/FileChannel;

    .line 8
    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    goto :goto_1

    .line 12
    :cond_0
    :try_start_0
    new-instance v1, Ljava/io/File;

    .line 13
    .line 14
    invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v1}, Ljava/io/File;->getParentFile()Ljava/io/File;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    if-eqz v2, :cond_1

    .line 22
    .line 23
    invoke-virtual {v2}, Ljava/io/File;->mkdirs()Z

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :catchall_0
    move-exception v1

    .line 28
    goto :goto_2

    .line 29
    :cond_1
    :goto_0
    new-instance v2, Ljava/io/FileOutputStream;

    .line 30
    .line 31
    invoke-direct {v2, v1}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {v2}, Ljava/io/FileOutputStream;->getChannel()Ljava/nio/channels/FileChannel;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    iput-object v1, p0, Lb81/d;->f:Ljava/lang/Object;

    .line 39
    .line 40
    if-eqz v1, :cond_2

    .line 41
    .line 42
    invoke-virtual {v1}, Ljava/nio/channels/FileChannel;->lock()Ljava/nio/channels/FileLock;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 43
    .line 44
    .line 45
    :cond_2
    :goto_1
    return-void

    .line 46
    :goto_2
    iget-object v2, p0, Lb81/d;->f:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast v2, Ljava/nio/channels/FileChannel;

    .line 49
    .line 50
    if-eqz v2, :cond_3

    .line 51
    .line 52
    invoke-virtual {v2}, Ljava/nio/channels/spi/AbstractInterruptibleChannel;->close()V

    .line 53
    .line 54
    .line 55
    :cond_3
    const/4 v2, 0x0

    .line 56
    iput-object v2, p0, Lb81/d;->f:Ljava/lang/Object;

    .line 57
    .line 58
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 59
    .line 60
    const-string v2, "Unable to lock file: \'"

    .line 61
    .line 62
    const-string v3, "\'."

    .line 63
    .line 64
    invoke-static {v2, v0, v3}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    invoke-direct {p0, v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 69
    .line 70
    .line 71
    throw p0
.end method

.method public onApplyWindowInsets(Landroid/view/View;Ld6/w1;)Ld6/w1;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    iget-object v3, v0, Lb81/d;->e:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v3, Lb6/f;

    .line 10
    .line 11
    iget-object v0, v0, Lb81/d;->f:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Lm8/j;

    .line 14
    .line 15
    iget v4, v0, Lm8/j;->a:I

    .line 16
    .line 17
    iget v5, v0, Lm8/j;->b:I

    .line 18
    .line 19
    iget v0, v0, Lm8/j;->c:I

    .line 20
    .line 21
    iget-object v6, v2, Ld6/w1;->a:Ld6/s1;

    .line 22
    .line 23
    const/16 v7, 0x207

    .line 24
    .line 25
    invoke-virtual {v6, v7}, Ld6/s1;->g(I)Ls5/b;

    .line 26
    .line 27
    .line 28
    move-result-object v7

    .line 29
    const/16 v8, 0x20

    .line 30
    .line 31
    invoke-virtual {v6, v8}, Ld6/s1;->g(I)Ls5/b;

    .line 32
    .line 33
    .line 34
    move-result-object v6

    .line 35
    iget-object v8, v3, Lb6/f;->e:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v8, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;

    .line 38
    .line 39
    iget v9, v7, Ls5/b;->b:I

    .line 40
    .line 41
    iget v10, v7, Ls5/b;->c:I

    .line 42
    .line 43
    iget v11, v7, Ls5/b;->a:I

    .line 44
    .line 45
    iput v9, v8, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->w:I

    .line 46
    .line 47
    invoke-virtual {v1}, Landroid/view/View;->getLayoutDirection()I

    .line 48
    .line 49
    .line 50
    move-result v9

    .line 51
    const/4 v13, 0x1

    .line 52
    if-ne v9, v13, :cond_0

    .line 53
    .line 54
    move v9, v13

    .line 55
    goto :goto_0

    .line 56
    :cond_0
    const/4 v9, 0x0

    .line 57
    :goto_0
    invoke-virtual {v1}, Landroid/view/View;->getPaddingBottom()I

    .line 58
    .line 59
    .line 60
    move-result v14

    .line 61
    invoke-virtual {v1}, Landroid/view/View;->getPaddingLeft()I

    .line 62
    .line 63
    .line 64
    move-result v15

    .line 65
    invoke-virtual {v1}, Landroid/view/View;->getPaddingRight()I

    .line 66
    .line 67
    .line 68
    move-result v16

    .line 69
    iget-boolean v12, v8, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->o:Z

    .line 70
    .line 71
    if-eqz v12, :cond_1

    .line 72
    .line 73
    invoke-virtual {v2}, Ld6/w1;->a()I

    .line 74
    .line 75
    .line 76
    move-result v14

    .line 77
    iput v14, v8, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->v:I

    .line 78
    .line 79
    add-int/2addr v14, v0

    .line 80
    :cond_1
    iget-boolean v0, v8, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->p:Z

    .line 81
    .line 82
    if-eqz v0, :cond_3

    .line 83
    .line 84
    if-eqz v9, :cond_2

    .line 85
    .line 86
    move v0, v5

    .line 87
    goto :goto_1

    .line 88
    :cond_2
    move v0, v4

    .line 89
    :goto_1
    add-int v15, v0, v11

    .line 90
    .line 91
    :cond_3
    iget-boolean v0, v8, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->q:Z

    .line 92
    .line 93
    if-eqz v0, :cond_5

    .line 94
    .line 95
    if-eqz v9, :cond_4

    .line 96
    .line 97
    goto :goto_2

    .line 98
    :cond_4
    move v4, v5

    .line 99
    :goto_2
    add-int v16, v4, v10

    .line 100
    .line 101
    :cond_5
    move/from16 v0, v16

    .line 102
    .line 103
    invoke-virtual {v1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 104
    .line 105
    .line 106
    move-result-object v4

    .line 107
    check-cast v4, Landroid/view/ViewGroup$MarginLayoutParams;

    .line 108
    .line 109
    iget-boolean v5, v8, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->s:Z

    .line 110
    .line 111
    if-eqz v5, :cond_6

    .line 112
    .line 113
    iget v5, v4, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    .line 114
    .line 115
    if-eq v5, v11, :cond_6

    .line 116
    .line 117
    iput v11, v4, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    .line 118
    .line 119
    move v5, v13

    .line 120
    goto :goto_3

    .line 121
    :cond_6
    const/4 v5, 0x0

    .line 122
    :goto_3
    iget-boolean v9, v8, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->t:Z

    .line 123
    .line 124
    if-eqz v9, :cond_7

    .line 125
    .line 126
    iget v9, v4, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    .line 127
    .line 128
    if-eq v9, v10, :cond_7

    .line 129
    .line 130
    iput v10, v4, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    .line 131
    .line 132
    move v5, v13

    .line 133
    :cond_7
    iget-boolean v9, v8, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->u:Z

    .line 134
    .line 135
    if-eqz v9, :cond_8

    .line 136
    .line 137
    iget v9, v4, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    .line 138
    .line 139
    iget v7, v7, Ls5/b;->b:I

    .line 140
    .line 141
    if-eq v9, v7, :cond_8

    .line 142
    .line 143
    iput v7, v4, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    .line 144
    .line 145
    goto :goto_4

    .line 146
    :cond_8
    move v13, v5

    .line 147
    :goto_4
    if-eqz v13, :cond_9

    .line 148
    .line 149
    invoke-virtual {v1, v4}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 150
    .line 151
    .line 152
    :cond_9
    invoke-virtual {v1}, Landroid/view/View;->getPaddingTop()I

    .line 153
    .line 154
    .line 155
    move-result v4

    .line 156
    invoke-virtual {v1, v15, v4, v0, v14}, Landroid/view/View;->setPadding(IIII)V

    .line 157
    .line 158
    .line 159
    iget-boolean v0, v3, Lb6/f;->d:Z

    .line 160
    .line 161
    if-eqz v0, :cond_a

    .line 162
    .line 163
    iget v1, v6, Ls5/b;->d:I

    .line 164
    .line 165
    iput v1, v8, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->m:I

    .line 166
    .line 167
    :cond_a
    if-nez v12, :cond_c

    .line 168
    .line 169
    if-eqz v0, :cond_b

    .line 170
    .line 171
    goto :goto_5

    .line 172
    :cond_b
    return-object v2

    .line 173
    :cond_c
    :goto_5
    invoke-virtual {v8}, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->I()V

    .line 174
    .line 175
    .line 176
    return-object v2
.end method

.method public p(Lka/v0;I)Lb8/i;
    .locals 4

    .line 1
    iget-object p0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroidx/collection/a1;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Landroidx/collection/a1;->indexOfKey(Ljava/lang/Object;)I

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    const/4 v0, 0x0

    .line 10
    if-gez p1, :cond_0

    .line 11
    .line 12
    goto :goto_1

    .line 13
    :cond_0
    invoke-virtual {p0, p1}, Landroidx/collection/a1;->valueAt(I)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    check-cast v1, Lka/f1;

    .line 18
    .line 19
    if-eqz v1, :cond_4

    .line 20
    .line 21
    iget v2, v1, Lka/f1;->a:I

    .line 22
    .line 23
    and-int v3, v2, p2

    .line 24
    .line 25
    if-eqz v3, :cond_4

    .line 26
    .line 27
    not-int v3, p2

    .line 28
    and-int/2addr v2, v3

    .line 29
    iput v2, v1, Lka/f1;->a:I

    .line 30
    .line 31
    const/4 v3, 0x4

    .line 32
    if-ne p2, v3, :cond_1

    .line 33
    .line 34
    iget-object p2, v1, Lka/f1;->b:Lb8/i;

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_1
    const/16 v3, 0x8

    .line 38
    .line 39
    if-ne p2, v3, :cond_3

    .line 40
    .line 41
    iget-object p2, v1, Lka/f1;->c:Lb8/i;

    .line 42
    .line 43
    :goto_0
    and-int/lit8 v2, v2, 0xc

    .line 44
    .line 45
    if-nez v2, :cond_2

    .line 46
    .line 47
    invoke-virtual {p0, p1}, Landroidx/collection/a1;->removeAt(I)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    const/4 p0, 0x0

    .line 51
    iput p0, v1, Lka/f1;->a:I

    .line 52
    .line 53
    iput-object v0, v1, Lka/f1;->b:Lb8/i;

    .line 54
    .line 55
    iput-object v0, v1, Lka/f1;->c:Lb8/i;

    .line 56
    .line 57
    sget-object p0, Lka/f1;->d:La5/e;

    .line 58
    .line 59
    invoke-virtual {p0, v1}, La5/e;->c(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    :cond_2
    return-object p2

    .line 63
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 64
    .line 65
    const-string p1, "Must provide flag PRE or POST"

    .line 66
    .line 67
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    throw p0

    .line 71
    :cond_4
    :goto_1
    return-object v0
.end method

.method public q(Lmw/j;Lnw/g;)V
    .locals 8

    .line 1
    iget-object v0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lkw/g;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_4

    .line 7
    .line 8
    iget-object p0, p0, Lb81/d;->f:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v2, p0

    .line 11
    check-cast v2, Lkw/i;

    .line 12
    .line 13
    if-eqz v2, :cond_3

    .line 14
    .line 15
    if-nez p1, :cond_0

    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    iget-object p0, p2, Lnw/g;->b:Lnw/f;

    .line 19
    .line 20
    iget-object v1, p1, Lmw/j;->h:Lrw/b;

    .line 21
    .line 22
    iget-object p1, p1, Lmw/j;->b:Ljava/util/ArrayList;

    .line 23
    .line 24
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 25
    .line 26
    .line 27
    move-result p1

    .line 28
    const/4 v3, 0x0

    .line 29
    invoke-static {v3, p1}, Lkp/r9;->m(II)Lgy0/j;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    invoke-virtual {p1}, Lgy0/h;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    move-object v3, p1

    .line 38
    check-cast v3, Lgy0/i;

    .line 39
    .line 40
    iget-boolean v4, v3, Lgy0/i;->f:Z

    .line 41
    .line 42
    if-eqz v4, :cond_2

    .line 43
    .line 44
    check-cast p1, Lmx0/w;

    .line 45
    .line 46
    invoke-virtual {p1}, Lmx0/w;->nextInt()I

    .line 47
    .line 48
    .line 49
    move-result v4

    .line 50
    invoke-virtual {p0, v4, v1}, Lnw/f;->a(ILrw/b;)Lnw/e;

    .line 51
    .line 52
    .line 53
    move-result-object v4

    .line 54
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 55
    .line 56
    .line 57
    const/4 v4, 0x0

    .line 58
    move v5, v4

    .line 59
    :goto_0
    iget-boolean v6, v3, Lgy0/i;->f:Z

    .line 60
    .line 61
    if-eqz v6, :cond_1

    .line 62
    .line 63
    invoke-virtual {p1}, Lmx0/w;->nextInt()I

    .line 64
    .line 65
    .line 66
    move-result v6

    .line 67
    invoke-virtual {p0, v6, v1}, Lnw/f;->a(ILrw/b;)Lnw/e;

    .line 68
    .line 69
    .line 70
    move-result-object v6

    .line 71
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 72
    .line 73
    .line 74
    invoke-static {v5, v4}, Ljava/lang/Math;->max(FF)F

    .line 75
    .line 76
    .line 77
    move-result v5

    .line 78
    goto :goto_0

    .line 79
    :cond_1
    invoke-interface {v0, v5}, Lpw/f;->c(F)F

    .line 80
    .line 81
    .line 82
    move-result p0

    .line 83
    iget p1, p2, Lnw/g;->c:F

    .line 84
    .line 85
    invoke-interface {v0, p1}, Lpw/f;->c(F)F

    .line 86
    .line 87
    .line 88
    move-result p1

    .line 89
    add-float v3, p1, p0

    .line 90
    .line 91
    invoke-interface {v0}, Lkw/g;->l()Lkw/f;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    iget p1, p1, Lkw/f;->a:F

    .line 96
    .line 97
    invoke-interface {v0, p1}, Lpw/f;->c(F)F

    .line 98
    .line 99
    .line 100
    move-result v4

    .line 101
    invoke-interface {v0}, Lkw/g;->l()Lkw/f;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    iget p1, p1, Lkw/f;->b:F

    .line 106
    .line 107
    invoke-interface {v0, p1}, Lpw/f;->c(F)F

    .line 108
    .line 109
    .line 110
    move-result v5

    .line 111
    const/4 p1, 0x2

    .line 112
    int-to-float p1, p1

    .line 113
    div-float/2addr p0, p1

    .line 114
    invoke-interface {v0}, Lkw/g;->l()Lkw/f;

    .line 115
    .line 116
    .line 117
    move-result-object p1

    .line 118
    iget p1, p1, Lkw/f;->c:F

    .line 119
    .line 120
    invoke-interface {v0, p1}, Lpw/f;->c(F)F

    .line 121
    .line 122
    .line 123
    move-result p1

    .line 124
    add-float v6, p1, p0

    .line 125
    .line 126
    invoke-interface {v0}, Lkw/g;->l()Lkw/f;

    .line 127
    .line 128
    .line 129
    move-result-object p1

    .line 130
    iget p1, p1, Lkw/f;->d:F

    .line 131
    .line 132
    invoke-interface {v0, p1}, Lpw/f;->c(F)F

    .line 133
    .line 134
    .line 135
    move-result p1

    .line 136
    add-float v7, p1, p0

    .line 137
    .line 138
    invoke-virtual/range {v2 .. v7}, Lkw/i;->a(FFFFF)V

    .line 139
    .line 140
    .line 141
    return-void

    .line 142
    :cond_2
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 143
    .line 144
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 145
    .line 146
    .line 147
    throw p0

    .line 148
    :cond_3
    const-string p0, "horizontalDimensions"

    .line 149
    .line 150
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    throw v1

    .line 154
    :cond_4
    const-string p0, "context"

    .line 155
    .line 156
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 157
    .line 158
    .line 159
    throw v1
.end method

.method public r(Lka/v0;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroidx/collection/a1;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Landroidx/collection/a1;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lka/f1;

    .line 10
    .line 11
    if-nez p0, :cond_0

    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    iget p1, p0, Lka/f1;->a:I

    .line 15
    .line 16
    and-int/lit8 p1, p1, -0x2

    .line 17
    .line 18
    iput p1, p0, Lka/f1;->a:I

    .line 19
    .line 20
    return-void
.end method

.method public s(Lka/v0;)V
    .locals 6

    .line 1
    iget-object v0, p0, Lb81/d;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/collection/u;

    .line 4
    .line 5
    invoke-virtual {v0}, Landroidx/collection/u;->h()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const/4 v2, 0x1

    .line 10
    sub-int/2addr v1, v2

    .line 11
    :goto_0
    if-ltz v1, :cond_1

    .line 12
    .line 13
    invoke-virtual {v0, v1}, Landroidx/collection/u;->i(I)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    if-ne p1, v3, :cond_0

    .line 18
    .line 19
    iget-object v3, v0, Landroidx/collection/u;->f:[Ljava/lang/Object;

    .line 20
    .line 21
    aget-object v4, v3, v1

    .line 22
    .line 23
    sget-object v5, Landroidx/collection/v;->a:Ljava/lang/Object;

    .line 24
    .line 25
    if-eq v4, v5, :cond_1

    .line 26
    .line 27
    aput-object v5, v3, v1

    .line 28
    .line 29
    iput-boolean v2, v0, Landroidx/collection/u;->d:Z

    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_0
    add-int/lit8 v1, v1, -0x1

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    :goto_1
    iget-object p0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p0, Landroidx/collection/a1;

    .line 38
    .line 39
    invoke-virtual {p0, p1}, Landroidx/collection/a1;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    check-cast p0, Lka/f1;

    .line 44
    .line 45
    if-eqz p0, :cond_2

    .line 46
    .line 47
    const/4 p1, 0x0

    .line 48
    iput p1, p0, Lka/f1;->a:I

    .line 49
    .line 50
    const/4 p1, 0x0

    .line 51
    iput-object p1, p0, Lka/f1;->b:Lb8/i;

    .line 52
    .line 53
    iput-object p1, p0, Lka/f1;->c:Lb8/i;

    .line 54
    .line 55
    sget-object p1, Lka/f1;->d:La5/e;

    .line 56
    .line 57
    invoke-virtual {p1, p0}, La5/e;->c(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    :cond_2
    return-void
.end method

.method public bridge synthetic setValue(Ljava/lang/Object;Lhy0/z;Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p3, Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0, p2, p3}, Lb81/d;->d(Lhy0/z;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget v0, p0, Lb81/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v1, "Bounds{lower="

    .line 14
    .line 15
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v1, Ls5/b;

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v1, " upper="

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    iget-object p0, p0, Lb81/d;->f:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Ls5/b;

    .line 33
    .line 34
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    const-string p0, "}"

    .line 38
    .line 39
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
    :pswitch_data_0
    .packed-switch 0x3
        :pswitch_0
    .end packed-switch
.end method

.method public y(Ljava/lang/Throwable;)V
    .locals 3

    .line 1
    iget v0, p0, Lb81/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 7
    .line 8
    const-string v0, "Future should never fail. Did it get completed by GC?"

    .line 9
    .line 10
    invoke-direct {p0, v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 11
    .line 12
    .line 13
    throw p0

    .line 14
    :pswitch_0
    iget-object p0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, Lp0/k;

    .line 17
    .line 18
    iget p0, p0, Lp0/k;->f:I

    .line 19
    .line 20
    const/4 v0, 0x2

    .line 21
    const-string v1, "DualSurfaceProcessorNode"

    .line 22
    .line 23
    if-ne p0, v0, :cond_0

    .line 24
    .line 25
    instance-of v0, p1, Ljava/util/concurrent/CancellationException;

    .line 26
    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    const-string p0, "Downstream VideoCapture failed to provide Surface."

    .line 30
    .line 31
    invoke-static {v1, p0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 36
    .line 37
    const-string v2, "Downstream node failed to provide Surface. Target: "

    .line 38
    .line 39
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    invoke-static {p0}, Ljp/yc;->c(I)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    invoke-static {v1, p0, p1}, Ljp/v1;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 54
    .line 55
    .line 56
    :goto_0
    return-void

    .line 57
    :pswitch_1
    iget-object p0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast p0, Lp0/k;

    .line 60
    .line 61
    iget p0, p0, Lp0/k;->f:I

    .line 62
    .line 63
    const/4 v0, 0x2

    .line 64
    const-string v1, "SurfaceProcessorNode"

    .line 65
    .line 66
    if-ne p0, v0, :cond_1

    .line 67
    .line 68
    instance-of v0, p1, Ljava/util/concurrent/CancellationException;

    .line 69
    .line 70
    if-eqz v0, :cond_1

    .line 71
    .line 72
    const-string p0, "Downstream VideoCapture failed to provide Surface."

    .line 73
    .line 74
    invoke-static {v1, p0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 79
    .line 80
    const-string v2, "Downstream node failed to provide Surface. Target: "

    .line 81
    .line 82
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    invoke-static {p0}, Ljp/yc;->c(I)Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    invoke-static {v1, p0, p1}, Ljp/v1;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 97
    .line 98
    .line 99
    :goto_1
    return-void

    .line 100
    nop

    .line 101
    :pswitch_data_0
    .packed-switch 0x12
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
