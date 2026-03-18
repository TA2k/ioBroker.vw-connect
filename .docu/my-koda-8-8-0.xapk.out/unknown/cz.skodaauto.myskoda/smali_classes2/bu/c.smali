.class public Lbu/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lb0/z0;
.implements Lk0/c;
.implements Lc1/q;
.implements Llo/n;
.implements Ler/h;
.implements Lh0/c1;
.implements Llo/l;
.implements Lm/d1;
.implements Lh1/b;


# static fields
.field public static volatile f:Lbu/c;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;


# direct methods
.method public constructor <init>(FF)V
    .locals 2

    const/4 v0, 0x7

    iput v0, p0, Lbu/c;->d:I

    .line 25
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 26
    new-instance v0, Lc1/d0;

    const v1, 0x3c23d70a    # 0.01f

    .line 27
    invoke-direct {v0, p1, p2, v1}, Lc1/d0;-><init>(FFF)V

    .line 28
    iput-object v0, p0, Lbu/c;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(I)V
    .locals 1

    iput p1, p0, Lbu/c;->d:I

    sparse-switch p1, :sswitch_data_0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    new-instance p1, Ljava/util/HashSet;

    invoke-direct {p1}, Ljava/util/HashSet;-><init>()V

    iput-object p1, p0, Lbu/c;->e:Ljava/lang/Object;

    return-void

    .line 4
    :sswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    new-instance p1, Ljava/util/LinkedHashSet;

    invoke-direct {p1}, Ljava/util/LinkedHashSet;-><init>()V

    iput-object p1, p0, Lbu/c;->e:Ljava/lang/Object;

    return-void

    .line 6
    :sswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    new-instance p1, Ljava/security/SecureRandom;

    invoke-direct {p1}, Ljava/security/SecureRandom;-><init>()V

    iput-object p1, p0, Lbu/c;->e:Ljava/lang/Object;

    return-void

    .line 8
    :sswitch_2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    new-instance p1, Le6/e;

    .line 10
    invoke-direct {p1, p0}, Le6/e;-><init>(Lbu/c;)V

    .line 11
    iput-object p1, p0, Lbu/c;->e:Ljava/lang/Object;

    return-void

    .line 12
    :sswitch_3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 13
    new-instance p1, Landroid/graphics/Region;

    invoke-direct {p1}, Landroid/graphics/Region;-><init>()V

    iput-object p1, p0, Lbu/c;->e:Ljava/lang/Object;

    return-void

    .line 14
    :sswitch_4
    sget-object p1, Ljava/util/concurrent/TimeUnit;->MINUTES:Ljava/util/concurrent/TimeUnit;

    .line 15
    const-string v0, "timeUnit"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    sget-object p1, Lg01/c;->l:Lg01/c;

    .line 17
    const-string v0, "taskRunner"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    new-instance v0, Lh01/q;

    invoke-direct {v0, p1}, Lh01/q;-><init>(Lg01/c;)V

    .line 19
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 20
    iput-object v0, p0, Lbu/c;->e:Ljava/lang/Object;

    return-void

    .line 21
    :sswitch_5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 22
    new-instance p1, Lio/o;

    const/4 v0, 0x2

    invoke-direct {p1, v0}, Lio/o;-><init>(I)V

    iput-object p1, p0, Lbu/c;->e:Ljava/lang/Object;

    return-void

    .line 23
    :sswitch_6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void

    nop

    :sswitch_data_0
    .sparse-switch
        0x1 -> :sswitch_6
        0x3 -> :sswitch_5
        0xe -> :sswitch_4
        0xf -> :sswitch_3
        0x11 -> :sswitch_2
        0x15 -> :sswitch_1
        0x1c -> :sswitch_0
    .end sparse-switch
.end method

.method public constructor <init>(Ljava/io/Serializable;)V
    .locals 1

    const/16 v0, 0x12

    iput v0, p0, Lbu/c;->d:I

    .line 24
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    check-cast p1, Ljava/io/Serializable;

    iput-object p1, p0, Lbu/c;->e:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lbu/c;->d:I

    iput-object p1, p0, Lbu/c;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static k(Lb0/a1;)Lb0/p1;
    .locals 8

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p0, :cond_0

    .line 3
    .line 4
    return-object v0

    .line 5
    :cond_0
    sget-object v1, Lh0/j2;->b:Lh0/j2;

    .line 6
    .line 7
    new-instance v2, Lb0/p1;

    .line 8
    .line 9
    new-instance v3, Landroid/util/Size;

    .line 10
    .line 11
    invoke-interface {p0}, Lb0/a1;->o()I

    .line 12
    .line 13
    .line 14
    move-result v4

    .line 15
    invoke-interface {p0}, Lb0/a1;->m()I

    .line 16
    .line 17
    .line 18
    move-result v5

    .line 19
    invoke-direct {v3, v4, v5}, Landroid/util/Size;-><init>(II)V

    .line 20
    .line 21
    .line 22
    new-instance v4, Ll0/c;

    .line 23
    .line 24
    new-instance v5, Lh6/j;

    .line 25
    .line 26
    invoke-interface {p0}, Lb0/a1;->i0()Lb0/v0;

    .line 27
    .line 28
    .line 29
    move-result-object v6

    .line 30
    invoke-interface {v6}, Lb0/v0;->c()J

    .line 31
    .line 32
    .line 33
    move-result-wide v6

    .line 34
    invoke-direct {v5, v0, v1, v6, v7}, Lh6/j;-><init>(Lh0/s;Lh0/j2;J)V

    .line 35
    .line 36
    .line 37
    invoke-direct {v4, v5}, Ll0/c;-><init>(Lh0/s;)V

    .line 38
    .line 39
    .line 40
    invoke-direct {v2, p0, v3, v4}, Lb0/p1;-><init>(Lb0/a1;Landroid/util/Size;Lb0/v0;)V

    .line 41
    .line 42
    .line 43
    return-object v2
.end method


# virtual methods
.method public A(JFF)V
    .locals 4

    .line 1
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lgw0/c;

    .line 4
    .line 5
    invoke-virtual {p0}, Lgw0/c;->h()Le3/r;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const/16 v0, 0x20

    .line 10
    .line 11
    shr-long v0, p1, v0

    .line 12
    .line 13
    long-to-int v0, v0

    .line 14
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    const-wide v2, 0xffffffffL

    .line 19
    .line 20
    .line 21
    .line 22
    .line 23
    and-long/2addr p1, v2

    .line 24
    long-to-int p1, p1

    .line 25
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 26
    .line 27
    .line 28
    move-result p2

    .line 29
    invoke-interface {p0, v1, p2}, Le3/r;->h(FF)V

    .line 30
    .line 31
    .line 32
    invoke-interface {p0, p3, p4}, Le3/r;->a(FF)V

    .line 33
    .line 34
    .line 35
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 36
    .line 37
    .line 38
    move-result p2

    .line 39
    neg-float p2, p2

    .line 40
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 41
    .line 42
    .line 43
    move-result p1

    .line 44
    neg-float p1, p1

    .line 45
    invoke-interface {p0, p2, p1}, Le3/r;->h(FF)V

    .line 46
    .line 47
    .line 48
    return-void
.end method

.method public B(FF)V
    .locals 0

    .line 1
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lgw0/c;

    .line 4
    .line 5
    invoke-virtual {p0}, Lgw0/c;->h()Le3/r;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-interface {p0, p1, p2}, Le3/r;->h(FF)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public I(Lg1/e2;Ljava/lang/Float;Ljava/lang/Float;Lay0/k;Lh1/f;)Ljava/lang/Object;
    .locals 7

    .line 1
    invoke-virtual {p2}, Ljava/lang/Number;->floatValue()F

    .line 2
    .line 3
    .line 4
    move-result v2

    .line 5
    invoke-virtual {p3}, Ljava/lang/Number;->floatValue()F

    .line 6
    .line 7
    .line 8
    move-result p2

    .line 9
    const/4 p3, 0x0

    .line 10
    const/16 v0, 0x1c

    .line 11
    .line 12
    invoke-static {p3, p2, v0}, Lc1/d;->b(FFI)Lc1/k;

    .line 13
    .line 14
    .line 15
    move-result-object v3

    .line 16
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    .line 17
    .line 18
    .line 19
    move-result p3

    .line 20
    invoke-static {p2}, Ljava/lang/Math;->signum(F)F

    .line 21
    .line 22
    .line 23
    move-result p2

    .line 24
    mul-float v1, p2, p3

    .line 25
    .line 26
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 27
    .line 28
    move-object v4, p0

    .line 29
    check-cast v4, Lc1/j;

    .line 30
    .line 31
    move-object v0, p1

    .line 32
    move-object v5, p4

    .line 33
    move-object v6, p5

    .line 34
    invoke-static/range {v0 .. v6}, Lh1/k;->b(Lg1/e2;FFLc1/k;Lc1/j;Lay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 39
    .line 40
    if-ne p0, p1, :cond_0

    .line 41
    .line 42
    return-object p0

    .line 43
    :cond_0
    check-cast p0, Lh1/a;

    .line 44
    .line 45
    return-object p0
.end method

.method public Q()V
    .locals 0

    .line 1
    return-void
.end method

.method public bridge synthetic a()Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ler/g;

    .line 4
    .line 5
    invoke-virtual {p0}, Ler/g;->a()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    new-instance v0, Lcr/b;

    .line 10
    .line 11
    check-cast p0, Lcr/e;

    .line 12
    .line 13
    invoke-direct {v0, p0}, Lcr/b;-><init>(Lcr/e;)V

    .line 14
    .line 15
    .line 16
    return-object v0
.end method

.method public accept(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 7

    .line 1
    iget v0, p0, Lbu/c;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    packed-switch v0, :pswitch_data_0

    .line 5
    .line 6
    .line 7
    check-cast p2, Laq/k;

    .line 8
    .line 9
    check-cast p1, Lgp/f;

    .line 10
    .line 11
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Landroid/app/PendingIntent;

    .line 14
    .line 15
    const-string v0, "PendingIntent can not be null."

    .line 16
    .line 17
    invoke-static {p0, v0}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    new-instance v0, Lgp/l;

    .line 21
    .line 22
    const-string v2, ""

    .line 23
    .line 24
    invoke-direct {v0, v1, p0, v2}, Lgp/l;-><init>(Ljava/util/List;Landroid/app/PendingIntent;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p1, v0, p2}, Lgp/f;->C(Lgp/l;Laq/k;)V

    .line 28
    .line 29
    .line 30
    return-void

    .line 31
    :pswitch_0
    check-cast p1, Lcq/t1;

    .line 32
    .line 33
    check-cast p2, Laq/k;

    .line 34
    .line 35
    new-instance v0, La0/j;

    .line 36
    .line 37
    const/16 v2, 0xb

    .line 38
    .line 39
    invoke-direct {v0, p2, v2}, La0/j;-><init>(Ljava/lang/Object;I)V

    .line 40
    .line 41
    .line 42
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast p0, Leu0/b;

    .line 45
    .line 46
    iget-object p2, p1, Lcq/t1;->E:Lev/c;

    .line 47
    .line 48
    const-string v2, "service.removeListener: "

    .line 49
    .line 50
    const-string v3, "remove Listener unknown: "

    .line 51
    .line 52
    iget-object v4, p2, Lev/c;->a:Ljava/util/HashMap;

    .line 53
    .line 54
    monitor-enter v4

    .line 55
    :try_start_0
    iget-object v5, p2, Lev/c;->a:Ljava/util/HashMap;

    .line 56
    .line 57
    invoke-virtual {v5, p0}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v5

    .line 61
    check-cast v5, Lcq/u1;

    .line 62
    .line 63
    const/4 v6, 0x2

    .line 64
    if-nez v5, :cond_1

    .line 65
    .line 66
    const-string p1, "WearableClient"

    .line 67
    .line 68
    invoke-static {p1, v6}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 69
    .line 70
    .line 71
    move-result p1

    .line 72
    if-eqz p1, :cond_0

    .line 73
    .line 74
    const-string p1, "WearableClient"

    .line 75
    .line 76
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    invoke-virtual {v3, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    invoke-static {p1, p0}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 85
    .line 86
    .line 87
    goto :goto_0

    .line 88
    :catchall_0
    move-exception p0

    .line 89
    goto :goto_2

    .line 90
    :cond_0
    :goto_0
    new-instance p0, Lcom/google/android/gms/common/api/Status;

    .line 91
    .line 92
    const/16 p1, 0xfa2

    .line 93
    .line 94
    invoke-direct {p0, p1, v1, v1, v1}, Lcom/google/android/gms/common/api/Status;-><init>(ILjava/lang/String;Landroid/app/PendingIntent;Ljo/b;)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {v0, p0}, La0/j;->z(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    monitor-exit v4

    .line 101
    goto :goto_1

    .line 102
    :cond_1
    invoke-virtual {v5}, Lcq/u1;->T()V

    .line 103
    .line 104
    .line 105
    const-string v1, "WearableClient"

    .line 106
    .line 107
    invoke-static {v1, v6}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 108
    .line 109
    .line 110
    move-result v1

    .line 111
    if-eqz v1, :cond_2

    .line 112
    .line 113
    const-string v1, "WearableClient"

    .line 114
    .line 115
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object v3

    .line 119
    invoke-virtual {v2, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object v2

    .line 123
    invoke-static {v1, v2}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 124
    .line 125
    .line 126
    :cond_2
    invoke-virtual {p1}, Lno/e;->r()Landroid/os/IInterface;

    .line 127
    .line 128
    .line 129
    move-result-object p1

    .line 130
    check-cast p1, Lcq/w0;

    .line 131
    .line 132
    new-instance v1, Lcq/y0;

    .line 133
    .line 134
    iget-object p2, p2, Lev/c;->a:Ljava/util/HashMap;

    .line 135
    .line 136
    invoke-direct {v1, p2, p0, v0}, Lcq/y0;-><init>(Ljava/util/HashMap;Ljava/lang/Object;La0/j;)V

    .line 137
    .line 138
    .line 139
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    iget-object p2, p1, Lbp/a;->e:Ljava/lang/String;

    .line 144
    .line 145
    invoke-virtual {p0, p2}, Landroid/os/Parcel;->writeInterfaceToken(Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    sget p2, Lop/e;->a:I

    .line 149
    .line 150
    invoke-virtual {p0, v1}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 151
    .line 152
    .line 153
    const/4 p2, 0x1

    .line 154
    invoke-virtual {p0, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 155
    .line 156
    .line 157
    const/16 v0, 0x4f45

    .line 158
    .line 159
    invoke-static {p0, v0}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 160
    .line 161
    .line 162
    move-result v0

    .line 163
    const/4 v1, 0x4

    .line 164
    invoke-static {p0, p2, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 165
    .line 166
    .line 167
    invoke-virtual {p0, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 168
    .line 169
    .line 170
    invoke-interface {v5}, Landroid/os/IInterface;->asBinder()Landroid/os/IBinder;

    .line 171
    .line 172
    .line 173
    move-result-object p2

    .line 174
    invoke-static {p0, v6, p2}, Ljp/dc;->i(Landroid/os/Parcel;ILandroid/os/IBinder;)V

    .line 175
    .line 176
    .line 177
    invoke-static {p0, v0}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 178
    .line 179
    .line 180
    const/16 p2, 0x11

    .line 181
    .line 182
    invoke-virtual {p1, p0, p2}, Lbp/a;->R(Landroid/os/Parcel;I)V

    .line 183
    .line 184
    .line 185
    monitor-exit v4

    .line 186
    :goto_1
    return-void

    .line 187
    :goto_2
    monitor-exit v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 188
    throw p0

    .line 189
    :pswitch_data_0
    .packed-switch 0xc
        :pswitch_0
    .end packed-switch
.end method

.method public b()Lb0/a1;
    .locals 0

    .line 1
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lcom/google/android/gms/internal/measurement/i4;

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/i4;->b()Lb0/a1;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-static {p0}, Lbu/c;->k(Lb0/a1;)Lb0/p1;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public bridge synthetic c(Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/Void;

    .line 2
    .line 3
    return-void
.end method

.method public close()V
    .locals 0

    .line 1
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lcom/google/android/gms/internal/measurement/i4;

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/i4;->close()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public d()I
    .locals 0

    .line 1
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lcom/google/android/gms/internal/measurement/i4;

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/i4;->d()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public e()V
    .locals 0

    .line 1
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lcom/google/android/gms/internal/measurement/i4;

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/i4;->e()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public f()I
    .locals 0

    .line 1
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lcom/google/android/gms/internal/measurement/i4;

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/i4;->f()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public g(Lh0/b1;Ljava/util/concurrent/Executor;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcom/google/android/gms/internal/measurement/i4;

    .line 4
    .line 5
    new-instance v1, La0/h;

    .line 6
    .line 7
    const/16 v2, 0xf

    .line 8
    .line 9
    invoke-direct {v1, v2, p0, p1}, La0/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, v1, p2}, Lcom/google/android/gms/internal/measurement/i4;->g(Lh0/b1;Ljava/util/concurrent/Executor;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public get(I)Lc1/b0;
    .locals 0

    .line 1
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lc1/d0;

    .line 4
    .line 5
    return-object p0
.end method

.method public getSurface()Landroid/view/Surface;
    .locals 0

    .line 1
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lcom/google/android/gms/internal/measurement/i4;

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/i4;->getSurface()Landroid/view/Surface;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public h()Lb0/a1;
    .locals 0

    .line 1
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lcom/google/android/gms/internal/measurement/i4;

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/i4;->h()Lb0/a1;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-static {p0}, Lbu/c;->k(Lb0/a1;)Lb0/p1;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public i(ILe6/d;Ljava/lang/String;Landroid/os/Bundle;)V
    .locals 0

    .line 1
    return-void
.end method

.method public j(I)Le6/d;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public l(Ljava/lang/Object;)Ljava/lang/String;
    .locals 6

    .line 1
    new-instance v1, Ljava/io/StringWriter;

    .line 2
    .line 3
    invoke-direct {v1}, Ljava/io/StringWriter;-><init>()V

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance v0, Lbt/e;

    .line 7
    .line 8
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Lbt/d;

    .line 11
    .line 12
    iget-object v2, p0, Lbt/d;->d:Ljava/util/HashMap;

    .line 13
    .line 14
    iget-object v3, p0, Lbt/d;->e:Ljava/util/HashMap;

    .line 15
    .line 16
    iget-object v4, p0, Lbt/d;->f:Lbt/a;

    .line 17
    .line 18
    iget-boolean v5, p0, Lbt/d;->g:Z

    .line 19
    .line 20
    invoke-direct/range {v0 .. v5}, Lbt/e;-><init>(Ljava/io/Writer;Ljava/util/Map;Ljava/util/Map;Lzs/d;Z)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0, p1}, Lbt/e;->h(Ljava/lang/Object;)Lbt/e;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0}, Lbt/e;->j()V

    .line 27
    .line 28
    .line 29
    iget-object p0, v0, Lbt/e;->b:Landroid/util/JsonWriter;

    .line 30
    .line 31
    invoke-virtual {p0}, Landroid/util/JsonWriter;->flush()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 32
    .line 33
    .line 34
    :catch_0
    invoke-virtual {v1}, Ljava/io/StringWriter;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0
.end method

.method public m()I
    .locals 0

    .line 1
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lcom/google/android/gms/internal/measurement/i4;

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/i4;->m()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public n()Ljava/nio/ByteBuffer;
    .locals 0

    .line 1
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/media/Image$Plane;

    .line 4
    .line 5
    invoke-virtual {p0}, Landroid/media/Image$Plane;->getBuffer()Ljava/nio/ByteBuffer;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public o()I
    .locals 0

    .line 1
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lcom/google/android/gms/internal/measurement/i4;

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/i4;->o()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public p()I
    .locals 0

    .line 1
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/media/Image$Plane;

    .line 4
    .line 5
    invoke-virtual {p0}, Landroid/media/Image$Plane;->getRowStride()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public q(Ljava/lang/Object;)V
    .locals 6

    .line 1
    check-cast p1, Lhg0/b;

    .line 2
    .line 3
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Lcom/google/android/gms/location/LocationResult;

    .line 6
    .line 7
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    const-string v0, "locationResult"

    .line 11
    .line 12
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    iget-object p0, p0, Lcom/google/android/gms/location/LocationResult;->d:Ljava/util/List;

    .line 16
    .line 17
    const-string v0, "getLocations(...)"

    .line 18
    .line 19
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    check-cast p0, Ljava/lang/Iterable;

    .line 23
    .line 24
    iget-object p1, p1, Lhg0/b;->a:Lhg0/g;

    .line 25
    .line 26
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_0

    .line 35
    .line 36
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    check-cast v0, Landroid/location/Location;

    .line 41
    .line 42
    new-instance v1, Lgg0/a;

    .line 43
    .line 44
    invoke-virtual {v0}, Landroid/location/Location;->getLatitude()D

    .line 45
    .line 46
    .line 47
    move-result-wide v2

    .line 48
    invoke-virtual {v0}, Landroid/location/Location;->getLongitude()D

    .line 49
    .line 50
    .line 51
    move-result-wide v4

    .line 52
    invoke-direct {v1, v2, v3, v4, v5}, Lgg0/a;-><init>(DD)V

    .line 53
    .line 54
    .line 55
    iget-object v0, p1, Lhg0/g;->a:Ldg0/a;

    .line 56
    .line 57
    iget-object v0, v0, Ldg0/a;->a:Lyy0/c2;

    .line 58
    .line 59
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 60
    .line 61
    .line 62
    const/4 v2, 0x0

    .line 63
    invoke-virtual {v0, v2, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_0
    return-void
.end method

.method public r()I
    .locals 0

    .line 1
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/media/Image$Plane;

    .line 4
    .line 5
    invoke-virtual {p0}, Landroid/media/Image$Plane;->getPixelStride()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public s()V
    .locals 3

    .line 1
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lh01/q;

    .line 4
    .line 5
    iget-object v0, p0, Lh01/q;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Ljava/util/concurrent/ConcurrentLinkedQueue;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentLinkedQueue;->iterator()Ljava/util/Iterator;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    const-string v1, "iterator(...)"

    .line 14
    .line 15
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_2

    .line 23
    .line 24
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    check-cast v1, Lh01/p;

    .line 29
    .line 30
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    monitor-enter v1

    .line 34
    :try_start_0
    iget-object v2, v1, Lh01/p;->p:Ljava/util/ArrayList;

    .line 35
    .line 36
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    if-eqz v2, :cond_1

    .line 41
    .line 42
    invoke-interface {v0}, Ljava/util/Iterator;->remove()V

    .line 43
    .line 44
    .line 45
    const/4 v2, 0x1

    .line 46
    iput-boolean v2, v1, Lh01/p;->j:Z

    .line 47
    .line 48
    iget-object v2, v1, Lh01/p;->e:Ljava/net/Socket;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :catchall_0
    move-exception p0

    .line 52
    goto :goto_2

    .line 53
    :cond_1
    const/4 v2, 0x0

    .line 54
    :goto_1
    monitor-exit v1

    .line 55
    if-eqz v2, :cond_0

    .line 56
    .line 57
    invoke-static {v2}, Le01/g;->c(Ljava/net/Socket;)V

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :goto_2
    monitor-exit v1

    .line 62
    throw p0

    .line 63
    :cond_2
    iget-object v0, p0, Lh01/q;->h:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast v0, Ljava/util/concurrent/ConcurrentLinkedQueue;

    .line 66
    .line 67
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentLinkedQueue;->isEmpty()Z

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    if-eqz v0, :cond_3

    .line 72
    .line 73
    iget-object p0, p0, Lh01/q;->f:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast p0, Lg01/b;

    .line 76
    .line 77
    invoke-virtual {p0}, Lg01/b;->a()V

    .line 78
    .line 79
    .line 80
    :cond_3
    return-void
.end method

.method public t(I)Le6/d;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public u()J
    .locals 6

    .line 1
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/widget/Magnifier;

    .line 4
    .line 5
    invoke-virtual {p0}, Landroid/widget/Magnifier;->getWidth()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    invoke-virtual {p0}, Landroid/widget/Magnifier;->getHeight()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    int-to-long v0, v0

    .line 14
    const/16 v2, 0x20

    .line 15
    .line 16
    shl-long/2addr v0, v2

    .line 17
    int-to-long v2, p0

    .line 18
    const-wide v4, 0xffffffffL

    .line 19
    .line 20
    .line 21
    .line 22
    .line 23
    and-long/2addr v2, v4

    .line 24
    or-long/2addr v0, v2

    .line 25
    return-wide v0
.end method

.method public v(FFFF)V
    .locals 8

    .line 1
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lgw0/c;

    .line 4
    .line 5
    invoke-virtual {p0}, Lgw0/c;->h()Le3/r;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {p0}, Lgw0/c;->o()J

    .line 10
    .line 11
    .line 12
    move-result-wide v1

    .line 13
    const/16 v3, 0x20

    .line 14
    .line 15
    shr-long/2addr v1, v3

    .line 16
    long-to-int v1, v1

    .line 17
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    add-float/2addr p3, p1

    .line 22
    sub-float/2addr v1, p3

    .line 23
    invoke-virtual {p0}, Lgw0/c;->o()J

    .line 24
    .line 25
    .line 26
    move-result-wide v4

    .line 27
    const-wide v6, 0xffffffffL

    .line 28
    .line 29
    .line 30
    .line 31
    .line 32
    and-long/2addr v4, v6

    .line 33
    long-to-int p3, v4

    .line 34
    invoke-static {p3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 35
    .line 36
    .line 37
    move-result p3

    .line 38
    add-float/2addr p4, p2

    .line 39
    sub-float/2addr p3, p4

    .line 40
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 41
    .line 42
    .line 43
    move-result p4

    .line 44
    int-to-long v1, p4

    .line 45
    invoke-static {p3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 46
    .line 47
    .line 48
    move-result p3

    .line 49
    int-to-long p3, p3

    .line 50
    shl-long/2addr v1, v3

    .line 51
    and-long/2addr p3, v6

    .line 52
    or-long/2addr p3, v1

    .line 53
    shr-long v1, p3, v3

    .line 54
    .line 55
    long-to-int v1, v1

    .line 56
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    const/4 v2, 0x0

    .line 61
    cmpl-float v1, v1, v2

    .line 62
    .line 63
    if-ltz v1, :cond_0

    .line 64
    .line 65
    and-long v3, p3, v6

    .line 66
    .line 67
    long-to-int v1, v3

    .line 68
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    cmpl-float v1, v1, v2

    .line 73
    .line 74
    if-ltz v1, :cond_0

    .line 75
    .line 76
    const/4 v1, 0x1

    .line 77
    goto :goto_0

    .line 78
    :cond_0
    const/4 v1, 0x0

    .line 79
    :goto_0
    if-nez v1, :cond_1

    .line 80
    .line 81
    const-string v1, "Width and height must be greater than or equal to zero"

    .line 82
    .line 83
    invoke-static {v1}, Le3/a0;->a(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    :cond_1
    invoke-virtual {p0, p3, p4}, Lgw0/c;->B(J)V

    .line 87
    .line 88
    .line 89
    invoke-interface {v0, p1, p2}, Le3/r;->h(FF)V

    .line 90
    .line 91
    .line 92
    return-void
.end method

.method public w(IILandroid/os/Bundle;)Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public x(Landroid/app/Activity;)V
    .locals 4

    .line 1
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lio/o;

    .line 4
    .line 5
    iget-object v0, p0, Lio/o;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    :cond_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    if-eqz v2, :cond_1

    .line 18
    .line 19
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    check-cast v2, Ljava/lang/ref/WeakReference;

    .line 24
    .line 25
    invoke-virtual {v2}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    if-ne v3, p1, :cond_0

    .line 30
    .line 31
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    :cond_1
    invoke-virtual {p1}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    iget-object p0, p0, Lio/o;->g:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast p0, Landroidx/core/app/f;

    .line 41
    .line 42
    invoke-virtual {p1, p0}, Landroid/view/Window;->removeOnFrameMetricsAvailableListener(Landroid/view/Window$OnFrameMetricsAvailableListener;)V

    .line 43
    .line 44
    .line 45
    return-void
.end method

.method public y(Ljava/lang/Throwable;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lb0/a1;

    .line 4
    .line 5
    invoke-interface {p0}, Ljava/lang/AutoCloseable;->close()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public z(JF)V
    .locals 4

    .line 1
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lgw0/c;

    .line 4
    .line 5
    invoke-virtual {p0}, Lgw0/c;->h()Le3/r;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const/16 v0, 0x20

    .line 10
    .line 11
    shr-long v0, p1, v0

    .line 12
    .line 13
    long-to-int v0, v0

    .line 14
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    const-wide v2, 0xffffffffL

    .line 19
    .line 20
    .line 21
    .line 22
    .line 23
    and-long/2addr p1, v2

    .line 24
    long-to-int p1, p1

    .line 25
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 26
    .line 27
    .line 28
    move-result p2

    .line 29
    invoke-interface {p0, v1, p2}, Le3/r;->h(FF)V

    .line 30
    .line 31
    .line 32
    invoke-interface {p0, p3}, Le3/r;->m(F)V

    .line 33
    .line 34
    .line 35
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 36
    .line 37
    .line 38
    move-result p2

    .line 39
    neg-float p2, p2

    .line 40
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 41
    .line 42
    .line 43
    move-result p1

    .line 44
    neg-float p1, p1

    .line 45
    invoke-interface {p0, p2, p1}, Le3/r;->h(FF)V

    .line 46
    .line 47
    .line 48
    return-void
.end method
