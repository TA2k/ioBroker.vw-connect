.class public final La8/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements La8/v0;
.implements Lpv/c;


# instance fields
.field public d:Z

.field public e:Z

.field public final f:Ljava/lang/Object;

.field public final g:Ljava/lang/Object;

.field public h:Ljava/lang/Object;

.field public i:Ljava/lang/Object;


# direct methods
.method public constructor <init>(La8/q0;Lw7/r;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, La8/l;->g:Ljava/lang/Object;

    .line 4
    new-instance p1, La8/s1;

    invoke-direct {p1, p2}, La8/s1;-><init>(Lw7/r;)V

    iput-object p1, p0, La8/l;->f:Ljava/lang/Object;

    const/4 p1, 0x1

    .line 5
    iput-boolean p1, p0, La8/l;->d:Z

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lm8/y;)V
    .locals 0

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    iput-object p1, p0, La8/l;->f:Ljava/lang/Object;

    .line 8
    iput-object p2, p0, La8/l;->g:Ljava/lang/Object;

    .line 9
    sget-object p1, Lw7/r;->a:Lw7/r;

    iput-object p1, p0, La8/l;->i:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lqv/a;Llp/lg;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La8/l;->f:Ljava/lang/Object;

    iput-object p2, p0, La8/l;->g:Ljava/lang/Object;

    iput-object p3, p0, La8/l;->h:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public a(Lmv/a;)Lov/d;
    .locals 10

    .line 1
    iget-object v0, p0, La8/l;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lov/f;

    .line 4
    .line 5
    iget-object v1, p0, La8/l;->i:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Llp/pg;

    .line 8
    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, La8/l;->l()V

    .line 12
    .line 13
    .line 14
    :cond_0
    iget-object v1, p0, La8/l;->i:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v1, Llp/pg;

    .line 17
    .line 18
    invoke-static {v1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    iget-boolean v2, p0, La8/l;->d:Z

    .line 22
    .line 23
    const/4 v3, 0x1

    .line 24
    if-nez v2, :cond_1

    .line 25
    .line 26
    :try_start_0
    invoke-virtual {v1}, Lbp/a;->S()Landroid/os/Parcel;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    invoke-virtual {v1, v2, v3}, Lbp/a;->U(Landroid/os/Parcel;I)V

    .line 31
    .line 32
    .line 33
    iput-boolean v3, p0, La8/l;->d:Z
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :catch_0
    move-exception p0

    .line 37
    check-cast v0, Lqv/a;

    .line 38
    .line 39
    invoke-virtual {v0}, Lqv/a;->b()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    new-instance v0, Lbv/a;

    .line 44
    .line 45
    const-string v1, "Failed to init text recognizer "

    .line 46
    .line 47
    invoke-virtual {v1, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    invoke-direct {v0, p1, p0}, Lbv/a;-><init>(Ljava/lang/String;Ljava/lang/Exception;)V

    .line 52
    .line 53
    .line 54
    throw v0

    .line 55
    :cond_1
    :goto_0
    iget p0, p1, Lmv/a;->f:I

    .line 56
    .line 57
    iget v2, p1, Lmv/a;->c:I

    .line 58
    .line 59
    iget v4, p1, Lmv/a;->d:I

    .line 60
    .line 61
    iget v5, p1, Lmv/a;->e:I

    .line 62
    .line 63
    invoke-static {v5}, Ljp/xa;->a(I)I

    .line 64
    .line 65
    .line 66
    move-result v5

    .line 67
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 68
    .line 69
    .line 70
    move-result-wide v6

    .line 71
    invoke-static {p1}, Lnv/d;->a(Lmv/a;)Lyo/b;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    :try_start_1
    invoke-virtual {v1}, Lbp/a;->S()Landroid/os/Parcel;

    .line 76
    .line 77
    .line 78
    move-result-object v8

    .line 79
    sget v9, Llp/s;->a:I

    .line 80
    .line 81
    invoke-virtual {v8, p1}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 82
    .line 83
    .line 84
    invoke-virtual {v8, v3}, Landroid/os/Parcel;->writeInt(I)V

    .line 85
    .line 86
    .line 87
    const/16 p1, 0x4f45

    .line 88
    .line 89
    invoke-static {v8, p1}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 90
    .line 91
    .line 92
    move-result p1

    .line 93
    const/4 v9, 0x4

    .line 94
    invoke-static {v8, v3, v9}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {v8, p0}, Landroid/os/Parcel;->writeInt(I)V

    .line 98
    .line 99
    .line 100
    const/4 p0, 0x2

    .line 101
    invoke-static {v8, p0, v9}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {v8, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 105
    .line 106
    .line 107
    const/4 p0, 0x3

    .line 108
    invoke-static {v8, p0, v9}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {v8, v4}, Landroid/os/Parcel;->writeInt(I)V

    .line 112
    .line 113
    .line 114
    invoke-static {v8, v9, v9}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v8, v5}, Landroid/os/Parcel;->writeInt(I)V

    .line 118
    .line 119
    .line 120
    const/4 v2, 0x5

    .line 121
    const/16 v3, 0x8

    .line 122
    .line 123
    invoke-static {v8, v2, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {v8, v6, v7}, Landroid/os/Parcel;->writeLong(J)V

    .line 127
    .line 128
    .line 129
    invoke-static {v8, p1}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v1, v8, p0}, Lbp/a;->T(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    sget-object p1, Llp/wg;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 137
    .line 138
    invoke-virtual {p0}, Landroid/os/Parcel;->readInt()I

    .line 139
    .line 140
    .line 141
    move-result v1

    .line 142
    if-nez v1, :cond_2

    .line 143
    .line 144
    const/4 p1, 0x0

    .line 145
    goto :goto_1

    .line 146
    :cond_2
    invoke-interface {p1, p0}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object p1

    .line 150
    check-cast p1, Landroid/os/Parcelable;

    .line 151
    .line 152
    :goto_1
    check-cast p1, Llp/wg;

    .line 153
    .line 154
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V

    .line 155
    .line 156
    .line 157
    new-instance p0, Lov/d;

    .line 158
    .line 159
    invoke-direct {p0, p1}, Lov/d;-><init>(Llp/wg;)V
    :try_end_1
    .catch Landroid/os/RemoteException; {:try_start_1 .. :try_end_1} :catch_1

    .line 160
    .line 161
    .line 162
    return-object p0

    .line 163
    :catch_1
    move-exception p0

    .line 164
    check-cast v0, Lqv/a;

    .line 165
    .line 166
    invoke-virtual {v0}, Lqv/a;->b()Ljava/lang/String;

    .line 167
    .line 168
    .line 169
    move-result-object p1

    .line 170
    new-instance v0, Lbv/a;

    .line 171
    .line 172
    const-string v1, "Failed to run text recognizer "

    .line 173
    .line 174
    invoke-virtual {v1, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 175
    .line 176
    .line 177
    move-result-object p1

    .line 178
    invoke-direct {v0, p1, p0}, Lbv/a;-><init>(Ljava/lang/String;Ljava/lang/Exception;)V

    .line 179
    .line 180
    .line 181
    throw v0
.end method

.method public b()Z
    .locals 1

    .line 1
    iget-boolean v0, p0, La8/l;->d:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, La8/l;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, La8/s1;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    const/4 p0, 0x0

    .line 13
    return p0

    .line 14
    :cond_0
    iget-object p0, p0, La8/l;->i:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, La8/v0;

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    invoke-interface {p0}, La8/v0;->b()Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    return p0
.end method

.method public c()Lt7/g0;
    .locals 1

    .line 1
    iget-object v0, p0, La8/l;->i:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, La8/v0;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-interface {v0}, La8/v0;->c()Lt7/g0;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    iget-object p0, p0, La8/l;->f:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, La8/s1;

    .line 15
    .line 16
    iget-object p0, p0, La8/s1;->h:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Lt7/g0;

    .line 19
    .line 20
    return-object p0
.end method

.method public d(Lt7/g0;)V
    .locals 1

    .line 1
    iget-object v0, p0, La8/l;->i:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, La8/v0;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-interface {v0, p1}, La8/v0;->d(Lt7/g0;)V

    .line 8
    .line 9
    .line 10
    iget-object p1, p0, La8/l;->i:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p1, La8/v0;

    .line 13
    .line 14
    invoke-interface {p1}, La8/v0;->c()Lt7/g0;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    :cond_0
    iget-object p0, p0, La8/l;->f:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, La8/s1;

    .line 21
    .line 22
    invoke-virtual {p0, p1}, La8/s1;->d(Lt7/g0;)V

    .line 23
    .line 24
    .line 25
    return-void
.end method

.method public e()J
    .locals 2

    .line 1
    iget-boolean v0, p0, La8/l;->d:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, La8/l;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, La8/s1;

    .line 8
    .line 9
    invoke-virtual {p0}, La8/s1;->e()J

    .line 10
    .line 11
    .line 12
    move-result-wide v0

    .line 13
    return-wide v0

    .line 14
    :cond_0
    iget-object p0, p0, La8/l;->i:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, La8/v0;

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    invoke-interface {p0}, La8/v0;->e()J

    .line 22
    .line 23
    .line 24
    move-result-wide v0

    .line 25
    return-wide v0
.end method

.method public f(La8/f;)V
    .locals 2

    .line 1
    invoke-virtual {p1}, La8/f;->j()La8/v0;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    iget-object v1, p0, La8/l;->i:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v1, La8/v0;

    .line 10
    .line 11
    if-eq v0, v1, :cond_1

    .line 12
    .line 13
    if-nez v1, :cond_0

    .line 14
    .line 15
    iput-object v0, p0, La8/l;->i:Ljava/lang/Object;

    .line 16
    .line 17
    iput-object p1, p0, La8/l;->h:Ljava/lang/Object;

    .line 18
    .line 19
    iget-object p0, p0, La8/l;->f:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast p0, La8/s1;

    .line 22
    .line 23
    iget-object p0, p0, La8/s1;->h:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast p0, Lt7/g0;

    .line 26
    .line 27
    check-cast v0, Lc8/a0;

    .line 28
    .line 29
    invoke-virtual {v0, p0}, Lc8/a0;->d(Lt7/g0;)V

    .line 30
    .line 31
    .line 32
    return-void

    .line 33
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 34
    .line 35
    const-string p1, "Multiple renderer media clocks enabled."

    .line 36
    .line 37
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    new-instance p1, La8/o;

    .line 41
    .line 42
    const/4 v0, 0x2

    .line 43
    const/16 v1, 0x3e8

    .line 44
    .line 45
    invoke-direct {p1, v0, p0, v1}, La8/o;-><init>(ILjava/lang/Exception;I)V

    .line 46
    .line 47
    .line 48
    throw p1

    .line 49
    :cond_1
    return-void
.end method

.method public j()V
    .locals 3

    .line 1
    iget-object v0, p0, La8/l;->i:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Llp/pg;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    :try_start_0
    invoke-virtual {v0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    const/4 v2, 0x2

    .line 12
    invoke-virtual {v0, v1, v2}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 13
    .line 14
    .line 15
    goto :goto_0

    .line 16
    :catch_0
    move-exception v0

    .line 17
    iget-object v1, p0, La8/l;->g:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v1, Lov/f;

    .line 20
    .line 21
    check-cast v1, Lqv/a;

    .line 22
    .line 23
    invoke-virtual {v1}, Lqv/a;->b()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    const-string v2, "Failed to release text recognizer "

    .line 28
    .line 29
    invoke-virtual {v2, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    const-string v2, "DecoupledTextDelegate"

    .line 34
    .line 35
    invoke-static {v2, v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 36
    .line 37
    .line 38
    :goto_0
    const/4 v0, 0x0

    .line 39
    iput-object v0, p0, La8/l;->i:Ljava/lang/Object;

    .line 40
    .line 41
    :cond_0
    const/4 v0, 0x0

    .line 42
    iput-boolean v0, p0, La8/l;->d:Z

    .line 43
    .line 44
    return-void
.end method

.method public l()V
    .locals 15

    .line 1
    iget-object v0, p0, La8/l;->h:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Llp/lg;

    .line 5
    .line 6
    iget-object v0, p0, La8/l;->f:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v2, v0

    .line 9
    check-cast v2, Landroid/content/Context;

    .line 10
    .line 11
    iget-object v0, p0, La8/l;->g:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v3, v0

    .line 14
    check-cast v3, Lov/f;

    .line 15
    .line 16
    iget-object v0, p0, La8/l;->i:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v0, Llp/pg;

    .line 19
    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    return-void

    .line 23
    :cond_0
    const/4 v4, 0x1

    .line 24
    :try_start_0
    move-object v0, v3

    .line 25
    check-cast v0, Lqv/a;

    .line 26
    .line 27
    invoke-virtual {v0}, Lqv/a;->a()Z

    .line 28
    .line 29
    .line 30
    move-result v0
    :try_end_0
    .catch Lzo/a; {:try_start_0 .. :try_end_0} :catch_1
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 31
    const/4 v5, 0x7

    .line 32
    const/4 v6, 0x0

    .line 33
    const-string v7, "com.google.mlkit.vision.text.aidls.ITextRecognizerCreator"

    .line 34
    .line 35
    const-string v8, "com.google.mlkit.dynamite.text.latin"

    .line 36
    .line 37
    const-string v9, "com.google.android.gms.vision.ocr"

    .line 38
    .line 39
    const-string v10, "DecoupledTextDelegate"

    .line 40
    .line 41
    if-eqz v0, :cond_4

    .line 42
    .line 43
    :try_start_1
    const-string v0, "Start loading thick OCR module."

    .line 44
    .line 45
    invoke-static {v10, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 46
    .line 47
    .line 48
    sget-object v0, Lzo/d;->c:Lst/b;

    .line 49
    .line 50
    move-object v10, v3

    .line 51
    check-cast v10, Lqv/a;

    .line 52
    .line 53
    invoke-virtual {v10}, Lqv/a;->a()Z

    .line 54
    .line 55
    .line 56
    move-result v10

    .line 57
    if-eq v4, v10, :cond_1

    .line 58
    .line 59
    move-object v8, v9

    .line 60
    :cond_1
    invoke-static {v2, v0, v8}, Lzo/d;->c(Landroid/content/Context;Lzo/c;Ljava/lang/String;)Lzo/d;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    const-string v8, "com.google.mlkit.vision.text.bundled.common.BundledTextRecognizerCreator"

    .line 65
    .line 66
    invoke-virtual {v0, v8}, Lzo/d;->b(Ljava/lang/String;)Landroid/os/IBinder;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    sget v8, Llp/rg;->d:I

    .line 71
    .line 72
    if-nez v0, :cond_2

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_2
    invoke-interface {v0, v7}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 76
    .line 77
    .line 78
    move-result-object v6

    .line 79
    instance-of v8, v6, Llp/sg;

    .line 80
    .line 81
    if-eqz v8, :cond_3

    .line 82
    .line 83
    check-cast v6, Llp/sg;

    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_3
    new-instance v6, Llp/qg;

    .line 87
    .line 88
    invoke-direct {v6, v0, v7, v5}, Lbp/a;-><init>(Landroid/os/IBinder;Ljava/lang/String;I)V

    .line 89
    .line 90
    .line 91
    :goto_0
    new-instance v0, Lyo/b;

    .line 92
    .line 93
    invoke-direct {v0, v2}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    new-instance v7, Llp/xg;

    .line 97
    .line 98
    move-object v5, v3

    .line 99
    check-cast v5, Lqv/a;

    .line 100
    .line 101
    iget-object v9, v5, Lqv/a;->b:Ljava/lang/String;

    .line 102
    .line 103
    const-string v10, "optional-module-text-latin"

    .line 104
    .line 105
    const-string v12, "en"

    .line 106
    .line 107
    const/4 v11, 0x0

    .line 108
    const/4 v14, 0x0

    .line 109
    const/4 v13, 0x1

    .line 110
    const/4 v8, 0x1

    .line 111
    invoke-direct/range {v7 .. v14}, Llp/xg;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)V

    .line 112
    .line 113
    .line 114
    check-cast v6, Llp/qg;

    .line 115
    .line 116
    invoke-virtual {v6, v0, v7}, Llp/qg;->X(Lyo/b;Llp/xg;)Llp/pg;

    .line 117
    .line 118
    .line 119
    move-result-object v0

    .line 120
    goto :goto_2

    .line 121
    :catch_0
    move-exception v0

    .line 122
    move-object p0, v0

    .line 123
    goto :goto_3

    .line 124
    :catch_1
    move-exception v0

    .line 125
    goto/16 :goto_4

    .line 126
    .line 127
    :cond_4
    const-string v0, "Start loading thin OCR module."

    .line 128
    .line 129
    invoke-static {v10, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 130
    .line 131
    .line 132
    sget-object v0, Lzo/d;->b:Lrb0/a;

    .line 133
    .line 134
    move-object v10, v3

    .line 135
    check-cast v10, Lqv/a;

    .line 136
    .line 137
    invoke-virtual {v10}, Lqv/a;->a()Z

    .line 138
    .line 139
    .line 140
    move-result v10

    .line 141
    if-eq v4, v10, :cond_5

    .line 142
    .line 143
    move-object v8, v9

    .line 144
    :cond_5
    invoke-static {v2, v0, v8}, Lzo/d;->c(Landroid/content/Context;Lzo/c;Ljava/lang/String;)Lzo/d;

    .line 145
    .line 146
    .line 147
    move-result-object v0

    .line 148
    const-string v8, "com.google.android.gms.vision.text.mlkit.TextRecognizerCreator"

    .line 149
    .line 150
    invoke-virtual {v0, v8}, Lzo/d;->b(Ljava/lang/String;)Landroid/os/IBinder;

    .line 151
    .line 152
    .line 153
    move-result-object v0

    .line 154
    sget v8, Llp/rg;->d:I

    .line 155
    .line 156
    if-nez v0, :cond_6

    .line 157
    .line 158
    goto :goto_1

    .line 159
    :cond_6
    invoke-interface {v0, v7}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 160
    .line 161
    .line 162
    move-result-object v6

    .line 163
    instance-of v8, v6, Llp/sg;

    .line 164
    .line 165
    if-eqz v8, :cond_7

    .line 166
    .line 167
    check-cast v6, Llp/sg;

    .line 168
    .line 169
    goto :goto_1

    .line 170
    :cond_7
    new-instance v6, Llp/qg;

    .line 171
    .line 172
    invoke-direct {v6, v0, v7, v5}, Lbp/a;-><init>(Landroid/os/IBinder;Ljava/lang/String;I)V

    .line 173
    .line 174
    .line 175
    :goto_1
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 176
    .line 177
    .line 178
    new-instance v0, Lyo/b;

    .line 179
    .line 180
    invoke-direct {v0, v2}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 181
    .line 182
    .line 183
    check-cast v6, Llp/qg;

    .line 184
    .line 185
    invoke-virtual {v6, v0}, Llp/qg;->W(Lyo/b;)Llp/pg;

    .line 186
    .line 187
    .line 188
    move-result-object v0

    .line 189
    :goto_2
    iput-object v0, p0, La8/l;->i:Ljava/lang/Object;

    .line 190
    .line 191
    move-object v0, v3

    .line 192
    check-cast v0, Lqv/a;

    .line 193
    .line 194
    invoke-virtual {v0}, Lqv/a;->a()Z

    .line 195
    .line 196
    .line 197
    move-result v0

    .line 198
    sget-object v5, Llp/tb;->e:Llp/tb;

    .line 199
    .line 200
    new-instance v6, Lb6/f;

    .line 201
    .line 202
    invoke-direct {v6, v5, v0}, Lb6/f;-><init>(Ljava/lang/Object;Z)V

    .line 203
    .line 204
    .line 205
    sget-object v0, Llp/ub;->m:Llp/ub;

    .line 206
    .line 207
    invoke-virtual {v1, v6, v0}, Llp/lg;->b(Llp/kg;Llp/ub;)V
    :try_end_1
    .catch Lzo/a; {:try_start_1 .. :try_end_1} :catch_1
    .catch Landroid/os/RemoteException; {:try_start_1 .. :try_end_1} :catch_0

    .line 208
    .line 209
    .line 210
    return-void

    .line 211
    :goto_3
    check-cast v3, Lqv/a;

    .line 212
    .line 213
    invoke-virtual {v3}, Lqv/a;->a()Z

    .line 214
    .line 215
    .line 216
    move-result v0

    .line 217
    new-instance v2, Lb6/f;

    .line 218
    .line 219
    sget-object v4, Llp/tb;->h:Llp/tb;

    .line 220
    .line 221
    invoke-direct {v2, v4, v0}, Lb6/f;-><init>(Ljava/lang/Object;Z)V

    .line 222
    .line 223
    .line 224
    sget-object v0, Llp/ub;->m:Llp/ub;

    .line 225
    .line 226
    invoke-virtual {v1, v2, v0}, Llp/lg;->b(Llp/kg;Llp/ub;)V

    .line 227
    .line 228
    .line 229
    invoke-virtual {v3}, Lqv/a;->b()Ljava/lang/String;

    .line 230
    .line 231
    .line 232
    move-result-object v0

    .line 233
    new-instance v1, Lbv/a;

    .line 234
    .line 235
    const-string v2, "Failed to create text recognizer "

    .line 236
    .line 237
    invoke-virtual {v2, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 238
    .line 239
    .line 240
    move-result-object v0

    .line 241
    invoke-direct {v1, v0, p0}, Lbv/a;-><init>(Ljava/lang/String;Ljava/lang/Exception;)V

    .line 242
    .line 243
    .line 244
    throw v1

    .line 245
    :goto_4
    check-cast v3, Lqv/a;

    .line 246
    .line 247
    invoke-virtual {v3}, Lqv/a;->a()Z

    .line 248
    .line 249
    .line 250
    move-result v5

    .line 251
    new-instance v6, Lb6/f;

    .line 252
    .line 253
    sget-object v7, Llp/tb;->g:Llp/tb;

    .line 254
    .line 255
    invoke-direct {v6, v7, v5}, Lb6/f;-><init>(Ljava/lang/Object;Z)V

    .line 256
    .line 257
    .line 258
    sget-object v5, Llp/ub;->m:Llp/ub;

    .line 259
    .line 260
    invoke-virtual {v1, v6, v5}, Llp/lg;->b(Llp/kg;Llp/ub;)V

    .line 261
    .line 262
    .line 263
    invoke-virtual {v3}, Lqv/a;->a()Z

    .line 264
    .line 265
    .line 266
    move-result v1

    .line 267
    if-nez v1, :cond_a

    .line 268
    .line 269
    iget-boolean v0, p0, La8/l;->e:Z

    .line 270
    .line 271
    if-nez v0, :cond_9

    .line 272
    .line 273
    invoke-virtual {v3}, Lqv/a;->a()Z

    .line 274
    .line 275
    .line 276
    move-result v0

    .line 277
    if-eqz v0, :cond_8

    .line 278
    .line 279
    sget-object v0, Lfv/h;->a:[Ljo/d;

    .line 280
    .line 281
    goto :goto_5

    .line 282
    :cond_8
    sget-object v0, Lfv/h;->c:Ljo/d;

    .line 283
    .line 284
    filled-new-array {v0}, [Ljo/d;

    .line 285
    .line 286
    .line 287
    move-result-object v0

    .line 288
    :goto_5
    invoke-static {v2, v0}, Lfv/h;->b(Landroid/content/Context;[Ljo/d;)V

    .line 289
    .line 290
    .line 291
    iput-boolean v4, p0, La8/l;->e:Z

    .line 292
    .line 293
    :cond_9
    new-instance p0, Lbv/a;

    .line 294
    .line 295
    const-string v0, "Waiting for the text optional module to be downloaded. Please wait."

    .line 296
    .line 297
    const/16 v1, 0xe

    .line 298
    .line 299
    invoke-direct {p0, v0, v1}, Lbv/a;-><init>(Ljava/lang/String;I)V

    .line 300
    .line 301
    .line 302
    throw p0

    .line 303
    :cond_a
    new-instance p0, Lbv/a;

    .line 304
    .line 305
    invoke-virtual {v3}, Lqv/a;->b()Ljava/lang/String;

    .line 306
    .line 307
    .line 308
    move-result-object v1

    .line 309
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 310
    .line 311
    .line 312
    move-result-object v2

    .line 313
    const-string v3, "Failed to load text module "

    .line 314
    .line 315
    const-string v4, ". "

    .line 316
    .line 317
    invoke-static {v3, v1, v4, v2}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 318
    .line 319
    .line 320
    move-result-object v1

    .line 321
    invoke-direct {p0, v1, v0}, Lbv/a;-><init>(Ljava/lang/String;Ljava/lang/Exception;)V

    .line 322
    .line 323
    .line 324
    throw p0
.end method
