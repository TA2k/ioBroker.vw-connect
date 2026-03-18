.class public final Luu/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final h:Lu2/l;


# instance fields
.field public final a:Ll2/j1;

.field public final b:Ll2/j1;

.field public final c:Ll2/j1;

.field public final d:Llx0/b0;

.field public final e:Ll2/j1;

.field public final f:Ll2/j1;

.field public final g:Ll2/j1;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ltf0/a;

    .line 2
    .line 3
    const/16 v1, 0x1d

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ltf0/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Lu2/d;

    .line 9
    .line 10
    const/16 v2, 0x1c

    .line 11
    .line 12
    invoke-direct {v1, v2}, Lu2/d;-><init>(I)V

    .line 13
    .line 14
    .line 15
    new-instance v2, Lu2/l;

    .line 16
    .line 17
    invoke-direct {v2, v0, v1}, Lu2/l;-><init>(Lay0/n;Lay0/k;)V

    .line 18
    .line 19
    .line 20
    sput-object v2, Luu/g;->h:Lu2/l;

    .line 21
    .line 22
    return-void
.end method

.method public constructor <init>(Lcom/google/android/gms/maps/model/CameraPosition;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 5
    .line 6
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iput-object v0, p0, Luu/g;->a:Ll2/j1;

    .line 11
    .line 12
    sget-object v0, Luu/b;->g:Luu/b;

    .line 13
    .line 14
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    iput-object v0, p0, Luu/g;->b:Ll2/j1;

    .line 19
    .line 20
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    iput-object p1, p0, Luu/g;->c:Ll2/j1;

    .line 25
    .line 26
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 27
    .line 28
    iput-object p1, p0, Luu/g;->d:Llx0/b0;

    .line 29
    .line 30
    const/4 p1, 0x0

    .line 31
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    iput-object v0, p0, Luu/g;->e:Ll2/j1;

    .line 36
    .line 37
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    iput-object v0, p0, Luu/g;->f:Ll2/j1;

    .line 42
    .line 43
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    iput-object p1, p0, Luu/g;->g:Ll2/j1;

    .line 48
    .line 49
    return-void
.end method

.method public static final a(Luu/g;Lqp/g;Lpv/g;ILvy0/l;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    new-instance v0, Lpv/g;

    .line 5
    .line 6
    const/16 v1, 0xe

    .line 7
    .line 8
    invoke-direct {v0, p4, v1}, Lpv/g;-><init>(Ljava/lang/Object;I)V

    .line 9
    .line 10
    .line 11
    const p4, 0x7fffffff

    .line 12
    .line 13
    .line 14
    const-string v1, "CameraUpdate must not be null."

    .line 15
    .line 16
    if-ne p3, p4, :cond_0

    .line 17
    .line 18
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    :try_start_0
    invoke-static {p2, v1}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    iget-object p3, p1, Lqp/g;->a:Lrp/f;

    .line 25
    .line 26
    iget-object p2, p2, Lpv/g;->e:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p2, Lyo/a;

    .line 29
    .line 30
    new-instance p4, Lqp/j;

    .line 31
    .line 32
    invoke-direct {p4, v0}, Lqp/j;-><init>(Lpv/g;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p3}, Lbp/a;->S()Landroid/os/Parcel;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    invoke-static {v0, p2}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 40
    .line 41
    .line 42
    invoke-static {v0, p4}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 43
    .line 44
    .line 45
    const/4 p2, 0x6

    .line 46
    invoke-virtual {p3, v0, p2}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :catch_0
    move-exception p0

    .line 51
    new-instance p1, La8/r0;

    .line 52
    .line 53
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 54
    .line 55
    .line 56
    throw p1

    .line 57
    :cond_0
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 58
    .line 59
    .line 60
    :try_start_1
    invoke-static {p2, v1}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    iget-object p4, p1, Lqp/g;->a:Lrp/f;

    .line 64
    .line 65
    iget-object p2, p2, Lpv/g;->e:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast p2, Lyo/a;

    .line 68
    .line 69
    new-instance v1, Lqp/j;

    .line 70
    .line 71
    invoke-direct {v1, v0}, Lqp/j;-><init>(Lpv/g;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {p4}, Lbp/a;->S()Landroid/os/Parcel;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    invoke-static {v0, p2}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {v0, p3}, Landroid/os/Parcel;->writeInt(I)V

    .line 82
    .line 83
    .line 84
    invoke-static {v0, v1}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 85
    .line 86
    .line 87
    const/4 p2, 0x7

    .line 88
    invoke-virtual {p4, v0, p2}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_1
    .catch Landroid/os/RemoteException; {:try_start_1 .. :try_end_1} :catch_1

    .line 89
    .line 90
    .line 91
    :goto_0
    new-instance p2, Luu/c;

    .line 92
    .line 93
    const/4 p3, 0x1

    .line 94
    invoke-direct {p2, p1, p3}, Luu/c;-><init>(Ljava/lang/Object;I)V

    .line 95
    .line 96
    .line 97
    iget-object p0, p0, Luu/g;->f:Ll2/j1;

    .line 98
    .line 99
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    check-cast p1, Luu/d;

    .line 104
    .line 105
    if-eqz p1, :cond_1

    .line 106
    .line 107
    invoke-interface {p1}, Luu/d;->a()V

    .line 108
    .line 109
    .line 110
    :cond_1
    invoke-virtual {p0, p2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    return-void

    .line 114
    :catch_1
    move-exception p0

    .line 115
    new-instance p1, La8/r0;

    .line 116
    .line 117
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 118
    .line 119
    .line 120
    throw p1
.end method


# virtual methods
.method public final b(Lpv/g;ILrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p3, Luu/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Luu/e;

    .line 7
    .line 8
    iget v1, v0, Luu/e;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Luu/e;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Luu/e;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Luu/e;-><init>(Luu/g;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Luu/e;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Luu/e;->g:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    if-ne v2, v4, :cond_1

    .line 36
    .line 37
    iget-object p1, v0, Luu/e;->d:Lvy0/i1;

    .line 38
    .line 39
    :try_start_0
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 40
    .line 41
    .line 42
    goto :goto_2

    .line 43
    :catchall_0
    move-exception p2

    .line 44
    goto/16 :goto_5

    .line 45
    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 58
    .line 59
    .line 60
    move-result-object p3

    .line 61
    sget-object v2, Lvy0/h1;->d:Lvy0/h1;

    .line 62
    .line 63
    invoke-interface {p3, v2}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 64
    .line 65
    .line 66
    move-result-object p3

    .line 67
    check-cast p3, Lvy0/i1;

    .line 68
    .line 69
    :try_start_1
    iput-object p3, v0, Luu/e;->d:Lvy0/i1;

    .line 70
    .line 71
    iput v4, v0, Luu/e;->g:I

    .line 72
    .line 73
    new-instance v2, Lvy0/l;

    .line 74
    .line 75
    invoke-static {v0}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    invoke-direct {v2, v4, v0}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {v2}, Lvy0/l;->q()V

    .line 83
    .line 84
    .line 85
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 86
    .line 87
    monitor-enter v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_3

    .line 88
    :try_start_2
    iget-object v4, p0, Luu/g;->g:Ll2/j1;

    .line 89
    .line 90
    invoke-virtual {v4, p3}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {p0}, Luu/g;->c()Lqp/g;

    .line 94
    .line 95
    .line 96
    move-result-object v4

    .line 97
    if-nez v4, :cond_4

    .line 98
    .line 99
    new-instance v4, Luu/f;

    .line 100
    .line 101
    invoke-direct {v4, v2, p0, p1, p2}, Luu/f;-><init>(Lvy0/l;Luu/g;Lpv/g;I)V

    .line 102
    .line 103
    .line 104
    iget-object p1, p0, Luu/g;->f:Ll2/j1;

    .line 105
    .line 106
    invoke-virtual {p1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object p2

    .line 110
    check-cast p2, Luu/d;

    .line 111
    .line 112
    if-eqz p2, :cond_3

    .line 113
    .line 114
    invoke-interface {p2}, Luu/d;->a()V

    .line 115
    .line 116
    .line 117
    :cond_3
    invoke-virtual {p1, v4}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    new-instance p1, Lc41/g;

    .line 121
    .line 122
    const/16 p2, 0x16

    .line 123
    .line 124
    invoke-direct {p1, p2, p0, v4}, Lc41/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {v2, p1}, Lvy0/l;->s(Lay0/k;)V

    .line 128
    .line 129
    .line 130
    goto :goto_1

    .line 131
    :catchall_1
    move-exception p1

    .line 132
    goto :goto_4

    .line 133
    :cond_4
    invoke-static {p0, v4, p1, p2, v2}, Luu/g;->a(Luu/g;Lqp/g;Lpv/g;ILvy0/l;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 134
    .line 135
    .line 136
    :goto_1
    :try_start_3
    monitor-exit v0

    .line 137
    invoke-virtual {v2}, Lvy0/l;->p()Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 141
    if-ne p1, v1, :cond_5

    .line 142
    .line 143
    return-object v1

    .line 144
    :cond_5
    move-object p1, p3

    .line 145
    :goto_2
    iget-object p2, p0, Luu/g;->d:Llx0/b0;

    .line 146
    .line 147
    monitor-enter p2

    .line 148
    if-eqz p1, :cond_6

    .line 149
    .line 150
    :try_start_4
    iget-object p3, p0, Luu/g;->g:Ll2/j1;

    .line 151
    .line 152
    invoke-virtual {p3}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object p3

    .line 156
    if-ne p3, p1, :cond_6

    .line 157
    .line 158
    iget-object p1, p0, Luu/g;->g:Ll2/j1;

    .line 159
    .line 160
    invoke-virtual {p1, v3}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 161
    .line 162
    .line 163
    invoke-virtual {p0}, Luu/g;->c()Lqp/g;

    .line 164
    .line 165
    .line 166
    move-result-object p0

    .line 167
    if-eqz p0, :cond_6

    .line 168
    .line 169
    invoke-virtual {p0}, Lqp/g;->m()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 170
    .line 171
    .line 172
    goto :goto_3

    .line 173
    :catchall_2
    move-exception p0

    .line 174
    monitor-exit p2

    .line 175
    throw p0

    .line 176
    :cond_6
    :goto_3
    monitor-exit p2

    .line 177
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 178
    .line 179
    return-object p0

    .line 180
    :catchall_3
    move-exception p2

    .line 181
    move-object p1, p3

    .line 182
    goto :goto_5

    .line 183
    :goto_4
    :try_start_5
    monitor-exit v0

    .line 184
    throw p1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 185
    :goto_5
    iget-object p3, p0, Luu/g;->d:Llx0/b0;

    .line 186
    .line 187
    monitor-enter p3

    .line 188
    if-eqz p1, :cond_7

    .line 189
    .line 190
    :try_start_6
    iget-object v0, p0, Luu/g;->g:Ll2/j1;

    .line 191
    .line 192
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v0

    .line 196
    if-ne v0, p1, :cond_7

    .line 197
    .line 198
    iget-object p1, p0, Luu/g;->g:Ll2/j1;

    .line 199
    .line 200
    invoke-virtual {p1, v3}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 201
    .line 202
    .line 203
    invoke-virtual {p0}, Luu/g;->c()Lqp/g;

    .line 204
    .line 205
    .line 206
    move-result-object p0

    .line 207
    if-eqz p0, :cond_7

    .line 208
    .line 209
    invoke-virtual {p0}, Lqp/g;->m()V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_4

    .line 210
    .line 211
    .line 212
    goto :goto_6

    .line 213
    :catchall_4
    move-exception p0

    .line 214
    monitor-exit p3

    .line 215
    throw p0

    .line 216
    :cond_7
    :goto_6
    monitor-exit p3

    .line 217
    throw p2
.end method

.method public final c()Lqp/g;
    .locals 0

    .line 1
    iget-object p0, p0, Luu/g;->e:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lqp/g;

    .line 8
    .line 9
    return-object p0
.end method

.method public final d()Lcom/google/android/gms/maps/model/CameraPosition;
    .locals 0

    .line 1
    iget-object p0, p0, Luu/g;->c:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/google/android/gms/maps/model/CameraPosition;

    .line 8
    .line 9
    return-object p0
.end method

.method public final e(Lpv/g;)V
    .locals 4

    .line 1
    iget-object v0, p0, Luu/g;->d:Llx0/b0;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    invoke-virtual {p0}, Luu/g;->c()Lqp/g;

    .line 5
    .line 6
    .line 7
    move-result-object v1

    .line 8
    iget-object v2, p0, Luu/g;->g:Ll2/j1;

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    invoke-virtual {v2, v3}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    if-nez v1, :cond_1

    .line 15
    .line 16
    new-instance v1, Luu/c;

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-direct {v1, p1, v2}, Luu/c;-><init>(Ljava/lang/Object;I)V

    .line 20
    .line 21
    .line 22
    iget-object p0, p0, Luu/g;->f:Ll2/j1;

    .line 23
    .line 24
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    check-cast p1, Luu/d;

    .line 29
    .line 30
    if-eqz p1, :cond_0

    .line 31
    .line 32
    invoke-interface {p1}, Luu/d;->a()V

    .line 33
    .line 34
    .line 35
    :cond_0
    invoke-virtual {p0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    goto :goto_0

    .line 39
    :catchall_0
    move-exception p0

    .line 40
    goto :goto_1

    .line 41
    :cond_1
    invoke-virtual {v1, p1}, Lqp/g;->e(Lpv/g;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 42
    .line 43
    .line 44
    :goto_0
    monitor-exit v0

    .line 45
    return-void

    .line 46
    :goto_1
    monitor-exit v0

    .line 47
    throw p0
.end method

.method public final f(Lqp/g;)V
    .locals 3

    .line 1
    iget-object v0, p0, Luu/g;->d:Llx0/b0;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    invoke-virtual {p0}, Luu/g;->c()Lqp/g;

    .line 5
    .line 6
    .line 7
    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    if-nez p1, :cond_0

    .line 11
    .line 12
    monitor-exit v0

    .line 13
    return-void

    .line 14
    :cond_0
    :try_start_1
    invoke-virtual {p0}, Luu/g;->c()Lqp/g;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    if-eqz v1, :cond_2

    .line 19
    .line 20
    if-nez p1, :cond_1

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 24
    .line 25
    const-string p1, "CameraPositionState may only be associated with one GoogleMap at a time"

    .line 26
    .line 27
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :catchall_0
    move-exception p0

    .line 32
    goto :goto_2

    .line 33
    :cond_2
    :goto_0
    iget-object v1, p0, Luu/g;->e:Ll2/j1;

    .line 34
    .line 35
    invoke-virtual {v1, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    if-nez p1, :cond_3

    .line 39
    .line 40
    iget-object v1, p0, Luu/g;->a:Ll2/j1;

    .line 41
    .line 42
    sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 43
    .line 44
    invoke-virtual {v1, v2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_3
    invoke-virtual {p0}, Luu/g;->d()Lcom/google/android/gms/maps/model/CameraPosition;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    invoke-static {v1}, Ljp/wf;->b(Lcom/google/android/gms/maps/model/CameraPosition;)Lpv/g;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    invoke-virtual {p1, v1}, Lqp/g;->e(Lpv/g;)V

    .line 57
    .line 58
    .line 59
    :goto_1
    iget-object v1, p0, Luu/g;->f:Ll2/j1;

    .line 60
    .line 61
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    check-cast v1, Luu/d;

    .line 66
    .line 67
    if-eqz v1, :cond_4

    .line 68
    .line 69
    iget-object p0, p0, Luu/g;->f:Ll2/j1;

    .line 70
    .line 71
    const/4 v2, 0x0

    .line 72
    invoke-virtual {p0, v2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    invoke-interface {v1, p1}, Luu/d;->b(Lqp/g;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 76
    .line 77
    .line 78
    :cond_4
    monitor-exit v0

    .line 79
    return-void

    .line 80
    :goto_2
    monitor-exit v0

    .line 81
    throw p0
.end method

.method public final g(Lcom/google/android/gms/maps/model/CameraPosition;)V
    .locals 2

    .line 1
    iget-object v0, p0, Luu/g;->d:Llx0/b0;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    invoke-virtual {p0}, Luu/g;->c()Lqp/g;

    .line 5
    .line 6
    .line 7
    move-result-object v1

    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    iget-object p0, p0, Luu/g;->c:Ll2/j1;

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-static {p1}, Ljp/wf;->b(Lcom/google/android/gms/maps/model/CameraPosition;)Lpv/g;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-virtual {v1, p0}, Lqp/g;->e(Lpv/g;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    .line 22
    .line 23
    :goto_0
    monitor-exit v0

    .line 24
    return-void

    .line 25
    :catchall_0
    move-exception p0

    .line 26
    monitor-exit v0

    .line 27
    throw p0
.end method
