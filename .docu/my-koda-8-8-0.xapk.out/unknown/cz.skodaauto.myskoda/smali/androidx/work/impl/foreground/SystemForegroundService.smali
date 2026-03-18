.class public Landroidx/work/impl/foreground/SystemForegroundService;
.super Landroidx/lifecycle/a0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final h:Ljava/lang/String;


# instance fields
.field public e:Z

.field public f:Llb/b;

.field public g:Landroid/app/NotificationManager;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "SystemFgService"

    .line 2
    .line 3
    invoke-static {v0}, Leb/w;->f(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Landroidx/work/impl/foreground/SystemForegroundService;->h:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/a0;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 2

    .line 1
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-string v1, "notification"

    .line 6
    .line 7
    invoke-virtual {v0, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    check-cast v0, Landroid/app/NotificationManager;

    .line 12
    .line 13
    iput-object v0, p0, Landroidx/work/impl/foreground/SystemForegroundService;->g:Landroid/app/NotificationManager;

    .line 14
    .line 15
    new-instance v0, Llb/b;

    .line 16
    .line 17
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-direct {v0, v1}, Llb/b;-><init>(Landroid/content/Context;)V

    .line 22
    .line 23
    .line 24
    iput-object v0, p0, Landroidx/work/impl/foreground/SystemForegroundService;->f:Llb/b;

    .line 25
    .line 26
    iget-object v1, v0, Llb/b;->l:Landroidx/work/impl/foreground/SystemForegroundService;

    .line 27
    .line 28
    if-eqz v1, :cond_0

    .line 29
    .line 30
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    sget-object v0, Llb/b;->m:Ljava/lang/String;

    .line 35
    .line 36
    const-string v1, "A callback already exists."

    .line 37
    .line 38
    invoke-virtual {p0, v0, v1}, Leb/w;->b(Ljava/lang/String;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :cond_0
    iput-object p0, v0, Llb/b;->l:Landroidx/work/impl/foreground/SystemForegroundService;

    .line 43
    .line 44
    return-void
.end method

.method public final b(IILandroid/app/Notification;)V
    .locals 3

    .line 1
    sget-object v0, Landroidx/work/impl/foreground/SystemForegroundService;->h:Ljava/lang/String;

    .line 2
    .line 3
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 4
    .line 5
    const/16 v2, 0x1f

    .line 6
    .line 7
    if-lt v1, v2, :cond_1

    .line 8
    .line 9
    const-string v1, "Unable to start foreground service"

    .line 10
    .line 11
    const/4 v2, 0x5

    .line 12
    :try_start_0
    invoke-virtual {p0, p1, p3, p2}, Landroid/app/Service;->startForeground(ILandroid/app/Notification;I)V
    :try_end_0
    .catch Landroid/app/ForegroundServiceStartNotAllowedException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_0

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :catch_0
    move-exception p0

    .line 17
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    iget p1, p1, Leb/w;->a:I

    .line 22
    .line 23
    if-gt p1, v2, :cond_0

    .line 24
    .line 25
    invoke-static {v0, v1, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :catch_1
    move-exception p0

    .line 30
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    iget p1, p1, Leb/w;->a:I

    .line 35
    .line 36
    if-gt p1, v2, :cond_0

    .line 37
    .line 38
    invoke-static {v0, v1, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 39
    .line 40
    .line 41
    :cond_0
    :goto_0
    return-void

    .line 42
    :cond_1
    invoke-virtual {p0, p1, p3, p2}, Landroid/app/Service;->startForeground(ILandroid/app/Notification;I)V

    .line 43
    .line 44
    .line 45
    return-void
.end method

.method public final onCreate()V
    .locals 0

    .line 1
    invoke-super {p0}, Landroidx/lifecycle/a0;->onCreate()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Landroidx/work/impl/foreground/SystemForegroundService;->a()V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public final onDestroy()V
    .locals 0

    .line 1
    invoke-super {p0}, Landroidx/lifecycle/a0;->onDestroy()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Landroidx/work/impl/foreground/SystemForegroundService;->f:Llb/b;

    .line 5
    .line 6
    invoke-virtual {p0}, Llb/b;->e()V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final onStartCommand(Landroid/content/Intent;II)I
    .locals 4

    .line 1
    invoke-super {p0, p1, p2, p3}, Landroid/app/Service;->onStartCommand(Landroid/content/Intent;II)I

    .line 2
    .line 3
    .line 4
    iget-boolean p2, p0, Landroidx/work/impl/foreground/SystemForegroundService;->e:Z

    .line 5
    .line 6
    sget-object v0, Landroidx/work/impl/foreground/SystemForegroundService;->h:Ljava/lang/String;

    .line 7
    .line 8
    if-eqz p2, :cond_0

    .line 9
    .line 10
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 11
    .line 12
    .line 13
    move-result-object p2

    .line 14
    const-string v1, "Re-initializing SystemForegroundService after a request to shut-down."

    .line 15
    .line 16
    invoke-virtual {p2, v0, v1}, Leb/w;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    iget-object p2, p0, Landroidx/work/impl/foreground/SystemForegroundService;->f:Llb/b;

    .line 20
    .line 21
    invoke-virtual {p2}, Llb/b;->e()V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0}, Landroidx/work/impl/foreground/SystemForegroundService;->a()V

    .line 25
    .line 26
    .line 27
    const/4 p2, 0x0

    .line 28
    iput-boolean p2, p0, Landroidx/work/impl/foreground/SystemForegroundService;->e:Z

    .line 29
    .line 30
    :cond_0
    if-eqz p1, :cond_4

    .line 31
    .line 32
    iget-object p0, p0, Landroidx/work/impl/foreground/SystemForegroundService;->f:Llb/b;

    .line 33
    .line 34
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 35
    .line 36
    .line 37
    sget-object p2, Llb/b;->m:Ljava/lang/String;

    .line 38
    .line 39
    invoke-virtual {p1}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    const-string v2, "ACTION_START_FOREGROUND"

    .line 44
    .line 45
    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    const-string v3, "KEY_WORKSPEC_ID"

    .line 50
    .line 51
    if-eqz v2, :cond_1

    .line 52
    .line 53
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 54
    .line 55
    .line 56
    move-result-object p3

    .line 57
    new-instance v0, Ljava/lang/StringBuilder;

    .line 58
    .line 59
    const-string v1, "Started foreground service "

    .line 60
    .line 61
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    invoke-virtual {p3, p2, v0}, Leb/w;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {p1, v3}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p2

    .line 78
    iget-object p3, p0, Llb/b;->e:Lob/a;

    .line 79
    .line 80
    new-instance v0, Llr/b;

    .line 81
    .line 82
    const/16 v1, 0xc

    .line 83
    .line 84
    const/4 v2, 0x0

    .line 85
    invoke-direct {v0, p0, p2, v2, v1}, Llr/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 86
    .line 87
    .line 88
    iget-object p2, p3, Lob/a;->a:Lla/a0;

    .line 89
    .line 90
    invoke-virtual {p2, v0}, Lla/a0;->execute(Ljava/lang/Runnable;)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {p0, p1}, Llb/b;->c(Landroid/content/Intent;)V

    .line 94
    .line 95
    .line 96
    goto/16 :goto_0

    .line 97
    .line 98
    :cond_1
    const-string v2, "ACTION_NOTIFY"

    .line 99
    .line 100
    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result v2

    .line 104
    if-eqz v2, :cond_2

    .line 105
    .line 106
    invoke-virtual {p0, p1}, Llb/b;->c(Landroid/content/Intent;)V

    .line 107
    .line 108
    .line 109
    goto/16 :goto_0

    .line 110
    .line 111
    :cond_2
    const-string v2, "ACTION_CANCEL_WORK"

    .line 112
    .line 113
    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result v2

    .line 117
    if-eqz v2, :cond_3

    .line 118
    .line 119
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 120
    .line 121
    .line 122
    move-result-object p3

    .line 123
    new-instance v0, Ljava/lang/StringBuilder;

    .line 124
    .line 125
    const-string v1, "Stopping foreground work for "

    .line 126
    .line 127
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 134
    .line 135
    .line 136
    move-result-object v0

    .line 137
    invoke-virtual {p3, p2, v0}, Leb/w;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {p1, v3}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    if-eqz p1, :cond_4

    .line 145
    .line 146
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 147
    .line 148
    .line 149
    move-result p2

    .line 150
    if-nez p2, :cond_4

    .line 151
    .line 152
    iget-object p0, p0, Llb/b;->d:Lfb/u;

    .line 153
    .line 154
    invoke-static {p1}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;

    .line 155
    .line 156
    .line 157
    move-result-object p1

    .line 158
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 159
    .line 160
    .line 161
    const-string p2, "id"

    .line 162
    .line 163
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    iget-object p2, p0, Lfb/u;->b:Leb/b;

    .line 167
    .line 168
    iget-object p2, p2, Leb/b;->m:Leb/j;

    .line 169
    .line 170
    iget-object p3, p0, Lfb/u;->d:Lob/a;

    .line 171
    .line 172
    iget-object p3, p3, Lob/a;->a:Lla/a0;

    .line 173
    .line 174
    const-string v0, "getSerialTaskExecutor(...)"

    .line 175
    .line 176
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    new-instance v0, Llk/j;

    .line 180
    .line 181
    const/16 v1, 0x12

    .line 182
    .line 183
    invoke-direct {v0, v1, p0, p1}, Llk/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 184
    .line 185
    .line 186
    const-string p0, "CancelWorkById"

    .line 187
    .line 188
    invoke-static {p2, p0, p3, v0}, Lkp/e6;->b(Leb/j;Ljava/lang/String;Ljava/util/concurrent/Executor;Lay0/a;)Leb/c0;

    .line 189
    .line 190
    .line 191
    goto :goto_0

    .line 192
    :cond_3
    const-string p1, "ACTION_STOP_FOREGROUND"

    .line 193
    .line 194
    invoke-virtual {p1, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 195
    .line 196
    .line 197
    move-result p1

    .line 198
    if-eqz p1, :cond_4

    .line 199
    .line 200
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 201
    .line 202
    .line 203
    move-result-object p1

    .line 204
    const-string v1, "Stopping foreground service"

    .line 205
    .line 206
    invoke-virtual {p1, p2, v1}, Leb/w;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 207
    .line 208
    .line 209
    iget-object p0, p0, Llb/b;->l:Landroidx/work/impl/foreground/SystemForegroundService;

    .line 210
    .line 211
    if-eqz p0, :cond_4

    .line 212
    .line 213
    const/4 p1, 0x1

    .line 214
    iput-boolean p1, p0, Landroidx/work/impl/foreground/SystemForegroundService;->e:Z

    .line 215
    .line 216
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 217
    .line 218
    .line 219
    move-result-object p2

    .line 220
    const-string v1, "Shutting down."

    .line 221
    .line 222
    invoke-virtual {p2, v0, v1}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 223
    .line 224
    .line 225
    invoke-virtual {p0, p1}, Landroid/app/Service;->stopForeground(Z)V

    .line 226
    .line 227
    .line 228
    invoke-virtual {p0, p3}, Landroid/app/Service;->stopSelf(I)V

    .line 229
    .line 230
    .line 231
    :cond_4
    :goto_0
    const/4 p0, 0x3

    .line 232
    return p0
.end method

.method public final onTimeout(I)V
    .locals 2

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x23

    if-lt v0, v1, :cond_0

    return-void

    .line 2
    :cond_0
    iget-object p0, p0, Landroidx/work/impl/foreground/SystemForegroundService;->f:Llb/b;

    const/16 v0, 0x800

    invoke-virtual {p0, p1, v0}, Llb/b;->f(II)V

    return-void
.end method

.method public final onTimeout(II)V
    .locals 0

    .line 3
    iget-object p0, p0, Landroidx/work/impl/foreground/SystemForegroundService;->f:Llb/b;

    invoke-virtual {p0, p1, p2}, Llb/b;->f(II)V

    return-void
.end method
