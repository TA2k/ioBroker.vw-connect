.class public final Llb/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lib/f;
.implements Lfb/b;


# static fields
.field public static final m:Ljava/lang/String;


# instance fields
.field public final d:Lfb/u;

.field public final e:Lob/a;

.field public final f:Ljava/lang/Object;

.field public g:Lmb/i;

.field public final h:Ljava/util/LinkedHashMap;

.field public final i:Ljava/util/HashMap;

.field public final j:Ljava/util/HashMap;

.field public final k:Laq/m;

.field public l:Landroidx/work/impl/foreground/SystemForegroundService;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "SystemFgDispatcher"

    .line 2
    .line 3
    invoke-static {v0}, Leb/w;->f(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Llb/b;->m:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/Object;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Llb/b;->f:Ljava/lang/Object;

    .line 10
    .line 11
    invoke-static {p1}, Lfb/u;->f(Landroid/content/Context;)Lfb/u;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    iput-object p1, p0, Llb/b;->d:Lfb/u;

    .line 16
    .line 17
    iget-object v0, p1, Lfb/u;->d:Lob/a;

    .line 18
    .line 19
    iput-object v0, p0, Llb/b;->e:Lob/a;

    .line 20
    .line 21
    const/4 v0, 0x0

    .line 22
    iput-object v0, p0, Llb/b;->g:Lmb/i;

    .line 23
    .line 24
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 25
    .line 26
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 27
    .line 28
    .line 29
    iput-object v0, p0, Llb/b;->h:Ljava/util/LinkedHashMap;

    .line 30
    .line 31
    new-instance v0, Ljava/util/HashMap;

    .line 32
    .line 33
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 34
    .line 35
    .line 36
    iput-object v0, p0, Llb/b;->j:Ljava/util/HashMap;

    .line 37
    .line 38
    new-instance v0, Ljava/util/HashMap;

    .line 39
    .line 40
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 41
    .line 42
    .line 43
    iput-object v0, p0, Llb/b;->i:Ljava/util/HashMap;

    .line 44
    .line 45
    new-instance v0, Laq/m;

    .line 46
    .line 47
    iget-object v1, p1, Lfb/u;->j:Lkb/i;

    .line 48
    .line 49
    invoke-direct {v0, v1}, Laq/m;-><init>(Lkb/i;)V

    .line 50
    .line 51
    .line 52
    iput-object v0, p0, Llb/b;->k:Laq/m;

    .line 53
    .line 54
    iget-object p1, p1, Lfb/u;->f:Lfb/e;

    .line 55
    .line 56
    invoke-virtual {p1, p0}, Lfb/e;->a(Lfb/b;)V

    .line 57
    .line 58
    .line 59
    return-void
.end method

.method public static a(Landroid/content/Context;Lmb/i;Leb/n;)Landroid/content/Intent;
    .locals 2

    .line 1
    new-instance v0, Landroid/content/Intent;

    .line 2
    .line 3
    const-class v1, Landroidx/work/impl/foreground/SystemForegroundService;

    .line 4
    .line 5
    invoke-direct {v0, p0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 6
    .line 7
    .line 8
    const-string p0, "ACTION_START_FOREGROUND"

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    .line 11
    .line 12
    .line 13
    const-string p0, "KEY_WORKSPEC_ID"

    .line 14
    .line 15
    iget-object v1, p1, Lmb/i;->a:Ljava/lang/String;

    .line 16
    .line 17
    invoke-virtual {v0, p0, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 18
    .line 19
    .line 20
    const-string p0, "KEY_GENERATION"

    .line 21
    .line 22
    iget p1, p1, Lmb/i;->b:I

    .line 23
    .line 24
    invoke-virtual {v0, p0, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    .line 25
    .line 26
    .line 27
    const-string p0, "KEY_NOTIFICATION_ID"

    .line 28
    .line 29
    iget p1, p2, Leb/n;->a:I

    .line 30
    .line 31
    invoke-virtual {v0, p0, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    .line 32
    .line 33
    .line 34
    const-string p0, "KEY_FOREGROUND_SERVICE_TYPE"

    .line 35
    .line 36
    iget p1, p2, Leb/n;->b:I

    .line 37
    .line 38
    invoke-virtual {v0, p0, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    .line 39
    .line 40
    .line 41
    const-string p0, "KEY_NOTIFICATION"

    .line 42
    .line 43
    iget-object p1, p2, Leb/n;->c:Landroid/app/Notification;

    .line 44
    .line 45
    invoke-virtual {v0, p0, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    .line 46
    .line 47
    .line 48
    return-object v0
.end method


# virtual methods
.method public final b(Lmb/i;Z)V
    .locals 5

    .line 1
    iget-object p2, p0, Llb/b;->f:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter p2

    .line 4
    :try_start_0
    iget-object v0, p0, Llb/b;->i:Ljava/util/HashMap;

    .line 5
    .line 6
    invoke-virtual {v0, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    check-cast v0, Lmb/o;

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    iget-object v0, p0, Llb/b;->j:Ljava/util/HashMap;

    .line 16
    .line 17
    invoke-virtual {v0, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, Lvy0/i1;

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :catchall_0
    move-exception p0

    .line 25
    goto/16 :goto_3

    .line 26
    .line 27
    :cond_0
    move-object v0, v1

    .line 28
    :goto_0
    if-eqz v0, :cond_1

    .line 29
    .line 30
    invoke-interface {v0, v1}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 31
    .line 32
    .line 33
    :cond_1
    monitor-exit p2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 34
    iget-object p2, p0, Llb/b;->h:Ljava/util/LinkedHashMap;

    .line 35
    .line 36
    invoke-interface {p2, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p2

    .line 40
    check-cast p2, Leb/n;

    .line 41
    .line 42
    iget-object v0, p0, Llb/b;->g:Lmb/i;

    .line 43
    .line 44
    invoke-virtual {p1, v0}, Lmb/i;->equals(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-eqz v0, :cond_4

    .line 49
    .line 50
    iget-object v0, p0, Llb/b;->h:Ljava/util/LinkedHashMap;

    .line 51
    .line 52
    invoke-interface {v0}, Ljava/util/Map;->size()I

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    if-lez v0, :cond_3

    .line 57
    .line 58
    iget-object v0, p0, Llb/b;->h:Ljava/util/LinkedHashMap;

    .line 59
    .line 60
    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    check-cast v1, Ljava/util/Map$Entry;

    .line 73
    .line 74
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 75
    .line 76
    .line 77
    move-result v2

    .line 78
    if-eqz v2, :cond_2

    .line 79
    .line 80
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v1

    .line 84
    check-cast v1, Ljava/util/Map$Entry;

    .line 85
    .line 86
    goto :goto_1

    .line 87
    :cond_2
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    check-cast v0, Lmb/i;

    .line 92
    .line 93
    iput-object v0, p0, Llb/b;->g:Lmb/i;

    .line 94
    .line 95
    iget-object v0, p0, Llb/b;->l:Landroidx/work/impl/foreground/SystemForegroundService;

    .line 96
    .line 97
    if-eqz v0, :cond_4

    .line 98
    .line 99
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    check-cast v0, Leb/n;

    .line 104
    .line 105
    iget-object v1, p0, Llb/b;->l:Landroidx/work/impl/foreground/SystemForegroundService;

    .line 106
    .line 107
    iget v2, v0, Leb/n;->a:I

    .line 108
    .line 109
    iget v3, v0, Leb/n;->b:I

    .line 110
    .line 111
    iget-object v4, v0, Leb/n;->c:Landroid/app/Notification;

    .line 112
    .line 113
    invoke-virtual {v1, v2, v3, v4}, Landroidx/work/impl/foreground/SystemForegroundService;->b(IILandroid/app/Notification;)V

    .line 114
    .line 115
    .line 116
    iget-object v1, p0, Llb/b;->l:Landroidx/work/impl/foreground/SystemForegroundService;

    .line 117
    .line 118
    iget v0, v0, Leb/n;->a:I

    .line 119
    .line 120
    iget-object v1, v1, Landroidx/work/impl/foreground/SystemForegroundService;->g:Landroid/app/NotificationManager;

    .line 121
    .line 122
    invoke-virtual {v1, v0}, Landroid/app/NotificationManager;->cancel(I)V

    .line 123
    .line 124
    .line 125
    goto :goto_2

    .line 126
    :cond_3
    iput-object v1, p0, Llb/b;->g:Lmb/i;

    .line 127
    .line 128
    :cond_4
    :goto_2
    iget-object p0, p0, Llb/b;->l:Landroidx/work/impl/foreground/SystemForegroundService;

    .line 129
    .line 130
    if-eqz p2, :cond_5

    .line 131
    .line 132
    if-eqz p0, :cond_5

    .line 133
    .line 134
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 135
    .line 136
    .line 137
    move-result-object v0

    .line 138
    sget-object v1, Llb/b;->m:Ljava/lang/String;

    .line 139
    .line 140
    new-instance v2, Ljava/lang/StringBuilder;

    .line 141
    .line 142
    const-string v3, "Removing Notification (id: "

    .line 143
    .line 144
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    iget v3, p2, Leb/n;->a:I

    .line 148
    .line 149
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 150
    .line 151
    .line 152
    const-string v3, ", workSpecId: "

    .line 153
    .line 154
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 155
    .line 156
    .line 157
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 158
    .line 159
    .line 160
    const-string p1, ", notificationType: "

    .line 161
    .line 162
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 163
    .line 164
    .line 165
    iget p1, p2, Leb/n;->b:I

    .line 166
    .line 167
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 168
    .line 169
    .line 170
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 171
    .line 172
    .line 173
    move-result-object p1

    .line 174
    invoke-virtual {v0, v1, p1}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 175
    .line 176
    .line 177
    iget p1, p2, Leb/n;->a:I

    .line 178
    .line 179
    iget-object p0, p0, Landroidx/work/impl/foreground/SystemForegroundService;->g:Landroid/app/NotificationManager;

    .line 180
    .line 181
    invoke-virtual {p0, p1}, Landroid/app/NotificationManager;->cancel(I)V

    .line 182
    .line 183
    .line 184
    :cond_5
    return-void

    .line 185
    :goto_3
    :try_start_1
    monitor-exit p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 186
    throw p0
.end method

.method public final c(Landroid/content/Intent;)V
    .locals 9

    .line 1
    iget-object v0, p0, Llb/b;->l:Landroidx/work/impl/foreground/SystemForegroundService;

    .line 2
    .line 3
    if-eqz v0, :cond_3

    .line 4
    .line 5
    const-string v0, "KEY_NOTIFICATION_ID"

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-virtual {p1, v0, v1}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    const-string v2, "KEY_FOREGROUND_SERVICE_TYPE"

    .line 13
    .line 14
    invoke-virtual {p1, v2, v1}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    const-string v3, "KEY_WORKSPEC_ID"

    .line 19
    .line 20
    invoke-virtual {p1, v3}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    const-string v4, "KEY_GENERATION"

    .line 25
    .line 26
    invoke-virtual {p1, v4, v1}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    new-instance v5, Lmb/i;

    .line 31
    .line 32
    invoke-direct {v5, v3, v4}, Lmb/i;-><init>(Ljava/lang/String;I)V

    .line 33
    .line 34
    .line 35
    const-string v4, "KEY_NOTIFICATION"

    .line 36
    .line 37
    invoke-virtual {p1, v4}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    check-cast p1, Landroid/app/Notification;

    .line 42
    .line 43
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    const-string v6, ", workSpecId: "

    .line 48
    .line 49
    const-string v7, ", notificationType :"

    .line 50
    .line 51
    const-string v8, "Notifying with (id:"

    .line 52
    .line 53
    invoke-static {v8, v0, v6, v3, v7}, Lf2/m0;->o(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    move-result-object v3

    .line 57
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    const-string v6, ")"

    .line 61
    .line 62
    invoke-virtual {v3, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v3

    .line 69
    sget-object v6, Llb/b;->m:Ljava/lang/String;

    .line 70
    .line 71
    invoke-virtual {v4, v6, v3}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    if-eqz p1, :cond_2

    .line 75
    .line 76
    new-instance v3, Leb/n;

    .line 77
    .line 78
    invoke-direct {v3, v0, v2, p1}, Leb/n;-><init>(IILandroid/app/Notification;)V

    .line 79
    .line 80
    .line 81
    iget-object v2, p0, Llb/b;->h:Ljava/util/LinkedHashMap;

    .line 82
    .line 83
    invoke-interface {v2, v5, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    iget-object v4, p0, Llb/b;->g:Lmb/i;

    .line 87
    .line 88
    invoke-virtual {v2, v4}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v4

    .line 92
    check-cast v4, Leb/n;

    .line 93
    .line 94
    if-nez v4, :cond_0

    .line 95
    .line 96
    iput-object v5, p0, Llb/b;->g:Lmb/i;

    .line 97
    .line 98
    goto :goto_1

    .line 99
    :cond_0
    iget-object v3, p0, Llb/b;->l:Landroidx/work/impl/foreground/SystemForegroundService;

    .line 100
    .line 101
    iget-object v3, v3, Landroidx/work/impl/foreground/SystemForegroundService;->g:Landroid/app/NotificationManager;

    .line 102
    .line 103
    invoke-virtual {v3, v0, p1}, Landroid/app/NotificationManager;->notify(ILandroid/app/Notification;)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v2}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 115
    .line 116
    .line 117
    move-result v0

    .line 118
    if-eqz v0, :cond_1

    .line 119
    .line 120
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    check-cast v0, Ljava/util/Map$Entry;

    .line 125
    .line 126
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object v0

    .line 130
    check-cast v0, Leb/n;

    .line 131
    .line 132
    iget v0, v0, Leb/n;->b:I

    .line 133
    .line 134
    or-int/2addr v1, v0

    .line 135
    goto :goto_0

    .line 136
    :cond_1
    new-instance v3, Leb/n;

    .line 137
    .line 138
    iget p1, v4, Leb/n;->a:I

    .line 139
    .line 140
    iget-object v0, v4, Leb/n;->c:Landroid/app/Notification;

    .line 141
    .line 142
    invoke-direct {v3, p1, v1, v0}, Leb/n;-><init>(IILandroid/app/Notification;)V

    .line 143
    .line 144
    .line 145
    :goto_1
    iget-object p0, p0, Llb/b;->l:Landroidx/work/impl/foreground/SystemForegroundService;

    .line 146
    .line 147
    iget p1, v3, Leb/n;->b:I

    .line 148
    .line 149
    iget-object v0, v3, Leb/n;->c:Landroid/app/Notification;

    .line 150
    .line 151
    iget v1, v3, Leb/n;->a:I

    .line 152
    .line 153
    invoke-virtual {p0, v1, p1, v0}, Landroidx/work/impl/foreground/SystemForegroundService;->b(IILandroid/app/Notification;)V

    .line 154
    .line 155
    .line 156
    return-void

    .line 157
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 158
    .line 159
    const-string p1, "Notification passed in the intent was null."

    .line 160
    .line 161
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    throw p0

    .line 165
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 166
    .line 167
    const-string p1, "handleNotify was called on the destroyed dispatcher"

    .line 168
    .line 169
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 170
    .line 171
    .line 172
    throw p0
.end method

.method public final d(Lmb/o;Lib/c;)V
    .locals 4

    .line 1
    instance-of v0, p2, Lib/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p1, Lmb/o;->a:Ljava/lang/String;

    .line 6
    .line 7
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    new-instance v2, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v3, "Constraints unmet for WorkSpec "

    .line 14
    .line 15
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sget-object v2, Llb/b;->m:Ljava/lang/String;

    .line 26
    .line 27
    invoke-virtual {v1, v2, v0}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    invoke-static {p1}, Ljp/y0;->c(Lmb/o;)Lmb/i;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    check-cast p2, Lib/b;

    .line 35
    .line 36
    iget p2, p2, Lib/b;->a:I

    .line 37
    .line 38
    iget-object p0, p0, Llb/b;->d:Lfb/u;

    .line 39
    .line 40
    iget-object v0, p0, Lfb/u;->d:Lob/a;

    .line 41
    .line 42
    new-instance v1, Lnb/h;

    .line 43
    .line 44
    iget-object p0, p0, Lfb/u;->f:Lfb/e;

    .line 45
    .line 46
    new-instance v2, Lfb/j;

    .line 47
    .line 48
    invoke-direct {v2, p1}, Lfb/j;-><init>(Lmb/i;)V

    .line 49
    .line 50
    .line 51
    const/4 p1, 0x1

    .line 52
    invoke-direct {v1, p0, v2, p1, p2}, Lnb/h;-><init>(Lfb/e;Lfb/j;ZI)V

    .line 53
    .line 54
    .line 55
    iget-object p0, v0, Lob/a;->a:Lla/a0;

    .line 56
    .line 57
    invoke-virtual {p0, v1}, Lla/a0;->execute(Ljava/lang/Runnable;)V

    .line 58
    .line 59
    .line 60
    :cond_0
    return-void
.end method

.method public final e()V
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Llb/b;->l:Landroidx/work/impl/foreground/SystemForegroundService;

    .line 3
    .line 4
    iget-object v1, p0, Llb/b;->f:Ljava/lang/Object;

    .line 5
    .line 6
    monitor-enter v1

    .line 7
    :try_start_0
    iget-object v2, p0, Llb/b;->j:Ljava/util/HashMap;

    .line 8
    .line 9
    invoke-virtual {v2}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    invoke-interface {v2}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    if-eqz v3, :cond_0

    .line 22
    .line 23
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    check-cast v3, Lvy0/i1;

    .line 28
    .line 29
    invoke-interface {v3, v0}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :catchall_0
    move-exception p0

    .line 34
    goto :goto_1

    .line 35
    :cond_0
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 36
    iget-object v0, p0, Llb/b;->d:Lfb/u;

    .line 37
    .line 38
    iget-object v0, v0, Lfb/u;->f:Lfb/e;

    .line 39
    .line 40
    iget-object v2, v0, Lfb/e;->k:Ljava/lang/Object;

    .line 41
    .line 42
    monitor-enter v2

    .line 43
    :try_start_1
    iget-object v0, v0, Lfb/e;->j:Ljava/util/ArrayList;

    .line 44
    .line 45
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    monitor-exit v2

    .line 49
    return-void

    .line 50
    :catchall_1
    move-exception p0

    .line 51
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 52
    throw p0

    .line 53
    :goto_1
    :try_start_2
    monitor-exit v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 54
    throw p0
.end method

.method public final f(II)V
    .locals 7

    .line 1
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v2, "Foreground service timed out, FGS type: "

    .line 8
    .line 9
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    sget-object v2, Llb/b;->m:Ljava/lang/String;

    .line 20
    .line 21
    invoke-virtual {v0, v2, v1}, Leb/w;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    iget-object v0, p0, Llb/b;->h:Ljava/util/LinkedHashMap;

    .line 25
    .line 26
    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    const/4 v2, 0x1

    .line 39
    if-eqz v1, :cond_1

    .line 40
    .line 41
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    check-cast v1, Ljava/util/Map$Entry;

    .line 46
    .line 47
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v3

    .line 51
    check-cast v3, Leb/n;

    .line 52
    .line 53
    iget v3, v3, Leb/n;->b:I

    .line 54
    .line 55
    if-ne v3, p2, :cond_0

    .line 56
    .line 57
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    check-cast v1, Lmb/i;

    .line 62
    .line 63
    iget-object v3, p0, Llb/b;->d:Lfb/u;

    .line 64
    .line 65
    iget-object v4, v3, Lfb/u;->d:Lob/a;

    .line 66
    .line 67
    new-instance v5, Lnb/h;

    .line 68
    .line 69
    iget-object v3, v3, Lfb/u;->f:Lfb/e;

    .line 70
    .line 71
    new-instance v6, Lfb/j;

    .line 72
    .line 73
    invoke-direct {v6, v1}, Lfb/j;-><init>(Lmb/i;)V

    .line 74
    .line 75
    .line 76
    const/16 v1, -0x80

    .line 77
    .line 78
    invoke-direct {v5, v3, v6, v2, v1}, Lnb/h;-><init>(Lfb/e;Lfb/j;ZI)V

    .line 79
    .line 80
    .line 81
    iget-object v1, v4, Lob/a;->a:Lla/a0;

    .line 82
    .line 83
    invoke-virtual {v1, v5}, Lla/a0;->execute(Ljava/lang/Runnable;)V

    .line 84
    .line 85
    .line 86
    goto :goto_0

    .line 87
    :cond_1
    iget-object p0, p0, Llb/b;->l:Landroidx/work/impl/foreground/SystemForegroundService;

    .line 88
    .line 89
    if-eqz p0, :cond_2

    .line 90
    .line 91
    iput-boolean v2, p0, Landroidx/work/impl/foreground/SystemForegroundService;->e:Z

    .line 92
    .line 93
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 94
    .line 95
    .line 96
    move-result-object p2

    .line 97
    sget-object v0, Landroidx/work/impl/foreground/SystemForegroundService;->h:Ljava/lang/String;

    .line 98
    .line 99
    const-string v1, "Shutting down."

    .line 100
    .line 101
    invoke-virtual {p2, v0, v1}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {p0, v2}, Landroid/app/Service;->stopForeground(Z)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {p0, p1}, Landroid/app/Service;->stopSelf(I)V

    .line 108
    .line 109
    .line 110
    :cond_2
    return-void
.end method
