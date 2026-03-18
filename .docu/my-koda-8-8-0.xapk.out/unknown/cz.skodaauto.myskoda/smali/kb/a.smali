.class public final Lkb/a;
.super Lh2/s;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Lc8/e;

.field public final synthetic g:I


# direct methods
.method public constructor <init>(Landroid/content/Context;Lob/a;I)V
    .locals 0

    .line 1
    iput p3, p0, Lkb/a;->g:I

    .line 2
    .line 3
    invoke-direct {p0, p1, p2}, Lh2/s;-><init>(Landroid/content/Context;Lob/a;)V

    .line 4
    .line 5
    .line 6
    new-instance p1, Lc8/e;

    .line 7
    .line 8
    const/4 p2, 0x3

    .line 9
    invoke-direct {p1, p0, p2}, Lc8/e;-><init>(Ljava/lang/Object;I)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lkb/a;->f:Lc8/e;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a()Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lkb/a;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh2/s;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Landroid/content/Context;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    invoke-virtual {p0}, Lkb/a;->f()Landroid/content/IntentFilter;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-virtual {v0, v1, p0}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    const/4 v0, 0x1

    .line 20
    if-eqz p0, :cond_4

    .line 21
    .line 22
    invoke-virtual {p0}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    if-nez v1, :cond_0

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_0
    invoke-virtual {p0}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    const/4 v1, 0x0

    .line 34
    if-eqz p0, :cond_3

    .line 35
    .line 36
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    const v3, -0x46671f94

    .line 41
    .line 42
    .line 43
    if-eq v2, v3, :cond_2

    .line 44
    .line 45
    const v3, -0x2b8fb65c

    .line 46
    .line 47
    .line 48
    if-eq v2, v3, :cond_1

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_1
    const-string v2, "android.intent.action.DEVICE_STORAGE_OK"

    .line 52
    .line 53
    invoke-virtual {p0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    if-nez p0, :cond_4

    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_2
    const-string v0, "android.intent.action.DEVICE_STORAGE_LOW"

    .line 61
    .line 62
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result p0

    .line 66
    :cond_3
    :goto_0
    move v0, v1

    .line 67
    :cond_4
    :goto_1
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    return-object p0

    .line 72
    :pswitch_0
    new-instance v0, Landroid/content/IntentFilter;

    .line 73
    .line 74
    const-string v1, "android.intent.action.BATTERY_CHANGED"

    .line 75
    .line 76
    invoke-direct {v0, v1}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    iget-object p0, p0, Lh2/s;->b:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast p0, Landroid/content/Context;

    .line 82
    .line 83
    const/4 v1, 0x0

    .line 84
    invoke-virtual {p0, v1, v0}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    if-nez p0, :cond_5

    .line 89
    .line 90
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    sget-object v0, Lkb/c;->a:Ljava/lang/String;

    .line 95
    .line 96
    const-string v1, "getInitialState - null intent received"

    .line 97
    .line 98
    invoke-virtual {p0, v0, v1}, Leb/w;->b(Ljava/lang/String;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 102
    .line 103
    goto :goto_3

    .line 104
    :cond_5
    const-string v0, "status"

    .line 105
    .line 106
    const/4 v1, -0x1

    .line 107
    invoke-virtual {p0, v0, v1}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 108
    .line 109
    .line 110
    move-result v0

    .line 111
    const-string v2, "level"

    .line 112
    .line 113
    invoke-virtual {p0, v2, v1}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 114
    .line 115
    .line 116
    move-result v2

    .line 117
    const-string v3, "scale"

    .line 118
    .line 119
    invoke-virtual {p0, v3, v1}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 120
    .line 121
    .line 122
    move-result p0

    .line 123
    int-to-float v1, v2

    .line 124
    int-to-float p0, p0

    .line 125
    div-float/2addr v1, p0

    .line 126
    const/4 p0, 0x1

    .line 127
    if-eq v0, p0, :cond_7

    .line 128
    .line 129
    const v0, 0x3e19999a    # 0.15f

    .line 130
    .line 131
    .line 132
    cmpl-float v0, v1, v0

    .line 133
    .line 134
    if-lez v0, :cond_6

    .line 135
    .line 136
    goto :goto_2

    .line 137
    :cond_6
    const/4 p0, 0x0

    .line 138
    :cond_7
    :goto_2
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    :goto_3
    return-object p0

    .line 143
    :pswitch_1
    new-instance v0, Landroid/content/IntentFilter;

    .line 144
    .line 145
    const-string v1, "android.intent.action.BATTERY_CHANGED"

    .line 146
    .line 147
    invoke-direct {v0, v1}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    iget-object p0, p0, Lh2/s;->b:Ljava/lang/Object;

    .line 151
    .line 152
    check-cast p0, Landroid/content/Context;

    .line 153
    .line 154
    const/4 v1, 0x0

    .line 155
    invoke-virtual {p0, v1, v0}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    if-nez p0, :cond_8

    .line 160
    .line 161
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    sget-object v0, Lkb/b;->a:Ljava/lang/String;

    .line 166
    .line 167
    const-string v1, "getInitialState - null intent received"

    .line 168
    .line 169
    invoke-virtual {p0, v0, v1}, Leb/w;->b(Ljava/lang/String;Ljava/lang/String;)V

    .line 170
    .line 171
    .line 172
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 173
    .line 174
    goto :goto_6

    .line 175
    :cond_8
    const-string v0, "status"

    .line 176
    .line 177
    const/4 v1, -0x1

    .line 178
    invoke-virtual {p0, v0, v1}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 179
    .line 180
    .line 181
    move-result p0

    .line 182
    const/4 v0, 0x2

    .line 183
    if-eq p0, v0, :cond_a

    .line 184
    .line 185
    const/4 v0, 0x5

    .line 186
    if-ne p0, v0, :cond_9

    .line 187
    .line 188
    goto :goto_4

    .line 189
    :cond_9
    const/4 p0, 0x0

    .line 190
    goto :goto_5

    .line 191
    :cond_a
    :goto_4
    const/4 p0, 0x1

    .line 192
    :goto_5
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 193
    .line 194
    .line 195
    move-result-object p0

    .line 196
    :goto_6
    return-object p0

    .line 197
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final d()V
    .locals 4

    .line 1
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget-object v1, Lkb/d;->a:Ljava/lang/String;

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    invoke-virtual {v2}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    const-string v3, ": registering receiver"

    .line 16
    .line 17
    invoke-virtual {v2, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    invoke-virtual {v0, v1, v2}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    iget-object v0, p0, Lh2/s;->b:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v0, Landroid/content/Context;

    .line 27
    .line 28
    iget-object v1, p0, Lkb/a;->f:Lc8/e;

    .line 29
    .line 30
    invoke-virtual {p0}, Lkb/a;->f()Landroid/content/IntentFilter;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-virtual {v0, v1, p0}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method public final e()V
    .locals 4

    .line 1
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget-object v1, Lkb/d;->a:Ljava/lang/String;

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    invoke-virtual {v2}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    const-string v3, ": unregistering receiver"

    .line 16
    .line 17
    invoke-virtual {v2, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    invoke-virtual {v0, v1, v2}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    iget-object v0, p0, Lh2/s;->b:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v0, Landroid/content/Context;

    .line 27
    .line 28
    iget-object p0, p0, Lkb/a;->f:Lc8/e;

    .line 29
    .line 30
    invoke-virtual {v0, p0}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V

    .line 31
    .line 32
    .line 33
    return-void
.end method

.method public final f()Landroid/content/IntentFilter;
    .locals 1

    .line 1
    iget p0, p0, Lkb/a;->g:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Landroid/content/IntentFilter;

    .line 7
    .line 8
    invoke-direct {p0}, Landroid/content/IntentFilter;-><init>()V

    .line 9
    .line 10
    .line 11
    const-string v0, "android.intent.action.DEVICE_STORAGE_OK"

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "android.intent.action.DEVICE_STORAGE_LOW"

    .line 17
    .line 18
    invoke-virtual {p0, v0}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    return-object p0

    .line 22
    :pswitch_0
    new-instance p0, Landroid/content/IntentFilter;

    .line 23
    .line 24
    invoke-direct {p0}, Landroid/content/IntentFilter;-><init>()V

    .line 25
    .line 26
    .line 27
    const-string v0, "android.intent.action.BATTERY_OKAY"

    .line 28
    .line 29
    invoke-virtual {p0, v0}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    const-string v0, "android.intent.action.BATTERY_LOW"

    .line 33
    .line 34
    invoke-virtual {p0, v0}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    return-object p0

    .line 38
    :pswitch_1
    new-instance p0, Landroid/content/IntentFilter;

    .line 39
    .line 40
    invoke-direct {p0}, Landroid/content/IntentFilter;-><init>()V

    .line 41
    .line 42
    .line 43
    const-string v0, "android.os.action.CHARGING"

    .line 44
    .line 45
    invoke-virtual {p0, v0}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    const-string v0, "android.os.action.DISCHARGING"

    .line 49
    .line 50
    invoke-virtual {p0, v0}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    return-object p0

    .line 54
    nop

    .line 55
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
