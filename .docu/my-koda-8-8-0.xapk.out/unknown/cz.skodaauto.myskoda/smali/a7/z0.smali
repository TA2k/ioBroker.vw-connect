.class public abstract La7/z0;
.super Landroid/appwidget/AppWidgetProvider;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lcz0/e;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Landroid/appwidget/AppWidgetProvider;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lvy0/p0;->a:Lcz0/e;

    .line 5
    .line 6
    iput-object v0, p0, La7/z0;->d:Lcz0/e;

    .line 7
    .line 8
    return-void
.end method

.method public static final a(La7/z0;Lvy0/b0;Landroid/content/Context;)V
    .locals 3

    .line 1
    new-instance v0, La50/c;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v1, p2, p0, v2}, La50/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 6
    .line 7
    .line 8
    const/4 p0, 0x3

    .line 9
    invoke-static {p1, v2, v2, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final onAppWidgetOptionsChanged(Landroid/content/Context;Landroid/appwidget/AppWidgetManager;ILandroid/os/Bundle;)V
    .locals 7

    .line 1
    new-instance v0, La7/w0;

    .line 2
    .line 3
    const/4 v5, 0x0

    .line 4
    const/4 v6, 0x0

    .line 5
    move-object v1, p0

    .line 6
    move-object v2, p1

    .line 7
    move v3, p3

    .line 8
    move-object v4, p4

    .line 9
    invoke-direct/range {v0 .. v6}, La7/w0;-><init>(La7/z0;Landroid/content/Context;ILjava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 10
    .line 11
    .line 12
    iget-object p0, v1, La7/z0;->d:Lcz0/e;

    .line 13
    .line 14
    invoke-static {v1, p0, v0}, Lfb/w;->d(Landroid/content/BroadcastReceiver;Lpx0/g;Lay0/n;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public final onDeleted(Landroid/content/Context;[I)V
    .locals 2

    .line 1
    new-instance v0, La7/x0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, p1, p2, v1}, La7/x0;-><init>(La7/z0;Landroid/content/Context;[ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    iget-object p1, p0, La7/z0;->d:Lcz0/e;

    .line 8
    .line 9
    invoke-static {p0, p1, v0}, Lfb/w;->d(Landroid/content/BroadcastReceiver;Lpx0/g;Lay0/n;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public final onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 8

    .line 1
    const-string v0, "appWidgetIds"

    .line 2
    .line 3
    :try_start_0
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    const v3, -0x122164c

    .line 14
    .line 15
    .line 16
    if-eq v2, v3, :cond_6

    .line 17
    .line 18
    const v3, 0x26af776f

    .line 19
    .line 20
    .line 21
    if-eq v2, v3, :cond_5

    .line 22
    .line 23
    const v0, 0x76997177

    .line 24
    .line 25
    .line 26
    if-eq v2, v0, :cond_1

    .line 27
    .line 28
    :cond_0
    :goto_0
    move-object v2, p0

    .line 29
    move-object v3, p1

    .line 30
    goto/16 :goto_2

    .line 31
    .line 32
    :cond_1
    const-string v0, "ACTION_TRIGGER_LAMBDA"

    .line 33
    .line 34
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    if-nez v0, :cond_2

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_2
    const-string v0, "EXTRA_ACTION_KEY"

    .line 42
    .line 43
    invoke-virtual {p2, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v5

    .line 47
    if-eqz v5, :cond_4

    .line 48
    .line 49
    const-string v0, "EXTRA_APPWIDGET_ID"

    .line 50
    .line 51
    const/4 v1, -0x1

    .line 52
    invoke-virtual {p2, v0, v1}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 53
    .line 54
    .line 55
    move-result v4

    .line 56
    if-eq v4, v1, :cond_3

    .line 57
    .line 58
    iget-object p2, p0, La7/z0;->d:Lcz0/e;

    .line 59
    .line 60
    new-instance v1, La7/w0;

    .line 61
    .line 62
    const/4 v6, 0x0

    .line 63
    const/4 v7, 0x1

    .line 64
    move-object v2, p0

    .line 65
    move-object v3, p1

    .line 66
    invoke-direct/range {v1 .. v7}, La7/w0;-><init>(La7/z0;Landroid/content/Context;ILjava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 67
    .line 68
    .line 69
    invoke-static {v2, p2, v1}, Lfb/w;->d(Landroid/content/BroadcastReceiver;Lpx0/g;Lay0/n;)V

    .line 70
    .line 71
    .line 72
    return-void

    .line 73
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 74
    .line 75
    const-string p1, "Intent is missing AppWidgetId extra"

    .line 76
    .line 77
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    throw p0

    .line 81
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 82
    .line 83
    const-string p1, "Intent is missing ActionKey extra"

    .line 84
    .line 85
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    throw p0

    .line 89
    :cond_5
    move-object v2, p0

    .line 90
    move-object v3, p1

    .line 91
    const-string p0, "androidx.glance.appwidget.action.DEBUG_UPDATE"

    .line 92
    .line 93
    invoke-virtual {v1, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result p0

    .line 97
    if-nez p0, :cond_7

    .line 98
    .line 99
    goto :goto_2

    .line 100
    :cond_6
    move-object v2, p0

    .line 101
    move-object v3, p1

    .line 102
    const-string p0, "android.intent.action.LOCALE_CHANGED"

    .line 103
    .line 104
    invoke-virtual {v1, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result p0

    .line 108
    if-nez p0, :cond_7

    .line 109
    .line 110
    goto :goto_2

    .line 111
    :cond_7
    invoke-static {v3}, Landroid/appwidget/AppWidgetManager;->getInstance(Landroid/content/Context;)Landroid/appwidget/AppWidgetManager;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    invoke-virtual {v3}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object p1

    .line 119
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 120
    .line 121
    .line 122
    move-result-object v1

    .line 123
    invoke-virtual {v1}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object v1

    .line 127
    if-eqz v1, :cond_9

    .line 128
    .line 129
    new-instance v4, Landroid/content/ComponentName;

    .line 130
    .line 131
    invoke-direct {v4, p1, v1}, Landroid/content/ComponentName;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    invoke-virtual {p2, v0}, Landroid/content/Intent;->hasExtra(Ljava/lang/String;)Z

    .line 135
    .line 136
    .line 137
    move-result p1

    .line 138
    if-eqz p1, :cond_8

    .line 139
    .line 140
    invoke-virtual {p2, v0}, Landroid/content/Intent;->getIntArrayExtra(Ljava/lang/String;)[I

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    goto :goto_1

    .line 148
    :cond_8
    invoke-virtual {p0, v4}, Landroid/appwidget/AppWidgetManager;->getAppWidgetIds(Landroid/content/ComponentName;)[I

    .line 149
    .line 150
    .line 151
    move-result-object p1

    .line 152
    :goto_1
    invoke-virtual {v2, v3, p0, p1}, La7/z0;->onUpdate(Landroid/content/Context;Landroid/appwidget/AppWidgetManager;[I)V

    .line 153
    .line 154
    .line 155
    return-void

    .line 156
    :cond_9
    const-string p0, "no canonical name"

    .line 157
    .line 158
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 159
    .line 160
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 161
    .line 162
    .line 163
    throw p1

    .line 164
    :goto_2
    invoke-super {v2, v3, p2}, Landroid/appwidget/AppWidgetProvider;->onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 165
    .line 166
    .line 167
    return-void

    .line 168
    :catchall_0
    move-exception v0

    .line 169
    move-object p0, v0

    .line 170
    const-string p1, "GlanceAppWidget"

    .line 171
    .line 172
    const-string p2, "Error in Glance App Widget"

    .line 173
    .line 174
    invoke-static {p1, p2, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 175
    .line 176
    .line 177
    :catch_0
    return-void
.end method

.method public onUpdate(Landroid/content/Context;Landroid/appwidget/AppWidgetManager;[I)V
    .locals 6

    .line 1
    new-instance v0, La7/k;

    .line 2
    .line 3
    const/4 v5, 0x0

    .line 4
    const/4 v1, 0x2

    .line 5
    move-object v2, p0

    .line 6
    move-object v3, p1

    .line 7
    move-object v4, p3

    .line 8
    invoke-direct/range {v0 .. v5}, La7/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, v2, La7/z0;->d:Lcz0/e;

    .line 12
    .line 13
    invoke-static {v2, p0, v0}, Lfb/w;->d(Landroid/content/BroadcastReceiver;Lpx0/g;Lay0/n;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method
