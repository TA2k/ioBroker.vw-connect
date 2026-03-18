.class public final Lcom/google/firebase/messaging/y;
.super Landroid/content/BroadcastReceiver;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public b:Landroid/content/Context;

.field public c:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lcom/google/firebase/messaging/y;->a:I

    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V

    return-void
.end method

.method public constructor <init>(Lb81/b;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lcom/google/firebase/messaging/y;->a:I

    .line 2
    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V

    iput-object p1, p0, Lcom/google/firebase/messaging/y;->c:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public a()V
    .locals 2

    .line 1
    const/4 v0, 0x3

    .line 2
    const-string v1, "FirebaseMessaging"

    .line 3
    .line 4
    invoke-static {v1, v0}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    const-string v0, "Connectivity change received registered"

    .line 11
    .line 12
    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 13
    .line 14
    .line 15
    :cond_0
    new-instance v0, Landroid/content/IntentFilter;

    .line 16
    .line 17
    const-string v1, "android.net.conn.CONNECTIVITY_CHANGE"

    .line 18
    .line 19
    invoke-direct {v0, v1}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iget-object v1, p0, Lcom/google/firebase/messaging/y;->c:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v1, Lcom/google/firebase/messaging/z;

    .line 25
    .line 26
    if-eqz v1, :cond_1

    .line 27
    .line 28
    iget-object v1, v1, Lcom/google/firebase/messaging/z;->g:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v1, Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 31
    .line 32
    iget-object v1, v1, Lcom/google/firebase/messaging/FirebaseMessaging;->b:Landroid/content/Context;

    .line 33
    .line 34
    iput-object v1, p0, Lcom/google/firebase/messaging/y;->b:Landroid/content/Context;

    .line 35
    .line 36
    invoke-virtual {v1, p0, v0}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;

    .line 37
    .line 38
    .line 39
    :cond_1
    return-void
.end method

.method public final onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 2

    .line 1
    iget p1, p0, Lcom/google/firebase/messaging/y;->a:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2}, Landroid/content/Intent;->getData()Landroid/net/Uri;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    const/4 p2, 0x0

    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    invoke-virtual {p1}, Landroid/net/Uri;->getSchemeSpecificPart()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move-object p1, p2

    .line 19
    :goto_0
    const-string v0, "com.google.android.gms"

    .line 20
    .line 21
    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    if-eqz p1, :cond_3

    .line 26
    .line 27
    iget-object p1, p0, Lcom/google/firebase/messaging/y;->c:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast p1, Lb81/b;

    .line 30
    .line 31
    iget-object v0, p1, Lb81/b;->f:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v0, Llr/b;

    .line 34
    .line 35
    iget-object v0, v0, Llr/b;->f:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v0, Llo/p;

    .line 38
    .line 39
    iget-object v1, v0, Llo/p;->f:Ljava/util/concurrent/atomic/AtomicReference;

    .line 40
    .line 41
    invoke-virtual {v1, p2}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    iget-object v0, v0, Llo/p;->j:Llo/g;

    .line 45
    .line 46
    iget-object v0, v0, Llo/g;->q:Lbp/c;

    .line 47
    .line 48
    const/4 v1, 0x3

    .line 49
    invoke-virtual {v0, v1}, Landroid/os/Handler;->obtainMessage(I)Landroid/os/Message;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    invoke-virtual {v0, v1}, Landroid/os/Handler;->sendMessage(Landroid/os/Message;)Z

    .line 54
    .line 55
    .line 56
    iget-object p1, p1, Lb81/b;->e:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast p1, Landroid/app/AlertDialog;

    .line 59
    .line 60
    invoke-virtual {p1}, Landroid/app/Dialog;->isShowing()Z

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    if-eqz v0, :cond_1

    .line 65
    .line 66
    invoke-virtual {p1}, Landroid/app/Dialog;->dismiss()V

    .line 67
    .line 68
    .line 69
    :cond_1
    monitor-enter p0

    .line 70
    :try_start_0
    iget-object p1, p0, Lcom/google/firebase/messaging/y;->b:Landroid/content/Context;

    .line 71
    .line 72
    if-eqz p1, :cond_2

    .line 73
    .line 74
    invoke-virtual {p1, p0}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V

    .line 75
    .line 76
    .line 77
    goto :goto_1

    .line 78
    :catchall_0
    move-exception p1

    .line 79
    goto :goto_2

    .line 80
    :cond_2
    :goto_1
    iput-object p2, p0, Lcom/google/firebase/messaging/y;->b:Landroid/content/Context;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 81
    .line 82
    monitor-exit p0

    .line 83
    goto :goto_3

    .line 84
    :goto_2
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 85
    throw p1

    .line 86
    :cond_3
    :goto_3
    return-void

    .line 87
    :pswitch_0
    const-string p1, "FirebaseMessaging"

    .line 88
    .line 89
    iget-object p2, p0, Lcom/google/firebase/messaging/y;->c:Ljava/lang/Object;

    .line 90
    .line 91
    check-cast p2, Lcom/google/firebase/messaging/z;

    .line 92
    .line 93
    if-nez p2, :cond_4

    .line 94
    .line 95
    goto :goto_4

    .line 96
    :cond_4
    invoke-virtual {p2}, Lcom/google/firebase/messaging/z;->a()Z

    .line 97
    .line 98
    .line 99
    move-result p2

    .line 100
    if-nez p2, :cond_5

    .line 101
    .line 102
    goto :goto_4

    .line 103
    :cond_5
    const/4 p2, 0x3

    .line 104
    invoke-static {p1, p2}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 105
    .line 106
    .line 107
    move-result p2

    .line 108
    if-eqz p2, :cond_6

    .line 109
    .line 110
    const-string p2, "Connectivity changed. Starting background sync."

    .line 111
    .line 112
    invoke-static {p1, p2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 113
    .line 114
    .line 115
    :cond_6
    iget-object p1, p0, Lcom/google/firebase/messaging/y;->c:Ljava/lang/Object;

    .line 116
    .line 117
    check-cast p1, Lcom/google/firebase/messaging/z;

    .line 118
    .line 119
    iget-object p2, p1, Lcom/google/firebase/messaging/z;->g:Ljava/lang/Object;

    .line 120
    .line 121
    check-cast p2, Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 122
    .line 123
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 124
    .line 125
    .line 126
    const-wide/16 v0, 0x0

    .line 127
    .line 128
    invoke-static {p1, v0, v1}, Lcom/google/firebase/messaging/FirebaseMessaging;->b(Ljava/lang/Runnable;J)V

    .line 129
    .line 130
    .line 131
    iget-object p1, p0, Lcom/google/firebase/messaging/y;->b:Landroid/content/Context;

    .line 132
    .line 133
    if-eqz p1, :cond_7

    .line 134
    .line 135
    invoke-virtual {p1, p0}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V

    .line 136
    .line 137
    .line 138
    :cond_7
    const/4 p1, 0x0

    .line 139
    iput-object p1, p0, Lcom/google/firebase/messaging/y;->c:Ljava/lang/Object;

    .line 140
    .line 141
    :goto_4
    return-void

    .line 142
    nop

    .line 143
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
