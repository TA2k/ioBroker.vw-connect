.class public final Lk61/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Closeable;


# instance fields
.field public final d:Landroid/content/Context;

.field public final e:Lyy0/c2;

.field public final f:Lyy0/l1;

.field public final g:Lc8/e;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 6

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk61/b;->d:Landroid/content/Context;

    .line 5
    .line 6
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 7
    .line 8
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iput-object v0, p0, Lk61/b;->e:Lyy0/c2;

    .line 13
    .line 14
    new-instance v1, Lyy0/l1;

    .line 15
    .line 16
    invoke-direct {v1, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 17
    .line 18
    .line 19
    iput-object v1, p0, Lk61/b;->f:Lyy0/l1;

    .line 20
    .line 21
    new-instance v1, Lc8/e;

    .line 22
    .line 23
    const/4 v2, 0x2

    .line 24
    invoke-direct {v1, p0, v2}, Lc8/e;-><init>(Ljava/lang/Object;I)V

    .line 25
    .line 26
    .line 27
    iput-object v1, p0, Lk61/b;->g:Lc8/e;

    .line 28
    .line 29
    const-string v2, "bluetooth"

    .line 30
    .line 31
    invoke-virtual {p1, v2}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    instance-of v3, v2, Landroid/bluetooth/BluetoothManager;

    .line 36
    .line 37
    const/4 v4, 0x0

    .line 38
    if-eqz v3, :cond_0

    .line 39
    .line 40
    check-cast v2, Landroid/bluetooth/BluetoothManager;

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    move-object v2, v4

    .line 44
    :goto_0
    const/4 v3, 0x0

    .line 45
    if-eqz v2, :cond_1

    .line 46
    .line 47
    invoke-virtual {v2}, Landroid/bluetooth/BluetoothManager;->getAdapter()Landroid/bluetooth/BluetoothAdapter;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    if-eqz v2, :cond_1

    .line 52
    .line 53
    invoke-virtual {v2}, Landroid/bluetooth/BluetoothAdapter;->isEnabled()Z

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    const/4 v5, 0x1

    .line 58
    if-ne v2, v5, :cond_1

    .line 59
    .line 60
    move v3, v5

    .line 61
    :cond_1
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    invoke-virtual {v0, v4, v2}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    :try_start_0
    new-instance v0, Landroid/content/IntentFilter;

    .line 69
    .line 70
    const-string v2, "android.bluetooth.adapter.action.STATE_CHANGED"

    .line 71
    .line 72
    invoke-direct {v0, v2}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {p1, v1, v0}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;

    .line 76
    .line 77
    .line 78
    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 79
    goto :goto_1

    .line 80
    :catchall_0
    move-exception p1

    .line 81
    invoke-static {p1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    :goto_1
    invoke-static {p1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 86
    .line 87
    .line 88
    move-result-object p1

    .line 89
    if-eqz p1, :cond_2

    .line 90
    .line 91
    new-instance v0, Lbp0/e;

    .line 92
    .line 93
    const/4 v1, 0x4

    .line 94
    invoke-direct {v0, p1, v1}, Lbp0/e;-><init>(Ljava/lang/Throwable;I)V

    .line 95
    .line 96
    .line 97
    invoke-static {p0, v0}, Llp/i1;->f(Ljava/lang/Object;Lay0/a;)V

    .line 98
    .line 99
    .line 100
    :cond_2
    return-void
.end method


# virtual methods
.method public final close()V
    .locals 2

    .line 1
    new-instance v0, Lqf0/d;

    .line 2
    .line 3
    const/16 v1, 0x18

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lqf0/d;-><init>(I)V

    .line 6
    .line 7
    .line 8
    invoke-static {p0, v0}, Llp/i1;->e(Ljava/lang/Object;Lay0/a;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Ljv0/c;

    .line 12
    .line 13
    const/4 v1, 0x3

    .line 14
    invoke-direct {v0, v1}, Ljv0/c;-><init>(I)V

    .line 15
    .line 16
    .line 17
    invoke-static {p0, v0}, Llp/i1;->e(Ljava/lang/Object;Lay0/a;)V

    .line 18
    .line 19
    .line 20
    :try_start_0
    iget-object v0, p0, Lk61/b;->d:Landroid/content/Context;

    .line 21
    .line 22
    iget-object p0, p0, Lk61/b;->g:Lc8/e;

    .line 23
    .line 24
    invoke-virtual {v0, p0}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :catchall_0
    move-exception p0

    .line 29
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 30
    .line 31
    .line 32
    return-void
.end method
