.class public final synthetic Lcom/google/firebase/messaging/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lcom/google/firebase/messaging/FirebaseMessaging;

.field public final synthetic f:Laq/k;


# direct methods
.method public synthetic constructor <init>(Lcom/google/firebase/messaging/FirebaseMessaging;Laq/k;I)V
    .locals 0

    .line 1
    iput p3, p0, Lcom/google/firebase/messaging/m;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lcom/google/firebase/messaging/m;->e:Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 4
    .line 5
    iput-object p2, p0, Lcom/google/firebase/messaging/m;->f:Laq/k;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 5

    .line 1
    iget v0, p0, Lcom/google/firebase/messaging/m;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/google/firebase/messaging/m;->e:Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 7
    .line 8
    iget-object p0, p0, Lcom/google/firebase/messaging/m;->f:Laq/k;

    .line 9
    .line 10
    sget-object v1, Lcom/google/firebase/messaging/FirebaseMessaging;->k:La0/j;

    .line 11
    .line 12
    :try_start_0
    iget-object v1, v0, Lcom/google/firebase/messaging/FirebaseMessaging;->c:Lin/z1;

    .line 13
    .line 14
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    new-instance v2, Landroid/os/Bundle;

    .line 18
    .line 19
    invoke-direct {v2}, Landroid/os/Bundle;-><init>()V

    .line 20
    .line 21
    .line 22
    const-string v3, "delete"

    .line 23
    .line 24
    const-string v4, "1"

    .line 25
    .line 26
    invoke-virtual {v2, v3, v4}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    iget-object v3, v1, Lin/z1;->a:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v3, Lsr/f;

    .line 32
    .line 33
    invoke-static {v3}, Lcom/google/firebase/messaging/r;->c(Lsr/f;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v3

    .line 37
    const-string v4, "*"

    .line 38
    .line 39
    invoke-virtual {v1, v3, v4, v2}, Lin/z1;->d0(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)Laq/t;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    invoke-virtual {v1, v2}, Lin/z1;->y(Laq/t;)Laq/t;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    invoke-static {v1}, Ljp/l1;->a(Laq/j;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    iget-object v1, v0, Lcom/google/firebase/messaging/FirebaseMessaging;->b:Landroid/content/Context;

    .line 51
    .line 52
    invoke-static {v1}, Lcom/google/firebase/messaging/FirebaseMessaging;->d(Landroid/content/Context;)La0/j;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    invoke-virtual {v0}, Lcom/google/firebase/messaging/FirebaseMessaging;->e()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    iget-object v0, v0, Lcom/google/firebase/messaging/FirebaseMessaging;->a:Lsr/f;

    .line 61
    .line 62
    invoke-static {v0}, Lcom/google/firebase/messaging/r;->c(Lsr/f;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    monitor-enter v1
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 67
    :try_start_1
    invoke-static {v2, v0}, La0/j;->U(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    iget-object v2, v1, La0/j;->e:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast v2, Landroid/content/SharedPreferences;

    .line 74
    .line 75
    invoke-interface {v2}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    invoke-interface {v2, v0}, Landroid/content/SharedPreferences$Editor;->remove(Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 80
    .line 81
    .line 82
    invoke-interface {v2}, Landroid/content/SharedPreferences$Editor;->commit()Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 83
    .line 84
    .line 85
    :try_start_2
    monitor-exit v1

    .line 86
    const/4 v0, 0x0

    .line 87
    invoke-virtual {p0, v0}, Laq/k;->b(Ljava/lang/Object;)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    .line 88
    .line 89
    .line 90
    goto :goto_1

    .line 91
    :catch_0
    move-exception v0

    .line 92
    goto :goto_0

    .line 93
    :catchall_0
    move-exception v0

    .line 94
    :try_start_3
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 95
    :try_start_4
    throw v0
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_0

    .line 96
    :goto_0
    invoke-virtual {p0, v0}, Laq/k;->a(Ljava/lang/Exception;)V

    .line 97
    .line 98
    .line 99
    :goto_1
    return-void

    .line 100
    :pswitch_0
    iget-object v0, p0, Lcom/google/firebase/messaging/m;->e:Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 101
    .line 102
    iget-object p0, p0, Lcom/google/firebase/messaging/m;->f:Laq/k;

    .line 103
    .line 104
    sget-object v1, Lcom/google/firebase/messaging/FirebaseMessaging;->k:La0/j;

    .line 105
    .line 106
    :try_start_5
    invoke-virtual {v0}, Lcom/google/firebase/messaging/FirebaseMessaging;->a()Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object v0

    .line 110
    invoke-virtual {p0, v0}, Laq/k;->b(Ljava/lang/Object;)V
    :try_end_5
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_1

    .line 111
    .line 112
    .line 113
    goto :goto_2

    .line 114
    :catch_1
    move-exception v0

    .line 115
    invoke-virtual {p0, v0}, Laq/k;->a(Ljava/lang/Exception;)V

    .line 116
    .line 117
    .line 118
    :goto_2
    return-void

    .line 119
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
