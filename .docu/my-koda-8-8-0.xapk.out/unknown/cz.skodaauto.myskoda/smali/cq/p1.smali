.class public final Lcq/p1;
.super Lcq/m1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final e:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(Lcq/l;Ljava/util/ArrayList;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lcq/m1;-><init>(Llo/e;)V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lcq/p1;->e:Ljava/util/ArrayList;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final K(Lcq/g1;)V
    .locals 5

    .line 1
    new-instance v0, Lcq/n;

    .line 2
    .line 3
    iget v1, p1, Lcq/g1;->d:I

    .line 4
    .line 5
    new-instance v2, Lcom/google/android/gms/common/api/Status;

    .line 6
    .line 7
    packed-switch v1, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    :pswitch_0
    invoke-static {v1}, Llp/xd;->a(I)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v3

    .line 14
    goto :goto_0

    .line 15
    :pswitch_1
    const-string v3, "WIFI_CONNECTION_FAILED"

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :pswitch_2
    const-string v3, "FEATURE_DISABLED"

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :pswitch_3
    const-string v3, "NO_MIGRATION_FOUND_TO_CANCEL"

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :pswitch_4
    const-string v3, "MIGRATION_NOT_CANCELLABLE"

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :pswitch_5
    const-string v3, "ACCOUNT_KEY_CREATION_FAILED"

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :pswitch_6
    const-string v3, "UNSUPPORTED_BY_TARGET"

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :pswitch_7
    const-string v3, "WIFI_CREDENTIAL_SYNC_NO_CREDENTIAL_FETCHED"

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :pswitch_8
    const-string v3, "UNKNOWN_CAPABILITY"

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :pswitch_9
    const-string v3, "DUPLICATE_CAPABILITY"

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :pswitch_a
    const-string v3, "ASSET_UNAVAILABLE"

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :pswitch_b
    const-string v3, "INVALID_TARGET_NODE"

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :pswitch_c
    const-string v3, "DATA_ITEM_TOO_LARGE"

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :pswitch_d
    const-string v3, "UNKNOWN_LISTENER"

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :pswitch_e
    const-string v3, "DUPLICATE_LISTENER"

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :pswitch_f
    const-string v3, "TARGET_NODE_NOT_CONNECTED"

    .line 58
    .line 59
    :goto_0
    const/4 v4, 0x0

    .line 60
    invoke-direct {v2, v1, v3, v4, v4}, Lcom/google/android/gms/common/api/Status;-><init>(ILjava/lang/String;Landroid/app/PendingIntent;Ljo/b;)V

    .line 61
    .line 62
    .line 63
    iget-object v1, p1, Lcq/g1;->e:Lcq/r;

    .line 64
    .line 65
    invoke-direct {v0, v2, v1}, Lcq/n;-><init>(Lcom/google/android/gms/common/api/Status;Lbq/b;)V

    .line 66
    .line 67
    .line 68
    iget-object v1, p0, Lcq/m1;->d:Llo/e;

    .line 69
    .line 70
    if-eqz v1, :cond_0

    .line 71
    .line 72
    invoke-interface {v1, v0}, Llo/e;->z(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    iput-object v4, p0, Lcq/m1;->d:Llo/e;

    .line 76
    .line 77
    :cond_0
    iget p1, p1, Lcq/g1;->d:I

    .line 78
    .line 79
    if-eqz p1, :cond_1

    .line 80
    .line 81
    iget-object p0, p0, Lcq/p1;->e:Ljava/util/ArrayList;

    .line 82
    .line 83
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 88
    .line 89
    .line 90
    move-result p1

    .line 91
    if-eqz p1, :cond_1

    .line 92
    .line 93
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object p1

    .line 97
    check-cast p1, Ljava/util/concurrent/FutureTask;

    .line 98
    .line 99
    const/4 v0, 0x1

    .line 100
    invoke-virtual {p1, v0}, Ljava/util/concurrent/FutureTask;->cancel(Z)Z

    .line 101
    .line 102
    .line 103
    goto :goto_1

    .line 104
    :cond_1
    return-void

    .line 105
    :pswitch_data_0
    .packed-switch 0xfa0
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method
