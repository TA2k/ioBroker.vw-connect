.class public final Lbp/l;
.super Llp/wd;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lbp/l;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public a(Landroid/content/Context;Landroid/os/Looper;Lin/z1;Ljava/lang/Object;Lko/j;Lko/k;)Lko/c;
    .locals 7

    .line 1
    iget v0, p0, Lbp/l;->a:I

    .line 2
    .line 3
    sparse-switch v0, :sswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super/range {p0 .. p6}, Llp/wd;->a(Landroid/content/Context;Landroid/os/Looper;Lin/z1;Ljava/lang/Object;Lko/j;Lko/k;)Lko/c;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :sswitch_0
    invoke-static {p4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->i(Ljava/lang/Object;)Ljava/lang/ClassCastException;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    throw p0

    .line 16
    :sswitch_1
    check-cast p4, Lxp/a;

    .line 17
    .line 18
    new-instance v0, Lyp/a;

    .line 19
    .line 20
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    iget-object p0, p3, Lin/z1;->f:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast p0, Ljava/lang/Integer;

    .line 26
    .line 27
    new-instance v4, Landroid/os/Bundle;

    .line 28
    .line 29
    invoke-direct {v4}, Landroid/os/Bundle;-><init>()V

    .line 30
    .line 31
    .line 32
    const-string p4, "com.google.android.gms.signin.internal.clientRequestedAccount"

    .line 33
    .line 34
    const/4 v1, 0x0

    .line 35
    invoke-virtual {v4, p4, v1}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 36
    .line 37
    .line 38
    if-eqz p0, :cond_0

    .line 39
    .line 40
    const-string p4, "com.google.android.gms.common.internal.ClientSettings.sessionId"

    .line 41
    .line 42
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    invoke-virtual {v4, p4, p0}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 47
    .line 48
    .line 49
    :cond_0
    const-string p0, "com.google.android.gms.signin.internal.offlineAccessRequested"

    .line 50
    .line 51
    const/4 p4, 0x0

    .line 52
    invoke-virtual {v4, p0, p4}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 53
    .line 54
    .line 55
    const-string p0, "com.google.android.gms.signin.internal.idTokenRequested"

    .line 56
    .line 57
    invoke-virtual {v4, p0, p4}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 58
    .line 59
    .line 60
    const-string p0, "com.google.android.gms.signin.internal.serverClientId"

    .line 61
    .line 62
    invoke-virtual {v4, p0, v1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    const-string p0, "com.google.android.gms.signin.internal.usePromptModeForAuthCode"

    .line 66
    .line 67
    const/4 v2, 0x1

    .line 68
    invoke-virtual {v4, p0, v2}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 69
    .line 70
    .line 71
    const-string p0, "com.google.android.gms.signin.internal.forceCodeForRefreshToken"

    .line 72
    .line 73
    invoke-virtual {v4, p0, p4}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 74
    .line 75
    .line 76
    const-string p0, "com.google.android.gms.signin.internal.hostedDomain"

    .line 77
    .line 78
    invoke-virtual {v4, p0, v1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    const-string p0, "com.google.android.gms.signin.internal.logSessionId"

    .line 82
    .line 83
    invoke-virtual {v4, p0, v1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    const-string p0, "com.google.android.gms.signin.internal.waitForAccessTokenRefresh"

    .line 87
    .line 88
    invoke-virtual {v4, p0, p4}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 89
    .line 90
    .line 91
    move-object v1, p1

    .line 92
    move-object v2, p2

    .line 93
    move-object v3, p3

    .line 94
    move-object v5, p5

    .line 95
    move-object v6, p6

    .line 96
    invoke-direct/range {v0 .. v6}, Lyp/a;-><init>(Landroid/content/Context;Landroid/os/Looper;Lin/z1;Landroid/os/Bundle;Lko/j;Lko/k;)V

    .line 97
    .line 98
    .line 99
    return-object v0

    .line 100
    :sswitch_2
    check-cast p4, Lbq/f;

    .line 101
    .line 102
    move-object v1, p1

    .line 103
    new-instance p1, Lcq/t1;

    .line 104
    .line 105
    check-cast p5, Llo/s;

    .line 106
    .line 107
    check-cast p6, Llo/s;

    .line 108
    .line 109
    move-object p4, p3

    .line 110
    move-object p3, p2

    .line 111
    move-object p2, v1

    .line 112
    invoke-direct/range {p1 .. p6}, Lcq/t1;-><init>(Landroid/content/Context;Landroid/os/Looper;Lin/z1;Llo/s;Llo/s;)V

    .line 113
    .line 114
    .line 115
    return-object p1

    .line 116
    nop

    .line 117
    :sswitch_data_0
    .sparse-switch
        0x2 -> :sswitch_2
        0x7 -> :sswitch_1
        0x8 -> :sswitch_0
    .end sparse-switch
.end method

.method public b(Landroid/content/Context;Landroid/os/Looper;Lin/z1;Ljava/lang/Object;Llo/s;Llo/s;)Lko/c;
    .locals 8

    .line 1
    iget v0, p0, Lbp/l;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    :pswitch_0
    invoke-super/range {p0 .. p6}, Llp/wd;->b(Landroid/content/Context;Landroid/os/Looper;Lin/z1;Ljava/lang/Object;Llo/s;Llo/s;)Lko/c;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_1
    move-object v1, p1

    .line 12
    move-object v2, p2

    .line 13
    move-object v4, p3

    .line 14
    move-object v5, p5

    .line 15
    move-object v6, p6

    .line 16
    check-cast p4, Lko/a;

    .line 17
    .line 18
    new-instance v0, Lxo/i;

    .line 19
    .line 20
    const/16 v3, 0x121

    .line 21
    .line 22
    const/4 v7, 0x0

    .line 23
    invoke-direct/range {v0 .. v7}, Lno/i;-><init>(Landroid/content/Context;Landroid/os/Looper;ILin/z1;Lko/j;Lko/k;I)V

    .line 24
    .line 25
    .line 26
    return-object v0

    .line 27
    :pswitch_2
    move-object v1, p1

    .line 28
    move-object v2, p2

    .line 29
    move-object v4, p3

    .line 30
    move-object v5, p5

    .line 31
    move-object v6, p6

    .line 32
    check-cast p4, Lko/a;

    .line 33
    .line 34
    new-instance v0, Lro/i;

    .line 35
    .line 36
    const/16 v3, 0x134

    .line 37
    .line 38
    const/4 v7, 0x0

    .line 39
    invoke-direct/range {v0 .. v7}, Lno/i;-><init>(Landroid/content/Context;Landroid/os/Looper;ILin/z1;Lko/j;Lko/k;I)V

    .line 40
    .line 41
    .line 42
    return-object v0

    .line 43
    :pswitch_3
    move-object v1, p1

    .line 44
    move-object v2, p2

    .line 45
    move-object v4, p3

    .line 46
    move-object v5, p5

    .line 47
    move-object v6, p6

    .line 48
    check-cast p4, Lno/q;

    .line 49
    .line 50
    new-instance v0, Lpo/c;

    .line 51
    .line 52
    move-object v3, v4

    .line 53
    move-object v4, p4

    .line 54
    invoke-direct/range {v0 .. v6}, Lpo/c;-><init>(Landroid/content/Context;Landroid/os/Looper;Lin/z1;Lno/q;Llo/s;Llo/s;)V

    .line 55
    .line 56
    .line 57
    return-object v0

    .line 58
    :pswitch_4
    move-object v1, p1

    .line 59
    move-object v2, p2

    .line 60
    move-object v4, p3

    .line 61
    move-object v5, p5

    .line 62
    move-object v6, p6

    .line 63
    check-cast p4, Lko/a;

    .line 64
    .line 65
    new-instance p1, Lgp/f;

    .line 66
    .line 67
    move-object p2, v1

    .line 68
    move-object p3, v2

    .line 69
    move-object p4, v4

    .line 70
    invoke-direct/range {p1 .. p6}, Lgp/f;-><init>(Landroid/content/Context;Landroid/os/Looper;Lin/z1;Llo/s;Llo/s;)V

    .line 71
    .line 72
    .line 73
    return-object p1

    .line 74
    :pswitch_5
    move-object v1, p1

    .line 75
    move-object v2, p2

    .line 76
    move-object v4, p3

    .line 77
    move-object v5, p5

    .line 78
    move-object v6, p6

    .line 79
    check-cast p4, Lko/a;

    .line 80
    .line 81
    new-instance v0, Lbp/w;

    .line 82
    .line 83
    const/16 v3, 0x71

    .line 84
    .line 85
    const/4 v7, 0x0

    .line 86
    invoke-direct/range {v0 .. v7}, Lno/i;-><init>(Landroid/content/Context;Landroid/os/Looper;ILin/z1;Lko/j;Lko/k;I)V

    .line 87
    .line 88
    .line 89
    return-object v0

    .line 90
    :pswitch_6
    move-object v1, p1

    .line 91
    move-object v2, p2

    .line 92
    move-object v4, p3

    .line 93
    move-object v5, p5

    .line 94
    move-object v6, p6

    .line 95
    check-cast p4, Lko/a;

    .line 96
    .line 97
    new-instance v0, Lbp/o;

    .line 98
    .line 99
    const/16 v3, 0x13

    .line 100
    .line 101
    const/4 v7, 0x0

    .line 102
    invoke-direct/range {v0 .. v7}, Lno/i;-><init>(Landroid/content/Context;Landroid/os/Looper;ILin/z1;Lko/j;Lko/k;I)V

    .line 103
    .line 104
    .line 105
    return-object v0

    .line 106
    nop

    .line 107
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method
