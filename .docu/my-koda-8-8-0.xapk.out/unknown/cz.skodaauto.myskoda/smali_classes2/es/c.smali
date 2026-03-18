.class public final synthetic Les/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Laq/i;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Les/d;


# direct methods
.method public synthetic constructor <init>(Les/d;I)V
    .locals 0

    .line 1
    iput p2, p0, Les/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Les/c;->e:Les/d;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final g(Ljava/lang/Object;)Laq/t;
    .locals 9

    .line 1
    iget v0, p0, Les/c;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iget-object p0, p0, Les/c;->e:Les/d;

    .line 5
    .line 6
    packed-switch v0, :pswitch_data_0

    .line 7
    .line 8
    .line 9
    check-cast p1, Les/b;

    .line 10
    .line 11
    iget-object v0, p0, Les/d;->b:Lcr/b;

    .line 12
    .line 13
    iget-object p0, p0, Les/d;->a:Ljava/lang/String;

    .line 14
    .line 15
    invoke-static {p0}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 16
    .line 17
    .line 18
    move-result-wide v2

    .line 19
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    iget-object p1, p1, Les/b;->a:Ljava/lang/String;

    .line 24
    .line 25
    new-instance v8, Lcr/g;

    .line 26
    .line 27
    invoke-direct {v8, p1, p0}, Lcr/g;-><init>(Ljava/lang/String;Ljava/lang/Long;)V

    .line 28
    .line 29
    .line 30
    iget-object v3, v0, Lcr/b;->a:Lcr/e;

    .line 31
    .line 32
    iget-object p0, v3, Lcr/e;->e:Ler/d;

    .line 33
    .line 34
    const/4 p1, 0x0

    .line 35
    if-eqz p0, :cond_3

    .line 36
    .line 37
    iget-object v0, v3, Lcr/e;->c:Landroid/content/Context;

    .line 38
    .line 39
    sget-object v2, Ler/f;->a:Ler/p;

    .line 40
    .line 41
    :try_start_0
    invoke-virtual {v0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    const-string v2, "com.android.vending"

    .line 46
    .line 47
    const/16 v4, 0x40

    .line 48
    .line 49
    invoke-virtual {v0, v2, v4}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;

    .line 50
    .line 51
    .line 52
    move-result-object v0
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 53
    iget-object v2, v0, Landroid/content/pm/PackageInfo;->applicationInfo:Landroid/content/pm/ApplicationInfo;

    .line 54
    .line 55
    if-eqz v2, :cond_1

    .line 56
    .line 57
    iget-boolean v2, v2, Landroid/content/pm/ApplicationInfo;->enabled:Z

    .line 58
    .line 59
    if-eqz v2, :cond_1

    .line 60
    .line 61
    iget-object v2, v0, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;

    .line 62
    .line 63
    invoke-static {v2}, Ler/f;->a([Landroid/content/pm/Signature;)Z

    .line 64
    .line 65
    .line 66
    move-result v2

    .line 67
    if-nez v2, :cond_0

    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_0
    iget v1, v0, Landroid/content/pm/PackageInfo;->versionCode:I

    .line 71
    .line 72
    :catch_0
    :cond_1
    :goto_0
    const v0, 0x4e904e0

    .line 73
    .line 74
    .line 75
    if-lt v1, v0, :cond_2

    .line 76
    .line 77
    :try_start_1
    iget-object p1, v8, Lcr/g;->a:Ljava/lang/String;

    .line 78
    .line 79
    const/16 v0, 0xa

    .line 80
    .line 81
    invoke-static {p1, v0}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    .line 82
    .line 83
    .line 84
    move-result-object v5
    :try_end_1
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_1

    .line 85
    iget-object p1, v3, Lcr/e;->a:Ler/p;

    .line 86
    .line 87
    filled-new-array {v8}, [Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    const-string v1, "requestIntegrityToken(%s)"

    .line 92
    .line 93
    invoke-virtual {p1, v1, v0}, Ler/p;->a(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    new-instance v4, Laq/k;

    .line 97
    .line 98
    invoke-direct {v4}, Laq/k;-><init>()V

    .line 99
    .line 100
    .line 101
    new-instance v2, Lcr/c;

    .line 102
    .line 103
    iget-object v6, v8, Lcr/g;->b:Ljava/lang/Long;

    .line 104
    .line 105
    move-object v7, v4

    .line 106
    invoke-direct/range {v2 .. v8}, Lcr/c;-><init>(Lcr/e;Laq/k;[BLjava/lang/Long;Laq/k;Lcr/g;)V

    .line 107
    .line 108
    .line 109
    new-instance p1, Ler/s;

    .line 110
    .line 111
    invoke-direct {p1, p0, v4, v4, v2}, Ler/s;-><init>(Ler/d;Laq/k;Laq/k;Lcr/c;)V

    .line 112
    .line 113
    .line 114
    invoke-virtual {p0}, Ler/d;->a()Landroid/os/Handler;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    invoke-virtual {p0, p1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 119
    .line 120
    .line 121
    iget-object p0, v4, Laq/k;->a:Laq/t;

    .line 122
    .line 123
    goto :goto_1

    .line 124
    :catch_1
    move-exception v0

    .line 125
    move-object p0, v0

    .line 126
    new-instance p1, Lcr/a;

    .line 127
    .line 128
    const/16 v0, -0xd

    .line 129
    .line 130
    invoke-direct {p1, v0, p0}, Lcr/a;-><init>(ILjava/lang/Exception;)V

    .line 131
    .line 132
    .line 133
    invoke-static {p1}, Ljp/l1;->d(Ljava/lang/Exception;)Laq/t;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    goto :goto_1

    .line 138
    :cond_2
    new-instance p0, Lcr/a;

    .line 139
    .line 140
    const/16 v0, -0xe

    .line 141
    .line 142
    invoke-direct {p0, v0, p1}, Lcr/a;-><init>(ILjava/lang/Exception;)V

    .line 143
    .line 144
    .line 145
    invoke-static {p0}, Ljp/l1;->d(Ljava/lang/Exception;)Laq/t;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    goto :goto_1

    .line 150
    :cond_3
    new-instance p0, Lcr/a;

    .line 151
    .line 152
    const/4 v0, -0x2

    .line 153
    invoke-direct {p0, v0, p1}, Lcr/a;-><init>(ILjava/lang/Exception;)V

    .line 154
    .line 155
    .line 156
    invoke-static {p0}, Ljp/l1;->d(Ljava/lang/Exception;)Laq/t;

    .line 157
    .line 158
    .line 159
    move-result-object p0

    .line 160
    :goto_1
    return-object p0

    .line 161
    :pswitch_0
    check-cast p1, Lcr/h;

    .line 162
    .line 163
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 164
    .line 165
    .line 166
    new-instance v0, Les/a;

    .line 167
    .line 168
    iget-object p1, p1, Lcr/h;->a:Ljava/lang/String;

    .line 169
    .line 170
    invoke-direct {v0, p1, v1}, Les/a;-><init>(Ljava/lang/String;Z)V

    .line 171
    .line 172
    .line 173
    iget-object p1, p0, Les/d;->e:Ljava/util/concurrent/Executor;

    .line 174
    .line 175
    new-instance v1, Lcom/google/firebase/messaging/h;

    .line 176
    .line 177
    const/4 v2, 0x2

    .line 178
    invoke-direct {v1, v2, p0, v0}, Lcom/google/firebase/messaging/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 179
    .line 180
    .line 181
    invoke-static {p1, v1}, Ljp/l1;->c(Ljava/util/concurrent/Executor;Ljava/util/concurrent/Callable;)Laq/t;

    .line 182
    .line 183
    .line 184
    move-result-object p0

    .line 185
    return-object p0

    .line 186
    nop

    .line 187
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
