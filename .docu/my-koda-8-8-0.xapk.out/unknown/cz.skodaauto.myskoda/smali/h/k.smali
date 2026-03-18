.class public final synthetic Lh/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Landroid/content/Context;


# direct methods
.method public synthetic constructor <init>(Landroid/content/Context;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh/k;->e:Landroid/content/Context;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 10

    .line 1
    iget v0, p0, Lh/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lha/c;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-direct {v0, v1}, Lha/c;-><init>(I)V

    .line 10
    .line 11
    .line 12
    sget-object v1, Lia/d;->a:Lgv/a;

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    iget-object p0, p0, Lh/k;->e:Landroid/content/Context;

    .line 16
    .line 17
    invoke-static {p0, v0, v1, v2}, Lia/d;->t(Landroid/content/Context;Ljava/util/concurrent/Executor;Lia/c;Z)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :pswitch_0
    new-instance v3, Ljava/util/concurrent/ThreadPoolExecutor;

    .line 22
    .line 23
    sget-object v8, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 24
    .line 25
    new-instance v9, Ljava/util/concurrent/LinkedBlockingQueue;

    .line 26
    .line 27
    invoke-direct {v9}, Ljava/util/concurrent/LinkedBlockingQueue;-><init>()V

    .line 28
    .line 29
    .line 30
    const/4 v4, 0x0

    .line 31
    const/4 v5, 0x1

    .line 32
    const-wide/16 v6, 0x0

    .line 33
    .line 34
    invoke-direct/range {v3 .. v9}, Ljava/util/concurrent/ThreadPoolExecutor;-><init>(IIJLjava/util/concurrent/TimeUnit;Ljava/util/concurrent/BlockingQueue;)V

    .line 35
    .line 36
    .line 37
    new-instance v0, Lh/k;

    .line 38
    .line 39
    const/4 v1, 0x3

    .line 40
    iget-object p0, p0, Lh/k;->e:Landroid/content/Context;

    .line 41
    .line 42
    invoke-direct {v0, p0, v1}, Lh/k;-><init>(Landroid/content/Context;I)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {v3, v0}, Ljava/util/concurrent/ThreadPoolExecutor;->execute(Ljava/lang/Runnable;)V

    .line 46
    .line 47
    .line 48
    return-void

    .line 49
    :pswitch_1
    iget-object p0, p0, Lh/k;->e:Landroid/content/Context;

    .line 50
    .line 51
    invoke-static {p0}, Lh/n;->q(Landroid/content/Context;)V

    .line 52
    .line 53
    .line 54
    return-void

    .line 55
    :pswitch_2
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 56
    .line 57
    const/16 v1, 0x21

    .line 58
    .line 59
    const/4 v2, 0x1

    .line 60
    if-lt v0, v1, :cond_1

    .line 61
    .line 62
    new-instance v0, Landroid/content/ComponentName;

    .line 63
    .line 64
    const-string v1, "androidx.appcompat.app.AppLocalesMetadataHolderService"

    .line 65
    .line 66
    iget-object p0, p0, Lh/k;->e:Landroid/content/Context;

    .line 67
    .line 68
    invoke-direct {v0, p0, v1}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 72
    .line 73
    .line 74
    move-result-object v1

    .line 75
    invoke-virtual {v1, v0}, Landroid/content/pm/PackageManager;->getComponentEnabledSetting(Landroid/content/ComponentName;)I

    .line 76
    .line 77
    .line 78
    move-result v1

    .line 79
    if-eq v1, v2, :cond_1

    .line 80
    .line 81
    invoke-static {}, Lh/n;->b()Ly5/c;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    iget-object v1, v1, Ly5/c;->a:Ly5/d;

    .line 86
    .line 87
    iget-object v1, v1, Ly5/d;->a:Landroid/os/LocaleList;

    .line 88
    .line 89
    invoke-virtual {v1}, Landroid/os/LocaleList;->isEmpty()Z

    .line 90
    .line 91
    .line 92
    move-result v1

    .line 93
    if-eqz v1, :cond_0

    .line 94
    .line 95
    invoke-static {p0}, Landroidx/core/app/c;->e(Landroid/content/Context;)Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object v1

    .line 99
    const-string v3, "locale"

    .line 100
    .line 101
    invoke-virtual {p0, v3}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v3

    .line 105
    if-eqz v3, :cond_0

    .line 106
    .line 107
    invoke-static {v1}, Lh/l;->a(Ljava/lang/String;)Landroid/os/LocaleList;

    .line 108
    .line 109
    .line 110
    move-result-object v1

    .line 111
    invoke-static {v3, v1}, Lh/m;->b(Ljava/lang/Object;Landroid/os/LocaleList;)V

    .line 112
    .line 113
    .line 114
    :cond_0
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    invoke-virtual {p0, v0, v2, v2}, Landroid/content/pm/PackageManager;->setComponentEnabledSetting(Landroid/content/ComponentName;II)V

    .line 119
    .line 120
    .line 121
    :cond_1
    sput-boolean v2, Lh/n;->i:Z

    .line 122
    .line 123
    return-void

    .line 124
    nop

    .line 125
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
