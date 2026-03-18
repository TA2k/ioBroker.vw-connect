.class public final Lmg0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroid/app/DownloadManager;

.field public final b:Lig0/g;

.field public final c:Lgm0/m;

.field public final d:Ljava/util/concurrent/ConcurrentHashMap;

.field public e:Lvy0/x1;

.field public final f:Ljava/util/concurrent/ConcurrentHashMap;

.field public final g:Llx0/q;

.field public final h:Llx0/q;


# direct methods
.method public constructor <init>(Landroid/app/DownloadManager;Lig0/g;Lgm0/m;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lmg0/e;->a:Landroid/app/DownloadManager;

    .line 5
    .line 6
    iput-object p2, p0, Lmg0/e;->b:Lig0/g;

    .line 7
    .line 8
    iput-object p3, p0, Lmg0/e;->c:Lgm0/m;

    .line 9
    .line 10
    new-instance p1, Ljava/util/concurrent/ConcurrentHashMap;

    .line 11
    .line 12
    invoke-direct {p1}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, Lmg0/e;->d:Ljava/util/concurrent/ConcurrentHashMap;

    .line 16
    .line 17
    new-instance p1, Ljava/util/concurrent/ConcurrentHashMap;

    .line 18
    .line 19
    invoke-direct {p1}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 20
    .line 21
    .line 22
    iput-object p1, p0, Lmg0/e;->f:Ljava/util/concurrent/ConcurrentHashMap;

    .line 23
    .line 24
    new-instance p1, Ll31/b;

    .line 25
    .line 26
    const/16 p2, 0x16

    .line 27
    .line 28
    invoke-direct {p1, p2}, Ll31/b;-><init>(I)V

    .line 29
    .line 30
    .line 31
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    iput-object p1, p0, Lmg0/e;->g:Llx0/q;

    .line 36
    .line 37
    new-instance p1, Lmc/e;

    .line 38
    .line 39
    const/4 p2, 0x2

    .line 40
    invoke-direct {p1, p0, p2}, Lmc/e;-><init>(Ljava/lang/Object;I)V

    .line 41
    .line 42
    .line 43
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    iput-object p1, p0, Lmg0/e;->h:Llx0/q;

    .line 48
    .line 49
    return-void
.end method

.method public static final a(Lmg0/e;Lcz/skodaauto/myskoda/app/main/system/MainActivity;JZ)Z
    .locals 4

    .line 1
    iget-object p0, p0, Lmg0/e;->a:Landroid/app/DownloadManager;

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    const/4 v1, 0x0

    .line 5
    :try_start_0
    invoke-virtual {p0, p2, p3}, Landroid/app/DownloadManager;->getUriForDownloadedFile(J)Landroid/net/Uri;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    const-string v3, "getUriForDownloadedFile(...)"

    .line 10
    .line 11
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0, p2, p3}, Landroid/app/DownloadManager;->getMimeTypeForDownloadedFile(J)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    const-string p2, "getMimeTypeForDownloadedFile(...)"

    .line 19
    .line 20
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    new-instance p2, Landroid/content/Intent;

    .line 24
    .line 25
    invoke-direct {p2}, Landroid/content/Intent;-><init>()V

    .line 26
    .line 27
    .line 28
    if-eqz p4, :cond_0

    .line 29
    .line 30
    const-string p3, "android.intent.extra.STREAM"

    .line 31
    .line 32
    invoke-virtual {p2, p3, v2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    .line 33
    .line 34
    .line 35
    const-string p3, "android.intent.action.SEND"

    .line 36
    .line 37
    invoke-virtual {p2, p3}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :catchall_0
    move-exception p0

    .line 42
    goto :goto_1

    .line 43
    :cond_0
    const-string p3, "android.intent.action.VIEW"

    .line 44
    .line 45
    invoke-virtual {p2, p3}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    .line 46
    .line 47
    .line 48
    :goto_0
    invoke-virtual {p2, v2, p0}, Landroid/content/Intent;->setDataAndType(Landroid/net/Uri;Ljava/lang/String;)Landroid/content/Intent;

    .line 49
    .line 50
    .line 51
    const p0, 0x10000001

    .line 52
    .line 53
    .line 54
    invoke-virtual {p2, p0}, Landroid/content/Intent;->setFlags(I)Landroid/content/Intent;

    .line 55
    .line 56
    .line 57
    invoke-virtual {p1, p2}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 58
    .line 59
    .line 60
    :try_start_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 61
    .line 62
    move v1, v0

    .line 63
    goto :goto_2

    .line 64
    :catchall_1
    move-exception p0

    .line 65
    move v1, v0

    .line 66
    :goto_1
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    :goto_2
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    if-eqz p0, :cond_1

    .line 75
    .line 76
    :try_start_2
    new-instance p0, Landroid/content/Intent;

    .line 77
    .line 78
    const-string p2, "android.intent.action.VIEW_DOWNLOADS"

    .line 79
    .line 80
    invoke-direct {p0, p2}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {p1, p0}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 84
    .line 85
    .line 86
    goto :goto_3

    .line 87
    :catchall_2
    move-exception p0

    .line 88
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 89
    .line 90
    .line 91
    :cond_1
    move v0, v1

    .line 92
    :goto_3
    return v0
.end method
