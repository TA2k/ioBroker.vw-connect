.class public Landroidx/work/impl/diagnostics/DiagnosticsReceiver;
.super Landroid/content/BroadcastReceiver;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "DiagnosticsRcvr"

    .line 2
    .line 3
    invoke-static {v0}, Leb/w;->f(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Landroidx/work/impl/diagnostics/DiagnosticsReceiver;->a:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 8

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    const-string p2, "Requesting diagnostics"

    .line 9
    .line 10
    sget-object v1, Landroidx/work/impl/diagnostics/DiagnosticsReceiver;->a:Ljava/lang/String;

    .line 11
    .line 12
    invoke-virtual {p0, v1, p2}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    :try_start_0
    const-string p0, "context"

    .line 16
    .line 17
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-static {p1}, Lfb/u;->f(Landroid/content/Context;)Lfb/u;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    const-class p0, Landroidx/work/impl/workers/DiagnosticsWorker;

    .line 25
    .line 26
    new-instance p1, Leb/y;

    .line 27
    .line 28
    const/4 p2, 0x0

    .line 29
    invoke-direct {p1, p2, p0}, Leb/y;-><init>(ILjava/lang/Class;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p1}, Leb/j0;->h()Leb/k0;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    check-cast p0, Leb/z;

    .line 37
    .line 38
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 39
    .line 40
    .line 41
    move-result-object v6

    .line 42
    invoke-interface {v6}, Ljava/util/List;->isEmpty()Z

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    if-nez p0, :cond_1

    .line 47
    .line 48
    new-instance v2, Lfb/o;

    .line 49
    .line 50
    sget-object v5, Leb/m;->e:Leb/m;

    .line 51
    .line 52
    const/4 v7, 0x0

    .line 53
    const/4 v4, 0x0

    .line 54
    invoke-direct/range {v2 .. v7}, Lfb/o;-><init>(Lfb/u;Ljava/lang/String;Leb/m;Ljava/util/List;I)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {v2}, Lfb/o;->d()Leb/c0;

    .line 58
    .line 59
    .line 60
    return-void

    .line 61
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 62
    .line 63
    const-string p1, "enqueue needs at least one WorkRequest."

    .line 64
    .line 65
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw p0
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 69
    :catch_0
    move-exception v0

    .line 70
    move-object p0, v0

    .line 71
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    const-string p2, "WorkManager is not initialized"

    .line 76
    .line 77
    invoke-virtual {p1, v1, p2, p0}, Leb/w;->c(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 78
    .line 79
    .line 80
    return-void
.end method
