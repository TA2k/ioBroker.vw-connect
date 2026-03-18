.class public final Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\n\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\u0008\u00c1\u0002\u0018\u00002\u00020\u0001\u00a8\u0006\u0002"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;",
        "",
        "remoteparkassistplugin_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final a:Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;

.field public static final b:Lyy0/c2;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->a:Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    sput-object v0, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->b:Lyy0/c2;

    .line 14
    .line 15
    return-void
.end method

.method public static a()Lcom/google/firebase/messaging/w;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->b:Lyy0/c2;

    .line 2
    .line 3
    invoke-interface {v0}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Ls61/a;

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget-object v0, v0, Ls61/a;->e:Lcom/google/firebase/messaging/w;

    .line 12
    .line 13
    return-object v0

    .line 14
    :cond_0
    const/4 v0, 0x0

    .line 15
    return-object v0
.end method


# virtual methods
.method public final declared-synchronized b(Ls61/a;)V
    .locals 4

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    new-instance v0, Lg61/f;

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    invoke-direct {v0, p1, v1}, Lg61/f;-><init>(Ls61/a;I)V

    .line 6
    .line 7
    .line 8
    invoke-static {p0, v0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 9
    .line 10
    .line 11
    sget-object v0, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->b:Lyy0/c2;

    .line 12
    .line 13
    invoke-interface {v0}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    check-cast v1, Ls61/a;

    .line 18
    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    invoke-virtual {v1}, Ls61/a;->close()V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :catchall_0
    move-exception p1

    .line 26
    goto :goto_1

    .line 27
    :cond_0
    :goto_0
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    move-object v3, v2

    .line 32
    check-cast v3, Ls61/a;

    .line 33
    .line 34
    invoke-virtual {v0, v2, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    if-eqz v2, :cond_0

    .line 39
    .line 40
    if-eqz v1, :cond_1

    .line 41
    .line 42
    iget-object p1, v1, Ls61/a;->j:Lay0/a;

    .line 43
    .line 44
    invoke-interface {p1}, Lay0/a;->invoke()Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 45
    .line 46
    .line 47
    :cond_1
    monitor-exit p0

    .line 48
    return-void

    .line 49
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 50
    throw p1
.end method
