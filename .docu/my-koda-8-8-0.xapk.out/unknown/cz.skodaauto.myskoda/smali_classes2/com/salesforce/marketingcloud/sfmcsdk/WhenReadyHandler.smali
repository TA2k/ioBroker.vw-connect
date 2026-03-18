.class public final Lcom/salesforce/marketingcloud/sfmcsdk/WhenReadyHandler;
.super Landroid/os/Handler;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0008\u0008\u0000\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J\u001f\u0010\t\u001a\u00020\u00082\u0006\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u0002H\u0002\u00a2\u0006\u0004\u0008\t\u0010\nJ\u0015\u0010\u000b\u001a\u00020\u00082\u0006\u0010\u0007\u001a\u00020\u0006\u00a2\u0006\u0004\u0008\u000b\u0010\u000cR\u0017\u0010\u0003\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0003\u0010\r\u001a\u0004\u0008\u000e\u0010\u000f\u00a8\u0006\u0010"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/WhenReadyHandler;",
        "Landroid/os/Handler;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkReadyListener;",
        "listener",
        "<init>",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkReadyListener;)V",
        "Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;",
        "sdk",
        "Llx0/b0;",
        "execute",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkReadyListener;)V",
        "deliverSdk",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;)V",
        "Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkReadyListener;",
        "getListener",
        "()Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkReadyListener;",
        "sfmcsdk_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x9,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field private final listener:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkReadyListener;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkReadyListener;)V
    .locals 1

    .line 1
    const-string v0, "listener"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    :cond_0
    invoke-direct {p0, v0}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/WhenReadyHandler;->listener:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkReadyListener;

    .line 20
    .line 21
    return-void
.end method

.method public static synthetic a(Lcom/salesforce/marketingcloud/sfmcsdk/WhenReadyHandler;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/WhenReadyHandler;->deliverSdk$lambda$0(Lcom/salesforce/marketingcloud/sfmcsdk/WhenReadyHandler;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static final deliverSdk$lambda$0(Lcom/salesforce/marketingcloud/sfmcsdk/WhenReadyHandler;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;)V
    .locals 1

    .line 1
    const-string v0, "this$0"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "$sdk"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/WhenReadyHandler;->listener:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkReadyListener;

    .line 12
    .line 13
    invoke-direct {p0, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/WhenReadyHandler;->execute(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkReadyListener;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method private final execute(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkReadyListener;)V
    .locals 1

    .line 1
    :try_start_0
    invoke-interface {p2, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkReadyListener;->ready(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 2
    .line 3
    .line 4
    return-void

    .line 5
    :catch_0
    move-exception p0

    .line 6
    sget-object p1, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 7
    .line 8
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/WhenReadyHandler$execute$1;

    .line 9
    .line 10
    invoke-direct {v0, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/WhenReadyHandler$execute$1;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkReadyListener;)V

    .line 11
    .line 12
    .line 13
    const-string p2, "~$WhenReadyHandler"

    .line 14
    .line 15
    invoke-virtual {p1, p2, p0, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->e(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final deliverSdk(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;)V
    .locals 1

    .line 1
    const-string v0, "sdk"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/b;

    .line 7
    .line 8
    invoke-direct {v0, p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/b;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/WhenReadyHandler;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0, v0}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final getListener()Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkReadyListener;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/WhenReadyHandler;->listener:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkReadyListener;

    .line 2
    .line 3
    return-object p0
.end method
