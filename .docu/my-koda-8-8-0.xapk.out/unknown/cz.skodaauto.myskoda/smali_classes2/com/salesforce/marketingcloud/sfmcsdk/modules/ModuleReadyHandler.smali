.class public final Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyHandler;
.super Landroid/os/Handler;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0008\u0008\u0000\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J\u001f\u0010\t\u001a\u00020\u00082\u0006\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u0002H\u0002\u00a2\u0006\u0004\u0008\t\u0010\nJ\u0015\u0010\u000b\u001a\u00020\u00082\u0006\u0010\u0007\u001a\u00020\u0006\u00a2\u0006\u0004\u0008\u000b\u0010\u000cR\u0017\u0010\u0003\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0003\u0010\r\u001a\u0004\u0008\u000e\u0010\u000f\u00a8\u0006\u0010"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyHandler;",
        "Landroid/os/Handler;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;",
        "listener",
        "<init>",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;)V",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;",
        "module",
        "Llx0/b0;",
        "execute",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;)V",
        "deliverModule",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;",
        "getListener",
        "()Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;",
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
.field private final listener:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;)V
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
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyHandler;->listener:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;

    .line 20
    .line 21
    return-void
.end method

.method public static synthetic a(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyHandler;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyHandler;->deliverModule$lambda$0(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyHandler;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static final deliverModule$lambda$0(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyHandler;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V
    .locals 1

    .line 1
    const-string v0, "this$0"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "$module"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyHandler;->listener:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;

    .line 12
    .line 13
    invoke-direct {p0, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyHandler;->execute(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method private final execute(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;)V
    .locals 2

    .line 1
    :try_start_0
    invoke-interface {p2, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;->ready(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V
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
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 7
    .line 8
    new-instance v1, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyHandler$execute$1;

    .line 9
    .line 10
    invoke-direct {v1, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyHandler$execute$1;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;)V

    .line 11
    .line 12
    .line 13
    const-string p1, "~$ModuleReadyHandler"

    .line 14
    .line 15
    invoke-virtual {v0, p1, p0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->e(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final deliverModule(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V
    .locals 2

    .line 1
    const-string v0, "module"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, La8/z;

    .line 7
    .line 8
    const/16 v1, 0x14

    .line 9
    .line 10
    invoke-direct {v0, v1, p0, p1}, La8/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0, v0}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public final getListener()Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyHandler;->listener:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;

    .line 2
    .line 3
    return-object p0
.end method
