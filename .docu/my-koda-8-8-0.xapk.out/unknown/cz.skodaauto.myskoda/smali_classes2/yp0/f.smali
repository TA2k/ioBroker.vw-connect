.class public final Lyp0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleReadyListener;


# instance fields
.field public final synthetic d:Lay0/k;


# direct methods
.method public constructor <init>(Lay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lyp0/f;->d:Lay0/k;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final bridge ready(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleReadyListener$DefaultImpls;->ready(Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleReadyListener;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V

    return-void
.end method

.method public final ready(Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleInterface;)V
    .locals 1

    const-string v0, "pushModule"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleInterface;->getPushMessageManager()Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;

    move-result-object p1

    iget-object p0, p0, Lyp0/f;->d:Lay0/k;

    .line 3
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method
