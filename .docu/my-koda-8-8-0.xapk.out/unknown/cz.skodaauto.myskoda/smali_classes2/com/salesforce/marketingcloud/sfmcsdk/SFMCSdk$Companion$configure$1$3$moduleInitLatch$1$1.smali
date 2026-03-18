.class final Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion$configure$1$3$moduleInitLatch$1$1;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;->configure(Landroid/content/Context;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;Lay0/k;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lkotlin/jvm/internal/n;",
        "Lay0/a;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0008\n\u0000\n\u0002\u0010\u000e\n\u0000\u0010\u0000\u001a\u00020\u0001H\n\u00a2\u0006\u0002\u0008\u0002"
    }
    d2 = {
        "<anonymous>",
        "",
        "invoke"
    }
    k = 0x3
    mv = {
        0x1,
        0x9,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field final synthetic $config:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion$configure$1$3$moduleInitLatch$1$1;->$config:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;

    .line 2
    .line 3
    const/4 p1, 0x0

    .line 4
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 5
    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion$configure$1$3$moduleInitLatch$1$1;->invoke()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public final invoke()Ljava/lang/String;
    .locals 2

    .line 2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion$configure$1$3$moduleInitLatch$1$1;->$config:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;->getConfigs$sfmcsdk_release()Ljava/util/List;

    move-result-object p0

    invoke-interface {p0}, Ljava/util/List;->size()I

    move-result p0

    const-string v0, "Initializing "

    const-string v1, " modules."

    .line 3
    invoke-static {v0, p0, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method
