.class public final synthetic Lcom/salesforce/marketingcloud/sfmcsdk/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/concurrent/CountDownLatch;

.field public final synthetic f:Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;


# direct methods
.method public synthetic constructor <init>(Ljava/util/concurrent/CountDownLatch;Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;I)V
    .locals 0

    .line 1
    iput p3, p0, Lcom/salesforce/marketingcloud/sfmcsdk/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/a;->e:Ljava/util/concurrent/CountDownLatch;

    .line 4
    .line 5
    iput-object p2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/a;->f:Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final ready(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V
    .locals 1

    .line 1
    iget v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/a;->e:Ljava/util/concurrent/CountDownLatch;

    .line 7
    .line 8
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/a;->f:Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;

    .line 9
    .line 10
    invoke-static {v0, p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion$configure$1$3$2$4;->a(Ljava/util/concurrent/CountDownLatch;Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/a;->e:Ljava/util/concurrent/CountDownLatch;

    .line 15
    .line 16
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/a;->f:Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;

    .line 17
    .line 18
    invoke-static {v0, p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion$configure$1$3$2$3;->a(Ljava/util/concurrent/CountDownLatch;Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    nop

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
