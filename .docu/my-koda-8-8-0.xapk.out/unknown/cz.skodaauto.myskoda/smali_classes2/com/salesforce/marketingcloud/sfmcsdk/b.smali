.class public final synthetic Lcom/salesforce/marketingcloud/sfmcsdk/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:Lcom/salesforce/marketingcloud/sfmcsdk/WhenReadyHandler;

.field public final synthetic e:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;


# direct methods
.method public synthetic constructor <init>(Lcom/salesforce/marketingcloud/sfmcsdk/WhenReadyHandler;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/b;->d:Lcom/salesforce/marketingcloud/sfmcsdk/WhenReadyHandler;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/b;->e:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/b;->d:Lcom/salesforce/marketingcloud/sfmcsdk/WhenReadyHandler;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/b;->e:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;

    .line 4
    .line 5
    invoke-static {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/WhenReadyHandler;->a(Lcom/salesforce/marketingcloud/sfmcsdk/WhenReadyHandler;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
