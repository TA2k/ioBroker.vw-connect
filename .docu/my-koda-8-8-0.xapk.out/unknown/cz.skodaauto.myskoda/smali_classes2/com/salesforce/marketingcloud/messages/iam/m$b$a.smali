.class Lcom/salesforce/marketingcloud/messages/iam/m$b$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/iam/m$b;->a()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic b:Lcom/salesforce/marketingcloud/messages/iam/m$b;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/messages/iam/m$b;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/m$b$a;->b:Lcom/salesforce/marketingcloud/messages/iam/m$b;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public run()V
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/m$b$a;->b:Lcom/salesforce/marketingcloud/messages/iam/m$b;

    .line 2
    .line 3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m$b;->d:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 4
    .line 5
    iget-object v0, v0, Lcom/salesforce/marketingcloud/messages/iam/m;->p:Lcom/salesforce/marketingcloud/messages/iam/InAppMessageManager$EventListener;

    .line 6
    .line 7
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/m$b;->c:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 8
    .line 9
    invoke-interface {v0, p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageManager$EventListener;->didShowMessage(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method
