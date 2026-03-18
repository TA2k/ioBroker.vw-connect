.class Lcom/salesforce/marketingcloud/messages/inbox/c$l$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/inbox/c$l;->a()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic b:Lcom/salesforce/marketingcloud/messages/inbox/c$l;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/messages/inbox/c$l;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$l$a;->b:Lcom/salesforce/marketingcloud/messages/inbox/c$l;

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
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$l$a;->b:Lcom/salesforce/marketingcloud/messages/inbox/c$l;

    .line 2
    .line 3
    iget-object v1, v0, Lcom/salesforce/marketingcloud/messages/inbox/c$l;->d:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 4
    .line 5
    iget-object v0, v0, Lcom/salesforce/marketingcloud/messages/inbox/c$l;->c:Ljava/util/List;

    .line 6
    .line 7
    invoke-virtual {v1, v0}, Lcom/salesforce/marketingcloud/messages/inbox/c;->a(Ljava/util/List;)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$l$a;->b:Lcom/salesforce/marketingcloud/messages/inbox/c$l;

    .line 11
    .line 12
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$l;->d:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 13
    .line 14
    const/4 v0, 0x1

    .line 15
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/messages/inbox/c;->b(Z)V

    .line 16
    .line 17
    .line 18
    return-void
.end method
