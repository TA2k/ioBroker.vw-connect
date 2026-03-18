.class final Lcom/salesforce/marketingcloud/c$d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/c$e;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/c;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x11
    name = "d"
.end annotation


# instance fields
.field final a:Landroid/content/Intent;

.field final b:I

.field final synthetic c:Lcom/salesforce/marketingcloud/c;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/c;Landroid/content/Intent;I)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/c$d;->c:Lcom/salesforce/marketingcloud/c;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p2, p0, Lcom/salesforce/marketingcloud/c$d;->a:Landroid/content/Intent;

    .line 7
    .line 8
    iput p3, p0, Lcom/salesforce/marketingcloud/c$d;->b:I

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public a()V
    .locals 3

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/c;->h:Ljava/lang/String;

    .line 2
    .line 3
    iget v1, p0, Lcom/salesforce/marketingcloud/c$d;->b:I

    .line 4
    .line 5
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    const-string v2, "Stopping self: #%d"

    .line 14
    .line 15
    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    iget-object v0, p0, Lcom/salesforce/marketingcloud/c$d;->c:Lcom/salesforce/marketingcloud/c;

    .line 19
    .line 20
    iget p0, p0, Lcom/salesforce/marketingcloud/c$d;->b:I

    .line 21
    .line 22
    invoke-virtual {v0, p0}, Landroid/app/Service;->stopSelf(I)V

    .line 23
    .line 24
    .line 25
    return-void
.end method

.method public b()Landroid/content/Intent;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/c$d;->a:Landroid/content/Intent;

    .line 2
    .line 3
    return-object p0
.end method
