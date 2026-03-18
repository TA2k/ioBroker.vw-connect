.class public final Lcom/salesforce/marketingcloud/push/carousel/d$o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/media/f;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/push/carousel/d;->b(Landroid/widget/RemoteViews;Lcom/salesforce/marketingcloud/push/carousel/a$a;Lcom/salesforce/marketingcloud/push/carousel/a;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation


# instance fields
.field final synthetic a:Lcom/salesforce/marketingcloud/push/carousel/d;

.field final synthetic b:Lcom/salesforce/marketingcloud/push/carousel/a$a;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/push/carousel/d;Lcom/salesforce/marketingcloud/push/carousel/a$a;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/push/carousel/d$o;->a:Lcom/salesforce/marketingcloud/push/carousel/d;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/push/carousel/d$o;->b:Lcom/salesforce/marketingcloud/push/carousel/a$a;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public a()V
    .locals 0

    .line 1
    return-void
.end method

.method public a(Ljava/lang/Exception;)V
    .locals 3

    .line 2
    sget-object v0, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/carousel/d$o;->a:Lcom/salesforce/marketingcloud/push/carousel/d;

    invoke-static {v1}, Lcom/salesforce/marketingcloud/push/carousel/d;->a(Lcom/salesforce/marketingcloud/push/carousel/d;)Ljava/lang/String;

    move-result-object v1

    new-instance v2, Lcom/salesforce/marketingcloud/push/carousel/d$o$a;

    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/d$o;->b:Lcom/salesforce/marketingcloud/push/carousel/a$a;

    invoke-direct {v2, p0}, Lcom/salesforce/marketingcloud/push/carousel/d$o$a;-><init>(Lcom/salesforce/marketingcloud/push/carousel/a$a;)V

    invoke-virtual {v0, v1, p1, v2}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    return-void
.end method
