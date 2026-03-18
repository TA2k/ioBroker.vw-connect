.class Lcom/salesforce/marketingcloud/media/c$a;
.super Landroidx/collection/w;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/media/c;-><init>(Landroid/content/Context;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Landroidx/collection/w;"
    }
.end annotation


# instance fields
.field final synthetic a:Lcom/salesforce/marketingcloud/media/c;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/media/c;I)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/c$a;->a:Lcom/salesforce/marketingcloud/media/c;

    .line 2
    .line 3
    invoke-direct {p0, p2}, Landroidx/collection/w;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public bridge synthetic sizeOf(Ljava/lang/Object;Ljava/lang/Object;)I
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/String;

    check-cast p2, Lcom/salesforce/marketingcloud/media/c$b;

    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/media/c$a;->sizeOf(Ljava/lang/String;Lcom/salesforce/marketingcloud/media/c$b;)I

    move-result p0

    return p0
.end method

.method public sizeOf(Ljava/lang/String;Lcom/salesforce/marketingcloud/media/c$b;)I
    .locals 0

    .line 2
    iget p0, p2, Lcom/salesforce/marketingcloud/media/c$b;->b:I

    return p0
.end method
