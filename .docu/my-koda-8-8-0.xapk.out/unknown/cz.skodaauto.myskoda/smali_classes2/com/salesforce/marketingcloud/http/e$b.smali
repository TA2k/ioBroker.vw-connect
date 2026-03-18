.class Lcom/salesforce/marketingcloud/http/e$b;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/c;Lcom/salesforce/marketingcloud/http/f;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/http/e$c;

.field final synthetic d:Lcom/salesforce/marketingcloud/http/c;

.field final synthetic e:Lcom/salesforce/marketingcloud/http/f;

.field final synthetic f:Lcom/salesforce/marketingcloud/http/e;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/http/e;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/http/e$c;Lcom/salesforce/marketingcloud/http/c;Lcom/salesforce/marketingcloud/http/f;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/http/e$b;->f:Lcom/salesforce/marketingcloud/http/e;

    .line 2
    .line 3
    iput-object p4, p0, Lcom/salesforce/marketingcloud/http/e$b;->c:Lcom/salesforce/marketingcloud/http/e$c;

    .line 4
    .line 5
    iput-object p5, p0, Lcom/salesforce/marketingcloud/http/e$b;->d:Lcom/salesforce/marketingcloud/http/c;

    .line 6
    .line 7
    iput-object p6, p0, Lcom/salesforce/marketingcloud/http/e$b;->e:Lcom/salesforce/marketingcloud/http/f;

    .line 8
    .line 9
    invoke-direct {p0, p2, p3}, Lcom/salesforce/marketingcloud/internal/i;-><init>(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public a()V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/http/e$b;->c:Lcom/salesforce/marketingcloud/http/e$c;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/http/e$b;->d:Lcom/salesforce/marketingcloud/http/c;

    .line 4
    .line 5
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/e$b;->e:Lcom/salesforce/marketingcloud/http/f;

    .line 6
    .line 7
    invoke-interface {v0, v1, p0}, Lcom/salesforce/marketingcloud/http/e$c;->a(Lcom/salesforce/marketingcloud/http/c;Lcom/salesforce/marketingcloud/http/f;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method
