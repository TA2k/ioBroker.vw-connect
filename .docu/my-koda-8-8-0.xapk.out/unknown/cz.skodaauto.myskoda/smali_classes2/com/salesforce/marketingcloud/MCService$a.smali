.class Lcom/salesforce/marketingcloud/MCService$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Laq/e;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/MCService;->d(Landroid/content/Context;Ljava/lang/String;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Laq/e;"
    }
.end annotation


# instance fields
.field final synthetic a:[Ljava/lang/String;

.field final synthetic b:Landroid/content/Context;

.field final synthetic c:Ljava/lang/String;


# direct methods
.method public constructor <init>([Ljava/lang/String;Landroid/content/Context;Ljava/lang/String;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/MCService$a;->a:[Ljava/lang/String;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/MCService$a;->b:Landroid/content/Context;

    .line 4
    .line 5
    iput-object p3, p0, Lcom/salesforce/marketingcloud/MCService$a;->c:Ljava/lang/String;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public onComplete(Laq/j;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Laq/j;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-virtual {p1}, Laq/j;->i()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    iget-object v0, p0, Lcom/salesforce/marketingcloud/MCService$a;->a:[Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {p1}, Laq/j;->g()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    check-cast p1, Ljava/lang/String;

    .line 15
    .line 16
    aput-object p1, v0, v1

    .line 17
    .line 18
    :cond_0
    iget-object p1, p0, Lcom/salesforce/marketingcloud/MCService$a;->b:Landroid/content/Context;

    .line 19
    .line 20
    iget-object v0, p0, Lcom/salesforce/marketingcloud/MCService$a;->a:[Ljava/lang/String;

    .line 21
    .line 22
    aget-object v0, v0, v1

    .line 23
    .line 24
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    xor-int/lit8 v0, v0, 0x1

    .line 29
    .line 30
    iget-object v2, p0, Lcom/salesforce/marketingcloud/MCService$a;->c:Ljava/lang/String;

    .line 31
    .line 32
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MCService$a;->a:[Ljava/lang/String;

    .line 33
    .line 34
    aget-object p0, p0, v1

    .line 35
    .line 36
    invoke-static {p1, v0, v2, p0}, Lcom/salesforce/marketingcloud/messages/push/a;->a(Landroid/content/Context;ZLjava/lang/String;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    return-void
.end method
