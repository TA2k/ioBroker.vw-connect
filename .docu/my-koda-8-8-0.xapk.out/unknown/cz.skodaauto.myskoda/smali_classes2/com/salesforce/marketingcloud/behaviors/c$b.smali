.class Lcom/salesforce/marketingcloud/behaviors/c$b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/behaviors/c;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "b"
.end annotation


# instance fields
.field final b:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lcom/salesforce/marketingcloud/behaviors/b;",
            ">;"
        }
    .end annotation
.end field

.field final c:Lcom/salesforce/marketingcloud/behaviors/a;

.field final d:Landroid/os/Bundle;


# direct methods
.method public constructor <init>(Ljava/util/Set;Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Set<",
            "Lcom/salesforce/marketingcloud/behaviors/b;",
            ">;",
            "Lcom/salesforce/marketingcloud/behaviors/a;",
            "Landroid/os/Bundle;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/behaviors/c$b;->b:Ljava/util/Set;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/salesforce/marketingcloud/behaviors/c$b;->c:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 7
    .line 8
    iput-object p3, p0, Lcom/salesforce/marketingcloud/behaviors/c$b;->d:Landroid/os/Bundle;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public run()V
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/behaviors/c$b;->b:Ljava/util/Set;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    check-cast v1, Lcom/salesforce/marketingcloud/behaviors/b;

    .line 18
    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    :try_start_0
    iget-object v2, p0, Lcom/salesforce/marketingcloud/behaviors/c$b;->c:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 22
    .line 23
    iget-object v3, p0, Lcom/salesforce/marketingcloud/behaviors/c$b;->d:Landroid/os/Bundle;

    .line 24
    .line 25
    invoke-interface {v1, v2, v3}, Lcom/salesforce/marketingcloud/behaviors/b;->onBehavior(Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :catch_0
    move-exception v2

    .line 30
    sget-object v3, Lcom/salesforce/marketingcloud/behaviors/c;->k:Ljava/lang/String;

    .line 31
    .line 32
    iget-object v4, p0, Lcom/salesforce/marketingcloud/behaviors/c$b;->c:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 33
    .line 34
    iget-object v4, v4, Lcom/salesforce/marketingcloud/behaviors/a;->b:Ljava/lang/String;

    .line 35
    .line 36
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    filled-new-array {v4, v1}, [Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    const-string v4, "Failure delivering behavior %s to %s"

    .line 49
    .line 50
    invoke-static {v3, v2, v4, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_1
    return-void
.end method
