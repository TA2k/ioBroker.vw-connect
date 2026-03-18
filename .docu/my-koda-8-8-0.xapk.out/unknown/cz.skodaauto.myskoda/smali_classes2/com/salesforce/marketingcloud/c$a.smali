.class final Lcom/salesforce/marketingcloud/c$a;
.super Landroid/os/AsyncTask;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "StaticFieldLeak"
    }
.end annotation

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/c;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x11
    name = "a"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Landroid/os/AsyncTask<",
        "Ljava/lang/Void;",
        "Ljava/lang/Void;",
        "Ljava/lang/Void;",
        ">;"
    }
.end annotation


# instance fields
.field final synthetic a:Lcom/salesforce/marketingcloud/c;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/c$a;->a:Lcom/salesforce/marketingcloud/c;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/os/AsyncTask;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public bridge synthetic doInBackground([Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, [Ljava/lang/Void;

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/c$a;->doInBackground([Ljava/lang/Void;)Ljava/lang/Void;

    move-result-object p0

    return-object p0
.end method

.method public varargs doInBackground([Ljava/lang/Void;)Ljava/lang/Void;
    .locals 4

    const/4 p1, 0x0

    .line 2
    :try_start_0
    sget-object v0, Lcom/salesforce/marketingcloud/c;->h:Ljava/lang/String;

    const-string v1, "Starting to dequeue work..."

    new-array v2, p1, [Ljava/lang/Object;

    invoke-static {v0, v1, v2}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 3
    :goto_0
    invoke-virtual {p0}, Landroid/os/AsyncTask;->isCancelled()Z

    move-result v0

    if-nez v0, :cond_0

    iget-object v0, p0, Lcom/salesforce/marketingcloud/c$a;->a:Lcom/salesforce/marketingcloud/c;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/c;->a()Lcom/salesforce/marketingcloud/c$e;

    move-result-object v0

    if-eqz v0, :cond_0

    .line 4
    sget-object v1, Lcom/salesforce/marketingcloud/c;->h:Ljava/lang/String;

    const-string v2, "Processing next work: action=%s"

    invoke-interface {v0}, Lcom/salesforce/marketingcloud/c$e;->b()Landroid/content/Intent;

    move-result-object v3

    invoke-virtual {v3}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    move-result-object v3

    filled-new-array {v3}, [Ljava/lang/Object;

    move-result-object v3

    invoke-static {v1, v2, v3}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 5
    iget-object v2, p0, Lcom/salesforce/marketingcloud/c$a;->a:Lcom/salesforce/marketingcloud/c;

    invoke-interface {v0}, Lcom/salesforce/marketingcloud/c$e;->b()Landroid/content/Intent;

    move-result-object v3

    invoke-virtual {v2, v3}, Lcom/salesforce/marketingcloud/c;->a(Landroid/content/Intent;)V

    .line 6
    const-string v2, "Completing work: action=%s"

    invoke-interface {v0}, Lcom/salesforce/marketingcloud/c$e;->b()Landroid/content/Intent;

    move-result-object v3

    invoke-virtual {v3}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    move-result-object v3

    filled-new-array {v3}, [Ljava/lang/Object;

    move-result-object v3

    invoke-static {v1, v2, v3}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 7
    invoke-interface {v0}, Lcom/salesforce/marketingcloud/c$e;->a()V

    goto :goto_0

    :catch_0
    move-exception p0

    goto :goto_1

    .line 8
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/c;->h:Ljava/lang/String;

    const-string v0, "Done processing work!"

    new-array v1, p1, [Ljava/lang/Object;

    invoke-static {p0, v0, v1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_2

    .line 9
    :goto_1
    sget-object v0, Lcom/salesforce/marketingcloud/c;->h:Ljava/lang/String;

    new-array p1, p1, [Ljava/lang/Object;

    const-string v1, "Exception thrown by JobIntentService"

    invoke-static {v0, p0, v1, p1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :goto_2
    const/4 p0, 0x0

    return-object p0
.end method

.method public bridge synthetic onCancelled(Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/Void;

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/c$a;->onCancelled(Ljava/lang/Void;)V

    return-void
.end method

.method public onCancelled(Ljava/lang/Void;)V
    .locals 0

    .line 2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/c$a;->a:Lcom/salesforce/marketingcloud/c;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/c;->e()V

    return-void
.end method

.method public bridge synthetic onPostExecute(Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/Void;

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/c$a;->onPostExecute(Ljava/lang/Void;)V

    return-void
.end method

.method public onPostExecute(Ljava/lang/Void;)V
    .locals 0

    .line 2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/c$a;->a:Lcom/salesforce/marketingcloud/c;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/c;->e()V

    return-void
.end method
