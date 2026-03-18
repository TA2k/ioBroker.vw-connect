.class final Lcom/salesforce/marketingcloud/c$f$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/c$e;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/c$f;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x11
    name = "a"
.end annotation


# instance fields
.field final a:Landroid/app/job/JobWorkItem;

.field final synthetic b:Lcom/salesforce/marketingcloud/c$f;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/c$f;Landroid/app/job/JobWorkItem;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/c$f$a;->b:Lcom/salesforce/marketingcloud/c$f;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p2, p0, Lcom/salesforce/marketingcloud/c$f$a;->a:Landroid/app/job/JobWorkItem;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public a()V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/c$f$a;->b:Lcom/salesforce/marketingcloud/c$f;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/salesforce/marketingcloud/c$f;->b:Ljava/lang/Object;

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/c$f$a;->b:Lcom/salesforce/marketingcloud/c$f;

    .line 7
    .line 8
    iget-object v1, v1, Lcom/salesforce/marketingcloud/c$f;->c:Landroid/app/job/JobParameters;

    .line 9
    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    iget-object p0, p0, Lcom/salesforce/marketingcloud/c$f$a;->a:Landroid/app/job/JobWorkItem;

    .line 13
    .line 14
    invoke-virtual {v1, p0}, Landroid/app/job/JobParameters;->completeWork(Landroid/app/job/JobWorkItem;)V

    .line 15
    .line 16
    .line 17
    goto :goto_0

    .line 18
    :catchall_0
    move-exception p0

    .line 19
    goto :goto_1

    .line 20
    :cond_0
    :goto_0
    monitor-exit v0

    .line 21
    return-void

    .line 22
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 23
    throw p0
.end method

.method public b()Landroid/content/Intent;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/c$f$a;->a:Landroid/app/job/JobWorkItem;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/app/job/JobWorkItem;->getIntent()Landroid/content/Intent;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
