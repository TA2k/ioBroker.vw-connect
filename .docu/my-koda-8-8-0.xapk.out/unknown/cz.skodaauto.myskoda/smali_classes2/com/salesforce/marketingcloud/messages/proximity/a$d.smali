.class Lcom/salesforce/marketingcloud/messages/proximity/a$d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/proximity/a;->a(Lcom/salesforce/marketingcloud/proximity/c;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic b:Lcom/salesforce/marketingcloud/proximity/c;

.field final synthetic c:Lcom/salesforce/marketingcloud/messages/proximity/a;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/messages/proximity/a;Lcom/salesforce/marketingcloud/proximity/c;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$d;->c:Lcom/salesforce/marketingcloud/messages/proximity/a;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$d;->b:Lcom/salesforce/marketingcloud/proximity/c;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public run()V
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$d;->c:Lcom/salesforce/marketingcloud/messages/proximity/a;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/salesforce/marketingcloud/messages/proximity/a;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->o()Lcom/salesforce/marketingcloud/storage/j;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$d;->b:Lcom/salesforce/marketingcloud/proximity/c;

    .line 10
    .line 11
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/proximity/c;->n()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$d;->c:Lcom/salesforce/marketingcloud/messages/proximity/a;

    .line 16
    .line 17
    iget-object v2, v2, Lcom/salesforce/marketingcloud/messages/proximity/a;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 18
    .line 19
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    invoke-interface {v0, v1, v2}, Lcom/salesforce/marketingcloud/storage/j;->a(Ljava/lang/String;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/messages/Region;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    if-nez v1, :cond_0

    .line 28
    .line 29
    sget-object v0, Lcom/salesforce/marketingcloud/messages/proximity/a;->j:Ljava/lang/String;

    .line 30
    .line 31
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$d;->b:Lcom/salesforce/marketingcloud/proximity/c;

    .line 32
    .line 33
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    const-string v1, "BeaconRegion [%s] did not have matching Region in storage."

    .line 38
    .line 39
    invoke-static {v0, v1, p0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    return-void

    .line 43
    :cond_0
    invoke-static {v1}, Lcom/salesforce/marketingcloud/internal/l;->a(Lcom/salesforce/marketingcloud/messages/Region;)Z

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    if-eqz v2, :cond_1

    .line 48
    .line 49
    const/4 v2, 0x0

    .line 50
    invoke-static {v1, v2}, Lcom/salesforce/marketingcloud/internal/l;->a(Lcom/salesforce/marketingcloud/messages/Region;Z)V

    .line 51
    .line 52
    .line 53
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$d;->c:Lcom/salesforce/marketingcloud/messages/proximity/a;

    .line 54
    .line 55
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a;->f:Lcom/salesforce/marketingcloud/messages/c$a;

    .line 56
    .line 57
    invoke-interface {p0, v1}, Lcom/salesforce/marketingcloud/messages/c$a;->a(Lcom/salesforce/marketingcloud/messages/Region;)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/messages/Region;->id()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    invoke-interface {v0, p0, v2}, Lcom/salesforce/marketingcloud/storage/j;->a(Ljava/lang/String;Z)V

    .line 65
    .line 66
    .line 67
    return-void

    .line 68
    :cond_1
    sget-object v0, Lcom/salesforce/marketingcloud/messages/proximity/a;->j:Ljava/lang/String;

    .line 69
    .line 70
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$d;->b:Lcom/salesforce/marketingcloud/proximity/c;

    .line 71
    .line 72
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    const-string v1, "Ignoring exit event.  Was not inside BeaconRegion [%s]"

    .line 77
    .line 78
    invoke-static {v0, v1, p0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    return-void
.end method
