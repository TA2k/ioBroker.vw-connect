.class Lcom/salesforce/marketingcloud/analytics/h$a;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/analytics/h;->trackInboxOpenEvent(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;

.field final synthetic d:Lcom/salesforce/marketingcloud/analytics/h;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/analytics/h;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h$a;->d:Lcom/salesforce/marketingcloud/analytics/h;

    .line 2
    .line 3
    iput-object p4, p0, Lcom/salesforce/marketingcloud/analytics/h$a;->c:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;

    .line 4
    .line 5
    invoke-direct {p0, p2, p3}, Lcom/salesforce/marketingcloud/internal/i;-><init>(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public a()V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h$a;->c:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;

    .line 2
    .line 3
    if-eqz v0, :cond_5

    .line 4
    .line 5
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h$a;->d:Lcom/salesforce/marketingcloud/analytics/h;

    .line 6
    .line 7
    iget-object v0, v0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 8
    .line 9
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->l()Lcom/salesforce/marketingcloud/storage/f;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/h$a;->c:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;

    .line 14
    .line 15
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->id()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    invoke-interface {v0, v1}, Lcom/salesforce/marketingcloud/storage/f;->e(Ljava/lang/String;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-nez v0, :cond_0

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h$a;->d:Lcom/salesforce/marketingcloud/analytics/h;

    .line 27
    .line 28
    iget-object v0, v0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    .line 29
    .line 30
    if-eqz v0, :cond_1

    .line 31
    .line 32
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/h$a;->c:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;

    .line 33
    .line 34
    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/analytics/i;->trackInboxOpenEvent(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V

    .line 35
    .line 36
    .line 37
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h$a;->d:Lcom/salesforce/marketingcloud/analytics/h;

    .line 38
    .line 39
    iget-object v0, v0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 40
    .line 41
    if-eqz v0, :cond_2

    .line 42
    .line 43
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/h$a;->c:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->trackInboxOpenEvent(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V

    .line 46
    .line 47
    .line 48
    :cond_2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h$a;->d:Lcom/salesforce/marketingcloud/analytics/h;

    .line 49
    .line 50
    iget-object v0, v0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 51
    .line 52
    if-eqz v0, :cond_3

    .line 53
    .line 54
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/h$a;->c:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;

    .line 55
    .line 56
    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/analytics/i;->trackInboxOpenEvent(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V

    .line 57
    .line 58
    .line 59
    :cond_3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h$a;->d:Lcom/salesforce/marketingcloud/analytics/h;

    .line 60
    .line 61
    iget-object v0, v0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 62
    .line 63
    if-eqz v0, :cond_4

    .line 64
    .line 65
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h$a;->c:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;

    .line 66
    .line 67
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/analytics/i;->trackInboxOpenEvent(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V

    .line 68
    .line 69
    .line 70
    :cond_4
    return-void

    .line 71
    :cond_5
    :goto_0
    sget-object p0, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    .line 72
    .line 73
    const/4 v0, 0x0

    .line 74
    new-array v0, v0, [Ljava/lang/Object;

    .line 75
    .line 76
    const-string v1, "InboxMessage is a Legacy message, null or unknown.  Call to trackInboxOpenEvent() ignored."

    .line 77
    .line 78
    invoke-static {p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    return-void
.end method
