.class public final Lcom/salesforce/marketingcloud/internal/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/internal/j$a;
    }
.end annotation


# static fields
.field public static final a:Lcom/salesforce/marketingcloud/internal/j$a;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/internal/j$a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/internal/j$a;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/internal/j;->a:Lcom/salesforce/marketingcloud/internal/j$a;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static final a(Lcom/salesforce/marketingcloud/messages/Message;Lcom/salesforce/marketingcloud/messages/Region;)Lcom/salesforce/marketingcloud/notifications/NotificationMessage;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/internal/j;->a:Lcom/salesforce/marketingcloud/internal/j$a;

    invoke-virtual {v0, p0, p1}, Lcom/salesforce/marketingcloud/internal/j$a;->a(Lcom/salesforce/marketingcloud/messages/Message;Lcom/salesforce/marketingcloud/messages/Region;)Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    move-result-object p0

    return-object p0
.end method

.method public static final a(Ljava/util/Map;)Lcom/salesforce/marketingcloud/notifications/NotificationMessage;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)",
            "Lcom/salesforce/marketingcloud/notifications/NotificationMessage;"
        }
    .end annotation

    .line 2
    sget-object v0, Lcom/salesforce/marketingcloud/internal/j;->a:Lcom/salesforce/marketingcloud/internal/j$a;

    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/internal/j$a;->a(Ljava/util/Map;)Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    move-result-object p0

    return-object p0
.end method

.method public static final a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;I)V
    .locals 1

    .line 3
    sget-object v0, Lcom/salesforce/marketingcloud/internal/j;->a:Lcom/salesforce/marketingcloud/internal/j$a;

    invoke-virtual {v0, p0, p1}, Lcom/salesforce/marketingcloud/internal/j$a;->a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;I)V

    return-void
.end method
