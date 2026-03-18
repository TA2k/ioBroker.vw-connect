.class public final Lcom/salesforce/marketingcloud/push/k$a$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/push/k$a;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/push/k$a$a$a;
    }
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/push/k$a$a;-><init>()V

    return-void
.end method

.method public static synthetic a(Lcom/salesforce/marketingcloud/push/k$a$a;Lcom/salesforce/marketingcloud/push/data/Template$Type;Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Lcom/salesforce/marketingcloud/media/o;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/push/k;
    .locals 0

    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_0

    const/4 p4, 0x0

    .line 1
    :cond_0
    invoke-virtual {p0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/push/k$a$a;->a(Lcom/salesforce/marketingcloud/push/data/Template$Type;Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Lcom/salesforce/marketingcloud/media/o;)Lcom/salesforce/marketingcloud/push/k;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public final a(Lcom/salesforce/marketingcloud/push/data/Template$Type;Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Lcom/salesforce/marketingcloud/media/o;)Lcom/salesforce/marketingcloud/push/k;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/push/data/Template$Type;",
            "Landroid/content/Context;",
            "Lcom/salesforce/marketingcloud/notifications/NotificationMessage;",
            "Lcom/salesforce/marketingcloud/media/o;",
            ")",
            "Lcom/salesforce/marketingcloud/push/k<",
            "Lcom/salesforce/marketingcloud/push/data/Template;",
            ">;"
        }
    .end annotation

    const-string p0, "type"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p0, "context"

    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p0, "message"

    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    sget-object p0, Lcom/salesforce/marketingcloud/push/k$a$a$a;->a:[I

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    aget p0, p0, p1

    const/4 p1, 0x1

    if-eq p0, p1, :cond_1

    const/4 p1, 0x2

    if-ne p0, p1, :cond_0

    .line 3
    new-instance p0, Lcom/salesforce/marketingcloud/push/buttons/c;

    new-instance p1, Lcom/salesforce/marketingcloud/push/b;

    invoke-direct {p1, p2, p3}, Lcom/salesforce/marketingcloud/push/b;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V

    invoke-direct {p0, p2, p1}, Lcom/salesforce/marketingcloud/push/buttons/c;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/push/b;)V

    return-object p0

    :cond_0
    new-instance p0, La8/r0;

    .line 4
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 5
    throw p0

    .line 6
    :cond_1
    new-instance p0, Lcom/salesforce/marketingcloud/push/carousel/d;

    .line 7
    new-instance p1, Lcom/salesforce/marketingcloud/push/carousel/b;

    invoke-direct {p1, p2, p3}, Lcom/salesforce/marketingcloud/push/carousel/b;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V

    .line 8
    invoke-direct {p0, p1, p2, p4}, Lcom/salesforce/marketingcloud/push/carousel/d;-><init>(Lcom/salesforce/marketingcloud/push/carousel/b;Landroid/content/Context;Lcom/salesforce/marketingcloud/media/o;)V

    return-object p0
.end method
