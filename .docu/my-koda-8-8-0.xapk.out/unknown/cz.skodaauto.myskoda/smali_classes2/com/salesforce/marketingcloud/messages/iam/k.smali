.class Lcom/salesforce/marketingcloud/messages/iam/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/salesforce/marketingcloud/messages/iam/k;",
            ">;"
        }
    .end annotation
.end field

.field private static final h:Ljava/lang/String;


# instance fields
.field private final b:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

.field private c:Lcom/salesforce/marketingcloud/messages/iam/i;

.field private d:J

.field private e:J

.field private f:J

.field private g:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/messages/iam/k$a;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/messages/iam/k$a;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/salesforce/marketingcloud/messages/iam/k;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 7
    .line 8
    const-string v0, "MessageHandler"

    .line 9
    .line 10
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    sput-object v0, Lcom/salesforce/marketingcloud/messages/iam/k;->h:Ljava/lang/String;

    .line 15
    .line 16
    return-void
.end method

.method public constructor <init>(Landroid/os/Parcel;)V
    .locals 2

    .line 8
    const-class v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v0

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->readParcelable(Ljava/lang/ClassLoader;)Landroid/os/Parcelable;

    move-result-object v0

    check-cast v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    invoke-direct {p0, v0}, Lcom/salesforce/marketingcloud/messages/iam/k;-><init>(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V

    .line 9
    invoke-virtual {p1}, Landroid/os/Parcel;->readLong()J

    move-result-wide v0

    iput-wide v0, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->d:J

    .line 10
    invoke-virtual {p1}, Landroid/os/Parcel;->readLong()J

    move-result-wide v0

    iput-wide v0, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->e:J

    .line 11
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result p1

    const/4 v0, 0x1

    if-ne p1, v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->g:Z

    return-void
.end method

.method public constructor <init>(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const-wide/16 v0, -0x1

    .line 2
    iput-wide v0, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->d:J

    const/4 v0, 0x1

    .line 3
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->g:Z

    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->b:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 5
    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->isInitializing()Z

    move-result p1

    if-nez p1, :cond_0

    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->isReady()Z

    move-result p1

    if-eqz p1, :cond_1

    .line 6
    :cond_0
    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getInstance()Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    move-result-object p1

    if-eqz p1, :cond_1

    .line 7
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getInAppMessageManager()Lcom/salesforce/marketingcloud/messages/iam/InAppMessageManager;

    move-result-object p1

    check-cast p1, Lcom/salesforce/marketingcloud/messages/iam/i;

    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->c:Lcom/salesforce/marketingcloud/messages/iam/i;

    :cond_1
    return-void
.end method

.method private p()V
    .locals 6

    .line 1
    iget-boolean v0, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->g:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->e:J

    .line 6
    .line 7
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 8
    .line 9
    .line 10
    move-result-wide v2

    .line 11
    iget-wide v4, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->f:J

    .line 12
    .line 13
    sub-long/2addr v2, v4

    .line 14
    add-long/2addr v2, v0

    .line 15
    iput-wide v2, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->e:J

    .line 16
    .line 17
    :cond_0
    return-void
.end method


# virtual methods
.method public a(Landroid/content/Context;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;)Landroid/app/PendingIntent;
    .locals 2

    .line 5
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->action()Ljava/lang/String;

    move-result-object v0

    .line 6
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->actionType()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;

    move-result-object p2

    sget-object v1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;->url:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button$ActionType;

    if-ne p2, v1, :cond_0

    if-eqz v0, :cond_0

    .line 7
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->c:Lcom/salesforce/marketingcloud/messages/iam/i;

    invoke-interface {p0}, Lcom/salesforce/marketingcloud/messages/iam/i;->urlHandler()Lcom/salesforce/marketingcloud/UrlHandler;

    move-result-object p0

    if-eqz p0, :cond_0

    .line 8
    :try_start_0
    const-string p2, "action"

    invoke-interface {p0, p1, v0, p2}, Lcom/salesforce/marketingcloud/UrlHandler;->handleUrl(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Landroid/app/PendingIntent;

    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    :catch_0
    move-exception p1

    .line 9
    sget-object p2, Lcom/salesforce/marketingcloud/messages/iam/k;->h:Ljava/lang/String;

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p0

    filled-new-array {p0}, [Ljava/lang/Object;

    move-result-object p0

    const-string v0, "Exception thrown by %s while handling url"

    invoke-static {p2, p1, v0, p0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_0
    const/4 p0, 0x0

    return-object p0
.end method

.method public a(Lcom/salesforce/marketingcloud/messages/iam/j;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->c:Lcom/salesforce/marketingcloud/messages/iam/i;

    if-eqz v0, :cond_1

    .line 2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->b:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    if-eqz p1, :cond_0

    goto :goto_0

    .line 3
    :cond_0
    invoke-static {}, Lcom/salesforce/marketingcloud/messages/iam/j;->m()Lcom/salesforce/marketingcloud/messages/iam/j;

    move-result-object p1

    .line 4
    :goto_0
    invoke-interface {v0, p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/i;->handleMessageFinished(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Lcom/salesforce/marketingcloud/messages/iam/j;)V

    :cond_1
    return-void
.end method

.method public describeContents()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public h()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->b:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->c:Lcom/salesforce/marketingcloud/messages/iam/i;

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    invoke-interface {p0, v0}, Lcom/salesforce/marketingcloud/messages/iam/i;->canDisplay(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    const/4 p0, 0x1

    .line 16
    return p0

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    return p0
.end method

.method public j()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->e:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public k()Ljava/util/Date;
    .locals 3

    .line 1
    new-instance v0, Ljava/util/Date;

    .line 2
    .line 3
    iget-wide v1, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->d:J

    .line 4
    .line 5
    invoke-direct {v0, v1, v2}, Ljava/util/Date;-><init>(J)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method

.method public l()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->b:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 2
    .line 3
    return-object p0
.end method

.method public m()Lcom/salesforce/marketingcloud/media/o;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->c:Lcom/salesforce/marketingcloud/messages/iam/i;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/messages/iam/i;->imageHandler()Lcom/salesforce/marketingcloud/media/o;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    return-object p0
.end method

.method public n()V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/iam/k;->p()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public o()V
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->d:J

    .line 2
    .line 3
    const-wide/16 v2, -0x1

    .line 4
    .line 5
    cmp-long v0, v0, v2

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 10
    .line 11
    .line 12
    move-result-wide v0

    .line 13
    iput-wide v0, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->d:J

    .line 14
    .line 15
    :cond_0
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 16
    .line 17
    .line 18
    move-result-wide v0

    .line 19
    iput-wide v0, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->f:J

    .line 20
    .line 21
    return-void
.end method

.method public q()I
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->c:Lcom/salesforce/marketingcloud/messages/iam/i;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/messages/iam/i;->getStatusBarColor()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    return p0
.end method

.method public r()V
    .locals 1

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/iam/k;->p()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->g:Z

    .line 6
    .line 7
    return-void
.end method

.method public s()Landroid/graphics/Typeface;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->c:Lcom/salesforce/marketingcloud/messages/iam/i;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/messages/iam/i;->getTypeface()Landroid/graphics/Typeface;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    return-object p0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->b:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 2
    .line 3
    invoke-virtual {p1, v0, p2}, Landroid/os/Parcel;->writeParcelable(Landroid/os/Parcelable;I)V

    .line 4
    .line 5
    .line 6
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->d:J

    .line 7
    .line 8
    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeLong(J)V

    .line 9
    .line 10
    .line 11
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->e:J

    .line 12
    .line 13
    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeLong(J)V

    .line 14
    .line 15
    .line 16
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/messages/iam/k;->g:Z

    .line 17
    .line 18
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeInt(I)V

    .line 19
    .line 20
    .line 21
    return-void
.end method
