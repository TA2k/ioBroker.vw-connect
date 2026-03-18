.class Lcom/salesforce/marketingcloud/media/m$c;
.super Ljava/util/concurrent/FutureTask;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Comparable;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/media/m;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "c"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/util/concurrent/FutureTask<",
        "Lcom/salesforce/marketingcloud/media/n;",
        ">;",
        "Ljava/lang/Comparable<",
        "Ljava/lang/Runnable;",
        ">;"
    }
.end annotation


# instance fields
.field private final b:Lcom/salesforce/marketingcloud/media/n;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/media/n;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, p1, v0}, Ljava/util/concurrent/FutureTask;-><init>(Ljava/lang/Runnable;Ljava/lang/Object;)V

    .line 3
    .line 4
    .line 5
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/m$c;->b:Lcom/salesforce/marketingcloud/media/n;

    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public a(Ljava/lang/Runnable;)I
    .locals 1

    .line 1
    instance-of v0, p1, Lcom/salesforce/marketingcloud/media/m$c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Lcom/salesforce/marketingcloud/media/m$c;

    .line 6
    .line 7
    iget-object p1, p1, Lcom/salesforce/marketingcloud/media/m$c;->b:Lcom/salesforce/marketingcloud/media/n;

    .line 8
    .line 9
    iget-object p1, p1, Lcom/salesforce/marketingcloud/media/n;->m:Lcom/salesforce/marketingcloud/media/o$c;

    .line 10
    .line 11
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/m$c;->b:Lcom/salesforce/marketingcloud/media/n;

    .line 16
    .line 17
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/n;->m:Lcom/salesforce/marketingcloud/media/o$c;

    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    sub-int/2addr p1, p0

    .line 24
    return p1

    .line 25
    :cond_0
    const/4 p0, 0x0

    .line 26
    return p0
.end method

.method public bridge synthetic compareTo(Ljava/lang/Object;)I
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/Runnable;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/media/m$c;->a(Ljava/lang/Runnable;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
