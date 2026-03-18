.class Lcom/salesforce/marketingcloud/events/c$b;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/events/c;->track([Lcom/salesforce/marketingcloud/events/Event;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:[Lcom/salesforce/marketingcloud/events/Event;

.field final synthetic d:Lcom/salesforce/marketingcloud/events/c;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/events/c;Ljava/lang/String;[Ljava/lang/Object;[Lcom/salesforce/marketingcloud/events/Event;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/events/c$b;->d:Lcom/salesforce/marketingcloud/events/c;

    .line 2
    .line 3
    iput-object p4, p0, Lcom/salesforce/marketingcloud/events/c$b;->c:[Lcom/salesforce/marketingcloud/events/Event;

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
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/events/c$b;->c:[Lcom/salesforce/marketingcloud/events/Event;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    array-length v1, v0

    .line 6
    if-lez v1, :cond_1

    .line 7
    .line 8
    iget-object v1, p0, Lcom/salesforce/marketingcloud/events/c$b;->d:Lcom/salesforce/marketingcloud/events/c;

    .line 9
    .line 10
    iget-object v2, v1, Lcom/salesforce/marketingcloud/events/c;->e:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    .line 11
    .line 12
    if-eqz v2, :cond_0

    .line 13
    .line 14
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;->getEventManager()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/c$b;->c:[Lcom/salesforce/marketingcloud/events/Event;

    .line 19
    .line 20
    sget-object v1, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;->PUSH:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;

    .line 21
    .line 22
    invoke-static {v1}, Ljava/util/EnumSet;->of(Ljava/lang/Enum;)Ljava/util/EnumSet;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-static {p0, v1}, Lcom/salesforce/marketingcloud/events/d;->b([Ljava/lang/Object;Ljava/util/EnumSet;)[Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;->track([Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :cond_0
    invoke-virtual {v1, v0}, Lcom/salesforce/marketingcloud/events/c;->a([Lcom/salesforce/marketingcloud/events/Event;)V

    .line 35
    .line 36
    .line 37
    :cond_1
    return-void
.end method
