.class public final Lcom/salesforce/marketingcloud/events/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/events/Event;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public attributes()Ljava/util/Map;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/Object;",
            ">;"
        }
    .end annotation

    .line 1
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 2
    .line 3
    return-object p0
.end method

.method public name()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "$appOpen"

    .line 2
    .line 3
    return-object p0
.end method
