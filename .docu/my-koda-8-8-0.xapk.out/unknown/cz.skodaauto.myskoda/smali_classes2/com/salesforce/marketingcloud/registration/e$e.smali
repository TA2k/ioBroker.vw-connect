.class abstract Lcom/salesforce/marketingcloud/registration/e$e;
.super Landroid/os/CountDownTimer;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/registration/e;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x409
    name = "e"
.end annotation


# direct methods
.method public constructor <init>(I)V
    .locals 4

    int-to-long v0, p1

    const-wide/16 v2, 0x3e8

    .line 1
    invoke-direct {p0, v0, v1, v2, v3}, Lcom/salesforce/marketingcloud/registration/e$e;-><init>(JJ)V

    return-void
.end method

.method private constructor <init>(JJ)V
    .locals 0

    .line 2
    invoke-direct {p0, p1, p2, p3, p4}, Landroid/os/CountDownTimer;-><init>(JJ)V

    return-void
.end method


# virtual methods
.method public onTick(J)V
    .locals 0

    .line 1
    return-void
.end method
