.class public final synthetic Lnd0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Laq/g;
.implements Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkReadyListener;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/k;


# direct methods
.method public synthetic constructor <init>(ILay0/k;)V
    .locals 0

    .line 1
    iput p1, p0, Lnd0/c;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lnd0/c;->e:Lay0/k;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public c(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lnd0/c;->e:Lay0/k;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public ready(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;)V
    .locals 1

    .line 1
    iget v0, p0, Lnd0/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string v0, "sdk"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Lyp0/g;

    .line 12
    .line 13
    iget-object p0, p0, Lnd0/c;->e:Lay0/k;

    .line 14
    .line 15
    invoke-direct {v0, p0}, Lyp0/g;-><init>(Lay0/k;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->mp(Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleReadyListener;)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :pswitch_0
    const-string v0, "sdk"

    .line 23
    .line 24
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    new-instance v0, Lyp0/f;

    .line 28
    .line 29
    iget-object p0, p0, Lnd0/c;->e:Lay0/k;

    .line 30
    .line 31
    invoke-direct {v0, p0}, Lyp0/f;-><init>(Lay0/k;)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->mp(Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleReadyListener;)V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method
