.class public final synthetic Lcom/google/gson/internal/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/gson/internal/m;
.implements Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkReadyListener;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;I)V
    .locals 0

    .line 1
    iput p2, p0, Lcom/google/gson/internal/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lcom/google/gson/internal/a;->e:Ljava/lang/String;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public a()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/gson/internal/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lcom/google/gson/o;

    .line 7
    .line 8
    iget-object p0, p0, Lcom/google/gson/internal/a;->e:Ljava/lang/String;

    .line 9
    .line 10
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw v0

    .line 14
    :pswitch_0
    new-instance v0, Lcom/google/gson/o;

    .line 15
    .line 16
    iget-object p0, p0, Lcom/google/gson/internal/a;->e:Ljava/lang/String;

    .line 17
    .line 18
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    throw v0

    .line 22
    :pswitch_1
    new-instance v0, Lcom/google/gson/o;

    .line 23
    .line 24
    iget-object p0, p0, Lcom/google/gson/internal/a;->e:Ljava/lang/String;

    .line 25
    .line 26
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw v0

    .line 30
    :pswitch_2
    new-instance v0, Lcom/google/gson/o;

    .line 31
    .line 32
    iget-object p0, p0, Lcom/google/gson/internal/a;->e:Ljava/lang/String;

    .line 33
    .line 34
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw v0

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public ready(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;)V
    .locals 7

    .line 1
    const-string v0, "sdk"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->getIdentity()Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    const/4 v5, 0x4

    .line 11
    const/4 v6, 0x0

    .line 12
    const-string v2, "ProfileId"

    .line 13
    .line 14
    iget-object v3, p0, Lcom/google/gson/internal/a;->e:Ljava/lang/String;

    .line 15
    .line 16
    const/4 v4, 0x0

    .line 17
    invoke-static/range {v1 .. v6}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->setProfileAttribute$default(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;Ljava/lang/String;Ljava/lang/String;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;ILjava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method
