.class public final synthetic Ltj/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;


# direct methods
.method public synthetic constructor <init>(Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;I)V
    .locals 0

    .line 1
    iput p2, p0, Ltj/h;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltj/h;->e:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ltj/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltj/h;->e:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 7
    .line 8
    check-cast p1, Ljava/lang/String;

    .line 9
    .line 10
    invoke-static {p0, p1}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->a(Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;Ljava/lang/String;)Llx0/b0;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    check-cast p1, Ljava/lang/Boolean;

    .line 16
    .line 17
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    iget-object p0, p0, Ltj/h;->e:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 22
    .line 23
    invoke-static {p0, p1}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->H(Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;Z)Llx0/b0;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0

    .line 28
    :pswitch_1
    iget-object p0, p0, Ltj/h;->e:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 29
    .line 30
    check-cast p1, Ltb/t;

    .line 31
    .line 32
    invoke-static {p0, p1}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->n(Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;Ltb/t;)Llx0/b0;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0

    .line 37
    :pswitch_2
    iget-object p0, p0, Ltj/h;->e:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 38
    .line 39
    check-cast p1, Lgi/c;

    .line 40
    .line 41
    invoke-static {p0, p1}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->r(Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;Lgi/c;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0

    .line 46
    :pswitch_3
    iget-object p0, p0, Ltj/h;->e:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 47
    .line 48
    check-cast p1, Lgi/c;

    .line 49
    .line 50
    invoke-static {p0, p1}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->p(Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;Lgi/c;)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    return-object p0

    .line 55
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
