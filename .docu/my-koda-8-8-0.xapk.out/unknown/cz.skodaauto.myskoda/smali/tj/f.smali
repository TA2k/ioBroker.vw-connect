.class public final synthetic Ltj/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

.field public final synthetic f:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(ILcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;Ljava/lang/String;)V
    .locals 0

    .line 1
    iput p1, p0, Ltj/f;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Ltj/f;->e:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 4
    .line 5
    iput-object p3, p0, Ltj/f;->f:Ljava/lang/String;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ltj/f;->d:I

    .line 2
    .line 3
    check-cast p1, Lay0/a;

    .line 4
    .line 5
    check-cast p2, Ll2/o;

    .line 6
    .line 7
    check-cast p3, Ljava/lang/Integer;

    .line 8
    .line 9
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result p3

    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Ltj/f;->e:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 17
    .line 18
    iget-object p0, p0, Ltj/f;->f:Ljava/lang/String;

    .line 19
    .line 20
    invoke-static {v0, p0, p1, p2, p3}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->j(Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;Ljava/lang/String;Lay0/a;Ll2/o;I)Llx0/b0;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :pswitch_0
    iget-object v0, p0, Ltj/f;->e:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 26
    .line 27
    iget-object p0, p0, Ltj/f;->f:Ljava/lang/String;

    .line 28
    .line 29
    invoke-static {v0, p0, p1, p2, p3}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->J(Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;Ljava/lang/String;Lay0/a;Ll2/o;I)Llx0/b0;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :pswitch_1
    iget-object v0, p0, Ltj/f;->e:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 35
    .line 36
    iget-object p0, p0, Ltj/f;->f:Ljava/lang/String;

    .line 37
    .line 38
    invoke-static {v0, p0, p1, p2, p3}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->E(Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;Ljava/lang/String;Lay0/a;Ll2/o;I)Llx0/b0;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
