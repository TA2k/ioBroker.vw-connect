.class public final synthetic Ltj/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;


# direct methods
.method public synthetic constructor <init>(ILcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;Ljava/lang/String;)V
    .locals 0

    .line 1
    iput p1, p0, Ltj/j;->d:I

    iput-object p3, p0, Ltj/j;->e:Ljava/lang/String;

    iput-object p2, p0, Ltj/j;->f:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;Ljava/lang/String;)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Ltj/j;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ltj/j;->f:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    iput-object p2, p0, Ltj/j;->e:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ltj/j;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 8
    .line 9
    .line 10
    move-result p2

    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Ltj/j;->f:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 15
    .line 16
    iget-object p0, p0, Ltj/j;->e:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v0, p0, p1, p2}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->g(Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;Ljava/lang/String;Ll2/o;I)Llx0/b0;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    iget-object v0, p0, Ltj/j;->f:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 24
    .line 25
    iget-object p0, p0, Ltj/j;->e:Ljava/lang/String;

    .line 26
    .line 27
    invoke-static {v0, p0, p1, p2}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->d(Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;Ljava/lang/String;Ll2/o;I)Llx0/b0;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    :pswitch_1
    iget-object v0, p0, Ltj/j;->f:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 33
    .line 34
    iget-object p0, p0, Ltj/j;->e:Ljava/lang/String;

    .line 35
    .line 36
    invoke-static {v0, p0, p1, p2}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->s(Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;Ljava/lang/String;Ll2/o;I)Llx0/b0;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
