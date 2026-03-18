.class public final synthetic Lrd/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lki/j;


# direct methods
.method public synthetic constructor <init>(Lki/j;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lrd/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lrd/b;->e:Lki/j;

    return-void
.end method

.method public synthetic constructor <init>(Lki/j;I)V
    .locals 0

    .line 2
    const/4 p2, 0x0

    iput p2, p0, Lrd/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lrd/b;->e:Lki/j;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lrd/b;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    iget-object p0, p0, Lrd/b;->e:Lki/j;

    .line 15
    .line 16
    invoke-static {p0, p1, p2}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->w(Lki/j;Ll2/o;I)Llx0/b0;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    const/16 p2, 0x9

    .line 25
    .line 26
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 27
    .line 28
    .line 29
    move-result p2

    .line 30
    iget-object p0, p0, Lrd/b;->e:Lki/j;

    .line 31
    .line 32
    invoke-static {p0, p1, p2}, Lkp/y;->a(Lki/j;Ll2/o;I)V

    .line 33
    .line 34
    .line 35
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    return-object p0

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
