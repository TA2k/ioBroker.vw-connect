.class public final synthetic Luz/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Ltz/z;


# direct methods
.method public synthetic constructor <init>(Lay0/k;Ltz/z;I)V
    .locals 0

    .line 1
    iput p3, p0, Luz/h;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Luz/h;->e:Lay0/k;

    .line 4
    .line 5
    iput-object p2, p0, Luz/h;->f:Ltz/z;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Luz/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Luz/h;->e:Lay0/k;

    .line 7
    .line 8
    iget-object p0, p0, Luz/h;->f:Ltz/z;

    .line 9
    .line 10
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    return-object p0

    .line 16
    :pswitch_0
    iget-object v0, p0, Luz/h;->e:Lay0/k;

    .line 17
    .line 18
    iget-object p0, p0, Luz/h;->f:Ltz/z;

    .line 19
    .line 20
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    goto :goto_0

    .line 24
    :pswitch_1
    iget-object v0, p0, Luz/h;->e:Lay0/k;

    .line 25
    .line 26
    iget-object p0, p0, Luz/h;->f:Ltz/z;

    .line 27
    .line 28
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    nop

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
