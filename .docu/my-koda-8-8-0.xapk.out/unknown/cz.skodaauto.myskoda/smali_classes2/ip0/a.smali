.class public final synthetic Lip0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lhp0/a;

.field public final synthetic f:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lhp0/a;Lay0/a;I)V
    .locals 0

    .line 1
    iput p3, p0, Lip0/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lip0/a;->e:Lhp0/a;

    .line 4
    .line 5
    iput-object p2, p0, Lip0/a;->f:Lay0/a;

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
    iget v0, p0, Lip0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lip0/a;->e:Lhp0/a;

    .line 7
    .line 8
    iget v0, v0, Lhp0/a;->b:I

    .line 9
    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    iget-object p0, p0, Lip0/a;->f:Lay0/a;

    .line 13
    .line 14
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 18
    .line 19
    return-object p0

    .line 20
    :pswitch_0
    iget-object v0, p0, Lip0/a;->e:Lhp0/a;

    .line 21
    .line 22
    iget v0, v0, Lhp0/a;->b:I

    .line 23
    .line 24
    if-nez v0, :cond_1

    .line 25
    .line 26
    iget-object p0, p0, Lip0/a;->f:Lay0/a;

    .line 27
    .line 28
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object p0

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
