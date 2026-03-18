.class public final synthetic Lh2/p3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/n;

.field public final synthetic f:Ljava/lang/Long;


# direct methods
.method public synthetic constructor <init>(Lay0/n;Ljava/lang/Long;I)V
    .locals 0

    .line 1
    iput p3, p0, Lh2/p3;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/p3;->e:Lay0/n;

    .line 4
    .line 5
    iput-object p2, p0, Lh2/p3;->f:Ljava/lang/Long;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lh2/p3;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh2/p3;->f:Ljava/lang/Long;

    .line 7
    .line 8
    check-cast p1, Ljava/lang/Long;

    .line 9
    .line 10
    iget-object p0, p0, Lh2/p3;->e:Lay0/n;

    .line 11
    .line 12
    invoke-interface {p0, v0, p1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_0
    iget-object v0, p0, Lh2/p3;->f:Ljava/lang/Long;

    .line 19
    .line 20
    check-cast p1, Ljava/lang/Long;

    .line 21
    .line 22
    iget-object p0, p0, Lh2/p3;->e:Lay0/n;

    .line 23
    .line 24
    invoke-interface {p0, p1, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
