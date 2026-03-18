.class public final Lna/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lna/b0;
.implements Lla/o;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lna/k;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lna/k;->b:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;Lay0/k;Lrx0/c;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lna/k;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lna/k;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lna/a0;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2, p3}, Lna/a0;->a(Ljava/lang/String;Lay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    iget-object p0, p0, Lna/k;->b:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Lna/o;

    .line 18
    .line 19
    invoke-virtual {p0, p1, p2, p3}, Lna/o;->a(Ljava/lang/String;Lay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final d()Lua/a;
    .locals 1

    .line 1
    iget v0, p0, Lna/k;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lna/k;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lna/a0;

    .line 9
    .line 10
    iget-object p0, p0, Lna/a0;->b:Lna/g;

    .line 11
    .line 12
    return-object p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lna/k;->b:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Lna/o;

    .line 16
    .line 17
    iget-object p0, p0, Lna/o;->b:Lua/a;

    .line 18
    .line 19
    return-object p0

    .line 20
    nop

    .line 21
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
