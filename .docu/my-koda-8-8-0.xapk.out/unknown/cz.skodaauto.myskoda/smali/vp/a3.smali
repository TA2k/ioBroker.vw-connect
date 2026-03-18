.class public final Lvp/a3;
.super Lvp/o;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic e:I

.field public final synthetic f:Lvp/d3;


# direct methods
.method public synthetic constructor <init>(Lvp/d3;Lvp/g1;I)V
    .locals 0

    .line 1
    iput p3, p0, Lvp/a3;->e:I

    .line 2
    .line 3
    iput-object p1, p0, Lvp/a3;->f:Lvp/d3;

    .line 4
    .line 5
    invoke-direct {p0, p2}, Lvp/o;-><init>(Lvp/o1;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 2

    .line 1
    iget v0, p0, Lvp/a3;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lvp/a3;->f:Lvp/d3;

    .line 7
    .line 8
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Lvp/g1;

    .line 11
    .line 12
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 13
    .line 14
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 15
    .line 16
    .line 17
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 18
    .line 19
    const-string v0, "Tasks have been queued for a long time"

    .line 20
    .line 21
    invoke-virtual {p0, v0}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :pswitch_0
    iget-object p0, p0, Lvp/a3;->f:Lvp/d3;

    .line 26
    .line 27
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 28
    .line 29
    .line 30
    invoke-virtual {p0}, Lvp/d3;->r0()Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-nez v0, :cond_0

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v0, Lvp/g1;

    .line 40
    .line 41
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 42
    .line 43
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 44
    .line 45
    .line 46
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 47
    .line 48
    const-string v1, "Inactivity, disconnecting from the service"

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {p0}, Lvp/d3;->i0()V

    .line 54
    .line 55
    .line 56
    :goto_0
    return-void

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
