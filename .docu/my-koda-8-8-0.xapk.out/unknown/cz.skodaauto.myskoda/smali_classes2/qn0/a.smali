.class public final synthetic Lqn0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Lon0/a0;


# direct methods
.method public synthetic constructor <init>(Lay0/k;Lon0/a0;I)V
    .locals 0

    .line 1
    iput p3, p0, Lqn0/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lqn0/a;->e:Lay0/k;

    .line 4
    .line 5
    iput-object p2, p0, Lqn0/a;->f:Lon0/a0;

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
    iget v0, p0, Lqn0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lqn0/a;->f:Lon0/a0;

    .line 7
    .line 8
    iget-object v0, v0, Lon0/a0;->d:Ljava/lang/String;

    .line 9
    .line 10
    iget-object p0, p0, Lqn0/a;->e:Lay0/k;

    .line 11
    .line 12
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget-object v0, p0, Lqn0/a;->f:Lon0/a0;

    .line 19
    .line 20
    iget-object v0, v0, Lon0/a0;->d:Ljava/lang/String;

    .line 21
    .line 22
    iget-object p0, p0, Lqn0/a;->e:Lay0/k;

    .line 23
    .line 24
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    :pswitch_1
    iget-object v0, p0, Lqn0/a;->f:Lon0/a0;

    .line 29
    .line 30
    iget-object v0, v0, Lon0/a0;->d:Ljava/lang/String;

    .line 31
    .line 32
    iget-object p0, p0, Lqn0/a;->e:Lay0/k;

    .line 33
    .line 34
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :pswitch_2
    iget-object v0, p0, Lqn0/a;->e:Lay0/k;

    .line 39
    .line 40
    iget-object p0, p0, Lqn0/a;->f:Lon0/a0;

    .line 41
    .line 42
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    nop

    .line 47
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
