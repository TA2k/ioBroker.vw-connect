.class public final synthetic Lt10/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Lao0/b;


# direct methods
.method public synthetic constructor <init>(Lay0/k;Lao0/b;I)V
    .locals 0

    .line 1
    iput p3, p0, Lt10/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lt10/j;->e:Lay0/k;

    .line 4
    .line 5
    iput-object p2, p0, Lt10/j;->f:Lao0/b;

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
    .locals 2

    .line 1
    iget v0, p0, Lt10/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lt10/j;->f:Lao0/b;

    .line 7
    .line 8
    iget-wide v0, v0, Lao0/b;->a:J

    .line 9
    .line 10
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iget-object p0, p0, Lt10/j;->e:Lay0/k;

    .line 15
    .line 16
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    return-object p0

    .line 22
    :pswitch_0
    iget-object v0, p0, Lt10/j;->f:Lao0/b;

    .line 23
    .line 24
    iget-wide v0, v0, Lao0/b;->a:J

    .line 25
    .line 26
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    iget-object p0, p0, Lt10/j;->e:Lay0/k;

    .line 31
    .line 32
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
