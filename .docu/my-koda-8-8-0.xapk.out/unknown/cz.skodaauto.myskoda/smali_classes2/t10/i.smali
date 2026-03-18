.class public final synthetic Lt10/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/n;

.field public final synthetic f:Lao0/b;


# direct methods
.method public synthetic constructor <init>(Lay0/n;Lao0/b;I)V
    .locals 0

    .line 1
    iput p3, p0, Lt10/i;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lt10/i;->e:Lay0/n;

    .line 4
    .line 5
    iput-object p2, p0, Lt10/i;->f:Lao0/b;

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
    .locals 2

    .line 1
    iget v0, p0, Lt10/i;->d:I

    .line 2
    .line 3
    check-cast p1, Ljava/lang/Boolean;

    .line 4
    .line 5
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 6
    .line 7
    .line 8
    packed-switch v0, :pswitch_data_0

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lt10/i;->f:Lao0/b;

    .line 12
    .line 13
    iget-wide v0, v0, Lao0/b;->a:J

    .line 14
    .line 15
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    iget-object p0, p0, Lt10/i;->e:Lay0/n;

    .line 20
    .line 21
    invoke-interface {p0, v0, p1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_0
    iget-object v0, p0, Lt10/i;->f:Lao0/b;

    .line 28
    .line 29
    iget-wide v0, v0, Lao0/b;->a:J

    .line 30
    .line 31
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    iget-object p0, p0, Lt10/i;->e:Lay0/n;

    .line 36
    .line 37
    invoke-interface {p0, v0, p1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
